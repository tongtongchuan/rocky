use std::{
    error::Error,
    fmt,
    future::Future,
    io, iter,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use futures_util::future::BoxFuture;
use http::{HeaderMap, Request, Response, Uri, uri::Scheme};
use hyper::{body::Incoming, rt};
use hyper_rustls::{HttpsConnector, MaybeHttpsStream};
use hyper_util::{
    client::legacy::{
        Client, Error as ClientError,
        connect::{
            CaptureConnection, Connected, Connection, HttpConnector, capture_connection, dns::Name,
        },
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use tokio::{
    net::TcpStream,
    sync::Semaphore,
    task::spawn_blocking,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tower_service::Service;

use crate::{
    body::Body,
    config::{Limits, Upstream, UpstreamProtocol},
};

static DNS_LOOKUPS: Semaphore = Semaphore::const_new(32);
const MAX_RESOLVED_ADDRESSES: usize = 64;
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(PartialEq, Eq)]
pub(super) struct TransportSettings {
    protocol: UpstreamProtocol,
    connect_timeout: Duration,
    max_idle_connections: usize,
    max_header_bytes: usize,
    max_buffer_bytes: usize,
    h2_connection_window: u32,
    trusted_certificates: Vec<CertificateDer<'static>>,
}

impl TransportSettings {
    pub(super) fn load(config: &Upstream, limits: &Limits) -> Result<Self> {
        let mut trusted_certificates = if let Some(file) = &config.trust_roots {
            read_certificates(file)?
        } else if config
            .endpoints
            .iter()
            .any(|endpoint| is_https(&endpoint.url))
        {
            let roots = rustls_native_certs::load_native_certs();
            ensure!(
                !roots.certs.is_empty(),
                "no system trust roots available for HTTPS upstreams"
            );
            roots.certs
        } else {
            Vec::new()
        };
        trusted_certificates.sort_unstable_by(|left, right| left.as_ref().cmp(right.as_ref()));
        trusted_certificates.dedup();
        Ok(Self {
            protocol: config.protocol,
            connect_timeout: config.connect_timeout,
            max_idle_connections: config.max_idle_connections,
            max_header_bytes: limits.max_header_bytes,
            max_buffer_bytes: limits.max_buffer_bytes,
            h2_connection_window: (limits.max_buffer_bytes as u32)
                .saturating_mul(limits.max_streams_per_connection)
                .clamp(65_535, i32::MAX as u32),
            trusted_certificates,
        })
    }

    pub(super) fn compatible(&self, previous: &Self, url: &Uri) -> bool {
        self.protocol == previous.protocol
            && self.connect_timeout == previous.connect_timeout
            && self.max_idle_connections == previous.max_idle_connections
            && self.max_header_bytes == previous.max_header_bytes
            && self.max_buffer_bytes == previous.max_buffer_bytes
            && (self.protocol == UpstreamProtocol::H1
                || self.h2_connection_window == previous.h2_connection_window)
            && (!is_https(url) || self.trusted_certificates == previous.trusted_certificates)
    }

    pub(super) fn tls_config(&self, explicit_roots: bool) -> Result<Arc<ClientConfig>> {
        let mut roots = RootCertStore::empty();
        if explicit_roots {
            for cert in &self.trusted_certificates {
                roots
                    .add(cert.clone())
                    .context("invalid upstream trust anchor")?;
            }
        } else {
            roots.add_parsable_certificates(self.trusted_certificates.iter().cloned());
            ensure!(
                self.trusted_certificates.is_empty() || !roots.is_empty(),
                "no usable system trust roots for HTTPS upstreams"
            );
        }
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![match self.protocol {
            UpstreamProtocol::H1 => b"http/1.1".to_vec(),
            UpstreamProtocol::H2 => b"h2".to_vec(),
        }];
        Ok(Arc::new(config))
    }
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open upstream trust roots {}", path.display()))?;
    let roots = rustls_pemfile::certs(&mut io::BufReader::new(file))
        .collect::<io::Result<Vec<_>>>()
        .with_context(|| format!("parse upstream trust roots {}", path.display()))?;
    ensure!(
        !roots.is_empty(),
        "no certificates in upstream trust roots {}",
        path.display()
    );
    Ok(roots)
}

pub(super) struct Transport {
    client: Client<Connector, Body>,
    probe_client: Client<Connector, Body>,
    pub(super) resolution: Arc<Resolution>,
    pub(super) in_flight: AtomicUsize,
    connect_timeout: Duration,
    max_header_bytes: usize,
}

impl Transport {
    pub(super) fn new(url: &Uri, settings: &TransportSettings, tls: Arc<ClientConfig>) -> Self {
        let resolution = Arc::new(Resolution::new(url));
        let mut http = HttpConnector::new_with_resolver(CachedResolver(Arc::clone(&resolution)));
        http.enforce_http(false);
        http.set_connect_timeout(Some(settings.connect_timeout));
        http.set_nodelay(true);
        let connector = Connector {
            inner: HttpsConnector::from((http, tls)),
            http2: settings.protocol == UpstreamProtocol::H2,
            connect_timeout: settings.connect_timeout,
        };
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .retry_canceled_requests(false)
            .set_host(false)
            .http2_only(connector.http2)
            .http1_max_buf_size(
                settings
                    .max_buffer_bytes
                    .min(settings.max_header_bytes.max(8192)),
            )
            .http1_max_headers(128)
            .http2_max_header_list_size(settings.max_header_bytes as u32)
            .http2_max_send_buf_size(settings.max_buffer_bytes)
            .http2_initial_stream_window_size(settings.max_buffer_bytes as u32)
            .http2_initial_connection_window_size(settings.h2_connection_window)
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(IDLE_CONNECTION_TIMEOUT)
            .pool_max_idle_per_host(settings.max_idle_connections);
        let client = builder.build(connector.clone());
        let probe_client = builder.pool_max_idle_per_host(0).build(connector);
        Self {
            client,
            probe_client,
            resolution,
            in_flight: AtomicUsize::new(0),
            connect_timeout: settings.connect_timeout,
            max_header_bytes: settings.max_header_bytes,
        }
    }

    pub(super) fn has_capacity(&self, limit: usize) -> bool {
        self.in_flight.load(Ordering::Relaxed) < limit
    }

    pub(super) fn reserve(&self, limit: usize) -> bool {
        let mut current = self.in_flight.load(Ordering::Relaxed);
        while current < limit {
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
        false
    }

    pub(super) async fn request(
        &self,
        mut request: Request<Body>,
        deadline: Instant,
        head_timeout: Duration,
    ) -> Result<UpstreamResponse, AttemptError> {
        let mut connection = capture_connection(&mut request);
        let mut response = self.client.request(request);
        let connect_deadline = deadline.min(Instant::now() + self.connect_timeout);
        let response = tokio::select! {
            biased;
            result = &mut response => self.check_response(result)?,
            _ = async { drop(connection.wait_for_connection_metadata().await) } => {
                let head_deadline = deadline.min(Instant::now() + head_timeout);
                self.check_response(timeout_at(head_deadline, response).await.map_err(|_| AttemptError::HeadTimeout)?)?
            }
            _ = sleep_until(connect_deadline) => return Err(AttemptError::ConnectTimeout),
        };
        let socket = response.extensions().get::<SocketAbort>().cloned();
        Ok(UpstreamResponse {
            response,
            connection: socket.map(|socket| Http2Connection { socket, connection }),
        })
    }

    pub(super) async fn probe(&self, request: Request<Body>, deadline: Duration) -> bool {
        match timeout(deadline, self.probe_client.request(request)).await {
            Ok(response) => self
                .check_response(response)
                .is_ok_and(|response| response.status().is_success()),
            Err(_) => false,
        }
    }

    fn check_response(
        &self,
        response: Result<Response<Incoming>, ClientError>,
    ) -> Result<Response<Incoming>, AttemptError> {
        let response = response.map_err(AttemptError::from_client)?;
        if response.status().is_informational()
            || !super::supports_transfer_encoding(response.headers(), response.version())
            || !within_header_limit(response.headers(), self.max_header_bytes)
        {
            return Err(AttemptError::Protocol);
        }
        Ok(response)
    }
}

pub(super) struct UpstreamResponse {
    pub(super) response: Response<Incoming>,
    pub(super) connection: Option<Http2Connection>,
}

pub(super) struct Http2Connection {
    socket: SocketAbort,
    connection: CaptureConnection,
}

impl Http2Connection {
    pub(super) fn retire_if_upload_stalls(
        self,
        upload_finished: CancellationToken,
        idle: Duration,
    ) {
        tokio::spawn(async move {
            if timeout(idle, upload_finished.cancelled()).await.is_err()
                && !upload_finished.is_cancelled()
            {
                // Hyper can leave its request sender parked on peer flow control after the
                // response has been dropped. Retire that socket after the idle deadline.
                if let Some(connected) = self.connection.connection_metadata().as_ref() {
                    connected.poison();
                }
                self.socket.0.cancel();
            }
        });
    }
}

fn within_header_limit(headers: &HeaderMap, limit: usize) -> bool {
    headers
        .iter()
        .try_fold(limit, |remaining, (name, value)| {
            remaining.checked_sub(name.as_str().len() + value.as_bytes().len() + 4)
        })
        .is_some()
}

#[derive(Clone, Copy, Debug)]
pub(super) enum AttemptError {
    Connect,
    ConnectTimeout,
    HeadTimeout,
    Protocol,
}

impl AttemptError {
    fn from_client(error: ClientError) -> Self {
        match error
            .source()
            .and_then(|source| source.downcast_ref::<DialError>())
        {
            Some(DialError::Timeout) => Self::ConnectTimeout,
            Some(DialError::Failed) => Self::Connect,
            None => Self::Protocol,
        }
    }

    pub(super) fn can_retry(self) -> bool {
        matches!(self, Self::Connect | Self::ConnectTimeout)
    }

    pub(super) fn timed_out(self) -> bool {
        matches!(self, Self::ConnectTimeout | Self::HeadTimeout)
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::ConnectTimeout => "connect_timeout",
            Self::HeadTimeout => "response_head_timeout",
            Self::Protocol => "protocol",
        }
    }
}

pub(super) struct Resolution {
    host: String,
    port: u16,
    literal: bool,
    state: Mutex<AddressState>,
}

#[derive(Default)]
struct AddressState {
    addresses: Vec<SocketAddr>,
    lookup_failed: bool,
    worker: Option<Arc<()>>,
}

impl Resolution {
    fn new(url: &Uri) -> Self {
        let host = url.host().unwrap().trim_matches(['[', ']']).to_owned();
        let port = url
            .port_u16()
            .unwrap_or(if is_https(url) { 443 } else { 80 });
        let literal = host.parse::<IpAddr>().ok();
        let mut state = AddressState::default();
        if let Some(ip) = literal {
            state.addresses.push(SocketAddr::new(ip, port));
        }
        Self {
            host,
            port,
            literal: literal.is_some(),
            state: Mutex::new(state),
        }
    }

    pub(super) fn ready(&self) -> bool {
        !self.state.lock().unwrap().addresses.is_empty()
    }

    pub(super) fn status(&self) -> (bool, bool) {
        let state = self.state.lock().unwrap();
        (!state.addresses.is_empty(), state.lookup_failed)
    }

    pub(super) fn needs_lookup(&self) -> bool {
        !self.literal
    }

    pub(super) fn activate(&self, worker: &Arc<()>) {
        self.state.lock().unwrap().worker = Some(Arc::clone(worker));
    }

    pub(super) fn deactivate(&self, worker: &Arc<()>) {
        let mut state = self.state.lock().unwrap();
        if owned_by(state.worker.as_ref(), worker) {
            state.worker = None;
        }
    }

    pub(super) async fn refresh(&self, worker: &Arc<()>, deadline: Duration) -> bool {
        let permit = DNS_LOOKUPS.acquire().await.unwrap();
        let host = self.host.clone();
        let port = self.port;
        let query = spawn_blocking(move || {
            // Keep the permit until the system resolver returns, even if its caller times out.
            let _permit = permit;
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.take(MAX_RESOLVED_ADDRESSES).collect::<Vec<_>>())
        });
        let result = timeout(deadline, query).await;
        let mut state = self.state.lock().unwrap();
        if !owned_by(state.worker.as_ref(), worker) {
            return false;
        }
        if let Ok(Ok(Ok(addresses))) = result
            && !addresses.is_empty()
        {
            let changed = state.addresses != addresses;
            state.addresses = addresses;
            state.lookup_failed = false;
            changed
        } else {
            state.lookup_failed = true;
            false
        }
    }
}

pub(super) fn owned_by(owner: Option<&Arc<()>>, worker: &Arc<()>) -> bool {
    owner.is_some_and(|owner| Arc::ptr_eq(owner, worker))
}

#[derive(Clone)]
struct CachedResolver(Arc<Resolution>);

impl Service<Name> for CachedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = std::future::Ready<io::Result<Self::Response>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let state = self.0.state.lock().unwrap();
        let result =
            if state.addresses.is_empty() || !self.0.host.eq_ignore_ascii_case(name.as_str()) {
                Err(io::Error::other("no cached upstream addresses"))
            } else {
                Ok(state.addresses.clone().into_iter())
            };
        std::future::ready(result)
    }
}

#[derive(Clone)]
struct Connector {
    inner: HttpsConnector<HttpConnector<CachedResolver>>,
    http2: bool,
    connect_timeout: Duration,
}

#[derive(Debug)]
enum DialError {
    Timeout,
    Failed,
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Timeout => "upstream connection deadline expired",
            Self::Failed => "upstream connection failed",
        })
    }
}

impl Error for DialError {}

impl Service<Uri> for Connector {
    type Response = UpstreamIo;
    type Error = DialError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|_| DialError::Failed)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let http2 = self.http2;
        let require_h2_alpn = http2 && is_https(&uri);
        let future = self.inner.call(uri);
        let deadline = self.connect_timeout;
        Box::pin(async move {
            let stream = timeout(deadline, future)
                .await
                .map_err(|_| DialError::Timeout)?
                .map_err(|error| {
                    let source: &dyn Error = error.as_ref();
                    if iter::successors(Some(source), |&error| error.source()).any(|cause| {
                        cause
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
                    }) {
                        DialError::Timeout
                    } else {
                        DialError::Failed
                    }
                })?;
            if require_h2_alpn && !stream.connected().is_negotiated_h2() {
                return Err(DialError::Failed);
            }
            Ok(UpstreamIo::new(stream, http2))
        })
    }
}

#[derive(Clone)]
struct SocketAbort(CancellationToken);

struct UpstreamIo {
    socket: MaybeHttpsStream<TokioIo<TcpStream>>,
    retired: Option<(SocketAbort, Pin<Box<WaitForCancellationFutureOwned>>)>,
}

impl UpstreamIo {
    fn new(socket: MaybeHttpsStream<TokioIo<TcpStream>>, http2: bool) -> Self {
        let retired = http2.then(|| {
            let token = CancellationToken::new();
            let wait = Box::pin(token.clone().cancelled_owned());
            (SocketAbort(token), wait)
        });
        Self { socket, retired }
    }

    fn check_retirement(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some((abort, wait)) = &mut self.retired
            && (abort.0.is_cancelled() || wait.as_mut().poll(cx).is_ready())
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stalled upstream HTTP/2 connection retired",
            ));
        }
        Ok(())
    }
}

impl Connection for UpstreamIo {
    fn connected(&self) -> Connected {
        let connected = self.socket.connected();
        match &self.retired {
            Some((abort, _)) => connected.extra(abort.clone()),
            None => connected,
        }
    }
}

impl rt::Read for UpstreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        self.check_retirement(cx)?;
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl rt::Write for UpstreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_retirement(cx)?;
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_retirement(cx)?;
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_retirement(cx)?;
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.socket.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.check_retirement(cx)?;
        Pin::new(&mut self.socket).poll_write_vectored(cx, bufs)
    }
}

fn is_https(uri: &Uri) -> bool {
    uri.scheme() == Some(&Scheme::HTTPS)
}
