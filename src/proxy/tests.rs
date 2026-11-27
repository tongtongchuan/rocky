use std::{
    convert::Infallible,
    future::{Future, pending},
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::AtomicUsize,
};

use http::{
    HeaderMap, HeaderValue, Uri, Version,
    header::{self, HOST},
};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    body::Incoming,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::CertifiedKey;
use rustls::ServerConfig;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;

use super::*;

const LIMITS: Limits = Limits {
    max_connections: 128,
    max_requests: 64,
    max_streams_per_connection: 64,
    max_header_bytes: 32 * 1024,
    max_body_bytes: 1024 * 1024,
    max_buffer_bytes: 64 * 1024,
    max_file_operations: 64,
    handshake_timeout: Duration::from_secs(1),
    request_head_timeout: Duration::from_secs(1),
    body_idle_timeout: Duration::from_secs(1),
};

struct Origin {
    address: SocketAddr,
    accept: JoinHandle<()>,
}

impl Origin {
    async fn start<F, Fut>(protocol: UpstreamProtocol, tls: Option<TlsAcceptor>, handler: F) -> Self
    where
        F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Response<Body>> + Send + 'static,
    {
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    next = socket.accept() => {
                        let (stream, _) = next.unwrap();
                        let service = handler.clone();
                        let tls = tls.clone();
                        connections.spawn(async move {
                            if let Some(tls) = tls {
                                if let Ok(stream) = tls.accept(stream).await {
                                    serve(stream, protocol, service).await;
                                }
                            } else {
                                serve(stream, protocol, service).await;
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        Self { address, accept }
    }

    fn uri(&self, scheme: &str) -> Uri {
        format!("{scheme}://{}/", self.address).parse().unwrap()
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn serve<I, F, Fut>(io: I, protocol: UpstreamProtocol, handler: F)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    F: Fn(Request<Incoming>) -> Fut + Send + 'static,
    Fut: Future<Output = Response<Body>> + Send + 'static,
{
    let service = service_fn(move |request| {
        let response = handler(request);
        async move { Ok::<_, Infallible>(response.await) }
    });
    let io = TokioIo::new(io);
    let _ = match protocol {
        UpstreamProtocol::H1 => http1::Builder::new().serve_connection(io, service).await,
        UpstreamProtocol::H2 => {
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
        }
    };
}

fn config(protocol: UpstreamProtocol, urls: impl IntoIterator<Item = Uri>) -> Upstream {
    Upstream {
        protocol,
        health_path: None,
        endpoints: urls
            .into_iter()
            .map(|url| Endpoint {
                url,
                weight: 1,
                max_connections: 8,
            })
            .collect(),
        trust_roots: None,
        connect_timeout: Duration::from_millis(300),
        response_head_timeout: Duration::from_millis(300),
        body_idle_timeout: Duration::from_millis(300),
        health_interval: Duration::from_millis(20),
        health_timeout: Duration::from_millis(300),
        dns_refresh: Duration::from_secs(5),
        cooldown: Duration::from_secs(2),
        max_idle_connections: 4,
    }
}

fn metadata(version: Version) -> Forwarding {
    Forwarding {
        client: "2001:db8::2".parse().unwrap(),
        authority: "public.test:8443".to_owned(),
        scheme: "https",
        version,
    }
}

async fn get(pool: &ProxyPool, version: Version) -> Result<Response<Body>, ProxyError> {
    let mut request = Request::new(body::empty());
    *request.version_mut() = version;
    pool.exchange(request, &metadata(version)).await
}

fn response_status(result: Result<Response<Body>, ProxyError>) -> StatusCode {
    result.map_or_else(|error| error.status(), |response| response.status())
}

fn payload(data: &'static str, trailer: &'static str) -> Body {
    let mut trailers = HeaderMap::new();
    trailers.insert(trailer, HeaderValue::from_static("checksum"));
    body::boxed(StreamBody::new(stream::iter([
        Ok::<_, Infallible>(Frame::data(data.into())),
        Ok(Frame::trailers(trailers)),
    ])))
}

#[tokio::test]
async fn rebuilds_http1_authority_and_forwarding_fields_and_streams_trailers() {
    let origin = Origin::start(UpstreamProtocol::H1, None, |request| async move {
        assert_eq!(request.version(), Version::HTTP_11);
        assert_eq!(request.uri(), "/api/items?q=one&q=two");
        assert!(
            request.headers()[HOST]
                .to_str()
                .unwrap()
                .starts_with("127.0.0.1:")
        );
        assert_eq!(
            request.headers()[header::FORWARDED],
            "for=\"[2001:db8::2]\";host=\"public.test:8443\";proto=https"
        );
        assert_eq!(request.headers()["x-forwarded-for"], "2001:db8::2");
        assert_eq!(request.headers().get_all(header::VIA).iter().count(), 2);
        assert_eq!(
            request
                .headers()
                .get_all(header::VIA)
                .iter()
                .next_back()
                .unwrap(),
            "1.1 rocky"
        );
        assert!(!request.headers().contains_key("x-connection-data"));
        assert!(!request.headers().contains_key("x-forwarded-port"));
        let data = request.into_body().collect().await.unwrap();
        assert_eq!(data.trailers().unwrap()["x-request-check"], "checksum");
        assert_eq!(data.to_bytes(), "request");

        Response::builder()
            .status(StatusCode::IM_A_TEAPOT)
            .header(header::CONNECTION, "X-Origin-Private")
            .header("x-origin-private", "remove")
            .header(header::ALT_SVC, "h3=\":5555\"")
            .header(header::TRAILER, "X-Response-Check, X-Origin-Private")
            .body(payload("response", "x-response-check"))
            .unwrap()
    })
    .await;
    let pool = ProxyPool::prepare(
        &config(UpstreamProtocol::H1, [origin.uri("http")]),
        &LIMITS,
        None,
    )
    .unwrap();
    let request = Request::builder()
        .uri("/api/items?q=one&q=two")
        .header(HOST, "public.test:8443")
        .header(header::FORWARDED, "for=forged")
        .header("x-forwarded-for", "forged")
        .header("x-forwarded-port", "42")
        .header(header::VIA, "1.1 prior")
        .header(header::CONNECTION, "TE, X-Connection-Data")
        .header("x-connection-data", "remove")
        .header(header::TE, "trailers")
        .header(header::TRAILER, "X-Request-Check")
        .method(Method::POST)
        .body(payload("request", "x-request-check"))
        .unwrap();
    let response = pool
        .exchange(request, &metadata(Version::HTTP_11))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert!(!response.headers().contains_key("x-origin-private"));
    assert!(!response.headers().contains_key(header::ALT_SVC));
    assert_eq!(response.headers()[header::TRAILER], "x-response-check");
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(
        collected.trailers().unwrap()["x-response-check"],
        "checksum"
    );
    assert_eq!(collected.to_bytes(), "response");
    assert!(pool.ready());
}

#[tokio::test]
async fn cleartext_h2_uses_prior_knowledge_and_routes_the_upstream_authority() {
    let origin = Origin::start(UpstreamProtocol::H2, None, |request| async move {
        assert_eq!(request.version(), Version::HTTP_2);
        assert!(
            request
                .uri()
                .authority()
                .unwrap()
                .as_str()
                .starts_with("127.0.0.1:")
        );
        assert!(!request.headers().contains_key(HOST));
        assert_eq!(request.headers()[header::VIA], "3 rocky");
        Response::new(payload("h2", "x-check"))
    })
    .await;
    let pool = ProxyPool::prepare(
        &config(UpstreamProtocol::H2, [origin.uri("http")]),
        &LIMITS,
        None,
    )
    .unwrap();
    let response = get(&pool, Version::HTTP_3).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(collected.trailers().unwrap()["x-check"], "checksum");
    assert_eq!(collected.to_bytes(), "h2");
}

#[tokio::test]
async fn h2_tls_requires_alpn_and_trusts_configured_roots() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let cert_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(cert_file.path(), cert.pem()).unwrap();
    let mut tls =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();

    let echo = |request: Request<Incoming>| async move {
        assert_eq!(request.version(), Version::HTTP_2);
        Response::new(body::empty())
    };
    let no_alpn = Origin::start(
        UpstreamProtocol::H2,
        Some(TlsAcceptor::from(Arc::new(tls.clone()))),
        echo,
    )
    .await;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let with_alpn = Origin::start(
        UpstreamProtocol::H2,
        Some(TlsAcceptor::from(Arc::new(tls))),
        echo,
    )
    .await;
    let mut config = config(UpstreamProtocol::H2, [no_alpn.uri("https")]);
    config.trust_roots = Some(cert_file.path().to_owned());
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    assert_eq!(
        response_status(get(&pool, Version::HTTP_11).await),
        StatusCode::BAD_GATEWAY
    );

    config.endpoints[0].url = with_alpn.uri("https");
    let pool = ProxyPool::prepare(&config, &LIMITS, Some(&pool)).unwrap();
    assert_eq!(
        response_status(get(&pool, Version::HTTP_11).await),
        StatusCode::OK
    );
}

#[tokio::test(start_paused = true)]
async fn balances_weights_and_allows_one_recovery_trial() {
    let mut config = config(
        UpstreamProtocol::H1,
        [
            "http://127.0.0.1:9001/".parse().unwrap(),
            "http://127.0.0.1:9002/".parse().unwrap(),
        ],
    );
    config.endpoints[0].weight = 2;
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    let order = (0..6)
        .map(|_| pool.select(None).unwrap().0)
        .collect::<Vec<_>>();
    assert_eq!(order, [0, 1, 0, 0, 1, 0]);
    let (_, failed) = pool.select(Some(1)).unwrap();
    failed.fail("test_failure");
    drop(failed);
    assert!(pool.select(Some(1)).is_none());
    tokio::time::advance(config.cooldown).await;
    let (index, trial) = pool.select(Some(1)).unwrap();
    assert_eq!(index, 0);
    assert!(pool.select(Some(1)).is_none());
    trial.complete_response();
    drop(trial);
    assert!(pool.select(Some(1)).is_some());
}

#[tokio::test]
async fn starts_pending_then_tracks_probe_health_for_a_resolved_hostname() {
    let healthy = Arc::new(AtomicBool::new(true));
    let origin = Origin::start(UpstreamProtocol::H1, None, {
        let healthy = Arc::clone(&healthy);
        move |request: Request<Incoming>| {
            let healthy = Arc::clone(&healthy);
            async move {
                assert_eq!(request.uri(), "/health");
                let status = if healthy.load(Ordering::Relaxed) {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                Response::builder()
                    .status(status)
                    .body(body::empty())
                    .unwrap()
            }
        }
    })
    .await;
    let url = format!("http://localhost:{}/", origin.address.port())
        .parse()
        .unwrap();
    let mut config = config(UpstreamProtocol::H1, [url]);
    config.health_path = Some("/health".to_owned());
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    assert!(!pool.ready());
    pool.start();
    wait_for_ready(&pool, true).await;
    healthy.store(false, Ordering::Relaxed);
    wait_for_ready(&pool, false).await;
    assert_eq!(
        response_status(get(&pool, Version::HTTP_11).await),
        StatusCode::SERVICE_UNAVAILABLE
    );
    healthy.store(true, Ordering::Relaxed);
    wait_for_ready(&pool, true).await;
    pool.stop();
}

async fn wait_for_ready(pool: &ProxyPool, ready: bool) {
    timeout(Duration::from_secs(3), async {
        while pool.ready() != ready {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn retries_only_bodyless_get_or_head_on_connection_failure() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = Origin::start(UpstreamProtocol::H1, None, {
        let hits = Arc::clone(&hits);
        move |request| {
            assert_eq!(request.headers()["x-request-id"], "retry");
            assert_eq!(request.headers()["x-forwarded-host"], "public.test:8443");
            hits.fetch_add(1, Ordering::Relaxed);
            async { Response::new(body::empty()) }
        }
    })
    .await;
    let closed = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    closed
        .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap();
    let unreachable = format!(
        "http://{}/",
        closed.local_addr().unwrap().as_socket().unwrap()
    )
    .parse::<Uri>()
    .unwrap();
    assert!(
        TcpStream::connect(closed.local_addr().unwrap().as_socket().unwrap())
            .await
            .is_err()
    );
    let config = config(UpstreamProtocol::H1, [unreachable, origin.uri("http")]);

    for (method, request_body) in [
        (Method::POST, body::empty()),
        (Method::GET, body::full("request")),
    ] {
        let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
        let request = Request::builder()
            .method(method)
            .body(request_body)
            .unwrap();
        let response = pool.exchange(request, &metadata(Version::HTTP_11)).await;
        assert_eq!(response_status(response), StatusCode::BAD_GATEWAY);
        assert_eq!(hits.load(Ordering::Relaxed), 0);
    }
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    let request = Request::builder()
        .header("x-request-id", "retry")
        .body(body::empty())
        .unwrap();
    assert_eq!(
        response_status(pool.exchange(request, &metadata(Version::HTTP_11)).await),
        StatusCode::OK
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn holds_endpoint_capacity_across_reload_and_reports_idle_body_failure() {
    let origin = Origin::start(UpstreamProtocol::H1, None, |_| async {
        Response::new(body::boxed(StreamBody::new(stream::pending::<
            Result<Frame<bytes::Bytes>, Infallible>,
        >())))
    })
    .await;
    let mut config = config(UpstreamProtocol::H1, [origin.uri("http")]);
    config.endpoints[0].max_connections = 1;
    config.body_idle_timeout = Duration::from_millis(20);
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    let response = get(&pool, Version::HTTP_11).await.unwrap();
    let mut updated_config = config.clone();
    updated_config.endpoints[0].weight = 3;
    let updated = ProxyPool::prepare(&updated_config, &LIMITS, Some(&pool)).unwrap();
    assert_eq!(
        response_status(get(&updated, Version::HTTP_11).await),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(response.into_body().frame().await.unwrap().is_err());
    assert_eq!(
        updated.status()["endpoints"][0]["last_failure"],
        "response_body_timeout"
    );
    assert_eq!(updated.status()["endpoints"][0]["in_flight"], 0);
}

#[tokio::test]
async fn response_head_timeout_returns_gateway_timeout() {
    let origin = Origin::start(UpstreamProtocol::H1, None, |_| pending()).await;
    let mut config = config(UpstreamProtocol::H1, [origin.uri("http")]);
    config.response_head_timeout = Duration::from_millis(20);
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    assert_eq!(
        response_status(get(&pool, Version::HTTP_11).await),
        StatusCode::GATEWAY_TIMEOUT
    );
    assert_eq!(
        pool.status()["endpoints"][0]["last_failure"],
        "response_head_timeout"
    );
}

#[tokio::test]
async fn early_h2_response_streams_during_upload_and_aborts_when_upload_exceeds_its_limit() {
    let origin = Origin::start(UpstreamProtocol::H2, None, |request| async move {
        Response::new(body::boxed(request.into_body()))
    })
    .await;
    let config = config(UpstreamProtocol::H2, [origin.uri("http")]);
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();

    let (sender, mut response, exceeded) = streaming_upload(&pool, 4).await;
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "one"
    );
    assert_eq!(pool.status()["endpoints"][0]["in_flight"], 1);
    sender.send("2".into()).await.unwrap();
    drop(sender);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "2"
    );
    assert!(!exceeded.load(Ordering::Acquire));

    let (sender, mut response, exceeded) = streaming_upload(&pool, 4).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.body_mut().frame().await.unwrap().is_ok());
    sender.send("too long".into()).await.unwrap();
    let frame = response.body_mut().frame().await.unwrap();
    assert!(frame.is_err());
    assert!(exceeded.load(Ordering::Acquire));
    assert!(pool.ready());
    assert_eq!(pool.status()["endpoints"][0]["passive_failures"], 0);
}

#[tokio::test]
async fn dropping_a_downstream_response_cancels_an_unfinished_upstream_upload() {
    let origin = Origin::start(UpstreamProtocol::H2, None, |request| async move {
        Response::new(body::boxed(request.into_body()))
    })
    .await;
    let config = config(UpstreamProtocol::H2, [origin.uri("http")]);
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    let (sender, response, _) = streaming_upload(&pool, 4).await;
    drop(response);
    timeout(Duration::from_secs(1), sender.closed())
        .await
        .unwrap();
    assert_eq!(pool.status()["endpoints"][0]["in_flight"], 0);
}

#[tokio::test]
async fn retires_socket_if_cancelled_h2_upload_stalls_on_peer_flow_control() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let connection_ended = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let service = service_fn(|request: Request<Incoming>| async move {
            let response = stream::unfold(request.into_body(), |upload| async move {
                pending::<()>().await;
                drop(upload);
                None::<(Result<Frame<bytes::Bytes>, Infallible>, Incoming)>
            });
            Ok::<_, Infallible>(Response::new(body::boxed(StreamBody::new(response))))
        });
        let _ = http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(0)
            .serve_connection(TokioIo::new(socket), service)
            .await;
    });
    let mut config = config(UpstreamProtocol::H2, [url]);
    config.body_idle_timeout = Duration::from_millis(50);
    let pool = ProxyPool::prepare(&config, &LIMITS, None).unwrap();
    let upload_polled = Arc::new(Notify::new());
    let payload = stream::unfold(Arc::clone(&upload_polled), |polled| async move {
        polled.notify_one();
        let data = bytes::Bytes::from_static(&[b'x'; 65_536]);
        Some((Ok::<_, Infallible>(Frame::data(data)), polled))
    });
    let request = Request::builder()
        .method(Method::POST)
        .version(Version::HTTP_3)
        .body(body::boxed(StreamBody::new(payload)))
        .unwrap();
    let response = pool
        .exchange(request, &metadata(Version::HTTP_3))
        .await
        .unwrap();
    timeout(Duration::from_secs(1), upload_polled.notified())
        .await
        .unwrap();
    let mut sibling = get(&pool, Version::HTTP_3).await.unwrap();
    assert_eq!(pool.status()["endpoints"][0]["in_flight"], 2);
    drop(response);

    timeout(Duration::from_secs(2), connection_ended)
        .await
        .unwrap()
        .unwrap();
    let sibling_error = sibling.body_mut().frame().await.unwrap().unwrap_err();
    assert_eq!(sibling_error.to_string(), "upstream response body failed");
    timeout(Duration::from_secs(1), async {
        while pool.status()["endpoints"][0]["in_flight"] != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn streaming_upload(
    pool: &ProxyPool,
    limit: u64,
) -> (
    tokio::sync::mpsc::Sender<bytes::Bytes>,
    Response<Body>,
    Arc<AtomicBool>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    sender.send("one".into()).await.unwrap();
    let incoming = body::boxed(StreamBody::new(stream::unfold(
        receiver,
        |mut receiver| async move {
            let data = receiver.recv().await?;
            Some((Ok::<_, Infallible>(Frame::data(data)), receiver))
        },
    )));
    let exceeded = Arc::new(AtomicBool::new(false));
    let request = Request::builder()
        .method(Method::POST)
        .version(Version::HTTP_3)
        .body(body::constrain(
            incoming,
            Duration::from_secs(1),
            Some((limit, Arc::clone(&exceeded))),
        ))
        .unwrap();
    let response = pool
        .exchange(request, &metadata(Version::HTTP_3))
        .await
        .unwrap();
    (sender, response, exceeded)
}
