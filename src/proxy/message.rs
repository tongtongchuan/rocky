use std::{
    collections::HashSet,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri, Version,
    header::{
        ALT_SVC, CONNECTION, CONTENT_LENGTH, EXPECT, FORWARDED, HOST, TE, TRAILER,
        TRANSFER_ENCODING, VIA,
    },
    request::Parts,
    uri::PathAndQuery,
};
use http_body::{Body as HttpBody, Frame, SizeHint};
use hyper::body::Incoming;
use tokio_util::sync::{CancellationToken, DropGuard, WaitForCancellationFutureOwned};

use super::{
    Lease, ProxyError,
    transport::{Http2Connection, UpstreamResponse},
};
use crate::{
    body::{self, Body, BodyError, Constrained},
    config::UpstreamProtocol,
};

pub struct Forwarding {
    pub client: IpAddr,
    pub authority: String,
    pub scheme: &'static str,
    pub version: Version,
}

pub fn supports_transfer_encoding(headers: &HeaderMap, version: Version) -> bool {
    let mut values = headers.get_all(TRANSFER_ENCODING).iter();
    let Some(coding) = values.next() else {
        return true;
    };
    version == Version::HTTP_11
        && coding
            .as_bytes()
            .trim_ascii()
            .eq_ignore_ascii_case(b"chunked")
        && values.next().is_none()
}

pub(super) struct RequestDraft {
    method: Method,
    target: PathAndQuery,
    headers: HeaderMap,
    trailers: Option<TrailerPolicy>,
    downstream_protocol: Version,
    upstream_protocol: UpstreamProtocol,
    accept_response_trailers: bool,
}

impl RequestDraft {
    pub(super) fn new(
        mut request: Parts,
        meta: &Forwarding,
        protocol: UpstreamProtocol,
    ) -> Result<Self, ProxyError> {
        let accept_response_trailers = accepts_trailers(meta.version, &request.headers);
        let mut blocked = strip_hop_fields(&mut request.headers);
        blocked.extend(strip_forwarding_fields(&mut request.headers));
        let request_trailers =
            TrailerPolicy::from_headers(&mut request.headers, blocked, true, protocol.version());

        // Hyper consumes 100-continue when Rocky begins polling the incoming body.
        if request
            .headers
            .get(EXPECT)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"))
        {
            request.headers.remove(EXPECT);
        }
        request.headers.remove(HOST);
        if accept_response_trailers {
            request
                .headers
                .insert(TE, HeaderValue::from_static("trailers"));
            if protocol == UpstreamProtocol::H1 {
                request
                    .headers
                    .insert(CONNECTION, HeaderValue::from_static("TE"));
            }
        }
        set_forwarding(&mut request.headers, meta)?;
        append_via(&mut request.headers, meta.version);
        Ok(Self {
            method: request.method,
            target: request
                .uri
                .path_and_query()
                .cloned()
                .unwrap_or_else(|| PathAndQuery::from_static("/")),
            headers: request.headers,
            trailers: Some(request_trailers),
            downstream_protocol: meta.version,
            upstream_protocol: protocol,
            accept_response_trailers,
        })
    }

    pub(super) fn build(
        &mut self,
        origin: &Uri,
        mut body: Body,
        lease: &Arc<Lease>,
        preserve_headers: bool,
    ) -> (Request<Body>, Option<DropGuard>) {
        let trailers = lease
            .upload
            .is_some()
            .then(|| self.trailers.take().expect("upload is built once"));
        let mut headers = if preserve_headers {
            self.headers.clone()
        } else {
            std::mem::take(&mut self.headers)
        };
        if self.upstream_protocol == UpstreamProtocol::H1 {
            insert_origin_host(&mut headers, origin);
            if let Some(trailers) = &trailers
                && (trailers.declared_for_h1()
                    || (body.size_hint().exact().is_none()
                        && !headers.contains_key(CONTENT_LENGTH)))
            {
                headers.remove(CONTENT_LENGTH);
                headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
            }
        }
        let cancel_upload = if let Some(trailers) = trailers {
            let cancel = CancellationToken::new();
            let guard = cancel.clone().drop_guard();
            body = body::boxed(UploadBody {
                inner: Some(body),
                lease: Arc::clone(lease),
                cancelled: Box::pin(cancel.cancelled_owned()),
                trailers,
            });
            Some(guard)
        } else {
            None
        };
        let mut request = Request::new(body);
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = origin_uri(origin, self.target.clone());
        *request.version_mut() = self.upstream_protocol.version();
        *request.headers_mut() = headers;
        (request, cancel_upload)
    }

    pub(super) fn response(
        &self,
        upstream: UpstreamResponse,
        lease: Arc<Lease>,
        cancel_upload: Option<DropGuard>,
        idle_timeout: Duration,
    ) -> Response<Body> {
        let (mut parts, incoming) = upstream.response.into_parts();
        let blocked = strip_hop_fields(&mut parts.headers);
        let trailers = TrailerPolicy::from_headers(
            &mut parts.headers,
            blocked,
            self.accept_response_trailers,
            self.downstream_protocol,
        );
        parts.headers.remove(ALT_SVC);
        append_via(&mut parts.headers, parts.version);
        parts.version = self.downstream_protocol;
        parts.extensions.clear();

        let body = if incoming.is_end_stream() {
            lease.complete_response();
            if let Some(guard) = cancel_upload {
                guard.disarm();
            }
            body::empty()
        } else {
            if trailers.declared_for_h1() && self.method != Method::HEAD {
                parts.headers.remove(CONTENT_LENGTH);
                parts
                    .headers
                    .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
            }
            let upload = cancel_upload.map(|cancel| DownloadUpload {
                cancel,
                rejected: Box::pin(lease.upload().rejected.clone().cancelled_owned()),
                connection: upstream.connection,
                idle_timeout,
            });
            body::boxed(DownloadBody {
                inner: Some(Constrained::new(incoming, idle_timeout, None)),
                lease: Some(lease),
                trailers,
                upload,
            })
        };
        Response::from_parts(parts, body)
    }
}

pub(super) fn probe_request(origin: &Uri, path: &str, protocol: UpstreamProtocol) -> Request<Body> {
    let mut request = Request::new(body::empty());
    *request.uri_mut() = origin_uri(
        origin,
        path.parse().expect("validated upstream health path"),
    );
    *request.version_mut() = protocol.version();
    if protocol == UpstreamProtocol::H1 {
        insert_origin_host(request.headers_mut(), origin);
    }
    request
}

fn origin_uri(origin: &Uri, target: PathAndQuery) -> Uri {
    let mut parts = origin.clone().into_parts();
    parts.path_and_query = Some(target);
    Uri::from_parts(parts).expect("validated upstream origin and request target")
}

fn insert_origin_host(headers: &mut HeaderMap, origin: &Uri) {
    let authority = origin.authority().expect("validated upstream origin");
    headers.insert(
        HOST,
        HeaderValue::from_str(authority.as_str()).expect("valid upstream authority"),
    );
}

impl UpstreamProtocol {
    fn version(self) -> Version {
        match self {
            Self::H1 => Version::HTTP_11,
            Self::H2 => Version::HTTP_2,
        }
    }
}

fn connection_field(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn forwarding_field(name: &HeaderName) -> bool {
    matches!(name.as_str(), "forwarded" | "x-real-ip") || name.as_str().starts_with("x-forwarded-")
}

fn strip_hop_fields(headers: &mut HeaderMap) -> HashSet<HeaderName> {
    let nominated: HashSet<_> = header_names(headers, CONNECTION).collect();
    remove_fields(headers, |name| {
        connection_field(name) || nominated.contains(name)
    });
    nominated
}

fn strip_forwarding_fields(headers: &mut HeaderMap) -> Vec<HeaderName> {
    remove_fields(headers, forwarding_field)
}

fn remove_fields(headers: &mut HeaderMap, remove: impl Fn(&HeaderName) -> bool) -> Vec<HeaderName> {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| remove(name))
        .cloned()
        .collect();
    for name in &names {
        headers.remove(name);
    }
    names
}

fn header_names(headers: &HeaderMap, header: HeaderName) -> impl Iterator<Item = HeaderName> + '_ {
    headers
        .get_all(header)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|name| HeaderName::from_bytes(name.trim_ascii()).ok())
}

fn set_forwarding(headers: &mut HeaderMap, meta: &Forwarding) -> Result<(), ProxyError> {
    let client = meta.client.to_canonical();
    let node = match client {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("\"[{ip}]\""),
    };
    let host = HeaderValue::from_str(&meta.authority).map_err(|_| ProxyError::Exchange)?;
    let forwarded = HeaderValue::from_str(&format!(
        "for={node};host=\"{}\";proto={}",
        meta.authority, meta.scheme
    ))
    .map_err(|_| ProxyError::Exchange)?;
    headers.insert(FORWARDED, forwarded);
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&client.to_string()).expect("valid IP"),
    );
    headers.insert("x-forwarded-host", host);
    headers.insert("x-forwarded-proto", HeaderValue::from_static(meta.scheme));
    Ok(())
}

fn append_via(headers: &mut HeaderMap, version: Version) {
    let value = match version {
        Version::HTTP_10 => "1.0 rocky",
        Version::HTTP_11 => "1.1 rocky",
        Version::HTTP_2 => "2 rocky",
        Version::HTTP_3 => "3 rocky",
        _ => return,
    };
    headers.append(VIA, HeaderValue::from_static(value));
}

fn accepts_trailers(version: Version, headers: &HeaderMap) -> bool {
    matches!(version, Version::HTTP_2 | Version::HTTP_3)
        || (version == Version::HTTP_11
            && headers
                .get_all(TE)
                .iter()
                .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"trailers")))
}

struct TrailerPolicy {
    mode: TrailerMode,
    blocked: HashSet<HeaderName>,
}

enum TrailerMode {
    None,
    Declared(HashSet<HeaderName>),
    Any,
}

impl TrailerPolicy {
    fn from_headers(
        headers: &mut HeaderMap,
        blocked: HashSet<HeaderName>,
        accepted: bool,
        version: Version,
    ) -> Self {
        let mut declared: Vec<_> = header_names(headers, TRAILER)
            .filter(|name| trailer_field(name) && !blocked.contains(name))
            .collect();
        declared.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        declared.dedup();
        headers.remove(TRAILER);

        let mode = if !accepted || version == Version::HTTP_10 {
            TrailerMode::None
        } else {
            if !declared.is_empty() {
                let names = declared
                    .iter()
                    .map(HeaderName::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                headers.insert(
                    TRAILER,
                    HeaderValue::from_str(&names).expect("valid trailer names"),
                );
            }
            match version {
                Version::HTTP_11 if !declared.is_empty() => {
                    TrailerMode::Declared(declared.into_iter().collect())
                }
                Version::HTTP_2 | Version::HTTP_3 => TrailerMode::Any,
                _ => TrailerMode::None,
            }
        };
        Self { mode, blocked }
    }

    fn declared_for_h1(&self) -> bool {
        matches!(self.mode, TrailerMode::Declared(_))
    }

    fn filter(&self, frame: Frame<Bytes>) -> Option<Frame<Bytes>> {
        let mut trailers = match frame.into_trailers() {
            Ok(trailers) => trailers,
            Err(frame) => return Some(frame),
        };
        if matches!(self.mode, TrailerMode::None) {
            return None;
        }
        remove_fields(&mut trailers, |name| {
            !trailer_field(name)
                || self.blocked.contains(name)
                || matches!(&self.mode, TrailerMode::Declared(fields) if !fields.contains(name))
        });
        (!trailers.is_empty()).then(|| Frame::trailers(trailers))
    }
}

fn trailer_field(name: &HeaderName) -> bool {
    !connection_field(name)
        && !forwarding_field(name)
        && !name.as_str().starts_with("if-")
        && !matches!(
            name.as_str(),
            "alt-svc"
                | "authorization"
                | "cache-control"
                | "content-encoding"
                | "content-length"
                | "content-range"
                | "content-type"
                | "cookie"
                | "expect"
                | "host"
                | "max-forwards"
                | "range"
                | "set-cookie"
                | "trailer"
                | "www-authenticate"
        )
}

struct UploadBody {
    inner: Option<Body>,
    lease: Arc<Lease>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    trailers: TrailerPolicy,
}

impl Drop for UploadBody {
    fn drop(&mut self) {
        self.lease.upload().complete();
    }
}

impl HttpBody for UploadBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        if this.inner.is_some() && this.cancelled.as_mut().poll(cx).is_ready() {
            this.inner = None;
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "downstream exchange ended",
            )
            .into())));
        }
        while let Some(inner) = &mut this.inner {
            let result = std::task::ready!(Pin::new(&mut *inner).poll_frame(cx));
            if matches!(&result, Some(Err(_))) {
                this.lease.upload().rejected.cancel();
            }
            if !matches!(&result, Some(Ok(_))) || inner.is_end_stream() {
                this.inner = None;
            }
            match result {
                None => return Poll::Ready(None),
                Some(Err(error)) => return Poll::Ready(Some(Err(error))),
                Some(Ok(frame)) => {
                    if let Some(frame) = this.trailers.filter(frame) {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                }
            }
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), HttpBody::size_hint)
    }
}

struct DownloadBody {
    inner: Option<Constrained<Incoming>>,
    lease: Option<Arc<Lease>>,
    trailers: TrailerPolicy,
    upload: Option<DownloadUpload>,
}

struct DownloadUpload {
    cancel: DropGuard,
    rejected: Pin<Box<WaitForCancellationFutureOwned>>,
    connection: Option<Http2Connection>,
    idle_timeout: Duration,
}

impl DownloadBody {
    fn complete(&mut self) {
        self.inner = None;
        self.lease.take().unwrap().complete_response();
        if let Some(upload) = self.upload.take() {
            upload.cancel.disarm();
        }
    }

    fn abort_upload(&mut self) {
        if let Some(upload) = self.upload.take() {
            drop(upload.cancel);
            let state = self.lease.as_ref().unwrap().upload();
            if state.is_pending()
                && let Some(connection) = upload.connection
            {
                connection.retire_if_upload_stalls(state.finished.clone(), upload.idle_timeout);
            }
        }
    }

    fn fail(
        &mut self,
        label: &'static str,
        error: io::Error,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.inner = None;
        self.abort_upload();
        self.lease.take().unwrap().fail(label);
        Poll::Ready(Some(Err(error.into())))
    }
}

impl Drop for DownloadBody {
    fn drop(&mut self) {
        self.abort_upload();
    }
}

impl HttpBody for DownloadBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        if let Some(upload) = &mut this.upload
            && upload.rejected.as_mut().poll(cx).is_ready()
        {
            return this.fail("request_body", io::Error::other("downstream upload failed"));
        }
        while let Some(inner) = &mut this.inner {
            match Pin::new(&mut *inner).poll_frame(cx) {
                Poll::Ready(None) => this.complete(),
                Poll::Ready(Some(Err(error))) => {
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|cause| cause.kind() == io::ErrorKind::TimedOut)
                    {
                        return this.fail(
                            "response_body_timeout",
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "upstream response body idle deadline expired",
                            ),
                        );
                    }
                    return this.fail(
                        "response_body",
                        io::Error::other("upstream response body failed"),
                    );
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if inner.is_end_stream() {
                        this.complete();
                    }
                    if let Some(frame) = this.trailers.filter(frame) {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), HttpBody::size_hint)
    }
}
