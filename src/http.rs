use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant as Monotonic,
};

use ::http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version, header, uri::Authority,
};
use http_body::Body as _;
use ipnet::IpNet;
use tokio::time::Instant;

use crate::{
    body::{self, Body},
    config::{normalize_host, normalize_path},
    listener::{Connection, Protocol},
    proxy::{Forwarding, supports_transfer_encoding},
    rate_limit::Admission,
    runtime::{ALT_SVC_AGE, Permit, RouteAction, Runtime, micros_since},
};

impl Runtime {
    pub async fn serve(&self, request: Request<Body>, connection: &Connection) -> Response<Body> {
        let started = Instant::now();
        let head = request.method() == Method::HEAD;
        let mut record = RequestLog {
            listener: connection.listener.clone(),
            protocol: version_name(request.version()),
            ..RequestLog::default()
        };
        let mut permit = None;
        let mut response = self
            .dispatch(request, connection, &mut record, &mut permit)
            .await;
        if head {
            *response.body_mut() = body::empty();
        }
        if let Some(value) = record.alt_svc.take() {
            response.headers_mut().insert(header::ALT_SVC, value);
        }
        let metrics = Arc::clone(&self.metrics);
        let status = response.status();
        response.map(move |body| {
            body::observe(body, move |transfer| {
                let _permit = permit;
                let micros = micros_since(started);
                metrics.requests.fetch_add(1, Ordering::Relaxed);
                metrics.request_micros.fetch_add(micros, Ordering::Relaxed);
                metrics
                    .response_bytes
                    .fetch_add(transfer.bytes, Ordering::Relaxed);
                if transfer.outcome == "body_error" {
                    metrics.body_errors.fetch_add(1, Ordering::Relaxed);
                }
                tracing::info!(
                    generation = record.generation, listener = %record.listener, site = record.site,
                    route = record.route, protocol = record.protocol, upstream = record.upstream,
                    status = status.as_u16(), latency_us = micros, bytes = transfer.bytes,
                    failure = record.failure.unwrap_or(transfer.outcome), "HTTP exchange"
                );
            })
        })
    }

    async fn dispatch(
        &self,
        mut request: Request<Body>,
        connection: &Connection,
        record: &mut RequestLog,
        permit: &mut Option<Permit>,
    ) -> Response<Body> {
        let Some(active) = self.active.load_full() else {
            return record.reject(StatusCode::SERVICE_UNAVAILABLE, "draining");
        };
        record.generation = active.id;
        let Some(binding) = connection.binding(&active) else {
            self.metrics
                .requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            return record.reject(StatusCode::SERVICE_UNAVAILABLE, "draining");
        };
        *permit = self.requests.enter(active.limits.max_requests);
        if permit.is_none() {
            self.metrics
                .requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            return record.reject(StatusCode::SERVICE_UNAVAILABLE, "request_capacity");
        }
        if header_size(&request) > active.limits.max_header_bytes {
            return record.reject(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "head_limit");
        }
        if request.method() == Method::CONNECT {
            return record.reject(StatusCode::NOT_IMPLEMENTED, "connect");
        }
        let scheme = if connection.tls.is_some() {
            "https"
        } else {
            "http"
        };
        let authority = match effective_authority(&request, scheme) {
            Ok(authority) => authority,
            Err(()) => return record.reject(StatusCode::BAD_REQUEST, "authority"),
        };
        let host = match &authority {
            Some(authority) => authority.host.as_str(),
            None => match binding.settings.default_site.as_deref() {
                Some(default) => default,
                None => return record.reject(StatusCode::BAD_REQUEST, "missing_default_site"),
            },
        };
        if connection.tls.as_ref().is_some_and(|tls| tls.host != host) {
            return record.reject(StatusCode::MISDIRECTED_REQUEST, "misdirected");
        }
        let Some(site) = binding.sites.get(host) else {
            return record.reject(StatusCode::NOT_FOUND, "unknown_site");
        };
        record.site = Some(site.host.clone());
        if connection.tls.is_some() && connection.protocol != Protocol::H3 {
            if let Some(port) = site.public_quic_port
                && site.quic.iter().any(|name| active.tls.ready(name, host))
            {
                record.alt_svc =
                    HeaderValue::from_str(&format!("h3=\":{port}\"; ma={}", ALT_SVC_AGE.as_secs()))
                        .ok();
            } else if site
                .clear_alt_svc
                .is_some_and(|until| Instant::now() < until)
            {
                record.alt_svc = Some(HeaderValue::from_static("clear"));
            }
        }
        if !supports_transfer_encoding(request.headers(), request.version()) {
            return record.reject(StatusCode::BAD_REQUEST, "transfer_encoding");
        }
        if matches!(request.version(), Version::HTTP_2 | Version::HTTP_3)
            && !valid_multiplexed_headers(request.headers())
        {
            return record.reject(StatusCode::BAD_REQUEST, "connection_fields");
        }
        let length = match content_length(request.headers()) {
            Ok(length) => length,
            Err(()) => return record.reject(StatusCode::BAD_REQUEST, "content_length"),
        };
        if length.is_some() && request.headers().contains_key(header::TRANSFER_ENCODING) {
            return record.reject(StatusCode::BAD_REQUEST, "ambiguous_framing");
        }
        if length.is_some_and(|length| length > active.limits.max_body_bytes) {
            return record.reject(StatusCode::PAYLOAD_TOO_LARGE, "body_limit");
        }
        if request.uri().path() == "*" {
            return if request.method() == Method::OPTIONS && request.uri().query().is_none() {
                reply(StatusCode::NO_CONTENT)
            } else {
                record.reject(StatusCode::BAD_REQUEST, "asterisk_target")
            };
        }
        let path = match normalize_path(request.uri().path()) {
            Ok(path) => path,
            Err(_) => return record.reject(StatusCode::BAD_REQUEST, "path"),
        };
        let target = match request.uri().query() {
            Some(query) => format!("{path}?{query}"),
            None => path.clone(),
        };
        if connection.tls.is_none() {
            if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/")
                && !token.is_empty()
                && !token.contains('/')
                && (request.method() == Method::GET || request.method() == Method::HEAD)
                && let Some(value) = active.tls.challenge(&binding.name, host, token)
            {
                return text_reply(StatusCode::OK, value);
            }
            if site.redirect_http {
                if !site.https.iter().any(|name| active.tls.ready(name, host)) {
                    return record.reject(StatusCode::SERVICE_UNAVAILABLE, "certificate_pending");
                }
                let port = site
                    .public_https_port
                    .expect("redirect port is validated in configuration");
                let authority = if port == 443 {
                    site.host.clone()
                } else {
                    format!("{}:{port}", site.host)
                };
                return Response::builder()
                    .status(StatusCode::PERMANENT_REDIRECT)
                    .header(header::LOCATION, format!("https://{authority}{target}"))
                    .header(header::CONTENT_LENGTH, "0")
                    .body(body::empty())
                    .unwrap_or_else(|_| reply(StatusCode::BAD_REQUEST));
            }
        }
        let Some(route) = site
            .routes
            .iter()
            .find(|route| prefix_matches(&path, &route.prefix))
            .cloned()
        else {
            return record.reject(StatusCode::NOT_FOUND, "no_route");
        };
        record.route = Some(route.name.clone());
        let client = client_ip(
            request.headers(),
            connection.peer.ip(),
            &binding.settings.trusted_proxies,
        );
        let forwarded_authority =
            authority.map_or_else(|| site.host.clone(), |authority| authority.effective);
        if let Some((_, limiter)) = &route.rate_limit {
            match limiter.check(client, Monotonic::now()) {
                Admission::Allowed => {}
                Admission::Limited { retry_after } => {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    let mut response = record.reject(StatusCode::TOO_MANY_REQUESTS, "rate_limit");
                    response
                        .headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
                    return response;
                }
                Admission::AtCapacity => {
                    self.metrics
                        .rate_limit_capacity
                        .fetch_add(1, Ordering::Relaxed);
                    return record.reject(StatusCode::SERVICE_UNAVAILABLE, "rate_limit_capacity");
                }
            }
        }
        let idle = active.limits.body_idle_timeout;
        let max_body = active.limits.max_body_bytes;
        drop(active);

        let Ok(uri) = target.parse() else {
            return record.reject(StatusCode::BAD_REQUEST, "path");
        };
        *request.uri_mut() = uri;
        let response = match &route.action {
            RouteAction::Files(root) => {
                let relative = path.strip_prefix(&route.prefix).unwrap_or_default();
                let relative = relative.strip_prefix('/').unwrap_or(relative);
                root.serve(request.into_parts().0, relative, idle).await
            }
            RouteAction::Proxy(name, pool) => {
                record.upstream = Some(name.clone());
                let meta = Forwarding {
                    client,
                    authority: forwarded_authority,
                    scheme,
                    version: request.version(),
                };
                let (request, exceeded) = if request.body().is_end_stream() {
                    (request, None)
                } else {
                    let exceeded = Arc::new(AtomicBool::new(false));
                    let request = request.map(|body| {
                        body::constrain(body, idle, Some((max_body, Arc::clone(&exceeded))))
                    });
                    (request, Some(exceeded))
                };
                match pool.exchange(request, &meta).await {
                    _ if exceeded.is_some_and(|flag| flag.load(Ordering::Acquire)) => {
                        record.reject(StatusCode::PAYLOAD_TOO_LARGE, "body_limit")
                    }
                    Ok(response) => response,
                    Err(err) => {
                        tracing::debug!(generation = record.generation, upstream = %name, error = %err, "upstream exchange failed");
                        record.reject(err.status(), "upstream")
                    }
                }
            }
        };
        response.map(|body| body::constrain(body, idle, None))
    }
}

#[derive(Default)]
struct RequestLog {
    generation: u64,
    listener: String,
    site: Option<String>,
    route: Option<String>,
    protocol: &'static str,
    upstream: Option<String>,
    failure: Option<&'static str>,
    alt_svc: Option<HeaderValue>,
}

impl RequestLog {
    fn reject(&mut self, status: StatusCode, reason: &'static str) -> Response<Body> {
        self.failure = Some(reason);
        reply(status)
    }
}

fn version_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "unknown",
    }
}

fn header_size(request: &Request<Body>) -> usize {
    let target = request.uri();
    let target_size = target
        .path_and_query()
        .map_or(0, |part| part.as_str().len())
        + target.authority().map_or(0, |part| part.as_str().len())
        + target.scheme_str().map_or(0, |scheme| scheme.len() + 3);
    request.headers().iter().fold(
        request.method().as_str().len() + target_size,
        |size, (name, value)| size.saturating_add(name.as_str().len() + value.as_bytes().len() + 4),
    )
}

fn valid_multiplexed_headers(headers: &HeaderMap) -> bool {
    !headers.keys().any(|name| {
        matches!(
            name.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "upgrade"
        )
    }) && headers.get_all(header::TE).iter().all(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .all(|coding| coding.trim_ascii().eq_ignore_ascii_case(b"trailers"))
    })
}

pub fn content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let mut length = None;
    for value in headers.get_all(header::CONTENT_LENGTH) {
        let value = value.to_str().map_err(|_| ())?.trim();
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        let current = value.parse().map_err(|_| ())?;
        if length.replace(current).is_some_and(|old| old != current) {
            return Err(());
        }
    }
    Ok(length)
}

struct EffectiveAuthority {
    host: String,
    effective: String,
}

fn effective_authority(
    request: &Request<Body>,
    scheme: &str,
) -> Result<Option<EffectiveAuthority>, ()> {
    let mut values = request.headers().get_all(header::HOST).iter();
    let host_field = values
        .next()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ())?
                .parse::<Authority>()
                .map_err(|_| ())
        })
        .transpose()?;
    if values.next().is_some() || request.version() == Version::HTTP_11 && host_field.is_none() {
        return Err(());
    }
    let host_field = host_field.as_ref().map(parse_authority).transpose()?;
    let target = request.uri();
    if target
        .scheme_str()
        .is_some_and(|target_scheme| target_scheme != scheme)
        || target.authority().is_some() != target.scheme().is_some()
    {
        return Err(());
    }
    let target = target.authority().map(parse_authority).transpose()?;
    if matches!(request.version(), Version::HTTP_2 | Version::HTTP_3)
        && let (Some(target), Some(host_field)) = (&target, &host_field)
        && target.effective != host_field.effective
    {
        return Err(());
    }
    let effective = target.or(host_field);
    if effective.is_none() && request.version() != Version::HTTP_10 {
        return Err(());
    }
    Ok(effective)
}

fn parse_authority(authority: &Authority) -> Result<EffectiveAuthority, ()> {
    let raw_host = authority.host();
    let host = normalize_host(raw_host).ok_or(())?;
    let effective = match authority.port_u16() {
        Some(port) if port != 0 && !authority.as_str().contains('@') => format!("{host}:{port}"),
        None if raw_host == authority.as_str() => host.clone(),
        _ => return Err(()),
    };
    Ok(EffectiveAuthority { host, effective })
}

fn prefix_matches(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn reply(status: StatusCode) -> Response<Body> {
    if status == StatusCode::NO_CONTENT {
        return Response::builder()
            .status(status)
            .body(body::empty())
            .expect("valid response");
    }
    text_reply(
        status,
        format!(
            "{}\n",
            status.canonical_reason().unwrap_or("Request failed")
        ),
    )
}

fn text_reply(status: StatusCode, value: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, value.len())
        .body(body::full(value))
        .expect("valid text response")
}

fn client_ip(headers: &HeaderMap, peer: IpAddr, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: IpAddr| trusted.iter().any(|network| network.contains(&ip));
    if !is_trusted(peer) {
        return peer;
    }
    let Some(chain) = forwarded_chain(headers) else {
        return peer;
    };
    let mut address = peer;
    for previous in chain.into_iter().rev() {
        if !is_trusted(address) {
            break;
        }
        address = previous.to_canonical();
    }
    address
}

fn forwarded_chain(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    if headers.get_all(header::CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|name| name.trim().eq_ignore_ascii_case("forwarded"))
        })
    }) {
        return None;
    }
    let mut chain = Vec::new();
    for header in headers.get_all("forwarded") {
        for entry in split_quoted(header.to_str().ok()?, ',')? {
            let mut ip = None;
            let mut names: Vec<&str> = Vec::new();
            for part in split_quoted(entry, ';')? {
                let (name, value) = part.trim().split_once('=')?;
                if !token(name) || names.iter().any(|old| old.eq_ignore_ascii_case(name)) {
                    return None;
                }
                names.push(name);
                let value = if let Some(value) = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                {
                    unquote(value)?
                } else if token(value) {
                    value.to_owned()
                } else {
                    return None;
                };
                if name.eq_ignore_ascii_case("for") {
                    ip = if let Some(bracketed) = value
                        .strip_prefix('[')
                        .and_then(|value| value.strip_suffix(']'))
                    {
                        bracketed.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
                    } else {
                        value
                            .parse::<std::net::Ipv4Addr>()
                            .ok()
                            .map(IpAddr::V4)
                            .or_else(|| value.parse::<SocketAddr>().ok().map(|socket| socket.ip()))
                    };
                }
            }
            chain.push(ip?);
        }
    }
    Some(chain)
}

fn split_quoted(value: &str, separator: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        match ch {
            _ if escaped => escaped = false,
            '\\' if quote => escaped = true,
            '"' => quote = !quote,
            _ if ch == separator && !quote => {
                parts.push(&value[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if quote || escaped {
        return None;
    }
    parts.push(&value[start..]);
    Some(parts)
}

fn unquote(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if ch.is_ascii_control() || ch == '"' && !escaped {
            return None;
        }
        if ch == '\\' && !escaped {
            escaped = true;
        } else {
            escaped = false;
            decoded.push(ch);
        }
    }
    (!escaped).then_some(decoded)
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_uses_nearest_untrusted_hop_and_falls_back_for_malformed_metadata() {
        let mut headers = HeaderMap::new();
        let trusted = ["10.0.0.0/8".parse().unwrap()];
        let peer = "10.0.0.1".parse().unwrap();
        headers.insert(
            "forwarded",
            HeaderValue::from_static(
                "for=192.0.2.3, for=\"[2001:db8::1]:443\";proto=https, for=10.2.2.2",
            ),
        );
        assert_eq!(
            client_ip(&headers, peer, &trusted),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=192.0.2.3, for=unknown"),
        );
        assert_eq!(client_ip(&headers, peer, &trusted), peer);
    }

    #[test]
    fn absolute_http1_target_wins_and_http2_authority_cannot_conflict() {
        let request = Request::builder()
            .uri("http://Example.Test:80/a?b=c")
            .header("host", "other.test")
            .body(body::empty())
            .unwrap();
        let authority = effective_authority(&request, "http").unwrap().unwrap();
        assert_eq!(authority.host, "example.test");
        assert_eq!(authority.effective, "example.test:80");
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.test/")
            .header("host", "other.test")
            .body(body::empty())
            .unwrap();
        assert!(effective_authority(&request, "https").is_err());
    }

    #[test]
    fn route_prefixes_require_a_segment_boundary() {
        assert!(prefix_matches("/api", "/api"));
        assert!(prefix_matches("/api/items", "/api"));
        assert!(!prefix_matches("/apix", "/api"));
    }
}
