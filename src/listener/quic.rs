use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::{Buf, Bytes};
use h3::{
    error::Code,
    server::{RequestResolver, RequestStream},
};
use http::Response;
use http_body::{Body as HttpBody, Frame};
use http_body_util::BodyExt;
use tokio::{
    task::JoinSet,
    time::{self, Instant},
};

use crate::{
    body::{self, Body, BodyError},
    config::Limits,
    http::content_length,
    runtime::{Driver, HttpBinding, Runtime},
};

use super::{
    Connection, Protocol, drain,
    quic_limits::{Checked, Limited},
};

pub async fn drive(runtime: Arc<Runtime>, driver: Arc<Driver>, endpoint: quinn::Endpoint) {
    loop {
        let incoming = tokio::select! {
            biased;
            _ = driver.stop.cancelled() => break,
            incoming = endpoint.accept() => match incoming { Some(incoming) => incoming, None => break },
        };
        let Some(active) = runtime.active.load_full() else {
            incoming.refuse();
            break;
        };
        let Some(binding) = active
            .bindings
            .get(&driver.key)
            .filter(|binding| Arc::ptr_eq(&driver, &binding.driver))
        else {
            incoming.refuse();
            break;
        };
        let Some(http) = binding.http() else {
            incoming.refuse();
            continue;
        };
        let Some(config) = active.tls.quic_config(&http.name) else {
            incoming.refuse();
            continue;
        };
        if !incoming.remote_address_validated() && incoming.may_retry() {
            let _ = incoming.retry();
            continue;
        }
        let Some(permits) = runtime.admit_connection(binding, &active.limits) else {
            incoming.refuse();
            continue;
        };
        let peer = incoming.remote_address();
        let Ok(connecting) = incoming.accept_with(config) else {
            continue;
        };
        let runtime = Arc::clone(&runtime);
        let driver = Arc::clone(&driver);
        let http = Arc::clone(http);
        let limits = active.limits.clone();
        runtime.tasks.clone().spawn(async move {
            let _permits = permits;
            connect(runtime, driver, http, limits, connecting, peer).await;
        });
    }
    endpoint.set_server_config(None);
}

async fn connect(
    runtime: Arc<Runtime>,
    driver: Arc<Driver>,
    binding: Arc<HttpBinding>,
    limits: Limits,
    connecting: quinn::Connecting,
    peer: std::net::SocketAddr,
) {
    let quic = tokio::select! {
        biased;
        _ = binding.lifetime.retired() => return,
        result = time::timeout(limits.handshake_timeout, connecting) => match result { Ok(Ok(connection)) => connection, _ => return },
    };
    let Some(handshake) = quic
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
    else {
        return;
    };
    let Some(connection) = Connection::open(
        driver,
        &binding,
        peer,
        Protocol::H3,
        handshake.server_name.as_deref(),
    ) else {
        return;
    };
    drop(binding);
    serve(runtime, Arc::new(connection), quic, limits).await;
}

async fn serve(
    runtime: Arc<Runtime>,
    connection: Arc<Connection>,
    quic: quinn::Connection,
    limits: Limits,
) {
    let mut builder = h3::server::builder();
    let h3 = builder
        .max_field_section_size(limits.max_header_bytes as u64)
        .build(Limited::new(
            h3_quinn::Connection::new(quic.clone()),
            limits.max_header_bytes,
        ));
    let Ok(Ok(mut h3)) = time::timeout(limits.handshake_timeout, h3).await else {
        return;
    };
    let mut requests = JoinSet::new();
    let per_connection_limit = limits.max_streams_per_connection as usize;
    let mut failed_heads = 0;
    let mut received_request = false;
    let deadline = loop {
        tokio::select! {
            biased;
            deadline = connection.retired() => break Some(deadline),
            _ = quic.closed() => break None,
            joined = requests.join_next(), if !requests.is_empty() => {
                if !matches!(joined, Some(Ok(true))) {
                    failed_heads += 1;
                    // A resolver that ends before parsing HEADERS can leave a
                    // request ID tracked by h3 until the connection closes.
                    if failed_heads >= per_connection_limit {
                        let timeout = runtime.active.load().as_ref().map_or(Duration::ZERO, |active| active.drain_timeout);
                        break Some(Instant::now() + timeout);
                    }
                }
            },
            incoming = h3.accept(), if requests.len() < per_connection_limit => match incoming {
                Ok(Some(request)) => {
                    received_request = true;
                    let runtime = Arc::clone(&runtime);
                    let connection = Arc::clone(&connection);
                    let limits = limits.clone();
                    requests.spawn(exchange(runtime, connection, request, limits));
                }
                _ => break None,
            }
        }
    };
    if let Some(deadline) = deadline {
        drain(&runtime.metrics, deadline, async {
            if h3.shutdown(usize::from(received_request)).await.is_err() {
                return;
            }
            loop {
                tokio::select! {
                    _ = quic.closed() => return,
                    joined = requests.join_next() => if joined.is_none() { break; },
                }
            }
            // Retain the connection while Quinn sends the final response data and GOAWAY.
            let linger = (3 * quic.rtt()).clamp(Duration::from_millis(100), Duration::from_secs(1));
            tokio::select! { _ = quic.closed() => {}, _ = time::sleep(linger) => {} }
        })
        .await;
    }
}

async fn exchange(
    runtime: Arc<Runtime>,
    connection: Arc<Connection>,
    resolver: RequestResolver<Limited<h3_quinn::Connection>, Bytes>,
    limits: Limits,
) -> bool {
    let Ok(Ok((request, stream))) =
        time::timeout(limits.request_head_timeout, resolver.resolve_request()).await
    else {
        return false;
    };
    let (send, receive) = stream.split();
    let remaining = content_length(request.headers()).ok().flatten();
    let mut upload = ReceiveBody {
        receive,
        phase: Phase::Data,
        remaining,
        first_frame: None,
    };
    upload.first_frame = std::future::poll_fn(|cx| {
        let frame = Pin::new(&mut upload).poll_frame(cx);
        Poll::Ready(if let Poll::Ready(frame) = frame {
            frame
        } else {
            None
        })
    })
    .await;
    let request = request.map(|()| body::boxed(upload));
    let mut response = Responder {
        send,
        finished: false,
    };
    let result = runtime.serve(request, &connection).await;
    if response
        .write(result, limits.max_buffer_bytes, limits.body_idle_timeout)
        .await
        .is_err()
    {
        tracing::debug!(listener = %connection.listener, "HTTP/3 response interrupted");
    }
    true
}

struct Responder {
    send: RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    finished: bool,
}

impl Responder {
    async fn write(
        &mut self,
        response: Response<Body>,
        buffer: usize,
        idle: Duration,
    ) -> Result<(), BodyError> {
        let (mut head, mut body) = response.into_parts();
        if !head.headers.contains_key(http::header::DATE)
            && let Ok(value) = httpdate::fmt_http_date(std::time::SystemTime::now()).parse()
        {
            head.headers.insert(http::header::DATE, value);
        }
        time::timeout(
            idle,
            self.send.send_response(Response::from_parts(head, ())),
        )
        .await??;
        while let Some(frame) = body.frame().await {
            match frame?.into_data() {
                Ok(mut data) => {
                    while !data.is_empty() {
                        let chunk = data.split_to(data.len().min(buffer));
                        time::timeout(idle, self.send.send_data(chunk)).await??;
                    }
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        time::timeout(idle, self.send.send_trailers(trailers)).await??;
                    }
                }
            }
        }
        time::timeout(idle, self.send.finish()).await??;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if !self.finished {
            self.send.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
    }
}

struct ReceiveBody {
    receive: RequestStream<Checked<h3_quinn::RecvStream>, Bytes>,
    phase: Phase,
    remaining: Option<u64>,
    first_frame: Option<Result<Frame<Bytes>, BodyError>>,
}

#[derive(PartialEq, Eq)]
enum Phase {
    Data,
    Trailers,
    End,
}

impl HttpBody for ReceiveBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if let Some(frame) = self.first_frame.take() {
            return Poll::Ready(Some(frame));
        }
        if self.phase == Phase::Data {
            match ready!(self.receive.poll_recv_data(cx)) {
                Ok(Some(mut chunk)) => {
                    let size = chunk.remaining();
                    if let Some(remaining) = &mut self.remaining {
                        let Some(left) = remaining.checked_sub(size as u64) else {
                            self.phase = Phase::End;
                            return Poll::Ready(Some(Err(length_error())));
                        };
                        *remaining = left;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(chunk.copy_to_bytes(size)))));
                }
                Ok(None) if self.remaining.unwrap_or(0) > 0 => {
                    self.phase = Phase::End;
                    return Poll::Ready(Some(Err(length_error())));
                }
                Ok(None) => self.phase = Phase::Trailers,
                Err(error) => {
                    self.phase = Phase::End;
                    return Poll::Ready(Some(Err(error.into())));
                }
            }
        }
        if self.phase == Phase::Trailers {
            let trailers = ready!(self.receive.poll_recv_trailers(cx));
            self.phase = Phase::End;
            return Poll::Ready(
                trailers
                    .map(|trailers| trailers.map(Frame::trailers))
                    .transpose()
                    .map(|frame| frame.map_err(Into::into)),
            );
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.phase == Phase::End && self.first_frame.is_none()
    }
}

fn length_error() -> BodyError {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP/3 payload does not match Content-Length",
    )
    .into()
}
