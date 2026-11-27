use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::Request;
use hyper::{
    body::Incoming,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time,
};
use tokio_rustls::TlsAcceptor;

use crate::{
    body,
    config::Limits,
    runtime::{Driver, HttpBinding, Runtime},
};

use super::{Connection, Protocol, drain};

pub async fn serve(
    runtime: Arc<Runtime>,
    driver: Arc<Driver>,
    binding: Arc<HttpBinding>,
    limits: Limits,
    socket: TcpStream,
    peer: std::net::SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
) {
    if !binding.settings.tls {
        let Some(connection) = Connection::open(driver, &binding, peer, Protocol::H1, None) else {
            return;
        };
        drop(binding);
        serve_http(runtime, Arc::new(connection), &limits, socket).await;
        return;
    }
    let Some(tls) = tls else { return };
    let socket = tokio::select! {
        biased;
        _ = binding.lifetime.retired() => return,
        result = time::timeout(limits.handshake_timeout, TlsAcceptor::from(tls).accept(socket)) => match result {
            Ok(Ok(socket)) => socket,
            _ => return,
        }
    };
    let session = socket.get_ref().1;
    let protocol = match session.alpn_protocol() {
        Some(b"h2") => Protocol::H2,
        Some(b"http/1.1") | None => Protocol::H1,
        _ => return,
    };
    let Some(connection) =
        Connection::open(driver, &binding, peer, protocol, session.server_name())
    else {
        return;
    };
    drop(binding);
    serve_http(runtime, Arc::new(connection), &limits, socket).await;
}

async fn serve_http<S>(
    runtime: Arc<Runtime>,
    connection: Arc<Connection>,
    limits: &Limits,
    socket: S,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn({
        let runtime = Arc::clone(&runtime);
        let connection = Arc::clone(&connection);
        move |request: Request<Incoming>| {
            let runtime = Arc::clone(&runtime);
            let connection = Arc::clone(&connection);
            async move {
                Ok::<_, Infallible>(runtime.serve(request.map(body::boxed), &connection).await)
            }
        }
    });
    let io = TokioIo::new(WriteIdle {
        socket,
        limit: limits.body_idle_timeout,
        timer: None,
    });
    match connection.protocol {
        Protocol::H1 => {
            let http = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.request_head_timeout)
                .max_buf_size(limits.max_header_bytes.max(8192))
                .serve_connection(io, service);
            tokio::pin!(http);
            tokio::select! {
                result = &mut http => log_connection(result, &connection),
                deadline = connection.retired() => {
                    http.as_mut().graceful_shutdown();
                    let _ = drain(&runtime.metrics, deadline, &mut http).await;
                }
            }
        }
        Protocol::H2 => {
            let window = limits.max_buffer_bytes as u32;
            let http = http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .header_table_size((limits.max_header_bytes as u32).min(4096))
                .max_header_list_size(limits.max_header_bytes as u32)
                .max_concurrent_streams(limits.max_streams_per_connection)
                .initial_stream_window_size(window)
                .initial_connection_window_size(window)
                .max_send_buf_size(limits.max_buffer_bytes)
                .keep_alive_interval(limits.request_head_timeout)
                .keep_alive_timeout(limits.handshake_timeout)
                .serve_connection(io, service);
            tokio::pin!(http);
            tokio::select! {
                result = &mut http => log_connection(result, &connection),
                deadline = connection.retired() => {
                    http.as_mut().graceful_shutdown();
                    let _ = drain(&runtime.metrics, deadline, &mut http).await;
                }
            }
        }
        Protocol::H3 => unreachable!("HTTP/3 uses a QUIC connection"),
    }
}

fn log_connection(result: Result<(), hyper::Error>, connection: &Connection) {
    if let Err(error) = result {
        // Hyper errors can carry caller-supplied text. Report only the error class.
        tracing::debug!(listener = %connection.listener, protocol = ?connection.protocol,
            timeout = error.is_timeout(), "HTTP connection ended with a protocol error");
    }
}

struct WriteIdle<S> {
    socket: S,
    limit: Duration,
    timer: Option<Pin<Box<time::Sleep>>>,
}

impl<S> WriteIdle<S> {
    fn check<T>(
        &mut self,
        progress: Poll<io::Result<T>>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<T>> {
        if progress.is_ready() {
            self.timer = None;
            return progress;
        }
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(time::sleep(self.limit)));
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "client write stalled",
            )));
        }
        Poll::Pending
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteIdle<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteIdle<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let progress = Pin::new(&mut self.socket).poll_write(cx, bytes);
        self.check(progress, cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let progress = Pin::new(&mut self.socket).poll_flush(cx);
        self.check(progress, cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let progress = Pin::new(&mut self.socket).poll_shutdown(cx);
        self.check(progress, cx)
    }
}
