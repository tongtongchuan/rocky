use std::{
    convert::Infallible,
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
    server,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::crypto::rustls::QuicClientConfig;
use serde_json::Value;
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    time,
};

const BINARY: &str = env!("CARGO_BIN_EXE_rocky");
const DEADLINE: Duration = Duration::from_secs(8);
type OriginBody = UnsyncBoxBody<Bytes, Infallible>;

struct Daemon {
    dir: TempDir,
    process: Child,
}

impl Daemon {
    async fn run(dir: TempDir, config: &str) -> Self {
        write_config(dir.path(), config);
        let log = File::create(dir.path().join("rocky.log")).unwrap();
        let process = Command::new(BINARY)
            .arg("run")
            .arg("--config")
            .arg(dir.path().join("rocky.toml"))
            .env("RUST_LOG", "rocky=info")
            .stderr(log)
            .spawn()
            .unwrap();
        let mut daemon = Self { dir, process };
        let started = time::timeout(DEADLINE, async {
            loop {
                assert!(
                    daemon.process.try_wait().unwrap().is_none(),
                    "{}",
                    daemon.logs()
                );
                if daemon.socket().exists() && daemon.call("status").status.success() {
                    break;
                }
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(started.is_ok(), "daemon did not start\n{}", daemon.logs());
        daemon
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("run/admin.sock")
    }

    fn logs(&self) -> String {
        fs::read_to_string(self.dir.path().join("rocky.log")).unwrap()
    }

    fn call(&self, command: &str) -> std::process::Output {
        Command::new(BINARY)
            .arg(command)
            .arg("--admin-socket")
            .arg(self.socket())
            .output()
            .unwrap()
    }

    fn status(&self) -> Value {
        let output = self.call("status");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn reload(&self, config: &str, succeeds: bool) {
        write_config(self.dir.path(), config);
        let output = self.call("reload");
        assert_eq!(
            output.status.success(),
            succeeds,
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            self.logs()
        );
    }

    async fn stop(&mut self) {
        use rustix::process::{Pid, Signal, kill_process};
        kill_process(
            Pid::from_raw(self.process.id() as i32).unwrap(),
            Signal::TERM,
        )
        .unwrap();
        time::timeout(DEADLINE, async {
            loop {
                if let Some(exit) = self.process.try_wait().unwrap() {
                    assert!(exit.success(), "{}", self.logs());
                    break;
                }
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(!self.socket().exists());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.process.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}

fn write_config(dir: &Path, value: &str) {
    fs::write(dir.join("candidate.toml"), value).unwrap();
    fs::rename(dir.join("candidate.toml"), dir.join("rocky.toml")).unwrap();
}

fn port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn quic_port() -> SocketAddr {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        if std::net::UdpSocket::bind(address).is_ok() {
            return address;
        }
    }
}

async fn origin() -> (SocketAddr, Arc<Notify>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let release = Arc::new(Notify::new());
    let complete = Arc::clone(&release);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let complete = Arc::clone(&complete);
            tokio::spawn(async move {
                let handle = service_fn(move |request: Request<Incoming>| {
                    let complete = Arc::clone(&complete);
                    async move {
                        let mut response = if request.uri().path().ends_with("/delay") {
                            let first = futures_util::stream::once(async {
                                Ok(Frame::data(Bytes::from_static(b"first")))
                            });
                            let last = futures_util::stream::once(async move {
                                complete.notified().await;
                                Ok(Frame::data(Bytes::from_static(b"last")))
                            });
                            use futures_util::StreamExt;
                            Response::new(StreamBody::new(first.chain(last)).boxed_unsync())
                        } else {
                            let (parts, body) = request.into_parts();
                            let echo = body
                                .collect()
                                .await
                                .map(|body| body.to_bytes())
                                .unwrap_or_default();
                            let content = format!(
                                "{} {} {}",
                                parts.method,
                                parts.uri,
                                String::from_utf8_lossy(&echo)
                            );
                            Response::new(Full::new(Bytes::from(content)).boxed_unsync())
                        };
                        response
                            .headers_mut()
                            .insert(http::header::ALT_SVC, "h3=\":1234\"".parse().unwrap());
                        Ok::<Response<OriginBody>, Infallible>(response)
                    }
                });
                let _ = server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), handle)
                    .await;
            });
        }
    });
    (address, release)
}

fn request(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn http1<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: S,
) -> http1::SendRequest<Full<Bytes>> {
    let (send, connection) = http1::handshake(TokioIo::new(socket)).await.unwrap();
    tokio::spawn(connection);
    send
}

async fn raw(address: SocketAddr, request: &[u8]) -> String {
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(request).await.unwrap();
    let mut response = String::new();
    time::timeout(DEADLINE, socket.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

#[tokio::test]
async fn http1_keeps_admitted_bodies_and_reloads_existing_connections() {
    time::timeout(DEADLINE, async {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("old")).unwrap();
        fs::create_dir(dir.path().join("new")).unwrap();
        fs::write(dir.path().join("old/index.html"), "old").unwrap();
        fs::write(dir.path().join("new/index.html"), "new").unwrap();
        let (origin, finish) = origin().await;
        let bind = port();
        let old = format!(r#"
schema_version = 1
admin_socket = "run/admin.sock"
state_dir = "state"
drain_timeout = "500ms"
[limits]
max_body_bytes = 16
max_header_bytes = 4096
[[listeners]]
name = "http"
bind = "{bind}"
protocols = ["http1"]
default_site = "localhost"
[[sites]]
host = "localhost"
listeners = ["http"]
[[sites.routes]]
name = "api"
path_prefix = "/api"
upstream = "app"
[[sites.routes]]
name = "home"
path_prefix = "/"
static_root = "old"
[upstreams.app]
endpoints = [{{ url = "http://{origin}" }}]
"#);
        let mut rocky = Daemon::run(dir, &old).await;
        let http10 = raw(bind, b"GET / HTTP/1.0\r\n\r\n").await;
        assert!(http10.starts_with("HTTP/1.0 200"), "{http10}");
        assert!(http10.ends_with("old"));
        for (wire, status) in [
            (&b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"[..], "400"),
            (&b"GET /%2Fetc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"[..], "400"),
            (&b"POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 17\r\nConnection: close\r\n\r\n12345678901234567"[..], "413"),
            (&b"POST /api HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n11\r\n12345678901234567\r\n0\r\n\r\n"[..], "413"),
            (&b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"[..], "204"),
        ] {
            assert!(raw(bind, wire).await.starts_with(&format!("HTTP/1.1 {status}")));
        }
        let oversized = format!("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Large: {}\r\n\r\n", "a".repeat(4500));
        assert!(raw(bind, oversized.as_bytes()).await.starts_with("HTTP/1.1 431"));
        let mut keep = http1(TcpStream::connect(bind).await.unwrap()).await;
        let first = keep.send_request(request("/api/%69tems?b=2&a=1")).await.unwrap();
        assert!(!first.headers().contains_key(http::header::ALT_SVC));
        assert_eq!(first.into_body().collect().await.unwrap().to_bytes(), "GET /api/items?b=2&a=1 ");
        assert_eq!(keep.send_request(request("/apix")).await.unwrap().status(), StatusCode::NOT_FOUND);
        let mut slow = http1(TcpStream::connect(bind).await.unwrap()).await;
        let mut admitted = slow.send_request(request("/api/delay")).await.unwrap().into_body();
        assert_eq!(admitted.frame().await.unwrap().unwrap().into_data().unwrap(), "first");

        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let free = port();
        let candidate = format!(r#"{old}
[[listeners]]
name = "added"
bind = "{free}"
protocols = ["http1"]
[[listeners]]
name = "occupied"
bind = "{}"
protocols = ["http1"]
"#, occupied.local_addr().unwrap());
        rocky.reload("schema_version = 'wrong'", false);
        rocky.reload(&old.replace("static_root = \"old\"", "static_root = \"absent\""), false);
        for _ in 0..3 { rocky.reload(&candidate, false); }
        assert!(TcpListener::bind(free).await.is_ok(), "candidate socket was retained");
        assert_eq!(rocky.status()["generation"], 1);
        assert_eq!(rocky.status()["metrics"]["rejected_reloads"], 5);
        let new = old.replace("static_root = \"old\"", "static_root = \"new\"");
        rocky.reload(&new, true);
        assert_eq!(rocky.status()["generation"], 2);
        assert_eq!(keep.send_request(request("/")).await.unwrap().into_body().collect().await.unwrap().to_bytes(), "new");
        finish.notify_one();
        assert_eq!(admitted.collect().await.unwrap().to_bytes(), "last");
        rocky.stop().await;
    }).await.unwrap();
}

fn tls_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    protocol: &[u8],
) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![protocol.to_vec()];
    config
}

async fn tcp_tls(
    address: SocketAddr,
    config: rustls::ClientConfig,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let socket = TcpStream::connect(address).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap()
}

#[tokio::test]
async fn tls_http2_and_http3_share_routes_and_limits_through_quic_drain() {
    time::timeout(DEADLINE, async {
        let dir = tempfile::tempdir().unwrap();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(dir.path().join("certificate.pem"), cert.pem()).unwrap();
        fs::write(dir.path().join("key.pem"), signing_key.serialize_pem()).unwrap();
        fs::create_dir(dir.path().join("www")).unwrap();
        fs::write(dir.path().join("www/index.html"), "static").unwrap();
        let (origin, finish) = origin().await;
        let address = quic_port();
        let config = format!(
            r#"
schema_version = 1
admin_socket = "run/admin.sock"
state_dir = "state"
drain_timeout = "2s"
[[listeners]]
name = "https"
bind = "{address}"
protocols = ["http1", "h2", "h3"]
tls = true
[[sites]]
host = "localhost"
listeners = ["https"]
tls = "manual"
certificate = "certificate.pem"
key = "key.pem"
[[sites.routes]]
name = "limited"
path_prefix = "/limited"
upstream = "app"
[sites.routes.rate_limit]
requests_per_second = 0.001
burst = 2
max_clients = 64
[[sites.routes]]
name = "api"
path_prefix = "/api"
upstream = "app"
[[sites.routes]]
name = "home"
path_prefix = "/"
static_root = "www"
[upstreams.app]
endpoints = [{{ url = "http://{origin}" }}]
"#
        );
        let mut rocky = Daemon::run(dir, &config).await;
        let mut h1 =
            http1(tcp_tls(address, tls_config(cert.der().clone(), b"http/1.1")).await).await;
        assert_eq!(
            h1.send_request(request("/limited"))
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "GET /limited "
        );
        let tls = tcp_tls(address, tls_config(cert.der().clone(), b"h2")).await;
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (mut h2, task) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(task);
        let h2_request = |path: &str| {
            Request::builder()
                .uri(format!("https://localhost:{}{path}", address.port()))
                .body(Full::new(Bytes::new()))
                .unwrap()
        };
        let response = h2.send_request(h2_request("/limited")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[http::header::ALT_SVC],
            format!("h3=\":{}\"; ma=300", address.port())
        );
        response.into_body().collect().await.unwrap();
        let wrong_host = Request::builder()
            .uri("https://other.test/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            h2.send_request(wrong_host).await.unwrap().status(),
            StatusCode::MISDIRECTED_REQUEST
        );

        let wrong_key = rcgen::KeyPair::generate().unwrap();
        fs::write(rocky.dir.path().join("key.pem"), wrong_key.serialize_pem()).unwrap();
        rocky.reload(&config, false);
        fs::write(
            rocky.dir.path().join("key.pem"),
            signing_key.serialize_pem(),
        )
        .unwrap();
        assert_eq!(rocky.status()["generation"], 1);

        let mut slow_h2 = h2
            .send_request(h2_request("/api/delay"))
            .await
            .unwrap()
            .into_body();
        assert_eq!(
            slow_h2.frame().await.unwrap().unwrap().into_data().unwrap(),
            "first"
        );
        let overlapping = h2.send_request(h2_request("/")).await.unwrap();
        assert_eq!(
            overlapping.into_body().collect().await.unwrap().to_bytes(),
            "static"
        );
        finish.notify_one();
        assert_eq!(slow_h2.collect().await.unwrap().to_bytes(), "last");

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let tls = QuicClientConfig::try_from(tls_config(cert.der().clone(), b"h3")).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(tls)));
        let connection = endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut h3) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        tokio::spawn(async move { driver.wait_idle().await });
        let h3_request = |path: &str| {
            Request::builder()
                .uri(format!("https://localhost:{}{path}", address.port()))
                .body(())
                .unwrap()
        };
        let mut limited = h3.send_request(h3_request("/limited")).await.unwrap();
        limited.finish().await.unwrap();
        let rate_limit = limited.recv_response().await.unwrap();
        assert_eq!(rate_limit.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(rate_limit.headers().contains_key(http::header::RETRY_AFTER));
        while limited.recv_data().await.unwrap().is_some() {}

        let mut active = h3.send_request(h3_request("/api/delay")).await.unwrap();
        active.finish().await.unwrap();
        assert_eq!(
            active.recv_response().await.unwrap().status(),
            StatusCode::OK
        );
        let mut data = active.recv_data().await.unwrap().unwrap();
        assert_eq!(data.copy_to_bytes(data.remaining()), "first");
        rocky.reload(&config.replace(", \"h3\"", ""), true);
        let tcp_fallback = h2.send_request(h2_request("/")).await.unwrap();
        assert_eq!(tcp_fallback.headers()[http::header::ALT_SVC], "clear");
        assert_eq!(
            tcp_fallback.into_body().collect().await.unwrap().to_bytes(),
            "static"
        );
        finish.notify_one();
        let mut last = Vec::new();
        while let Some(mut chunk) = active.recv_data().await.unwrap() {
            last.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(last, b"last");
        endpoint.close(0u32.into(), b"test finished");
        rocky.stop().await;
    })
    .await
    .unwrap();
}

async fn echo(upper: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 128];
                loop {
                    let Ok(read) = socket.read(&mut buffer).await else {
                        return;
                    };
                    if read == 0 {
                        let _ = socket.write_all(b"eof").await;
                        return;
                    }
                    let data = &mut buffer[..read];
                    if upper {
                        data.make_ascii_uppercase();
                    } else {
                        data.make_ascii_lowercase();
                    }
                    if socket.write_all(data).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    bind
}

async fn relay_echo(socket: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
    socket.write_all(bytes).await.unwrap();
    let mut response = vec![0; bytes.len()];
    socket.read_exact(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn tcp_relay_preserves_half_close_and_retires_changed_rules() {
    time::timeout(DEADLINE, async {
        let dir = tempfile::tempdir().unwrap();
        let original = echo(true).await;
        let next = echo(false).await;
        let bind = port();
        let config = format!(
            r#"
schema_version = 1
admin_socket = "run/admin.sock"
state_dir = "state"
drain_timeout = "500ms"
[[streams]]
name = "echo"
bind = "{bind}"
upstream = "{original}"
idle_timeout = "2s"
"#
        );
        let mut rocky = Daemon::run(dir, &config).await;
        let mut socket = TcpStream::connect(bind).await.unwrap();
        socket.write_all(b"hello").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut output = Vec::new();
        socket.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"HELLOeof");

        let mut retained = TcpStream::connect(bind).await.unwrap();
        assert_eq!(relay_echo(&mut retained, b"old").await, b"OLD");
        rocky.reload(
            &config.replace(&original.to_string(), &next.to_string()),
            true,
        );
        assert_eq!(relay_echo(&mut retained, b"old").await, b"OLD");
        let mut current = TcpStream::connect(bind).await.unwrap();
        assert_eq!(relay_echo(&mut current, b"NEW").await, b"new");
        let mut buffer = [0];
        assert_eq!(
            time::timeout(Duration::from_secs(1), retained.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            time::timeout(Duration::from_secs(3), current.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(rocky.status()["metrics"]["drains"].as_u64().unwrap() >= 1);
        let mut active = TcpStream::connect(bind).await.unwrap();
        assert_eq!(relay_echo(&mut active, b"OPEN").await, b"open");
        tokio::join!(rocky.stop(), async {
            time::sleep(Duration::from_millis(50)).await;
            assert_eq!(relay_echo(&mut active, b"DRAINING").await, b"draining");
            active.shutdown().await.unwrap();
            let mut eof = Vec::new();
            active.read_to_end(&mut eof).await.unwrap();
            assert_eq!(eof, b"eof");
        });
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn slow_http1_readers_release_request_capacity_after_cancel_or_idle_timeout() {
    time::timeout(DEADLINE, async {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("www")).unwrap();
        fs::write(dir.path().join("www/index.html"), "available").unwrap();
        File::create(dir.path().join("www/large"))
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();
        let bind = port();
        let config = format!(
            r#"
schema_version = 1
admin_socket = "run/admin.sock"
state_dir = "state"
[limits]
body_idle_timeout = "1s"
[[listeners]]
name = "http"
bind = "{bind}"
protocols = ["http1"]
[[sites]]
host = "localhost"
listeners = ["http"]
[[sites.routes]]
name = "home"
path_prefix = "/"
static_root = "www"
"#
        );
        let mut rocky = Daemon::run(dir, &config).await;
        for disconnect in [true, false] {
            let mut slow = TcpStream::connect(bind).await.unwrap();
            socket2::SockRef::from(&slow)
                .set_recv_buffer_size(1024)
                .unwrap();
            slow.write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let active = || {
                rocky.status()["metrics"]["requests_active"]
                    .as_u64()
                    .unwrap()
            };
            while active() == 0 {
                time::sleep(Duration::from_millis(10)).await;
            }
            let quick = raw(
                bind,
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(quick.ends_with("available"));
            let mut slow = Some(slow);
            if disconnect {
                slow.take();
            }
            time::timeout(Duration::from_secs(3), async {
                while active() != 0 {
                    time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("slow response kept its request permit");
            drop(slow);
        }
        rocky.stop().await;
    })
    .await
    .unwrap();
}
