mod quic;
mod quic_limits;
mod tcp;

use std::{
    future, io,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use socket2::{Domain, Protocol as IpProtocol, Socket as RawSocket, Type};
use tokio::{
    net::TcpListener,
    time::{self, Instant},
};

use crate::{
    config::{Protocols, normalize_host},
    runtime::{
        BindKey, BindingPolicy, Driver, Generation, HttpBinding, Lifetime, Metrics, Runtime,
        Transport, micros_since,
    },
    stream,
};

pub enum Socket {
    Tcp(TcpListener),
    Quic(quinn::Endpoint),
}

impl Socket {
    pub fn bind(key: BindKey, quic_tls: Option<Arc<quinn::ServerConfig>>) -> io::Result<Self> {
        let (kind, protocol) = match key.transport {
            Transport::Tcp => (Type::STREAM, IpProtocol::TCP),
            Transport::Quic => (Type::DGRAM, IpProtocol::UDP),
        };
        let socket = RawSocket::new(Domain::for_address(key.addr), kind, Some(protocol))?;
        if key.addr.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        if key.transport == Transport::Tcp {
            socket.set_reuse_address(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&key.addr.into())?;
        match key.transport {
            Transport::Tcp => {
                socket.listen(1024)?;
                Ok(Self::Tcp(TcpListener::from_std(socket.into())?))
            }
            Transport::Quic => {
                let config =
                    quic_tls.ok_or_else(|| io::Error::other("missing QUIC TLS configuration"))?;
                let endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(config.as_ref().clone()),
                    socket.into(),
                    Arc::new(quinn::TokioRuntime),
                )?;
                Ok(Self::Quic(endpoint))
            }
        }
    }
}

pub async fn drive(runtime: Arc<Runtime>, driver: Arc<Driver>, socket: Socket) {
    match socket {
        Socket::Tcp(socket) => drive_tcp(runtime, driver, socket).await,
        Socket::Quic(socket) => quic::drive(runtime, driver, socket).await,
    }
}

async fn drive_tcp(runtime: Arc<Runtime>, driver: Arc<Driver>, socket: TcpListener) {
    loop {
        let (socket, peer) = tokio::select! {
            biased;
            _ = driver.stop.cancelled() => break,
            pair = socket.accept() => match pair {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::warn!(bind = %driver.key.addr, %error, "TCP accept failed");
                    tokio::select! {
                        _ = driver.stop.cancelled() => break,
                        _ = time::sleep(Duration::from_millis(100)) => continue,
                    }
                }
            }
        };
        let Some(active) = runtime.active.load_full() else {
            break;
        };
        let Some(binding) = active
            .bindings
            .get(&driver.key)
            .filter(|binding| Arc::ptr_eq(&driver, &binding.driver))
        else {
            break;
        };
        let Some(permits) = runtime.admit_connection(binding, &active.limits) else {
            continue;
        };
        let runtime = Arc::clone(&runtime);
        let generation = active.id;
        let _ = socket.set_nodelay(true);
        match &binding.policy {
            BindingPolicy::Http(http) => {
                let http = Arc::clone(http);
                let driver = Arc::clone(&driver);
                let limits = active.limits.clone();
                let tls = active.tls.tcp_config(&http.name);
                runtime.tasks.clone().spawn(async move {
                    let _permits = permits;
                    tcp::serve(runtime, driver, http, limits, socket, peer, tls).await;
                });
            }
            BindingPolicy::Stream(rule) => {
                let rule = Arc::clone(rule);
                let metrics = Arc::clone(&runtime.metrics);
                runtime.tasks.spawn(async move {
                    let _permits = permits;
                    stream::relay(socket, rule, generation, metrics).await;
                });
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    H1,
    H2,
    H3,
}

impl Protocol {
    fn enabled(self, protocols: Protocols) -> bool {
        match self {
            Self::H1 => protocols.http1,
            Self::H2 => protocols.h2,
            Self::H3 => protocols.h3,
        }
    }
}

pub struct Connection {
    pub listener: String,
    pub peer: SocketAddr,
    pub protocol: Protocol,
    pub tls: Option<TlsPeer>,
    driver: Arc<Driver>,
    lifetime: Arc<Lifetime>,
}

pub struct TlsPeer {
    pub host: String,
    lifetime: Arc<Lifetime>,
}

impl Connection {
    fn open(
        driver: Arc<Driver>,
        binding: &HttpBinding,
        peer: SocketAddr,
        protocol: Protocol,
        sni: Option<&str>,
    ) -> Option<Self> {
        if !protocol.enabled(binding.settings.protocols) {
            return None;
        }
        let tls = if binding.settings.tls {
            let host = match sni {
                Some(name) => normalize_host(name)?,
                None => binding.settings.default_site.clone()?,
            };
            let (_, lifetime) = binding.tls_sites.get(&host)?;
            Some(TlsPeer {
                host,
                lifetime: Arc::clone(lifetime),
            })
        } else {
            None
        };
        Some(Self {
            listener: binding.name.clone(),
            peer,
            protocol,
            tls,
            driver,
            lifetime: Arc::clone(&binding.lifetime),
        })
    }

    pub fn binding<'a>(&self, generation: &'a Generation) -> Option<&'a HttpBinding> {
        let binding = generation.bindings.get(&self.driver.key)?;
        let policy = binding.http()?;
        if !Arc::ptr_eq(&binding.driver, &self.driver)
            || !Arc::ptr_eq(&policy.lifetime, &self.lifetime)
            || !self.protocol.enabled(policy.settings.protocols)
        {
            return None;
        }
        if let Some(tls) = &self.tls {
            let (_, lifetime) = policy.tls_sites.get(&tls.host)?;
            if !Arc::ptr_eq(lifetime, &tls.lifetime) {
                return None;
            }
        }
        Some(policy)
    }

    async fn retired(&self) -> Instant {
        match &self.tls {
            Some(tls) => tokio::select! {
                deadline = self.lifetime.retired() => deadline,
                deadline = tls.lifetime.retired() => deadline,
            },
            None => self.lifetime.retired().await,
        }
    }
}

pub async fn drain<F: future::Future>(
    metrics: &Metrics,
    deadline: Instant,
    work: F,
) -> Option<F::Output> {
    let start = Instant::now();
    metrics.drains.fetch_add(1, Ordering::Relaxed);
    let result = time::timeout_at(deadline, work).await.ok();
    metrics
        .drain_micros
        .fetch_add(micros_since(start), Ordering::Relaxed);
    result
}
