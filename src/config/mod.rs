mod compile;

use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, time::Duration};

pub use compile::{normalize_host, normalize_path};
use http::Uri;
use ipnet::IpNet;

#[derive(Debug, Clone)]
pub struct Config {
    pub admin_socket: PathBuf,
    pub state_dir: PathBuf,
    pub drain_timeout: Duration,
    pub limits: Limits,
    pub acme: Option<AcmeConfig>,
    pub listeners: BTreeMap<String, HttpListener>,
    pub sites: Vec<Site>,
    pub upstreams: BTreeMap<String, Upstream>,
    pub streams: BTreeMap<String, Stream>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_connections: usize,
    pub max_requests: usize,
    pub max_streams_per_connection: u32,
    pub max_header_bytes: usize,
    pub max_body_bytes: u64,
    pub max_buffer_bytes: usize,
    pub max_file_operations: usize,
    pub handshake_timeout: Duration,
    pub request_head_timeout: Duration,
    pub body_idle_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub contact: String,
    pub accept_terms: bool,
    pub trust_roots: Option<PathBuf>,
    pub max_concurrent_orders: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpListener {
    pub bind: SocketAddr,
    pub protocols: Protocols,
    pub tls: bool,
    pub default_site: Option<String>,
    pub trusted_proxies: Vec<IpNet>,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocols {
    pub http1: bool,
    pub h2: bool,
    pub h3: bool,
}

impl Protocols {
    pub fn tcp(self) -> bool {
        self.http1 || self.h2
    }
}

#[derive(Debug, Clone)]
pub struct Site {
    pub host: String,
    pub listeners: Vec<String>,
    pub tls: SiteTls,
    pub redirect_http: bool,
    pub public_https_port: Option<u16>,
    pub public_quic_port: Option<u16>,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteTls {
    Off,
    Acme,
    Manual { certificate: PathBuf, key: PathBuf },
}

#[derive(Debug, Clone)]
pub struct Route {
    pub name: String,
    pub path_prefix: String,
    pub action: Action,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone)]
pub enum Action {
    Static {
        root: PathBuf,
        index: Option<String>,
    },
    Proxy {
        upstream: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct RateLimit {
    pub requests_per_second: f64,
    pub burst: u32,
    pub max_clients: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub protocol: UpstreamProtocol,
    pub health_path: Option<String>,
    pub endpoints: Vec<Endpoint>,
    pub trust_roots: Option<PathBuf>,
    pub connect_timeout: Duration,
    pub response_head_timeout: Duration,
    pub body_idle_timeout: Duration,
    pub health_interval: Duration,
    pub health_timeout: Duration,
    pub dns_refresh: Duration,
    pub cooldown: Duration,
    pub max_idle_connections: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    H1,
    H2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub url: Uri,
    pub weight: u32,
    pub max_connections: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub bind: SocketAddr,
    pub upstream: String,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_connections: usize,
}
