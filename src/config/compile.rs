use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use http::{Uri, uri::Authority};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de};
use tokio::sync::Semaphore;

use super::{
    AcmeConfig, Action, Config, Endpoint, HttpListener, Limits, Protocols, RateLimit, Route, Site,
    SiteTls, Stream, Upstream, UpstreamProtocol,
};

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let path = std::path::absolute(path)?;
        let input = fs::read_to_string(&path)
            .with_context(|| format!("reading configuration {}", path.display()))?;
        let base = path
            .parent()
            .ok_or_else(|| anyhow!("configuration file must have a parent directory"))?;
        let raw: RawConfig = serde_path_to_error::deserialize(toml::de::Deserializer::new(&input))
            .map_err(|error| anyhow!("{}: {}", error.path(), error.inner()))?;
        raw.compile(base)
            .with_context(|| format!("validating configuration {}", path.display()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u32,
    admin_socket: PathBuf,
    state_dir: PathBuf,
    drain_timeout: Option<DurationSetting>,
    #[serde(default)]
    limits: RawLimits,
    acme: Option<RawAcme>,
    #[serde(default)]
    listeners: Vec<RawListener>,
    #[serde(default)]
    sites: Vec<RawSite>,
    #[serde(default)]
    upstreams: BTreeMap<String, RawUpstream>,
    #[serde(default)]
    streams: Vec<RawStream>,
}

impl RawConfig {
    fn compile(self, base: &Path) -> Result<Config> {
        ensure!(
            self.schema_version == 1,
            "schema_version must be 1, got {}",
            self.schema_version
        );

        let limits = self.limits.compile()?;
        let acme = self.acme.map(|section| section.compile(base)).transpose()?;
        let mut bindings = Bindings::default();
        let mut listeners = BTreeMap::new();
        let mut listener_fields = BTreeMap::new();
        for (index, listener) in self.listeners.into_iter().enumerate() {
            let field = format!("listeners[{index}]");
            validate_name(&listener.name, &format!("{field}.name"))?;
            let compiled = listener.compile(&field)?;
            ensure!(
                !listeners.contains_key(&listener.name),
                "{field}.name duplicates '{}' from an earlier listener",
                listener.name
            );
            let bind_field = format!("{field}.bind");
            if compiled.protocols.tcp() {
                bindings.tcp(compiled.bind, &bind_field)?;
            }
            if compiled.protocols.h3 {
                bindings.udp(compiled.bind, &bind_field)?;
            }
            listener_fields.insert(listener.name.clone(), field);
            listeners.insert(listener.name, compiled);
        }

        let mut streams = BTreeMap::new();
        for (index, stream) in self.streams.into_iter().enumerate() {
            let field = format!("streams[{index}]");
            validate_name(&stream.name, &format!("{field}.name"))?;
            ensure!(
                !streams.contains_key(&stream.name) && !listeners.contains_key(&stream.name),
                "{field}.name duplicates binding name '{}'",
                stream.name
            );
            let compiled = stream.compile(&field)?;
            bindings.tcp(compiled.bind, &format!("{field}.bind"))?;
            streams.insert(stream.name, compiled);
        }

        let mut upstreams = BTreeMap::new();
        for (name, pool) in self.upstreams {
            let field = format!("upstreams.{name}");
            validate_name(&name, &field)?;
            upstreams.insert(name, pool.compile(base, &field)?);
        }

        let mut sites = Vec::new();
        let mut assigned = BTreeSet::new();
        for (index, site) in self.sites.into_iter().enumerate() {
            let field = format!("sites[{index}]");
            let site = site.compile(base, &field, &listeners, &upstreams, acme.as_ref())?;
            for listener in &site.listeners {
                ensure!(
                    assigned.insert((listener.clone(), site.host.clone())),
                    "{field}.host duplicates '{}' on listener '{listener}'",
                    site.host
                );
            }
            sites.push(site);
        }
        for (name, listener) in &listeners {
            if let Some(host) = &listener.default_site {
                ensure!(
                    assigned.contains(&(name.clone(), host.clone())),
                    "{}.default_site refers to '{host}', which has no site on listener '{name}'",
                    listener_fields[name]
                );
            }
        }
        Ok(Config {
            admin_socket: resolve_path(base, self.admin_socket, "admin_socket")?,
            state_dir: resolve_path(base, self.state_dir, "state_dir")?,
            drain_timeout: duration(self.drain_timeout, 30),
            limits,
            acme,
            listeners,
            sites,
            upstreams,
            streams,
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_connections: Option<usize>,
    max_requests: Option<usize>,
    max_streams_per_connection: Option<u32>,
    max_header_bytes: Option<usize>,
    max_body_bytes: Option<u64>,
    max_buffer_bytes: Option<usize>,
    max_file_operations: Option<usize>,
    handshake_timeout: Option<DurationSetting>,
    request_head_timeout: Option<DurationSetting>,
    body_idle_timeout: Option<DurationSetting>,
}

impl RawLimits {
    fn compile(self) -> Result<Limits> {
        let max_streams_per_connection = self.max_streams_per_connection.unwrap_or(64);
        ensure!(
            max_streams_per_connection > 0,
            "limits.max_streams_per_connection must be positive"
        );
        let max_header_bytes = self.max_header_bytes.unwrap_or(32 * 1024);
        ensure!(
            (1..=u32::MAX as usize).contains(&max_header_bytes),
            "limits.max_header_bytes must be between 1 and {}",
            u32::MAX
        );
        let max_buffer_bytes = self.max_buffer_bytes.unwrap_or(64 * 1024);
        ensure!(
            (8192..=i32::MAX as usize).contains(&max_buffer_bytes),
            "limits.max_buffer_bytes must be between 8192 and {}",
            i32::MAX
        );
        Ok(Limits {
            max_connections: positive_count(self.max_connections, 1024, "limits.max_connections")?,
            max_requests: positive_count(self.max_requests, 512, "limits.max_requests")?,
            max_streams_per_connection,
            max_header_bytes,
            max_body_bytes: self.max_body_bytes.unwrap_or(16 * 1024 * 1024),
            max_buffer_bytes,
            max_file_operations: positive_count(
                self.max_file_operations,
                64,
                "limits.max_file_operations",
            )?,
            handshake_timeout: duration(self.handshake_timeout, 10),
            request_head_timeout: duration(self.request_head_timeout, 10),
            body_idle_timeout: duration(self.body_idle_timeout, 30),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAcme {
    directory_url: String,
    contact: String,
    accept_terms: bool,
    trust_roots: Option<PathBuf>,
    max_concurrent_orders: Option<usize>,
}

impl RawAcme {
    fn compile(self, base: &Path) -> Result<AcmeConfig> {
        let directory = parse_url(&self.directory_url).context("acme.directory_url")?;
        ensure!(
            directory.scheme_str() == Some("https"),
            "acme.directory_url must use HTTPS"
        );
        let valid_contact = self.contact.split_once(':').is_some_and(|(scheme, rest)| {
            scheme
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
                && scheme
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
                && !rest.is_empty()
                && rest.bytes().all(|byte| byte.is_ascii_graphic())
        });
        ensure!(
            valid_contact,
            "acme.contact must be an absolute contact URI"
        );
        Ok(AcmeConfig {
            directory_url: self.directory_url,
            contact: self.contact,
            accept_terms: self.accept_terms,
            trust_roots: optional_path(base, self.trust_roots, "acme.trust_roots")?,
            max_concurrent_orders: positive_count(
                self.max_concurrent_orders,
                4,
                "acme.max_concurrent_orders",
            )?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    name: String,
    bind: SocketAddr,
    protocols: Vec<Protocol>,
    #[serde(default)]
    tls: bool,
    default_site: Option<String>,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    max_connections: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Http1,
    H2,
    H3,
}

impl RawListener {
    fn compile(&self, field: &str) -> Result<HttpListener> {
        validate_bind(self.bind, &format!("{field}.bind"))?;
        ensure!(
            !self.protocols.is_empty(),
            "{field}.protocols must contain at least one protocol"
        );
        let mut protocols = Protocols {
            http1: false,
            h2: false,
            h3: false,
        };
        for (index, protocol) in self.protocols.iter().enumerate() {
            let enabled = match protocol {
                Protocol::Http1 => &mut protocols.http1,
                Protocol::H2 => &mut protocols.h2,
                Protocol::H3 => &mut protocols.h3,
            };
            ensure!(
                !*enabled,
                "{field}.protocols[{index}] duplicates an earlier protocol"
            );
            *enabled = true;
        }
        ensure!(
            self.tls || !(protocols.h2 || protocols.h3),
            "{field}.tls must be true for h2 or h3"
        );
        let default_site = self
            .default_site
            .as_deref()
            .map(|name| dns_host(name, &format!("{field}.default_site")))
            .transpose()?;
        let trusted_proxies = self
            .trusted_proxies
            .iter()
            .enumerate()
            .map(|(index, proxy)| {
                proxy
                    .parse::<IpNet>()
                    .map(|network| network.trunc())
                    .with_context(|| format!("{field}.trusted_proxies[{index}] must be a CIDR"))
            })
            .collect::<Result<_>>()?;
        Ok(HttpListener {
            bind: self.bind,
            protocols,
            tls: self.tls,
            default_site,
            trusted_proxies,
            max_connections: positive_count(
                self.max_connections,
                256,
                &format!("{field}.max_connections"),
            )?,
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TlsMode {
    #[default]
    Off,
    Acme,
    Manual,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSite {
    host: String,
    listeners: Vec<String>,
    #[serde(default)]
    tls: TlsMode,
    certificate: Option<PathBuf>,
    key: Option<PathBuf>,
    #[serde(default)]
    redirect_http: bool,
    public_https_port: Option<u16>,
    public_quic_port: Option<u16>,
    #[serde(default)]
    routes: Vec<RawRoute>,
}

impl RawSite {
    fn compile(
        self,
        base: &Path,
        field: &str,
        listeners: &BTreeMap<String, HttpListener>,
        upstreams: &BTreeMap<String, Upstream>,
        acme: Option<&AcmeConfig>,
    ) -> Result<Site> {
        let host = dns_host(&self.host, &format!("{field}.host"))?;
        ensure!(
            !self.listeners.is_empty(),
            "{field}.listeners must not be empty"
        );

        let mut seen = BTreeSet::new();
        let mut assigned = Vec::new();
        for (index, name) in self.listeners.iter().enumerate() {
            let listener_field = format!("{field}.listeners[{index}]");
            ensure!(seen.insert(name), "{listener_field} duplicates '{name}'");
            let listener = listeners
                .get(name)
                .ok_or_else(|| anyhow!("{listener_field} refers to unknown listener '{name}'"))?;
            assigned.push(listener);
        }

        let has_tls = assigned.iter().any(|listener| listener.tls);
        if !matches!(self.tls, TlsMode::Manual) {
            ensure!(
                self.certificate.is_none(),
                "{field}.certificate requires tls = 'manual'"
            );
            ensure!(self.key.is_none(), "{field}.key requires tls = 'manual'");
        }
        let tls = match self.tls {
            TlsMode::Off => {
                ensure!(!has_tls, "{field}.tls is required for encrypted listeners");
                SiteTls::Off
            }
            TlsMode::Acme => {
                ensure!(
                    has_tls,
                    "{field}.tls = 'acme' requires an encrypted listener"
                );
                ensure!(
                    host.parse::<IpAddr>().is_err(),
                    "{field}.host must be a DNS name for ACME HTTP-01"
                );
                ensure!(
                    acme.is_some_and(|settings| settings.accept_terms),
                    "{field}.tls = 'acme' requires acme.accept_terms = true"
                );
                ensure!(
                    assigned
                        .iter()
                        .any(|listener| !listener.tls && listener.protocols.http1),
                    "{field}.listeners needs a plaintext HTTP/1.x listener for ACME HTTP-01"
                );
                SiteTls::Acme
            }
            TlsMode::Manual => {
                let cert_field = format!("{field}.certificate");
                let key_field = format!("{field}.key");
                SiteTls::Manual {
                    certificate: resolve_path(
                        base,
                        self.certificate
                            .ok_or_else(|| anyhow!("{cert_field} is required"))?,
                        &cert_field,
                    )?,
                    key: resolve_path(
                        base,
                        self.key.ok_or_else(|| anyhow!("{key_field} is required"))?,
                        &key_field,
                    )?,
                }
            }
        };

        let https_ports = assigned
            .iter()
            .filter(|listener| listener.tls && listener.protocols.tcp())
            .map(|listener| listener.bind.port())
            .collect::<BTreeSet<_>>();
        let quic_ports = assigned
            .iter()
            .filter(|listener| listener.protocols.h3)
            .map(|listener| listener.bind.port())
            .collect::<BTreeSet<_>>();
        ensure!(
            !self.redirect_http || !https_ports.is_empty(),
            "{field}.redirect_http requires an encrypted TCP listener"
        );
        let public_https_port = public_port(
            self.public_https_port,
            &https_ports,
            self.redirect_http,
            &format!("{field}.public_https_port"),
        )?;
        let public_quic_port = public_port(
            self.public_quic_port,
            &quic_ports,
            !https_ports.is_empty() && !quic_ports.is_empty(),
            &format!("{field}.public_quic_port"),
        )?;

        let mut routes = Vec::new();
        let mut route_names = BTreeSet::new();
        let mut route_prefixes = BTreeSet::new();
        for (index, route) in self.routes.into_iter().enumerate() {
            let route_field = format!("{field}.routes[{index}]");
            let route = route.compile(base, &route_field, upstreams)?;
            ensure!(
                route_names.insert(route.name.clone()),
                "{route_field}.name duplicates '{}'",
                route.name
            );
            ensure!(
                route_prefixes.insert(route.path_prefix.clone()),
                "{route_field}.path_prefix duplicates normalized prefix '{}'",
                route.path_prefix
            );
            routes.push(route);
        }
        routes.sort_by_key(|route| std::cmp::Reverse(route.path_prefix.len()));
        Ok(Site {
            host,
            listeners: self.listeners,
            tls,
            redirect_http: self.redirect_http,
            public_https_port,
            public_quic_port,
            routes,
        })
    }
}

fn public_port(
    explicit: Option<u16>,
    ports: &BTreeSet<u16>,
    used: bool,
    field: &str,
) -> Result<Option<u16>> {
    match explicit {
        Some(port) => {
            ensure!(port != 0, "{field} must be nonzero");
            Ok((!ports.is_empty()).then_some(port))
        }
        None if ports.len() == 1 => Ok(ports.first().copied()),
        None if used => bail!("{field} is required when listener ports differ"),
        None => Ok(None),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    name: String,
    path_prefix: String,
    static_root: Option<PathBuf>,
    upstream: Option<String>,
    index: Option<String>,
    rate_limit: Option<RawRateLimit>,
}

impl RawRoute {
    fn compile(
        self,
        base: &Path,
        field: &str,
        upstreams: &BTreeMap<String, Upstream>,
    ) -> Result<Route> {
        validate_name(&self.name, &format!("{field}.name"))?;
        let mut path_prefix =
            normalize_path(&self.path_prefix).with_context(|| format!("{field}.path_prefix"))?;
        if path_prefix.len() > 1 && path_prefix.ends_with('/') {
            path_prefix.pop();
        }
        let action = match (self.static_root, self.upstream) {
            (Some(root), None) => {
                let index = self.index.unwrap_or_else(|| "index.html".into());
                ensure!(
                    !matches!(index.as_str(), "." | "..") && !index.contains(['/', '\\', '\0']),
                    "{field}.index must be a single filename or empty"
                );
                Action::Static {
                    root: resolve_path(base, root, &format!("{field}.static_root"))?,
                    index: (!index.is_empty()).then_some(index),
                }
            }
            (None, Some(upstream)) => {
                ensure!(self.index.is_none(), "{field}.index requires static_root");
                ensure!(
                    upstreams.contains_key(&upstream),
                    "{field}.upstream refers to unknown pool '{upstream}'"
                );
                Action::Proxy { upstream }
            }
            _ => bail!("{field} requires exactly one of static_root or upstream"),
        };
        Ok(Route {
            name: self.name,
            path_prefix,
            action,
            rate_limit: self
                .rate_limit
                .map(|limit| limit.compile(&format!("{field}.rate_limit")))
                .transpose()?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRateLimit {
    requests_per_second: f64,
    burst: u32,
    max_clients: usize,
}

impl RawRateLimit {
    fn compile(self, field: &str) -> Result<RateLimit> {
        ensure!(
            self.requests_per_second.is_finite() && self.requests_per_second > 0.0,
            "{field}.requests_per_second must be finite and positive"
        );
        ensure!(self.burst != 0, "{field}.burst must be positive");
        ensure!(
            self.max_clients != 0,
            "{field}.max_clients must be positive"
        );
        Ok(RateLimit {
            requests_per_second: self.requests_per_second,
            burst: self.burst,
            max_clients: self.max_clients,
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawUpstreamProtocol {
    #[default]
    H1,
    H2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpstream {
    #[serde(default)]
    protocol: RawUpstreamProtocol,
    endpoints: Vec<RawEndpoint>,
    health_path: Option<String>,
    trust_roots: Option<PathBuf>,
    connect_timeout: Option<DurationSetting>,
    response_head_timeout: Option<DurationSetting>,
    body_idle_timeout: Option<DurationSetting>,
    health_interval: Option<DurationSetting>,
    health_timeout: Option<DurationSetting>,
    dns_refresh: Option<DurationSetting>,
    cooldown: Option<DurationSetting>,
    max_idle_connections: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEndpoint {
    url: String,
    weight: Option<u32>,
    max_connections: Option<usize>,
}

impl RawUpstream {
    fn compile(self, base: &Path, field: &str) -> Result<Upstream> {
        let protocol = match self.protocol {
            RawUpstreamProtocol::H1 => UpstreamProtocol::H1,
            RawUpstreamProtocol::H2 => UpstreamProtocol::H2,
        };
        let health_path = self
            .health_path
            .as_deref()
            .map(normalize_health_path)
            .transpose()
            .with_context(|| format!("{field}.health_path"))?;
        ensure!(
            !self.endpoints.is_empty(),
            "{field}.endpoints must not be empty"
        );
        let mut identities = BTreeSet::new();
        let mut endpoints = Vec::new();
        for (index, endpoint) in self.endpoints.into_iter().enumerate() {
            let field = format!("{field}.endpoints[{index}]");
            let url = parse_url(&endpoint.url).with_context(|| format!("{field}.url"))?;
            ensure!(
                url.path() == "/" && url.query().is_none(),
                "{field}.url must be an origin URL with no path or query"
            );
            let scheme = url.scheme_str().expect("validated URL scheme");
            let authority = url.authority().expect("validated URL authority");
            let (host, port) = checked_authority(authority).expect("validated URL authority");
            let default_port = if scheme == "https" { 443 } else { 80 };
            ensure!(
                identities.insert((
                    scheme.to_string(),
                    host.clone(),
                    port.unwrap_or(default_port)
                )),
                "{field}.url duplicates a configured endpoint"
            );
            let weight = endpoint.weight.unwrap_or(1);
            ensure!(weight > 0, "{field}.weight must be positive");
            endpoints.push(Endpoint {
                url,
                weight,
                max_connections: positive_count(
                    endpoint.max_connections,
                    64,
                    &format!("{field}.max_connections"),
                )?,
            });
        }
        Ok(Upstream {
            protocol,
            health_path,
            endpoints,
            trust_roots: optional_path(base, self.trust_roots, &format!("{field}.trust_roots"))?,
            connect_timeout: duration(self.connect_timeout, 5),
            response_head_timeout: duration(self.response_head_timeout, 30),
            body_idle_timeout: duration(self.body_idle_timeout, 30),
            health_interval: duration(self.health_interval, 10),
            health_timeout: duration(self.health_timeout, 3),
            dns_refresh: duration(self.dns_refresh, 30),
            cooldown: duration(self.cooldown, 5),
            max_idle_connections: self.max_idle_connections.unwrap_or(8),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStream {
    name: String,
    bind: SocketAddr,
    upstream: String,
    connect_timeout: Option<DurationSetting>,
    idle_timeout: Option<DurationSetting>,
    max_connections: Option<usize>,
}

impl RawStream {
    fn compile(&self, field: &str) -> Result<Stream> {
        validate_bind(self.bind, &format!("{field}.bind"))?;
        let upstream = (|| {
            if let Ok(addr) = self.upstream.parse::<SocketAddr>() {
                ensure!(addr.port() != 0, "upstream port must be nonzero");
                return Ok(addr.to_string());
            }
            let authority = self.upstream.parse::<Authority>()?;
            let (_, port) = checked_authority(&authority)?;
            port.context("expected host:port")?;
            Ok(self.upstream.clone())
        })()
        .with_context(|| format!("{field}.upstream"))?;
        Ok(Stream {
            bind: self.bind,
            upstream,
            connect_timeout: duration(self.connect_timeout, 5),
            idle_timeout: duration(self.idle_timeout, 300),
            max_connections: positive_count(
                self.max_connections,
                128,
                &format!("{field}.max_connections"),
            )?,
        })
    }
}

#[derive(Default)]
struct Bindings {
    tcp: Vec<(SocketAddr, String)>,
    udp: Vec<(SocketAddr, String)>,
}

impl Bindings {
    fn tcp(&mut self, bind: SocketAddr, field: &str) -> Result<()> {
        Self::push(&mut self.tcp, bind, field, "TCP")
    }

    fn udp(&mut self, bind: SocketAddr, field: &str) -> Result<()> {
        Self::push(&mut self.udp, bind, field, "UDP")
    }

    fn push(
        bindings: &mut Vec<(SocketAddr, String)>,
        bind: SocketAddr,
        field: &str,
        transport: &str,
    ) -> Result<()> {
        if let Some((previous, earlier_field)) = bindings.iter().find(|(address, _)| {
            address.port() == bind.port()
                && address.is_ipv4() == bind.is_ipv4()
                && (address.ip() == bind.ip()
                    || address.ip().is_unspecified()
                    || bind.ip().is_unspecified())
        }) {
            bail!("{field} {transport} bind {bind} overlaps {earlier_field} ({previous})");
        }
        bindings.push((bind, field.to_string()));
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DurationSetting(Duration);

impl<'de> Deserialize<'de> for DurationSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let input = String::deserialize(deserializer)?;
        let duration = humantime::parse_duration(&input).map_err(de::Error::custom)?;
        if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
            return Err(de::Error::custom(
                "duration must be positive and representable",
            ));
        }
        Ok(Self(duration))
    }
}

fn duration(setting: Option<DurationSetting>, default_seconds: u64) -> Duration {
    setting.map_or(Duration::from_secs(default_seconds), |setting| setting.0)
}

fn positive_count(value: Option<usize>, default: usize, field: &str) -> Result<usize> {
    let value = value.unwrap_or(default);
    ensure!(
        (1..=Semaphore::MAX_PERMITS).contains(&value),
        "{field} must be between 1 and {}",
        Semaphore::MAX_PERMITS
    );
    Ok(value)
}

fn validate_name(name: &str, field: &str) -> Result<()> {
    ensure!(
        !name.trim().is_empty() && !name.chars().any(char::is_control),
        "{field} must be a nonempty name without control characters"
    );
    Ok(())
}

fn validate_bind(bind: SocketAddr, field: &str) -> Result<()> {
    ensure!(bind.port() != 0, "{field} port must be nonzero");
    if let IpAddr::V6(ip) = bind.ip() {
        ensure!(
            ip.to_ipv4_mapped().is_none(),
            "{field} must use a native address"
        );
    }
    Ok(())
}

fn resolve_path(base: &Path, path: PathBuf, field: &str) -> Result<PathBuf> {
    ensure!(
        !path.as_os_str().is_empty() && !path.as_os_str().as_bytes().contains(&0),
        "{field} must be a nonempty path without NUL bytes"
    );
    Ok(base.join(path))
}

fn optional_path(base: &Path, path: Option<PathBuf>, field: &str) -> Result<Option<PathBuf>> {
    path.map(|path| resolve_path(base, path, field)).transpose()
}

fn dns_host(host: &str, field: &str) -> Result<String> {
    normalize_host(host).ok_or_else(|| anyhow!("{field} must be an exact ASCII hostname"))
}

fn checked_authority(authority: &Authority) -> Result<(String, Option<u16>)> {
    let raw = authority.as_str();
    ensure!(
        !raw.contains('@'),
        "authority must not contain user information"
    );
    let host = authority.host();
    let normalized = match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(ip) => format!(
            "[{}]",
            ip.parse::<Ipv6Addr>().context("invalid IPv6 address")?
        ),
        None => normalize_host(host).context("invalid hostname")?,
    };
    let rest = &raw[host.len()..];
    let port = if rest.is_empty() {
        None
    } else {
        let port = rest.strip_prefix(':').context("invalid port")?;
        ensure!(
            !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid port"
        );
        let port: u16 = port.parse().context("invalid port")?;
        ensure!(port != 0, "port must be nonzero");
        Some(port)
    };
    Ok((normalized, port))
}

fn parse_url(input: &str) -> Result<Uri> {
    ensure!(!input.contains('#'), "URL must not contain a fragment");
    let url: Uri = input.parse().context("invalid URL")?;
    ensure!(
        matches!(url.scheme_str(), Some("http" | "https")),
        "URL must use HTTP or HTTPS"
    );
    checked_authority(url.authority().context("URL must contain an authority")?)?;
    Ok(url)
}

fn normalize_health_path(value: &str) -> Result<String> {
    ensure!(
        !value.contains('#'),
        "health target must not contain a fragment"
    );
    let path = value.split_once('?').map_or(value, |(path, _)| path);
    let mut normalized = normalize_path(path)?;
    normalized.push_str(&value[path.len()..]);
    normalized
        .parse::<http::uri::PathAndQuery>()
        .context("invalid health target")?;
    Ok(normalized)
}

pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.len() > 253
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

pub fn normalize_path(path: &str) -> Result<String> {
    let Some(relative) = path.strip_prefix('/') else {
        bail!("path must start with '/'");
    };
    let mut normalized = String::with_capacity(path.len());
    normalized.push('/');
    let mut segments = relative.split('/').peekable();
    while let Some(segment) = segments.next() {
        let start = normalized.len();
        let mut bytes = segment.bytes();
        while let Some(byte) = bytes.next() {
            match byte {
                b'%' => {
                    let high = bytes.next().and_then(hex_digit);
                    let low = bytes.next().and_then(hex_digit);
                    let (Some(high), Some(low)) = (high, low) else {
                        bail!("invalid percent escape in path");
                    };
                    let decoded = high << 4 | low;
                    ensure!(!matches!(decoded, b'/' | b'\\'), "encoded path separator");
                    if unreserved(decoded) {
                        normalized.push(char::from(decoded));
                    } else {
                        let hex = b"0123456789ABCDEF";
                        normalized.push('%');
                        normalized.push(char::from(hex[usize::from(high)]));
                        normalized.push(char::from(hex[usize::from(low)]));
                    }
                }
                b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
                | b':' | b'@' => normalized.push(char::from(byte)),
                byte if unreserved(byte) => normalized.push(char::from(byte)),
                _ => bail!("invalid character in path"),
            }
        }
        ensure!(
            !matches!(&normalized[start..], "." | ".."),
            "dot segment in path"
        );
        if segments.peek().is_some() {
            ensure!(normalized.len() > start, "empty interior path segment");
            normalized.push('/');
        }
    }
    Ok(normalized)
}

fn hex_digit(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
schema_version = 1
admin_socket = "run/admin.sock"
state_dir = "state"
"#;

    const HTTP: &str = r#"
[[listeners]]
name = "http"
bind = "0.0.0.0:8080"
protocols = ["http1"]
"#;

    fn load(input: &str) -> Result<Config> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("rocky.toml");
        fs::write(&path, input)?;
        Config::load(&path)
    }

    fn rejects(input: &str, field: &str) -> String {
        let message = format!("{:#}", load(input).expect_err("expected invalid config"));
        assert!(message.contains(field), "{message}");
        message
    }

    #[test]
    fn compiles_sites_routes_and_relative_paths() {
        let input = format!(
            "{BASE}{}",
            r#"
drain_timeout = "12s"

[acme]
directory_url = "https://acme.example.test/directory"
contact = "mailto:ops@example.test"
accept_terms = true
trust_roots = "issuer.pem"

[[listeners]]
name = "http"
bind = "127.0.0.1:8080"
protocols = ["http1"]
default_site = "EXAMPLE.Test."
trusted_proxies = ["10.2.3.4/8", "::1/128"]

[[listeners]]
name = "secure"
bind = "127.0.0.1:8443"
protocols = ["http1", "h2", "h3"]
tls = true

[[sites]]
host = "Example.TEST"
listeners = ["http", "secure"]
tls = "acme"
redirect_http = true
public_https_port = 443

[[sites.routes]]
name = "www"
path_prefix = "/"
static_root = "www"
index = ""

[[sites.routes]]
name = "api"
path_prefix = "/%61pi/"
upstream = "application"

[sites.routes.rate_limit]
requests_per_second = 20
burst = 40
max_clients = 10000

[upstreams.application]
protocol = "h2"
health_path = "/%72eady?deep=1"
endpoints = [{ url = "https://[::1]:9001", weight = 2 }]
trust_roots = "origin.pem"

[[streams]]
name = "mqtt"
bind = "127.0.0.1:1883"
upstream = "mqtt.internal.example:11883"
idle_timeout = "5m"
"#
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rocky.toml");
        fs::write(&path, input).unwrap();
        let config = Config::load(&path).unwrap();
        let base = directory.path();
        assert_eq!(config.admin_socket, base.join("run/admin.sock"));
        assert_eq!(config.state_dir, base.join("state"));
        assert_eq!(config.drain_timeout, Duration::from_secs(12));
        assert_eq!(config.limits.max_buffer_bytes, 64 * 1024);
        assert_eq!(
            config.acme.as_ref().unwrap().trust_roots,
            Some(base.join("issuer.pem"))
        );
        let plain = &config.listeners["http"];
        assert_eq!(plain.default_site.as_deref(), Some("example.test"));
        assert_eq!(plain.trusted_proxies[0].to_string(), "10.0.0.0/8");
        let site = &config.sites[0];
        assert_eq!(site.host, "example.test");
        assert_eq!(site.public_https_port, Some(443));
        assert_eq!(site.public_quic_port, Some(8443));
        assert_eq!(site.routes[0].path_prefix, "/api");
        assert_eq!(
            site.routes[0]
                .rate_limit
                .as_ref()
                .unwrap()
                .requests_per_second,
            20.0
        );
        let Action::Static { root, index } = &site.routes[1].action else {
            panic!("expected static route");
        };
        assert_eq!(*root, base.join("www"));
        assert!(index.is_none());
        let pool = &config.upstreams["application"];
        assert_eq!(pool.protocol, UpstreamProtocol::H2);
        assert_eq!(pool.health_path.as_deref(), Some("/ready?deep=1"));
        assert_eq!(pool.trust_roots, Some(base.join("origin.pem")));
        assert_eq!(pool.endpoints[0].weight, 2);
        assert_eq!(
            config.streams["mqtt"].idle_timeout,
            Duration::from_secs(300)
        );
    }

    #[test]
    fn checks_overlapping_binds_by_transport_and_ip_family() {
        let input = format!(
            "{BASE}{HTTP}{}",
            r#"
[[listeners]]
name = "quic"
bind = "127.0.0.1:8080"
protocols = ["h3"]
tls = true

[[listeners]]
name = "http6"
bind = "[::]:8080"
protocols = ["http1"]
"#
        );
        load(&input).unwrap();
        rejects(
            &format!(
                "{input}{}",
                r#"
[[streams]]
name = "raw"
bind = "127.0.0.2:8080"
upstream = "127.0.0.1:8888"
"#
            ),
            "streams[0].bind TCP bind",
        );
        rejects(
            &input.replace("[::]:8080", "[::ffff:127.0.0.1]:8080"),
            "listeners[2].bind",
        );
    }

    #[test]
    fn reports_structural_and_semantic_field_paths() {
        let base = format!("{BASE}{HTTP}");
        let unknown = rejects(&format!("{base}typo = true\n"), "listeners[0]");
        assert!(unknown.contains("unknown field"));
        rejects(
            &format!("{base}default_site = \"missing.test\"\n"),
            "listeners[0].default_site",
        );
        let site = format!(
            "{base}{}",
            r#"
[[sites]]
host = "example.test"
listeners = ["http"]

[[sites.routes]]
name = "files"
path_prefix = "/api"
static_root = "www"
"#
        );
        rejects(
            &format!("{site}upstream = \"application\"\n"),
            "exactly one",
        );
        rejects(
            &format!(
                "{site}{}",
                r#"
[[sites.routes]]
name = "api"
path_prefix = "/%61pi/"
static_root = "other"
"#
            ),
            "sites[0].routes[1].path_prefix",
        );
        rejects(
            &format!(
                "{site}{}",
                r#"
[[sites]]
host = "EXAMPLE.test."
listeners = ["http"]
"#
            ),
            "sites[1].host",
        );
        rejects(
            &site.replace("static_root = \"www\"", "upstream = \"application\""),
            "sites[0].routes[0].upstream",
        );
        rejects(
            &format!("{BASE}[limits]\nrequest_head_timeout = \"0s\"\n"),
            "limits.request_head_timeout",
        );
    }

    #[test]
    fn normalizes_only_unreserved_escapes_and_rejects_ambiguous_paths() {
        assert_eq!(normalize_path("/%61pi/%aB/%7E/").unwrap(), "/api/%AB/~/");
        assert_eq!(normalize_path("/%252f").unwrap(), "/%252f");
        for invalid in [
            "//",
            "/a//",
            "/a/./b",
            "/%2e%2E",
            "/a%2fb",
            "/a%5Cb",
            "/a\\b",
            "/a%",
            "/a?q=1",
            "/a#fragment",
        ] {
            assert!(normalize_path(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            normalize_host("Example.TEST.").as_deref(),
            Some("example.test")
        );
        for invalid in ["*.test", "example.test..", "bad_label.test", "bad-.test"] {
            assert!(normalize_host(invalid).is_none(), "{invalid}");
        }
    }
}
