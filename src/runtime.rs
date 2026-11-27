use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwapOption;
use serde_json::{Value, json};
use tokio::{
    sync::{Mutex, Semaphore},
    time::{self, Instant},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    config::{self, Action, Config, Limits, RateLimit},
    listener::{self, Socket},
    proxy::ProxyPool,
    rate_limit::RateLimiter,
    static_files::DocumentRoot,
    tls::{TlsGeneration, TlsManager},
};

pub struct Runtime {
    pub active: ArcSwapOption<Generation>,
    pub connections: Arc<Gate>,
    pub requests: Arc<Gate>,
    pub metrics: Arc<Metrics>,
    pub tasks: TaskTracker,
    writer: Mutex<()>,
    config_path: PathBuf,
    admin_socket: PathBuf,
    state_dir: PathBuf,
    tls: TlsManager,
}

impl Runtime {
    pub fn check(path: &Path) -> Result<()> {
        let config = Config::load(path)?;
        TlsManager::check(&config)?;
        let pools = prepare_pools(&config, None)?;
        prepare_sites(&config, None, &pools)?;
        Ok(())
    }

    pub fn start(config_path: PathBuf, config: Config) -> Result<Arc<Self>> {
        let tls = TlsManager::open(&config.state_dir)?;
        let runtime = Arc::new(Self {
            active: ArcSwapOption::empty(),
            connections: Arc::default(),
            requests: Arc::default(),
            metrics: Arc::default(),
            tasks: TaskTracker::new(),
            writer: Mutex::new(()),
            config_path,
            admin_socket: config.admin_socket.clone(),
            state_dir: config.state_dir.clone(),
            tls,
        });
        let prepared = runtime.prepare(config, None)?;
        runtime.publish(prepared);
        Ok(runtime)
    }

    pub async fn reload(self: &Arc<Self>) -> Result<u64> {
        let _writer = self.writer.lock().await;
        let old = self.active.load_full().context("daemon is shutting down")?;
        let started = Instant::now();
        let result = tokio::task::block_in_place(|| {
            let config = Config::load(&self.config_path)?;
            if config.admin_socket != self.admin_socket || config.state_dir != self.state_dir {
                bail!("changing admin_socket or state_dir requires a restart");
            }
            self.prepare(config, Some(&old))
        });
        self.metrics
            .reload_micros
            .fetch_add(micros_since(started), Ordering::Relaxed);
        match result {
            Ok(prepared) => {
                let id = prepared.generation.id;
                self.publish(prepared);
                self.metrics.reloads.fetch_add(1, Ordering::Relaxed);
                Ok(id)
            }
            Err(err) => {
                self.metrics
                    .rejected_reloads
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(generation = old.id, error = %err, "reload rejected");
                Err(err.context(format!("active generation {}", old.id)))
            }
        }
    }

    fn prepare(&self, config: Config, previous: Option<&Generation>) -> Result<Prepared> {
        let pools = prepare_pools(&config, previous)?;
        let (sites, file_work) = prepare_sites(&config, previous, &pools)?;
        let tls = self
            .tls
            .prepare(&config, previous.map(|old| old.tls.as_ref()))?;
        let mut bindings = BTreeMap::new();
        let mut sockets = Vec::new();
        let old_binding = |key| previous.and_then(|old| old.bindings.get(&key));
        let old_gates: BTreeMap<_, _> = previous
            .into_iter()
            .flat_map(|old| old.bindings.values())
            .map(|binding| {
                (
                    (binding.policy.is_http(), binding.name()),
                    Arc::clone(&binding.connections),
                )
            })
            .collect();
        for (name, settings) in &config.listeners {
            let connections = old_gates
                .get(&(true, name.as_str()))
                .cloned()
                .unwrap_or_default();
            let assignments: BTreeMap<_, _> = sites
                .iter()
                .filter(|site| site.listeners.contains(name))
                .map(|site| (site.host.clone(), Arc::clone(site)))
                .collect();
            for transport in [Transport::Tcp, Transport::Quic] {
                if transport == Transport::Tcp && !settings.protocols.tcp()
                    || transport == Transport::Quic && !settings.protocols.h3
                {
                    continue;
                }
                let key = BindKey {
                    addr: settings.bind,
                    transport,
                };
                let old = old_binding(key);
                let policy = HttpBinding::prepare(
                    name,
                    settings,
                    &config.limits,
                    transport,
                    &assignments,
                    &tls,
                    old,
                );
                let driver = prepare_driver(key, name, &tls, old, &mut sockets)?;
                bindings.insert(
                    key,
                    Binding {
                        driver,
                        policy: BindingPolicy::Http(Arc::new(policy)),
                        max_connections: settings.max_connections,
                        connections: Arc::clone(&connections),
                    },
                );
            }
        }
        for (name, settings) in config.streams {
            let key = BindKey {
                addr: settings.bind,
                transport: Transport::Tcp,
            };
            let old = old_binding(key);
            let lifetime = old
                .and_then(Binding::stream)
                .filter(|old| {
                    old.name == name
                        && old.settings.upstream == settings.upstream
                        && old.settings.connect_timeout == settings.connect_timeout
                        && old.settings.idle_timeout == settings.idle_timeout
                        && old.buffer_bytes == config.limits.max_buffer_bytes
                })
                .map(|old| Arc::clone(&old.lifetime))
                .unwrap_or_default();
            let driver = prepare_driver(key, &name, &tls, old, &mut sockets)?;
            let max_connections = settings.max_connections;
            let connections = old_gates
                .get(&(false, name.as_str()))
                .cloned()
                .unwrap_or_default();
            bindings.insert(
                key,
                Binding {
                    driver,
                    policy: BindingPolicy::Stream(Arc::new(StreamBinding {
                        name,
                        settings,
                        buffer_bytes: config.limits.max_buffer_bytes,
                        lifetime,
                    })),
                    max_connections,
                    connections,
                },
            );
        }
        let generation = Arc::new(Generation {
            id: previous.map_or(1, |old| old.id + 1),
            bindings,
            tls,
            pools,
            sites,
            file_work,
            limits: config.limits,
            drain_timeout: config.drain_timeout,
        });
        Ok(Prepared {
            generation,
            sockets,
        })
    }

    fn publish(
        self: &Arc<Self>,
        Prepared {
            generation,
            sockets,
        }: Prepared,
    ) {
        let old = self.active.swap(Some(Arc::clone(&generation)));
        if let Some(old) = old {
            old.retire(Some(&generation), Instant::now() + generation.drain_timeout);
        }
        self.tls.activate(&generation.tls);
        for pool in generation.pools.values() {
            pool.start();
        }
        for binding in generation.bindings.values() {
            if let Some(endpoint) = &binding.driver.quic_endpoint {
                endpoint.set_server_config(
                    generation
                        .tls
                        .quic_config(binding.name())
                        .map(|config| (*config).clone()),
                );
            }
        }
        for (driver, socket) in sockets {
            self.tasks
                .spawn(listener::drive(Arc::clone(self), driver, socket));
        }
        tracing::info!(generation = generation.id, "configuration published");
    }

    pub async fn shutdown(&self) {
        let deadline = {
            let _writer = self.writer.lock().await;
            let Some(old) = self.active.swap(None) else {
                return;
            };
            let deadline = Instant::now() + old.drain_timeout;
            old.retire(None, deadline);
            self.tls.stop();
            self.tasks.close();
            tracing::info!(generation = old.id, "draining listeners");
            deadline
        };
        let _ = time::timeout_at(deadline + Duration::from_millis(100), self.tasks.wait()).await;
    }

    pub fn status(&self) -> Value {
        let Some(active) = self.active.load_full() else {
            return json!({ "ready": false, "shutting_down": true });
        };
        let listeners: Vec<_> = active.bindings.iter().map(|(key, binding)| {
            let ready = binding.http().is_none_or(|http| {
                !http.settings.tls || (!http.sites.is_empty()
                    && http.sites.keys().all(|host| active.tls.ready(&http.name, host)))
            });
            json!({ "name": binding.name(), "bind": key.addr, "transport": key.transport.as_str(), "ready": ready })
        }).collect();
        let upstreams: BTreeMap<_, _> = active
            .pools
            .iter()
            .map(|(name, pool)| (name, pool.status()))
            .collect();
        let ready = listeners.iter().all(|listener| listener["ready"] == true)
            && active.pools.values().all(|pool| pool.ready());
        json!({
            "generation": active.id,
            "ready": ready,
            "listeners": listeners,
            "certificates": active.tls.status(),
            "upstreams": upstreams,
            "metrics": {
                "connections_active": self.connections.count(),
                "requests_active": self.requests.count(),
                "reloads": self.metrics.reloads.load(Ordering::Relaxed),
                "rejected_reloads": self.metrics.rejected_reloads.load(Ordering::Relaxed),
                "reload_time_us": self.metrics.reload_micros.load(Ordering::Relaxed),
                "requests": self.metrics.requests.load(Ordering::Relaxed),
                "request_time_us": self.metrics.request_micros.load(Ordering::Relaxed),
                "requests_rejected": self.metrics.requests_rejected.load(Ordering::Relaxed),
                "connections_rejected": self.metrics.connections_rejected.load(Ordering::Relaxed),
                "rate_limited": self.metrics.rate_limited.load(Ordering::Relaxed),
                "rate_limit_capacity": self.metrics.rate_limit_capacity.load(Ordering::Relaxed),
                "body_errors": self.metrics.body_errors.load(Ordering::Relaxed),
                "response_bytes": self.metrics.response_bytes.load(Ordering::Relaxed),
                "relays": self.metrics.relays.load(Ordering::Relaxed),
                "relay_upstream_bytes": self.metrics.relay_upstream_bytes.load(Ordering::Relaxed),
                "relay_downstream_bytes": self.metrics.relay_downstream_bytes.load(Ordering::Relaxed),
                "drains": self.metrics.drains.load(Ordering::Relaxed),
                "drain_time_us": self.metrics.drain_micros.load(Ordering::Relaxed),
            }
        })
    }

    pub fn admit_connection(&self, binding: &Binding, limits: &Limits) -> Option<(Permit, Permit)> {
        let permits = self
            .connections
            .enter(limits.max_connections)
            .and_then(|total| {
                binding
                    .connections
                    .enter(binding.max_connections)
                    .map(|local| (total, local))
            });
        if permits.is_none() {
            self.metrics
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
        }
        permits
    }
}

fn prepare_driver(
    key: BindKey,
    name: &str,
    tls: &TlsGeneration,
    old: Option<&Binding>,
    sockets: &mut Vec<(Arc<Driver>, Socket)>,
) -> Result<Arc<Driver>> {
    if let Some(old) = old {
        return Ok(Arc::clone(&old.driver));
    }
    let socket = Socket::bind(key, tls.quic_config(name))
        .with_context(|| format!("bind {} {} for {name}", key.transport.as_str(), key.addr))?;
    let quic_endpoint = match &socket {
        Socket::Quic(endpoint) => Some(endpoint.clone()),
        Socket::Tcp(_) => None,
    };
    let driver = Arc::new(Driver {
        key,
        stop: CancellationToken::new(),
        quic_endpoint,
    });
    sockets.push((Arc::clone(&driver), socket));
    Ok(driver)
}

fn prepare_pools(
    config: &Config,
    previous: Option<&Generation>,
) -> Result<BTreeMap<String, Arc<ProxyPool>>> {
    config
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            let old = previous.and_then(|old| old.pools.get(name));
            let pool = ProxyPool::prepare(upstream, &config.limits, old)
                .with_context(|| format!("upstreams.{name}"))?;
            Ok((name.clone(), pool))
        })
        .collect()
}

fn prepare_sites(
    config: &Config,
    previous: Option<&Generation>,
    pools: &BTreeMap<String, Arc<ProxyPool>>,
) -> Result<(Vec<Arc<Site>>, Arc<Semaphore>)> {
    let work = previous
        .filter(|old| old.limits.max_file_operations == config.limits.max_file_operations)
        .map(|old| Arc::clone(&old.file_work))
        .unwrap_or_else(|| Arc::new(Semaphore::new(config.limits.max_file_operations)));
    let mut sites = Vec::with_capacity(config.sites.len());
    for site in &config.sites {
        // Duplicate hosts can occur on disjoint listeners. Reuse state only for a unique owner.
        let owners: Vec<_> = previous
            .into_iter()
            .flat_map(|old| old.sites.iter())
            .filter(|old| old.overlaps(site))
            .collect();
        let previous = owners.first().filter(|old| {
            owners.len() == 1
                && config
                    .sites
                    .iter()
                    .filter(|site| old.overlaps(site))
                    .take(2)
                    .count()
                    == 1
        });
        let mut routes = Vec::with_capacity(site.routes.len());
        for route in &site.routes {
            let action = match &route.action {
                Action::Static { root, index } => {
                    let root = DocumentRoot::open(
                        root,
                        index.as_deref(),
                        Arc::clone(&work),
                        config.limits.max_buffer_bytes,
                    )
                    .with_context(|| {
                        format!("site {} route {} static_root", site.host, route.name)
                    })?;
                    RouteAction::Files(Arc::new(root))
                }
                Action::Proxy { upstream } => {
                    RouteAction::Proxy(upstream.clone(), Arc::clone(&pools[upstream]))
                }
            };
            let rate_limit = route.rate_limit.as_ref().map(|policy| {
                let current = previous
                    .and_then(|site| {
                        site.routes
                            .iter()
                            .find(|old| old.name == route.name && old.prefix == route.path_prefix)
                    })
                    .and_then(|old| old.rate_limit.as_ref());
                let limiter = current
                    .filter(|(old, _)| old == policy)
                    .map(|(_, limiter)| Arc::clone(limiter))
                    .unwrap_or_else(|| Arc::new(RateLimiter::new(policy.clone())));
                (policy.clone(), limiter)
            });
            routes.push(Arc::new(Route {
                name: route.name.clone(),
                prefix: route.path_prefix.clone(),
                action,
                rate_limit,
            }));
        }
        routes.sort_by_key(|route| std::cmp::Reverse(route.prefix.len()));
        let https = site
            .listeners
            .iter()
            .filter(|name| {
                let listener = &config.listeners[*name];
                listener.tls && listener.protocols.tcp()
            })
            .cloned()
            .collect();
        let quic = site
            .listeners
            .iter()
            .filter(|name| config.listeners[*name].protocols.h3)
            .cloned()
            .collect();
        let clear_alt_svc = if site.public_quic_port.is_none() {
            owners
                .iter()
                .filter_map(|old| {
                    if old.public_quic_port.is_some() {
                        Some(Instant::now() + ALT_SVC_AGE)
                    } else {
                        old.clear_alt_svc
                    }
                })
                .max()
        } else {
            None
        };
        sites.push(Arc::new(Site {
            host: site.host.clone(),
            listeners: site.listeners.clone(),
            redirect_http: site.redirect_http,
            public_https_port: site.public_https_port,
            public_quic_port: site.public_quic_port,
            https,
            quic,
            clear_alt_svc,
            routes,
        }));
    }
    Ok((sites, work))
}

pub const ALT_SVC_AGE: Duration = Duration::from_secs(300);

struct Prepared {
    generation: Arc<Generation>,
    sockets: Vec<(Arc<Driver>, Socket)>,
}

pub struct Generation {
    pub id: u64,
    pub bindings: BTreeMap<BindKey, Binding>,
    pub tls: Arc<TlsGeneration>,
    pub limits: Limits,
    pub drain_timeout: Duration,
    pools: BTreeMap<String, Arc<ProxyPool>>,
    sites: Vec<Arc<Site>>,
    file_work: Arc<Semaphore>,
}

impl Generation {
    fn retire(&self, replacement: Option<&Self>, deadline: Instant) {
        for (key, old) in &self.bindings {
            let next = replacement.and_then(|next| next.bindings.get(key));
            if next.is_none() {
                old.driver.stop.cancel();
            }
            let old_life = old.policy.lifetime();
            if !next.is_some_and(|new| Arc::ptr_eq(old_life, new.policy.lifetime())) {
                old_life.retire(deadline);
            }
            if let Some(old) = old.http() {
                let next = next.and_then(Binding::http);
                for (host, (_, old_life)) in &old.tls_sites {
                    if !next
                        .and_then(|next| next.tls_sites.get(host))
                        .is_some_and(|(_, life)| Arc::ptr_eq(old_life, life))
                    {
                        old_life.retire(deadline);
                    }
                }
            }
        }
        for (name, pool) in &self.pools {
            if !replacement
                .and_then(|next| next.pools.get(name))
                .is_some_and(|next| Arc::ptr_eq(pool, next))
            {
                pool.stop();
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Transport {
    Tcp,
    Quic,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct BindKey {
    pub addr: SocketAddr,
    pub transport: Transport,
}

pub struct Driver {
    pub key: BindKey,
    pub stop: CancellationToken,
    quic_endpoint: Option<quinn::Endpoint>,
}

pub struct Binding {
    pub driver: Arc<Driver>,
    pub policy: BindingPolicy,
    pub max_connections: usize,
    connections: Arc<Gate>,
}

impl Binding {
    pub fn http(&self) -> Option<&Arc<HttpBinding>> {
        match &self.policy {
            BindingPolicy::Http(settings) => Some(settings),
            _ => None,
        }
    }

    fn stream(&self) -> Option<&Arc<StreamBinding>> {
        match &self.policy {
            BindingPolicy::Stream(settings) => Some(settings),
            _ => None,
        }
    }

    fn name(&self) -> &str {
        match &self.policy {
            BindingPolicy::Http(http) => &http.name,
            BindingPolicy::Stream(stream) => &stream.name,
        }
    }
}

pub enum BindingPolicy {
    Http(Arc<HttpBinding>),
    Stream(Arc<StreamBinding>),
}

impl BindingPolicy {
    fn is_http(&self) -> bool {
        matches!(self, Self::Http(_))
    }

    fn lifetime(&self) -> &Arc<Lifetime> {
        match self {
            Self::Http(http) => &http.lifetime,
            Self::Stream(stream) => &stream.lifetime,
        }
    }
}

pub struct HttpBinding {
    pub name: String,
    pub settings: config::HttpListener,
    pub sites: BTreeMap<String, Arc<Site>>,
    pub tls_sites: BTreeMap<String, (u64, Arc<Lifetime>)>,
    pub lifetime: Arc<Lifetime>,
    wire: WirePolicy,
}

#[derive(PartialEq, Eq)]
struct WirePolicy {
    tls: bool,
    protocol_h1: bool,
    protocol_h2: bool,
    default_site: Option<String>,
    max_header_bytes: usize,
    max_buffer_bytes: usize,
    max_streams: u32,
    handshake_timeout: Duration,
    head_timeout: Duration,
    body_idle_timeout: Duration,
}

impl HttpBinding {
    fn prepare(
        name: &str,
        settings: &config::HttpListener,
        limits: &Limits,
        transport: Transport,
        sites: &BTreeMap<String, Arc<Site>>,
        tls: &TlsGeneration,
        previous: Option<&Binding>,
    ) -> Self {
        let wire = WirePolicy {
            tls: settings.tls,
            protocol_h1: transport == Transport::Tcp && settings.protocols.http1,
            protocol_h2: transport == Transport::Tcp && settings.protocols.h2,
            default_site: settings.default_site.clone(),
            max_header_bytes: limits.max_header_bytes,
            max_buffer_bytes: limits.max_buffer_bytes,
            max_streams: limits.max_streams_per_connection,
            handshake_timeout: limits.handshake_timeout,
            head_timeout: limits.request_head_timeout,
            body_idle_timeout: limits.body_idle_timeout,
        };
        let old = previous
            .and_then(Binding::http)
            .filter(|old| old.name == name && old.wire == wire);
        let lifetime = old.map(|old| Arc::clone(&old.lifetime)).unwrap_or_default();
        let tls_sites = sites
            .keys()
            .filter_map(|host| {
                let identity = tls.identity(name, host)?;
                let life = old
                    .and_then(|old| old.tls_sites.get(host))
                    .filter(|(old_id, _)| *old_id == identity)
                    .map(|(_, life)| Arc::clone(life))
                    .unwrap_or_default();
                Some((host.clone(), (identity, life)))
            })
            .collect();
        Self {
            name: name.to_owned(),
            settings: settings.clone(),
            sites: sites.clone(),
            tls_sites,
            lifetime,
            wire,
        }
    }
}

pub struct StreamBinding {
    pub name: String,
    pub settings: config::Stream,
    pub buffer_bytes: usize,
    pub lifetime: Arc<Lifetime>,
}

pub struct Site {
    pub host: String,
    listeners: Vec<String>,
    pub redirect_http: bool,
    pub public_https_port: Option<u16>,
    pub public_quic_port: Option<u16>,
    pub https: Vec<String>,
    pub quic: Vec<String>,
    pub clear_alt_svc: Option<Instant>,
    pub routes: Vec<Arc<Route>>,
}

impl Site {
    fn overlaps(&self, site: &config::Site) -> bool {
        self.host == site.host
            && self
                .listeners
                .iter()
                .any(|name| site.listeners.contains(name))
    }
}

pub struct Route {
    pub name: String,
    pub prefix: String,
    pub action: RouteAction,
    pub rate_limit: Option<(RateLimit, Arc<RateLimiter>)>,
}

pub enum RouteAction {
    Files(Arc<DocumentRoot>),
    Proxy(String, Arc<ProxyPool>),
}

#[derive(Default)]
pub struct Lifetime {
    deadline: OnceLock<Instant>,
    cancel: CancellationToken,
}

impl Lifetime {
    fn retire(&self, deadline: Instant) {
        let _ = self.deadline.set(deadline);
        self.cancel.cancel();
    }

    pub async fn retired(&self) -> Instant {
        self.cancel.cancelled().await;
        *self
            .deadline
            .get()
            .expect("retirement deadline is set before cancellation")
    }
}

#[derive(Default)]
pub struct Gate(AtomicUsize);

impl Gate {
    pub fn enter(self: &Arc<Self>, limit: usize) -> Option<Permit> {
        let mut count = self.0.load(Ordering::Relaxed);
        while count < limit {
            match self.0.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Permit(Arc::clone(self))),
                Err(current) => count = current,
            }
        }
        None
    }

    pub fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct Permit(Arc<Gate>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct Metrics {
    pub reloads: AtomicU64,
    pub rejected_reloads: AtomicU64,
    pub reload_micros: AtomicU64,
    pub requests: AtomicU64,
    pub request_micros: AtomicU64,
    pub requests_rejected: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub rate_limited: AtomicU64,
    pub rate_limit_capacity: AtomicU64,
    pub body_errors: AtomicU64,
    pub response_bytes: AtomicU64,
    pub relays: AtomicU64,
    pub relay_upstream_bytes: AtomicU64,
    pub relay_downstream_bytes: AtomicU64,
    pub drains: AtomicU64,
    pub drain_micros: AtomicU64,
}

pub fn micros_since(start: Instant) -> u64 {
    start.elapsed().as_micros().try_into().unwrap_or(u64::MAX)
}
