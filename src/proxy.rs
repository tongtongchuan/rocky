mod message;
#[cfg(test)]
mod tests;
mod transport;

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use futures_util::{StreamExt, stream};
use http::{Method, Request, Response, StatusCode};
use http_body::Body as _;
use serde_json::{Value, json};
use tokio::{
    sync::{Notify, Semaphore},
    time::{Instant, MissedTickBehavior, interval},
};
use tokio_util::sync::CancellationToken;

use crate::{
    body::{self, Body},
    config::{Endpoint, Limits, Upstream, UpstreamProtocol},
};

pub use message::{Forwarding, supports_transfer_encoding};
use message::{RequestDraft, probe_request};
use transport::{AttemptError, Transport, TransportSettings, owned_by};

static HEALTH_PROBES: Semaphore = Semaphore::const_new(64);
const JOB_CONCURRENCY_PER_POOL: usize = 4;

pub struct ProxyPool {
    config: Upstream,
    head_budget: Duration,
    transport_settings: TransportSettings,
    endpoints: Vec<PoolEndpoint>,
    weights: Mutex<Vec<i64>>,
    worker_id: Arc<()>,
    worker_state: Mutex<WorkerState>,
    stop: CancellationToken,
    probe_wakeup: Arc<Notify>,
}

struct PoolEndpoint {
    config: Endpoint,
    transport: Arc<Transport>,
    health: Arc<Mutex<Health>>,
}

#[derive(PartialEq, Eq)]
enum WorkerState {
    Prepared,
    Active,
    Stopped,
}

#[derive(Clone, Copy)]
enum Job {
    Resolve,
    Probe,
}

#[derive(Debug)]
pub enum ProxyError {
    Unavailable,
    Exchange,
    Timeout,
    UnsupportedTransferEncoding,
}

impl ProxyError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Exchange => StatusCode::BAD_GATEWAY,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UnsupportedTransferEncoding => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "no upstream endpoint available",
            Self::Exchange => "upstream exchange failed",
            Self::Timeout => "upstream deadline expired",
            Self::UnsupportedTransferEncoding => "unsupported request transfer encoding",
        })
    }
}

impl std::error::Error for ProxyError {}

impl ProxyPool {
    pub fn prepare(
        config: &Upstream,
        limits: &Limits,
        previous: Option<&Arc<Self>>,
    ) -> Result<Arc<Self>> {
        let settings = TransportSettings::load(config, limits)?;
        let previous = previous.filter(|pool| !pool.stop.is_cancelled());
        if let Some(pool) = previous
            && pool.config == *config
            && pool.transport_settings == settings
        {
            return Ok(Arc::clone(pool));
        }

        let head_budget = config
            .connect_timeout
            .checked_add(config.response_head_timeout)
            .filter(|budget| Instant::now().checked_add(*budget).is_some())
            .context(
                "combined connect_timeout and response_head_timeout overflow the upstream deadline",
            )?;
        let tls = settings.tls_config(config.trust_roots.is_some())?;
        let endpoints: Vec<_> = config
            .endpoints
            .iter()
            .map(|endpoint| {
                let old_endpoint = previous
                    .filter(|pool| settings.compatible(&pool.transport_settings, &endpoint.url))
                    .and_then(|pool| {
                        pool.endpoints
                            .iter()
                            .find(|old| endpoint.url == old.config.url)
                    });
                let transport = old_endpoint.map_or_else(
                    || Arc::new(Transport::new(&endpoint.url, &settings, Arc::clone(&tls))),
                    |old| Arc::clone(&old.transport),
                );
                let health = old_endpoint
                    .filter(|_| {
                        previous.is_some_and(|pool| same_health_policy(&pool.config, config))
                    })
                    .map_or_else(
                        || Arc::new(Mutex::new(Health::new(config.health_path.is_some()))),
                        |old| Arc::clone(&old.health),
                    );
                PoolEndpoint {
                    config: endpoint.clone(),
                    transport,
                    health,
                }
            })
            .collect();

        Ok(Arc::new(Self {
            config: config.clone(),
            head_budget,
            transport_settings: settings,
            weights: Mutex::new(vec![0; endpoints.len()]),
            endpoints,
            worker_id: Arc::new(()),
            worker_state: Mutex::new(WorkerState::Prepared),
            stop: CancellationToken::new(),
            probe_wakeup: Arc::default(),
        }))
    }

    pub fn start(self: &Arc<Self>) {
        let mut state = self.worker_state.lock().unwrap();
        if *state != WorkerState::Prepared {
            return;
        }
        for endpoint in &self.endpoints {
            endpoint.transport.resolution.activate(&self.worker_id);
            endpoint.health.lock().unwrap().worker = Some(Arc::clone(&self.worker_id));
        }
        *state = WorkerState::Active;
        if self
            .endpoints
            .iter()
            .any(|endpoint| endpoint.transport.resolution.needs_lookup())
        {
            self.spawn_job(Job::Resolve, self.config.dns_refresh);
        }
        if self.config.health_path.is_some() {
            self.spawn_job(Job::Probe, self.config.health_interval);
        }
    }

    pub fn stop(&self) {
        let mut state = self.worker_state.lock().unwrap();
        if *state == WorkerState::Active {
            for endpoint in &self.endpoints {
                endpoint.transport.resolution.deactivate(&self.worker_id);
                let mut health = endpoint.health.lock().unwrap();
                if owned_by(health.worker.as_ref(), &self.worker_id) {
                    health.worker = None;
                }
            }
        }
        *state = WorkerState::Stopped;
        self.stop.cancel();
    }

    pub fn ready(&self) -> bool {
        let now = Instant::now();
        self.endpoints.iter().any(|endpoint| {
            endpoint.transport.resolution.ready()
                && endpoint
                    .health
                    .lock()
                    .unwrap()
                    .eligible(now, self.config.health_path.is_some())
        })
    }

    pub fn status(&self) -> Value {
        let now = Instant::now();
        let active_health = self.config.health_path.is_some();
        let endpoints: Vec<_> = self
            .endpoints
            .iter()
            .map(|endpoint| {
                let (resolved, dns_lookup_failed) = endpoint.transport.resolution.status();
                let health = endpoint.health.lock().unwrap();
                json!({
                    "url": endpoint.config.url.to_string(),
                    "weight": endpoint.config.weight,
                    "healthy": resolved && health.eligible(now, active_health),
                    "state": if resolved { health.phase.label() } else { "awaiting_dns" },
                    "dns_lookup_failed": dns_lookup_failed,
                    "in_flight": endpoint.transport.in_flight.load(Ordering::Relaxed),
                    "max_connections": endpoint.config.max_connections,
                    "successful_probes": health.successful_probes,
                    "failed_probes": health.failed_probes,
                    "last_probe_ms": health.last_probe_ms,
                    "passive_failures": health.passive_failures,
                    "last_failure": health.last_failure,
                })
            })
            .collect();
        json!({
            "ready": self.ready(),
            "protocol": match self.config.protocol { UpstreamProtocol::H1 => "h1", UpstreamProtocol::H2 => "h2" },
            "endpoints": endpoints,
        })
    }

    pub async fn exchange(
        &self,
        request: Request<Body>,
        meta: &Forwarding,
    ) -> Result<Response<Body>, ProxyError> {
        if !supports_transfer_encoding(request.headers(), request.version()) {
            return Err(ProxyError::UnsupportedTransferEncoding);
        }
        let has_upload = !request.body().is_end_stream();
        let may_retry = matches!(*request.method(), Method::GET | Method::HEAD) && !has_upload;
        let deadline = Instant::now()
            .checked_add(self.head_budget)
            .ok_or(ProxyError::Timeout)?;
        let (parts, body) = request.into_parts();
        let mut draft = RequestDraft::new(parts, meta, self.config.protocol)?;
        let mut body = Some(body);
        let mut previous_attempt = None;

        loop {
            if Instant::now() >= deadline {
                return Err(ProxyError::Timeout);
            }
            let Some((index, mut lease)) =
                self.select(previous_attempt.as_ref().map(|(index, _)| *index))
            else {
                return Err(previous_attempt.map_or(ProxyError::Unavailable, |(_, error)| error));
            };
            let endpoint = &self.endpoints[index];
            lease.upload = has_upload.then(Upload::new);
            let lease = Arc::new(lease);
            let preserve_headers =
                may_retry && self.endpoints.len() > 1 && previous_attempt.is_none();
            let (outbound, cancel_upload) = draft.build(
                &endpoint.config.url,
                body.take().unwrap_or_else(body::empty),
                &lease,
                preserve_headers,
            );
            let exchange =
                endpoint
                    .transport
                    .request(outbound, deadline, self.config.response_head_timeout);
            let result = if let Some(upload) = &lease.upload {
                let result = tokio::select! {
                    biased;
                    _ = upload.rejected.cancelled() => return Err(ProxyError::Exchange),
                    result = exchange => result,
                };
                if upload.rejected.is_cancelled() {
                    return Err(ProxyError::Exchange);
                }
                result
            } else {
                exchange.await
            };

            match result {
                Ok(response) => {
                    return Ok(draft.response(
                        response,
                        lease,
                        cancel_upload,
                        self.config.body_idle_timeout,
                    ));
                }
                Err(error) => {
                    if !matches!(error, AttemptError::HeadTimeout)
                        || !lease.upload.as_ref().is_some_and(Upload::is_pending)
                    {
                        lease.fail(error.label());
                    }
                    let downstream = if error.timed_out() {
                        ProxyError::Timeout
                    } else {
                        ProxyError::Exchange
                    };
                    if !may_retry || previous_attempt.is_some() || !error.can_retry() {
                        return Err(downstream);
                    }
                    previous_attempt = Some((index, downstream));
                }
            }
        }
    }

    fn select(&self, exclude: Option<usize>) -> Option<(usize, Lease)> {
        let mut weights = self.weights.lock().unwrap();
        let mut eligible = Vec::new();
        let mut total = 0;
        let now = Instant::now();
        let checks = self.config.health_path.is_some();

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if Some(index) != exclude && endpoint.eligible(now, checks) {
                let weight = i64::from(endpoint.config.weight);
                weights[index] = weights[index].saturating_add(weight);
                total += weight;
                eligible.push(index);
            }
        }

        while let Some((position, &index)) = eligible
            .iter()
            .enumerate()
            .max_by_key(|(_, index)| (weights[**index], std::cmp::Reverse(**index)))
        {
            let endpoint = &self.endpoints[index];
            if let Some(lease) = endpoint.reserve(now, checks, self.config.cooldown) {
                weights[index] = weights[index].saturating_sub(total);
                return Some((index, lease));
            }
            // Health and capacity can change between scoring and reserving an endpoint.
            eligible.swap_remove(position);
            let weight = i64::from(endpoint.config.weight);
            weights[index] = weights[index].saturating_sub(weight);
            total -= weight;
        }
        None
    }

    fn spawn_job(self: &Arc<Self>, job: Job, period: Duration) {
        let weak = Arc::downgrade(self);
        let stop = self.stop.clone();
        let probe_wakeup = Arc::clone(&self.probe_wakeup);
        tokio::spawn(async move {
            let mut ticks = interval(period);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => break,
                    _ = ticks.tick() => {},
                    _ = probe_wakeup.notified(), if matches!(job, Job::Probe) => {},
                }
                let Some(pool) = weak.upgrade() else { break };
                let work = stream::iter(&pool.endpoints).for_each_concurrent(
                    JOB_CONCURRENCY_PER_POOL,
                    |endpoint| {
                        let pool = &pool;
                        async move {
                            match job {
                                Job::Resolve if endpoint.transport.resolution.needs_lookup() => {
                                    if endpoint
                                        .transport
                                        .resolution
                                        .refresh(&pool.worker_id, pool.config.connect_timeout)
                                        .await
                                    {
                                        pool.probe_wakeup.notify_one();
                                    }
                                }
                                Job::Probe if endpoint.transport.resolution.ready() => {
                                    pool.probe(endpoint).await
                                }
                                _ => {}
                            }
                        }
                    },
                );
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => break,
                    _ = work => {},
                }
            }
        });
    }

    async fn probe(&self, endpoint: &PoolEndpoint) {
        let _permit = HEALTH_PROBES.acquire().await.unwrap();
        let revision = endpoint.health.lock().unwrap().revision;
        let request = probe_request(
            &endpoint.config.url,
            self.config.health_path.as_deref().unwrap(),
            self.config.protocol,
        );
        let now = Instant::now();
        let healthy = endpoint
            .transport
            .probe(request, self.config.health_timeout)
            .await;
        let mut health = endpoint.health.lock().unwrap();
        if !owned_by(health.worker.as_ref(), &self.worker_id) {
            return;
        }
        health.last_probe_ms = Some(now.elapsed().as_millis() as u64);
        if healthy {
            health.successful_probes += 1;
        } else {
            health.failed_probes += 1;
        }
        // An observation that started before a newer passive failure must not clear it.
        if health.revision != revision {
            return;
        }
        if healthy {
            health.change(Phase::Healthy, None);
        } else {
            health.change(Phase::Unhealthy, Some("health_probe"));
        }
    }
}

impl Drop for ProxyPool {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn same_health_policy(left: &Upstream, right: &Upstream) -> bool {
    left.health_path == right.health_path
        && left.health_interval == right.health_interval
        && left.health_timeout == right.health_timeout
        && left.cooldown == right.cooldown
        && left.response_head_timeout == right.response_head_timeout
        && left.body_idle_timeout == right.body_idle_timeout
}

impl PoolEndpoint {
    fn eligible(&self, now: Instant, active_checks: bool) -> bool {
        self.transport.has_capacity(self.config.max_connections)
            && self.transport.resolution.ready()
            && self.health.lock().unwrap().eligible(now, active_checks)
    }

    fn reserve(&self, now: Instant, active_checks: bool, cooldown: Duration) -> Option<Lease> {
        let mut health = self.health.lock().unwrap();
        if !health.eligible(now, active_checks)
            || !self.transport.reserve(self.config.max_connections)
        {
            return None;
        }
        let trial = if matches!(health.phase, Phase::Cooldown(_)) {
            let last_failure = health.last_failure;
            health.change(Phase::Trial, last_failure);
            Some(health.revision)
        } else {
            None
        };
        Some(Lease {
            transport: Arc::clone(&self.transport),
            health: Arc::clone(&self.health),
            cooldown,
            trial,
            response_complete: AtomicBool::new(false),
            upload: None,
            failure_recorded: AtomicBool::new(false),
        })
    }
}

enum Phase {
    Pending,
    Healthy,
    Unhealthy,
    Cooldown(Instant),
    Trial,
}

impl Phase {
    fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
            Self::Cooldown(_) => "cooldown",
            Self::Trial => "recovery_trial",
        }
    }
}

struct Health {
    phase: Phase,
    revision: u64,
    worker: Option<Arc<()>>,
    last_failure: Option<&'static str>,
    successful_probes: u64,
    failed_probes: u64,
    last_probe_ms: Option<u64>,
    passive_failures: u64,
}

impl Health {
    fn new(active_checks: bool) -> Self {
        Self {
            phase: if active_checks {
                Phase::Pending
            } else {
                Phase::Healthy
            },
            revision: 0,
            worker: None,
            last_failure: None,
            successful_probes: 0,
            failed_probes: 0,
            last_probe_ms: None,
            passive_failures: 0,
        }
    }

    fn eligible(&self, now: Instant, active_checks: bool) -> bool {
        matches!(self.phase, Phase::Healthy)
            || (!active_checks && matches!(self.phase, Phase::Cooldown(until) if now >= until))
    }

    fn change(&mut self, phase: Phase, failure: Option<&'static str>) {
        self.revision = self.revision.wrapping_add(1);
        self.phase = phase;
        self.last_failure = failure;
    }
}

struct Lease {
    transport: Arc<Transport>,
    health: Arc<Mutex<Health>>,
    cooldown: Duration,
    trial: Option<u64>,
    response_complete: AtomicBool,
    upload: Option<Upload>,
    failure_recorded: AtomicBool,
}

struct Upload {
    pending: AtomicBool,
    finished: CancellationToken,
    rejected: CancellationToken,
}

impl Upload {
    fn new() -> Self {
        Self {
            pending: AtomicBool::new(true),
            finished: CancellationToken::new(),
            rejected: CancellationToken::new(),
        }
    }

    fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Relaxed)
    }

    fn complete(&self) {
        self.pending.store(false, Ordering::Relaxed);
        self.finished.cancel();
    }
}

impl Lease {
    fn upload(&self) -> &Upload {
        self.upload.as_ref().expect("upload state was initialized")
    }

    fn upload_rejected(&self) -> bool {
        self.upload
            .as_ref()
            .is_some_and(|upload| upload.rejected.is_cancelled())
    }

    fn complete_response(&self) {
        self.response_complete.store(true, Ordering::Relaxed);
    }

    fn fail(&self, label: &'static str) {
        if self.upload_rejected() || self.failure_recorded.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut health = self.health.lock().unwrap();
        health.passive_failures += 1;
        health.change(Phase::Cooldown(Instant::now() + self.cooldown), Some(label));
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.transport.in_flight.fetch_sub(1, Ordering::Relaxed);
        let Some(trial) = self.trial else { return };
        let mut health = self.health.lock().unwrap();
        if health.revision != trial {
            return;
        }
        if self.response_complete.load(Ordering::Relaxed) && !self.upload_rejected() {
            health.change(Phase::Healthy, None);
        } else {
            let last_failure = health.last_failure;
            health.change(Phase::Cooldown(Instant::now()), last_failure);
        }
    }
}
