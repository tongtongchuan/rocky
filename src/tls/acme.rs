use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http::{Request, header::RETRY_AFTER};
use http_body_util::Limited;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeStatus,
    ChallengeType, Error, HttpClient, Identifier, NewAccount, NewOrder, Order, OrderStatus,
    RetryPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;

use super::{CertificateSlot, StateDir, VerifiedCertificate, read_pem_input};
use crate::config::{AcmeConfig, Config, SiteTls};

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_BACKOFF: Duration = Duration::from_secs(60 * 60);

pub(super) struct Issuer {
    config: AcmeConfig,
    namespace: String,
    roots: rustls::RootCertStore,
    roots_hash: [u8; 32],
}

pub(super) fn configured_issuer(config: &Config) -> Result<Option<Issuer>> {
    let managed = config.sites.iter().any(|site| site.tls == SiteTls::Acme);
    let Some(acme) = &config.acme else {
        ensure!(!managed, "managed TLS sites require ACME settings");
        return Ok(None);
    };
    if !managed && acme.trust_roots.is_none() {
        return Ok(None);
    }

    let mut roots = rustls::RootCertStore::empty();
    let mut hash = Sha256::new();
    if let Some(path) = &acme.trust_roots {
        let pem = read_pem_input(path)
            .with_context(|| format!("read ACME trust roots {}", path.display()))?;
        for root in rustls_pemfile::certs(&mut pem.as_slice()) {
            let root = root.context("read ACME trust root PEM")?;
            hash.update((root.len() as u64).to_be_bytes());
            hash.update(&root);
            roots.add(root).context("load ACME trust root")?;
        }
    } else {
        for root in rustls_native_certs::load_native_certs().certs {
            hash.update((root.len() as u64).to_be_bytes());
            hash.update(&root);
            let _ = roots.add(root);
        }
    }
    ensure!(!roots.is_empty(), "ACME trust root store is empty");
    if !managed {
        return Ok(None);
    }
    let namespace = file_identity(&[&acme.directory_url, &acme.contact]);
    Ok(Some(Issuer {
        config: acme.clone(),
        namespace,
        roots,
        roots_hash: hash.finalize().into(),
    }))
}

pub(super) struct Plan {
    issuer: Arc<Issuer>,
    slots: BTreeMap<String, Arc<CertificateSlot>>,
}

impl Plan {
    pub(super) fn new(issuer: Issuer, previous: Option<&Self>) -> Self {
        let issuer = previous
            .filter(|previous| {
                previous.issuer.config == issuer.config
                    && previous.issuer.roots_hash == issuer.roots_hash
            })
            .map(|previous| Arc::clone(&previous.issuer))
            .unwrap_or_else(|| Arc::new(issuer));
        Self {
            issuer,
            slots: BTreeMap::new(),
        }
    }

    pub(super) fn slot(
        &mut self,
        host: &str,
        state: &StateDir,
        previous: Option<&Self>,
        allocate: impl FnOnce(Option<VerifiedCertificate>) -> Arc<CertificateSlot>,
    ) -> Arc<CertificateSlot> {
        if let Some(slot) = self.slots.get(host) {
            return Arc::clone(slot);
        }
        if let Some(slot) = previous
            .filter(|previous| previous.issuer.namespace == self.issuer.namespace)
            .and_then(|previous| previous.slots.get(host))
        {
            self.slots.insert(host.into(), Arc::clone(slot));
            return Arc::clone(slot);
        }

        let restored = restore_certificate(state, &self.issuer, host);
        let slot = match restored {
            Ok(certificate) => allocate(certificate),
            Err(error) => {
                let slot = allocate(None);
                slot.state
                    .lock()
                    .expect("certificate slot lock poisoned")
                    .last_error = Some(error.to_string());
                slot
            }
        };
        self.slots.insert(host.into(), Arc::clone(&slot));
        slot
    }

    pub(super) fn is_managed(&self, host: &str, slot: &Arc<CertificateSlot>) -> bool {
        self.slots
            .get(host)
            .is_some_and(|managed| Arc::ptr_eq(managed, slot))
    }
}

#[derive(Default)]
pub(super) struct SlotState {
    pub(super) last_error: Option<String>,
    pub(super) orders_succeeded: u64,
    pub(super) orders_failed: u64,
    challenge: Option<ChallengeResponse>,
}

impl SlotState {
    pub(super) fn challenge(&self, token: &str) -> Option<String> {
        self.challenge
            .as_ref()
            .filter(|challenge| challenge.token == token)
            .map(|challenge| challenge.authorization.clone())
    }
}

struct ChallengeResponse {
    token: String,
    authorization: String,
}

pub(super) struct Workers {
    account: Arc<IssuerAccount>,
    concurrency: Arc<Semaphore>,
    jobs: BTreeMap<String, Job>,
}

impl Workers {
    pub(super) fn reconcile(active: &mut Option<Self>, plan: &Plan, state: &Arc<StateDir>) {
        if !active
            .as_ref()
            .is_some_and(|workers| Arc::ptr_eq(&workers.account.issuer, &plan.issuer))
        {
            active.take();
        }
        let workers = active.get_or_insert_with(|| Self {
            account: Arc::new(IssuerAccount::new(
                Arc::clone(&plan.issuer),
                Arc::clone(state),
            )),
            concurrency: Arc::new(Semaphore::new(plan.issuer.config.max_concurrent_orders)),
            jobs: BTreeMap::new(),
        });
        workers
            .jobs
            .retain(|host, job| plan.is_managed(host, &job.slot));
        for (host, slot) in &plan.slots {
            workers.jobs.entry(host.clone()).or_insert_with(|| {
                let job = Job {
                    slot: Arc::clone(slot),
                    cancellation: CancellationToken::new(),
                };
                tokio::spawn(run_worker(
                    host.clone(),
                    Arc::clone(slot),
                    job.cancellation.clone(),
                    Arc::clone(&workers.account),
                    Arc::clone(&workers.concurrency),
                ));
                job
            });
        }
    }
}

struct Job {
    slot: Arc<CertificateSlot>,
    cancellation: CancellationToken,
}

impl Drop for Job {
    fn drop(&mut self) {
        let mut state = self
            .slot
            .state
            .lock()
            .expect("certificate slot lock poisoned");
        self.cancellation.cancel();
        state.challenge = None;
    }
}

struct Lease<'a> {
    slot: &'a CertificateSlot,
    cancellation: &'a CancellationToken,
}

impl Lease<'_> {
    fn active<T>(&self, operation: impl FnOnce(&mut SlotState) -> Result<T>) -> Result<T> {
        let mut state = self
            .slot
            .state
            .lock()
            .expect("certificate slot lock poisoned");
        ensure!(
            !self.cancellation.is_cancelled(),
            "certificate identity retired"
        );
        operation(&mut state)
    }
}

struct ChallengeGuard<'a>(&'a Lease<'a>);

impl Drop for ChallengeGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.active(|state| {
            state.challenge = None;
            Ok(())
        });
    }
}

struct IssuerAccount {
    issuer: Arc<Issuer>,
    state: Arc<StateDir>,
    account: OnceCell<Account>,
    retry_at: Arc<Mutex<Option<Instant>>>,
}

impl IssuerAccount {
    fn new(issuer: Arc<Issuer>, state: Arc<StateDir>) -> Self {
        Self {
            issuer,
            state,
            account: OnceCell::new(),
            retry_at: Arc::new(Mutex::new(None)),
        }
    }

    async fn account(&self, lease: &Lease<'_>) -> Result<&Account> {
        self.account
            .get_or_try_init(|| async {
                let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(self.issuer.roots.clone())
                .with_no_client_auth();
                let mut connector = HttpConnector::new();
                connector.enforce_http(false);
                connector.set_connect_timeout(Some(Duration::from_secs(10)));
                let https = HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_only()
                    .enable_http1()
                    .enable_http2()
                    .wrap_connector(connector);
                let client = Client::builder(TokioExecutor::new())
                    .pool_timer(TokioTimer::new())
                    .pool_idle_timeout(Duration::from_secs(30))
                    .pool_max_idle_per_host(2)
                    .build(https);
                let builder = Account::builder_with_http(Box::new(AcmeHttp {
                    client,
                    retry_at: Arc::clone(&self.retry_at),
                }));
                let name = account_name(&self.issuer);
                if let Some(record) = self.state.read::<AccountRecord>(&name)? {
                    let account = builder
                        .from_credentials(record.credentials)
                        .await
                        .context("restore ACME account")?;
                    ensure!(
                        account_identity(&account) == record.identity,
                        "stored ACME account identity mismatch"
                    );
                    return Ok(account);
                }

                let settings = &self.issuer.config;
                let (account, credentials) = builder
                    .create(
                        &NewAccount {
                            contact: &[settings.contact.as_str()],
                            terms_of_service_agreed: settings.accept_terms,
                            only_return_existing: false,
                        },
                        settings.directory_url.clone(),
                        None,
                    )
                    .await
                    .context("register ACME account")?;
                lease.active(|_| {
                    self.state.write(
                        &name,
                        &AccountRecord {
                            identity: account_identity(&account),
                            credentials,
                        },
                    )
                })?;
                Ok(account)
            })
            .await
    }

    async fn issue(&self, host: &str, lease: &Lease<'_>) -> Result<()> {
        let account = self.account(lease).await?;
        let identity = account_identity(account);
        let site = site_name(&self.issuer, host);
        let order_name = format!("{site}.order.json");
        let (mut order, record) = self
            .open_order(account, host, &identity, &order_name, lease)
            .await?;

        let outcome = complete_order(&mut order, &record.key, host, lease).await;
        if order.state().status == OrderStatus::Invalid {
            lease.active(|_| self.state.remove(&order_name))?;
        }
        let chain = outcome?;
        let certificate =
            match VerifiedCertificate::verify(host, chain.as_bytes(), record.key.as_bytes()) {
                Ok(certificate) => certificate,
                Err(error) => {
                    lease.active(|_| self.state.remove(&order_name))?;
                    return Err(error).context("validate issued certificate");
                }
            };
        let expires = certificate.not_after;
        lease.active(|state| {
            self.state.write(
                &format!("{site}.bundle.json"),
                &CertificateBundle {
                    account: identity,
                    chain,
                    key: record.key,
                },
            )?;
            self.state.remove(&order_name)?;
            lease.slot.current.store(Some(Arc::new(certificate)));
            state.last_error = None;
            state.orders_succeeded = state.orders_succeeded.saturating_add(1);
            Ok(())
        })?;
        tracing::info!(
            site = host,
            expires_at_unix = expires,
            "ACME certificate installed"
        );
        Ok(())
    }

    async fn open_order(
        &self,
        account: &Account,
        host: &str,
        identity: &str,
        name: &str,
        lease: &Lease<'_>,
    ) -> Result<(Order, PendingOrder)> {
        if let Some(record) = self.state.read::<PendingOrder>(name)?
            && record.account == identity
        {
            match account.order(record.url.clone()).await {
                Ok(mut order) => {
                    if order.state().status != OrderStatus::Invalid {
                        return Ok((order, record));
                    }
                }
                Err(Error::Api(problem)) if matches!(problem.status, Some(404 | 410)) => {}
                Err(error) => return Err(error).context("resume ACME order"),
            }
        }
        let order = account
            .new_order(&NewOrder::new(&[Identifier::Dns(host.into())]))
            .await
            .context("create ACME order")?;
        let key = rcgen::KeyPair::generate().context("generate certificate signing key")?;
        let record = PendingOrder {
            account: identity.into(),
            url: order.url().into(),
            key: key.serialize_pem(),
        };
        lease.active(|_| self.state.write(name, &record))?;
        Ok((order, record))
    }
}

async fn run_worker(
    host: String,
    slot: Arc<CertificateSlot>,
    cancellation: CancellationToken,
    account: Arc<IssuerAccount>,
    concurrency: Arc<Semaphore>,
) {
    let lease = Lease {
        slot: &slot,
        cancellation: &cancellation,
    };
    let mut delay = slot
        .current
        .load()
        .as_ref()
        .map_or(Duration::ZERO, |cert| cert.renewal_delay());
    let mut backoff = Duration::from_secs(1);
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        let permit = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            permit = concurrency.acquire() => permit.expect("ACME concurrency semaphore closed"),
        };
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            result = tokio::time::timeout(ATTEMPT_TIMEOUT, account.issue(&host, &lease)) => {
                result.context("ACME attempt deadline elapsed").and_then(|result| result)
            }
        };
        drop(permit);

        if let Err(error) = result {
            if lease
                .active(|state| {
                    state.last_error = Some(error.to_string());
                    state.orders_failed = state.orders_failed.saturating_add(1);
                    Ok(())
                })
                .is_err()
            {
                return;
            }
            tracing::warn!(site = host, reason = %error, "ACME certificate attempt failed");
            delay = backoff
                .mul_f64(rand::random_range(1.0..1.25))
                .min(MAX_BACKOFF);
            if let Some(next) = retry_deadline(&error, &account.retry_at) {
                delay = delay.max(next.saturating_duration_since(Instant::now()));
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        } else {
            backoff = Duration::from_secs(1);
            delay = slot
                .current
                .load()
                .as_ref()
                .map_or(MAX_BACKOFF, |cert| cert.renewal_delay().max(backoff));
        }
    }
}

async fn complete_order(
    order: &mut Order,
    key: &str,
    host: &str,
    lease: &Lease<'_>,
) -> Result<String> {
    let retry = RetryPolicy::new()
        .initial_delay(Duration::from_secs(1))
        .backoff(1.5)
        .timeout(Duration::from_secs(60));
    if order.state().status == OrderStatus::Pending {
        let _challenge = ChallengeGuard(lease);
        start_validation(order, host, lease).await?;
        let status = order
            .poll_ready(&retry)
            .await
            .context("wait for ACME HTTP-01 validation")?;
        ensure!(
            status == OrderStatus::Ready,
            "ACME HTTP-01 validation failed"
        );
    }
    if order.state().status == OrderStatus::Ready {
        let key = rcgen::KeyPair::from_pem(key).context("restore certificate signing key")?;
        let mut parameters = rcgen::CertificateParams::new(vec![host.into()])?;
        parameters.distinguished_name = rcgen::DistinguishedName::new();
        let csr = parameters.serialize_request(&key)?;
        order
            .finalize_csr(csr.der())
            .await
            .context("finalize ACME order")?;
    }
    match order.state().status {
        OrderStatus::Valid => order
            .certificate()
            .await
            .context("download ACME certificate")?
            .context("ACME order has no certificate"),
        OrderStatus::Ready | OrderStatus::Processing => order
            .poll_certificate(&retry)
            .await
            .context("wait for ACME certificate"),
        _ => bail!("ACME order is invalid"),
    }
}

async fn start_validation(order: &mut Order, host: &str, lease: &Lease<'_>) -> Result<()> {
    let mut authorizations = order.authorizations();
    let mut authorization = authorizations
        .next()
        .await
        .transpose()
        .context("read ACME authorization")?
        .context("ACME order has no authorization")?;
    let identifier = authorization.identifier();
    ensure!(
        matches!(identifier.identifier, Identifier::Dns(dns) if dns == host)
            && !identifier.wildcard,
        "ACME authorization did not match the configured site"
    );
    match authorization.status {
        AuthorizationStatus::Valid => {}
        AuthorizationStatus::Pending => {
            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .context("ACME issuer offered no HTTP-01 challenge")?;
            let token = challenge.token.clone();
            ensure!(
                !token.is_empty()
                    && token.len() <= 256
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
                "ACME issuer supplied an invalid HTTP-01 token"
            );
            match challenge.status {
                ChallengeStatus::Pending | ChallengeStatus::Processing => {
                    let authorization = challenge.key_authorization().as_str().to_owned();
                    lease.active(|state| {
                        state.challenge = Some(ChallengeResponse {
                            token,
                            authorization,
                        });
                        Ok(())
                    })?;
                    if challenge.status == ChallengeStatus::Pending {
                        challenge
                            .set_ready()
                            .await
                            .context("notify ACME issuer of HTTP-01 readiness")?;
                    }
                }
                ChallengeStatus::Valid => {}
                ChallengeStatus::Invalid => bail!("ACME HTTP-01 challenge is invalid"),
            }
        }
        _ => bail!("ACME authorization is invalid"),
    }
    ensure!(
        authorizations.next().await.is_none(),
        "ACME order contained additional authorizations"
    );
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct AccountRecord {
    identity: String,
    credentials: AccountCredentials,
}

#[derive(Deserialize, Serialize)]
struct PendingOrder {
    account: String,
    url: String,
    key: String,
}

#[derive(Deserialize, Serialize)]
struct CertificateBundle {
    account: String,
    chain: String,
    key: String,
}

fn restore_certificate(
    state: &StateDir,
    issuer: &Issuer,
    host: &str,
) -> Result<Option<VerifiedCertificate>> {
    let Some(account) = state.read::<AccountRecord>(&account_name(issuer))? else {
        return Ok(None);
    };
    let name = format!("{}.bundle.json", site_name(issuer, host));
    let Some(bundle) = state.read::<CertificateBundle>(&name)? else {
        return Ok(None);
    };
    if bundle.account != account.identity {
        return Ok(None);
    }
    let verified =
        VerifiedCertificate::verify(host, bundle.chain.as_bytes(), bundle.key.as_bytes())
            .context("restore managed certificate")?;
    Ok(Some(verified))
}

fn account_name(issuer: &Issuer) -> String {
    format!("{}.account.json", issuer.namespace)
}

fn account_identity(account: &Account) -> String {
    file_identity(&[account.id(), account.key_thumbprint()])
}

fn site_name(issuer: &Issuer, host: &str) -> String {
    file_identity(&[&issuer.namespace, host])
}

fn file_identity(values: &[&str]) -> String {
    let mut hash = Sha256::new();
    for value in values {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

struct AcmeHttp {
    client: Client<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>,
    retry_at: Arc<Mutex<Option<Instant>>>,
}

impl HttpClient for AcmeHttp {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let next = *self.retry_at.lock().expect("ACME retry lock poisoned");
        if next.is_some_and(|instant| instant > Instant::now()) {
            return Box::pin(async move { Err(Error::Timeout(next)) });
        }
        let response = self.client.request(request);
        let retry_at = Arc::clone(&self.retry_at);
        Box::pin(async move {
            let (mut parts, body) = response
                .await
                .map_err(|error| Error::Other(Box::new(error)))?
                .into_parts();
            if let Some(value) = parts
                .headers
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
            {
                if let Some(next) = parse_retry_after(value) {
                    if parts.status.is_client_error() || parts.status.is_server_error() {
                        let mut retry_at = retry_at.lock().expect("ACME retry lock poisoned");
                        *retry_at = (*retry_at).max(Some(next));
                    }
                } else {
                    parts.headers.remove(RETRY_AFTER);
                }
            }
            Ok(BytesResponse::from(http::Response::from_parts(
                parts,
                Limited::new(body, MAX_RESPONSE_BYTES),
            )))
        })
    }
}

fn parse_retry_after(value: &str) -> Option<Instant> {
    let value = value.trim();
    let delay = if let Ok(seconds) = value.parse::<u64>() {
        let delay = Duration::from_secs(seconds);
        SystemTime::now().checked_add(delay)?;
        delay
    } else {
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(SystemTime::now())
            .unwrap_or_default()
    };
    Instant::now().checked_add(delay)
}

fn retry_deadline(error: &anyhow::Error, retry_at: &Mutex<Option<Instant>>) -> Option<Instant> {
    let order_retry = error
        .chain()
        .find_map(|cause| match cause.downcast_ref::<Error>() {
            Some(Error::Timeout(next)) => *next,
            _ => None,
        });
    order_retry.max(*retry_at.lock().expect("ACME retry lock poisoned"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_accepts_valid_delays_and_dates() {
        let before = Instant::now();
        assert!(parse_retry_after("20").unwrap() >= before + Duration::from_secs(20));
        let until = SystemTime::now() + Duration::from_secs(10);
        assert!(parse_retry_after(&httpdate::fmt_http_date(until)).unwrap() > before);
        assert!(parse_retry_after("18446744073709551615").is_none());
        assert!(parse_retry_after("invalid").is_none());
    }

    #[test]
    fn a_retired_job_cannot_clear_its_replacement_challenge() {
        let slot = Arc::new(CertificateSlot {
            id: 1,
            current: Default::default(),
            state: Default::default(),
        });
        let retired = Job {
            slot: Arc::clone(&slot),
            cancellation: CancellationToken::new(),
        };
        let token = retired.cancellation.clone();
        let lease = Lease {
            slot: &slot,
            cancellation: &token,
        };
        let challenge = ChallengeGuard(&lease);
        lease
            .active(|state| {
                state.challenge = Some(ChallengeResponse {
                    token: "old".into(),
                    authorization: "old-proof".into(),
                });
                Ok(())
            })
            .unwrap();
        drop(retired);
        assert!(slot.state.lock().unwrap().challenge("old").is_none());
        slot.state.lock().unwrap().challenge = Some(ChallengeResponse {
            token: "new".into(),
            authorization: "new-proof".into(),
        });
        drop(challenge);
        assert_eq!(
            slot.state.lock().unwrap().challenge("new").as_deref(),
            Some("new-proof")
        );
    }
}
