mod acme;
mod state;

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwapOption;
use rustix::fs::{self, Mode, OFlags};
use rustls::{
    ServerConfig,
    client::verify_server_name,
    crypto::ring,
    pki_types::ServerName,
    server::{ClientHello, NoServerSessionStorage, ParsedCertificate, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

use crate::config::{Config, SiteTls, normalize_host};
use state::StateDir;

type ListenerSites = BTreeMap<String, Arc<CertificateSlot>>;
type ManualSlots = BTreeMap<(String, [u8; 32]), Arc<CertificateSlot>>;

pub struct TlsManager {
    state: Arc<StateDir>,
    next_id: AtomicU64,
    workers: Mutex<Option<acme::Workers>>,
}

pub struct TlsGeneration {
    sites: BTreeMap<String, ListenerSites>,
    tcp: BTreeMap<String, Arc<ServerConfig>>,
    quic: BTreeMap<String, Arc<quinn::ServerConfig>>,
    manual: ManualSlots,
    acme: Option<acme::Plan>,
}

impl TlsManager {
    pub fn open(state_dir: &Path) -> Result<Self> {
        Ok(Self {
            state: Arc::new(StateDir::open(state_dir)?),
            next_id: AtomicU64::new(1),
            workers: Mutex::new(None),
        })
    }

    pub fn check(config: &Config) -> Result<()> {
        acme::configured_issuer(config)?;
        if config
            .listeners
            .values()
            .any(|listener| listener.protocols.h3)
        {
            quic_transport(&config.limits)?;
        }
        for site in &config.sites {
            if let SiteTls::Manual { certificate, key } = &site.tls {
                load_manual(&site.host, certificate, key)?;
            }
        }
        Ok(())
    }

    pub fn prepare(
        &self,
        config: &Config,
        previous: Option<&TlsGeneration>,
    ) -> Result<Arc<TlsGeneration>> {
        let mut acme = acme::configured_issuer(config)?.map(|issuer| {
            acme::Plan::new(
                issuer,
                previous.and_then(|generation| generation.acme.as_ref()),
            )
        });
        let previous_acme = previous.and_then(|generation| generation.acme.as_ref());
        let mut manual = ManualSlots::new();
        let mut sites = BTreeMap::<String, ListenerSites>::new();

        for site in &config.sites {
            let slot = match &site.tls {
                SiteTls::Off => continue,
                SiteTls::Manual { certificate, key } => {
                    let cert = load_manual(&site.host, certificate, key)?;
                    let key = (site.host.clone(), cert.fingerprint);
                    manual
                        .entry(key.clone())
                        .or_insert_with(|| {
                            previous
                                .and_then(|generation| generation.manual.get(&key))
                                .cloned()
                                .unwrap_or_else(|| self.new_slot(Some(cert)))
                        })
                        .clone()
                }
                SiteTls::Acme => {
                    let plan = acme.as_mut().context("site requires an ACME issuer")?;
                    plan.slot(&site.host, &self.state, previous_acme, |certificate| {
                        self.new_slot(certificate)
                    })
                }
            };
            for listener in &site.listeners {
                sites
                    .entry(listener.clone())
                    .or_default()
                    .insert(site.host.clone(), Arc::clone(&slot));
            }
        }

        let mut tcp = BTreeMap::new();
        let mut quic = BTreeMap::new();
        for (name, listener) in &config.listeners {
            if !listener.tls {
                continue;
            }
            let resolver = Arc::new(ListenerCertificates {
                sites: sites.get(name).cloned().unwrap_or_default(),
                default_site: listener.default_site.clone(),
            });
            if listener.protocols.tcp() {
                let alpn = [
                    (listener.protocols.h2, b"h2".as_slice()),
                    (listener.protocols.http1, b"http/1.1".as_slice()),
                ]
                .into_iter()
                .filter(|(enabled, _)| *enabled)
                .map(|(_, alpn)| alpn.to_vec())
                .collect();
                let tcp_tls = server_config(Arc::clone(&resolver), alpn, false)?;
                tcp.insert(name.clone(), Arc::new(tcp_tls));
            }
            if listener.protocols.h3 {
                let quic_tls = server_config(resolver, vec![b"h3".to_vec()], true)?;
                let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(quic_tls)?;
                let mut quic_server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
                quic_server.migration(false);
                quic_server.transport_config(Arc::new(quic_transport(&config.limits)?));
                quic.insert(name.clone(), Arc::new(quic_server));
            }
        }

        Ok(Arc::new(TlsGeneration {
            sites,
            tcp,
            quic,
            manual,
            acme,
        }))
    }

    pub fn activate(&self, generation: &Arc<TlsGeneration>) {
        let mut workers = self
            .workers
            .lock()
            .expect("certificate workers lock poisoned");
        if let Some(plan) = &generation.acme {
            acme::Workers::reconcile(&mut workers, plan, &self.state);
        } else {
            workers.take();
        }
    }

    pub fn stop(&self) {
        self.workers
            .lock()
            .expect("certificate workers lock poisoned")
            .take();
    }

    fn new_slot(&self, cert: Option<VerifiedCertificate>) -> Arc<CertificateSlot> {
        Arc::new(CertificateSlot {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            current: ArcSwapOption::from(cert.map(Arc::new)),
            state: Mutex::new(acme::SlotState::default()),
        })
    }
}

impl TlsGeneration {
    pub fn tcp_config(&self, listener: &str) -> Option<Arc<ServerConfig>> {
        self.tcp.get(listener).cloned()
    }

    pub fn quic_config(&self, listener: &str) -> Option<Arc<quinn::ServerConfig>> {
        self.quic.get(listener).cloned()
    }

    pub fn identity(&self, listener: &str, host: &str) -> Option<u64> {
        Some(self.sites.get(listener)?.get(host)?.id)
    }

    pub fn ready(&self, listener: &str, host: &str) -> bool {
        self.sites
            .get(listener)
            .and_then(|sites| sites.get(host))
            .is_some_and(|slot| slot.ready().is_some())
    }

    pub fn challenge(&self, listener: &str, host: &str, token: &str) -> Option<String> {
        if self.tcp.contains_key(listener) || self.quic.contains_key(listener) {
            return None;
        }
        let slot = self.sites.get(listener)?.get(host)?;
        slot.state
            .lock()
            .expect("certificate slot lock poisoned")
            .challenge(token)
    }

    pub fn status(&self) -> Value {
        let mut status = BTreeMap::new();
        for (listener, sites) in &self.sites {
            let mut listener_status = BTreeMap::new();
            for (host, slot) in sites {
                let current = slot.current.load();
                let managed = self
                    .acme
                    .as_ref()
                    .is_some_and(|plan| plan.is_managed(host, slot));
                let state = slot.state.lock().expect("certificate slot lock poisoned");
                listener_status.insert(
                    host,
                    json!({
                        "managed": managed,
                        "ready": current.as_ref().is_some_and(|cert| cert.is_current()),
                        "expires_at_unix": current.as_ref().map(|cert| cert.not_after),
                        "last_renewal_error": state.last_error,
                        "orders_succeeded": state.orders_succeeded,
                        "orders_failed": state.orders_failed,
                    }),
                );
            }
            status.insert(listener, listener_status);
        }
        json!(status)
    }
}

struct CertificateSlot {
    id: u64,
    current: ArcSwapOption<VerifiedCertificate>,
    state: Mutex<acme::SlotState>,
}

impl CertificateSlot {
    fn ready(&self) -> Option<Arc<CertifiedKey>> {
        let current = self.current.load();
        let cert = current.as_ref().filter(|cert| cert.is_current())?;
        Some(Arc::clone(&cert.key))
    }
}

struct ListenerCertificates {
    sites: ListenerSites,
    default_site: Option<String>,
}

impl std::fmt::Debug for ListenerCertificates {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ListenerCertificates")
            .field("default_site", &self.default_site)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for ListenerCertificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match hello.server_name() {
            Some(host) => self.sites.get(&normalize_host(host)?)?.ready(),
            None => self.sites.get(self.default_site.as_deref()?)?.ready(),
        }
    }
}

fn server_config(
    resolver: Arc<ListenerCertificates>,
    alpn: Vec<Vec<u8>>,
    quic: bool,
) -> Result<ServerConfig> {
    let versions = if quic {
        &[&rustls::version::TLS13][..]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(versions)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn;
    config.max_early_data_size = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

fn quic_transport(limits: &crate::config::Limits) -> Result<quinn::TransportConfig> {
    const CONTROL_STREAMS: u32 = 8;

    let streams = u64::from(limits.max_streams_per_connection) + u64::from(CONTROL_STREAMS);
    let per_stream = limits.max_buffer_bytes as u64;
    let budget = per_stream
        .checked_mul(streams)
        .context("QUIC connection buffer limit is too large")?;
    let idle = limits
        .handshake_timeout
        .max(limits.request_head_timeout)
        .max(limits.body_idle_timeout);
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(limits.max_streams_per_connection.into())
        .max_concurrent_uni_streams(CONTROL_STREAMS.into())
        .stream_receive_window(quinn::VarInt::try_from(per_stream)?)
        .receive_window(quinn::VarInt::try_from(budget)?)
        .send_window(budget)
        .max_idle_timeout(Some(idle.try_into()?))
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0);
    Ok(config)
}

struct VerifiedCertificate {
    key: Arc<CertifiedKey>,
    not_before: i64,
    not_after: i64,
    fingerprint: [u8; 32],
}

impl VerifiedCertificate {
    fn verify(host: &str, chain_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let chain = rustls_pemfile::certs(&mut &*chain_pem)
            .collect::<std::io::Result<Vec<_>>>()
            .context("invalid certificate PEM")?;
        let key = rustls_pemfile::private_key(&mut &*key_pem)
            .context("invalid private key PEM")?
            .context("private key PEM is empty")?;
        let leaf = chain.first().context("certificate chain is empty")?;
        let name = ServerName::try_from(host).context("invalid TLS site name")?;
        let webpki_leaf = ParsedCertificate::try_from(leaf)?;
        verify_server_name(&webpki_leaf, &name)
            .context("certificate does not cover the site name")?;

        let mut fingerprint = Sha256::new();
        let validity = parse_der(leaf)?.validity().clone();
        for certificate in &chain[1..] {
            parse_der(certificate)?;
        }
        for certificate in &chain {
            fingerprint.update((certificate.len() as u64).to_be_bytes());
            fingerprint.update(certificate);
        }
        let signing_key = CertifiedKey::from_der(chain, key, &ring::default_provider())
            .context("load certificate and signing key")?;
        signing_key
            .keys_match()
            .context("certificate and signing key do not match")?;
        let verified = Self {
            key: Arc::new(signing_key),
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
            fingerprint: fingerprint.finalize().into(),
        };
        ensure!(
            verified.is_current(),
            "leaf certificate is outside its validity period"
        );
        Ok(verified)
    }

    fn is_current(&self) -> bool {
        let now = unix_time();
        self.not_before <= now && now < self.not_after
    }

    fn renewal_delay(&self) -> Duration {
        let remaining_fraction = rand::random_range(0.30..0.37);
        let lifetime = self.not_after.saturating_sub(self.not_before);
        let renewal_at = self
            .not_after
            .saturating_sub((lifetime as f64 * remaining_fraction) as i64);
        Duration::from_secs(renewal_at.saturating_sub(unix_time()).max(0) as u64)
    }
}

fn parse_der(bytes: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>> {
    let (rest, certificate) = parse_x509_certificate(bytes)
        .map_err(|_| anyhow::anyhow!("invalid DER in certificate chain"))?;
    ensure!(
        rest.is_empty(),
        "unexpected trailing bytes in certificate DER"
    );
    Ok(certificate)
}

fn load_manual(host: &str, certificate: &Path, key: &Path) -> Result<VerifiedCertificate> {
    let chain = read_pem_input(certificate)
        .with_context(|| format!("read certificate for {host} from {}", certificate.display()))?;
    let key = read_pem_input(key)
        .with_context(|| format!("read private key for {host} from {}", key.display()))?;
    VerifiedCertificate::verify(host, &chain, &key)
        .with_context(|| format!("validate manual certificate for {host}"))
}

fn read_pem_input(path: &Path) -> Result<Vec<u8>> {
    const MAX_PEM_BYTES: u64 = 16 * 1024 * 1024;
    let file = File::from(fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    ensure!(
        file.metadata()?.is_file(),
        "PEM input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_PEM_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_PEM_BYTES,
        "PEM input exceeds 16 MiB"
    );
    Ok(bytes)
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn certificate_checks_name_and_key_before_it_is_ready() -> Result<()> {
        let cert = rcgen::generate_simple_self_signed(vec!["test.example".into()])?;
        let other = rcgen::generate_simple_self_signed(vec!["test.example".into()])?;
        let pem = cert.cert.pem();
        let key = cert.signing_key.serialize_pem();

        let verified = VerifiedCertificate::verify("test.example", pem.as_bytes(), key.as_bytes())?;
        assert!(verified.is_current());
        assert!(
            VerifiedCertificate::verify("other.example", pem.as_bytes(), key.as_bytes()).is_err()
        );
        assert!(
            VerifiedCertificate::verify(
                "test.example",
                pem.as_bytes(),
                other.signing_key.serialize_pem().as_bytes()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn compatible_manual_slots_are_retained_on_reload() -> Result<()> {
        const SITE: &str = "test.example";
        let temp = tempfile::tempdir()?;
        let settings_path = temp.path().join("test.toml");
        fs::write(
            &settings_path,
            r#"
schema_version = 1
admin_socket = "admin.sock"
state_dir = "state"

[[listeners]]
name = "secure"
bind = "127.0.0.1:443"
protocols = ["http1", "h2", "h3"]
tls = true

[[sites]]
host = "test.example"
listeners = ["secure"]
tls = "manual"
certificate = "cert.pem"
key = "key.pem"

[[sites.routes]]
name = "root"
path_prefix = "/"
static_root = "."
"#,
        )?;
        let config = Config::load(&settings_path)?;
        let write_pair = || -> Result<()> {
            let pair = rcgen::generate_simple_self_signed(vec![SITE.into()])?;
            fs::write(temp.path().join("cert.pem"), pair.cert.pem())?;
            fs::write(
                temp.path().join("key.pem"),
                pair.signing_key.serialize_pem(),
            )?;
            Ok(())
        };

        write_pair()?;
        TlsManager::check(&config)?;
        assert!(!config.state_dir.exists());
        let manager = TlsManager::open(&config.state_dir)?;
        let first = manager.prepare(&config, None)?;
        let repeat = manager.prepare(&config, Some(&first))?;
        assert!(first.ready("secure", SITE));
        assert!(!first.ready("unassigned", SITE));
        assert_eq!(
            first.identity("secure", SITE),
            repeat.identity("secure", SITE)
        );
        assert_eq!(
            first.tcp_config("secure").unwrap().alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(first.quic_config("secure").is_some());

        write_pair()?;
        let rotated = manager.prepare(&config, Some(&repeat))?;
        assert!(rotated.ready("secure", SITE));
        assert_ne!(
            first.identity("secure", SITE),
            rotated.identity("secure", SITE)
        );
        Ok(())
    }
}
