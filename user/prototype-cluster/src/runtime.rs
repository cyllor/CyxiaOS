use crate::driver::Driver;
#[derive(Debug)]
pub(crate) enum AdvanceError {
    Custody,
    Tls(Error),
}
#[derive(Debug)]
pub(crate) enum NetworkTurn<P> {
    Offline,
    EntropyUnavailable,
    Connected { epoch: u64, pairing: P },
}
/// One bounded service turn. Custody is independent of network entropy.
pub(crate) fn advance_network<P>(
    driver: &mut Driver,
    now: u64,
    connection: impl FnOnce() -> Option<u64>,
    pairing: impl FnOnce() -> Result<P, Error>,
) -> Result<NetworkTurn<P>, AdvanceError> {
    driver
        .offline_tick(now)
        .map_err(|_| AdvanceError::Custody)?;
    let Some(epoch) = connection() else {
        return Ok(NetworkTurn::Offline);
    };
    match pairing() {
        Ok(pairing) => Ok(NetworkTurn::Connected { epoch, pairing }),
        Err(Error::Entropy) => Ok(NetworkTurn::EntropyUnavailable),
        Err(error) => Err(AdvanceError::Tls(error)),
    }
}
#[cfg(not(test))]
use crate::broker;
#[cfg(not(test))]
use alloc::sync::Arc;
use cyxia_cluster_transport::tls::Error;
#[cfg(not(test))]
use cyxia_cluster_transport::tls::{Buffers, IdentitySigner, Pairing, node_id, public_key};
#[cfg(not(test))]
use cyxia_prototype_cluster::abi::*;
#[cfg(not(test))]
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    time_provider::TimeProvider,
};
#[cfg(not(test))]
#[derive(Debug)]
struct Clock;
#[cfg(not(test))]
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        broker::time().map(|(_, s)| UnixTime::since_unix_epoch(core::time::Duration::from_secs(s)))
    }
}
#[cfg(not(test))]
use cyxia_prototype::domains::{Error as DomainError, ObjectKey};
#[cfg(not(test))]
use cyxia_prototype_cluster::domain_ingress::{TlsEgress, TlsIngress, TlsTransport};
impl cyxia_prototype_cluster::domain_ingress::RpcOutbox for Driver {
    fn outgoing(&self) -> &[u8] {
        Driver::outgoing(self)
    }
    fn consume(&mut self, bytes: usize) {
        self.consume_outgoing(bytes)
    }
}
#[cfg(not(test))]
struct BrokerTcp;
#[cfg(not(test))]
impl BrokerTcp {
    fn send(bytes: &[u8], reserved: bool) -> Result<usize, DomainError> {
        match broker::request(OP_WRITE, bytes, &mut [], 0, [u64::from(reserved), 0, 0]) {
            Ok((n, _)) if n <= bytes.len() => Ok(n),
            Ok(_) => Err(DomainError::Range),
            Err(AGAIN) => Err(DomainError::Again),
            Err(_) => Err(DomainError::Io),
        }
    }
}
#[cfg(not(test))]
impl TlsTransport for BrokerTcp {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, DomainError> {
        Self::send(bytes, false)
    }
    fn write_reserved(&mut self, bytes: &[u8]) -> Result<usize, DomainError> {
        Self::send(bytes, true)
    }
}
#[cfg(not(test))]
fn feedback(
    driver: &Driver,
    ingress: &mut TlsIngress,
    egress: Option<&TlsEgress>,
    now_ns: u64,
    pending_tls: bool,
) {
    let now = now_ns / 1_000_000;
    let input = broker::domains();
    let mut f = driver.domain_feedback(now_ns);
    f.unauth = ingress.receipt;
    f.auth_attempts = ingress.security.counters.attempts;
    f.auth_rejected = ingress.security.counters.rejected;
    f.auth_failures = ingress.security.counters.failures;
    let (normal, recovery) = ingress.security.active();
    f.auth_slots = normal as u64;
    f.recovery_slots = recovery as u64;
    if let Ok(Some(fields)) = ingress.observe(now) {
        f.security = fields;
        f.measurement_valid |= 2;
    }
    if let Some(egress) = egress {
        f.tx = egress.receipt;
        (f.tx_ordinary, f.tx_reserved) = egress.counts();
        let round = egress.last_round();
        f.tx_last_ordinary = round.ordinary as u64;
        f.tx_last_reserved = round.reserved as u64;
    }
    if input.network_valid & 3 == 3
        && now >= input.network_sample_ms
        && now - input.network_sample_ms <= 100
    {
        f.measurement_valid |= 1;
        f.network = [
            input.network_rtt_us,
            input.network_retrans_milli,
            input
                .network_queue_depth
                .saturating_add(driver.queued_frames() as u64)
                .saturating_add(u64::from(pending_tls)),
            input.network_active,
        ];
    }
    f.measurement_ms = now;
    broker::domain_feedback(f);
}
#[cfg(not(test))]
pub fn run() -> ! {
    let (boot, uuid, local, peer) = broker::boot();
    let service_generation = broker::service_generation();
    if boot == 0 || service_generation == 0 {
        broker::fatal(0x101);
    }
    let peer_file = include_bytes!(concat!(env!("OUT_DIR"), "/peer.pin"));
    if peer_file.len() != 32 || peer_file[..] != peer {
        broker::fatal(0x102);
    }
    let certificate =
        CertificateDer::from(&include_bytes!(concat!(env!("OUT_DIR"), "/cert.der"))[..]);
    if node_id(&certificate).ok() != Some(local) {
        broker::fatal(0x104);
    }
    let signer = IdentitySigner::new(
        include_bytes!(concat!(env!("OUT_DIR"), "/key.der")),
        public_key(&CertificateDer::from(
            &include_bytes!(concat!(env!("OUT_DIR"), "/cert.der"))[..],
        ))
        .unwrap_or_else(|_| broker::fatal(0x106)),
    )
    .unwrap_or_else(|_| broker::fatal(0x106));
    let peer_public: [u8; 32] = *include_bytes!(concat!(env!("OUT_DIR"), "/peer.pub"));
    let mut driver = crate::driver::Driver::new_native(
        boot,
        uuid,
        local,
        peer,
        signer,
        peer_public,
        crate::placement_queue(),
    )
    .unwrap_or_else(|_| broker::fatal(0x107));
    broker::trace(2);
    // Buffers owns four fixed-capacity heap allocations. Keeping only these
    // handles on the bounded service stack avoids a 96 KiB temporary frame.
    let mut buffers = Buffers::new();
    let mut input = [0u8; PAYLOAD];
    let mut ingress =
        TlsIngress::new(broker::clock_ns() / 1_000_000).unwrap_or_else(|_| broker::fatal(0x110));
    let mut egress: Option<TlsEgress> = None;
    loop {
        let now = broker::time().unwrap_or_else(|| broker::fatal(0x105)).0;
        let now_ns = broker::clock_ns();
        // Durable obligations and four-second local fallback remain live even
        // when the NIC or entropy source prevents starting a TLS session.
        driver
            .offline_tick(now)
            .unwrap_or_else(|_| broker::fatal(0x108));
        driver
            .domain_tick(now_ns)
            .unwrap_or_else(|_| broker::fatal(0x109));
        let policies = broker::domains();
        let _ = ingress.install_at(policies.unauth, now_ns);
        if let Some(outgoing) = egress.as_mut() {
            outgoing.expire_at(now_ns);
        }
        feedback(&driver, &mut ingress, egress.as_ref(), now_ns, false);
        let epoch = match broker::poll() {
            Ok((true, epoch)) if epoch != 0 => epoch,
            _ => {
                broker::yield_now();
                continue;
            }
        };
        let source = (broker::domains().peer_ipv4 as u32).to_be_bytes();
        let created = ingress.begin_at(source, broker::clock_ns(), || {
            Pairing::new(
                certificate.clone(),
                PrivatePkcs8KeyDer::from(&include_bytes!(concat!(env!("OUT_DIR"), "/key.der"))[..])
                    .into(),
                peer,
                Arc::new(Clock),
            )
            .map_err(|e| {
                if matches!(e, Error::Entropy) {
                    DomainError::Again
                } else {
                    DomainError::Io
                }
            })
        });
        let (ticket, pairing) = match created {
            Ok(v) => v,
            Err(_) => {
                broker::close();
                broker::yield_now();
                continue;
            }
        };
        let now = broker::time().unwrap_or_else(|| broker::fatal(0x105)).0;
        let created = if local < peer {
            pairing.client(&mut buffers, now)
        } else {
            pairing.server(&mut buffers, now)
        };
        let mut session = match created {
            Ok(session) => session,
            Err(_) => {
                let _ = ingress.finish_at(ticket, false, broker::clock_ns());
                broker::close();
                broker::yield_now();
                continue;
            }
        };
        if let Some(existing) = egress.as_mut() {
            existing
                .begin_session(epoch)
                .unwrap_or_else(|_| broker::fatal(0x111));
        } else {
            egress = Some(TlsEgress::new(epoch).unwrap_or_else(|_| broker::fatal(0x111)));
        }
        let outgoing = egress.as_mut().unwrap();
        let mut handshake = Some(ticket);
        let mut authenticated = None;
        loop {
            if !matches!(broker::poll(),Ok((true,e)) if e==epoch) {
                break;
            }
            let Some((now, _)) = broker::time() else {
                break;
            };
            let now_ns = broker::clock_ns();
            let policies = broker::domains();
            let _ = ingress.install_at(policies.unauth, now_ns);
            let _ = outgoing.install_at(policies.tx, now_ns);
            if driver.domain_tick(now_ns).is_err() {
                break;
            }
            match broker::request(OP_READ, &[], &mut input, 0, [0; 3]) {
                Ok((n, _)) => {
                    if n > 0 && session.receive_tls(&input[..n]).ok() != Some(n) {
                        break;
                    }
                }
                Err(AGAIN) => {}
                Err(_) => break,
            }
            if session.pump(now).is_err() {
                break;
            }
            if session.authenticated_peer().is_some() && authenticated.is_none() {
                let Some(ticket) = handshake.take() else {
                    break;
                };
                if ingress.finish_at(ticket, true, broker::clock_ns()).is_err() {
                    break;
                }
                let identity = ObjectKey {
                    id: 1,
                    generation: epoch,
                };
                match ingress.enter_authenticated_at(identity, broker::clock_ns(), || {
                    let mut challenge = [0; 32];
                    broker::entropy(&mut challenge).map_err(|_| DomainError::Again)?;
                    driver.connect(challenge, now).map_err(|_| DomainError::Io)
                }) {
                    Ok((ticket, ())) => {
                        authenticated = Some((identity, ticket));
                        driver.replay_authenticated(epoch, broker::clock_ns());
                        broker::trace(3);
                    }
                    Err(_) => break,
                }
            }
            if authenticated.is_some() {
                if !session.plaintext().is_empty() {
                    let accepted = match driver.ingest(session.plaintext(), now) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if session.consume_plaintext(accepted).is_err() {
                        break;
                    }
                }
                if driver.tick(now).is_err() {
                    break;
                }
                if driver.replay_wants_reconnect(epoch) { break; }
            }
            if outgoing
                .service_at(
                    &mut session,
                    &mut driver,
                    broker::clock_ns(),
                    &mut BrokerTcp,
                )
                .is_err()
            {
                break;
            }
            feedback(
                &driver,
                &mut ingress,
                Some(outgoing),
                broker::clock_ns(),
                !session.pending_tls().is_empty(),
            );
            broker::yield_now();
        }
        driver.disconnect();
        session.abort();
        drop(session);
        broker::close();
        if let Some(ticket) = handshake {
            let _ = ingress.finish_at(ticket, false, broker::clock_ns());
        }
        if let Some((identity, ticket)) = authenticated {
            let _ = ingress.leave_authenticated_at(identity, ticket, broker::clock_ns());
        }
        outgoing.reset_session();
        feedback(
            &driver,
            &mut ingress,
            Some(outgoing),
            broker::clock_ns(),
            false,
        );
        broker::trace(4);
        broker::yield_now();
    }
}
