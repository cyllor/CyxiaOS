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
use alloc::{boxed::Box, sync::Arc};
use cyxia_cluster_transport::tls::Error;
#[cfg(not(test))]
use cyxia_cluster_transport::tls::{
    Buffers, IdentitySigner, PLAINTEXT_BUFFER, Pairing, node_id, public_key,
};
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
pub fn run() -> ! {
    let (boot, uuid, local, peer) = broker::boot();
    if boot == 0 {
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
    let mut driver = crate::driver::Driver::new(boot, uuid, local, peer, signer, peer_public)
        .unwrap_or_else(|_| broker::fatal(0x107));
    broker::trace(2);
    let mut buffers = Box::new(Buffers::new());
    let mut input = [0u8; PAYLOAD];
    loop {
        let now = broker::time().unwrap_or_else(|| broker::fatal(0x105)).0;
        let turn = advance_network(
            &mut driver,
            now,
            || {
                broker::poll()
                    .ok()
                    .and_then(|(connected, epoch)| connected.then_some(epoch))
            },
            || {
                Pairing::new(
                    certificate.clone(),
                    PrivatePkcs8KeyDer::from(
                        &include_bytes!(concat!(env!("OUT_DIR"), "/key.der"))[..],
                    )
                    .into(),
                    peer,
                    Arc::new(Clock),
                )
            },
        );
        let (epoch, pairing) = match turn {
            Ok(NetworkTurn::Connected { epoch, pairing }) => (epoch, pairing),
            Ok(NetworkTurn::Offline) => {
                broker::yield_now();
                continue;
            }
            Ok(NetworkTurn::EntropyUnavailable) => {
                driver.disconnect();
                broker::close();
                broker::yield_now();
                continue;
            }
            Err(AdvanceError::Custody) => broker::fatal(0x108),
            Err(AdvanceError::Tls(_)) => broker::fatal(0x103),
        };
        let now = broker::time().unwrap_or_else(|| broker::fatal(0x105)).0;
        let created = if local < peer {
            pairing.client(&mut buffers, now)
        } else {
            pairing.server(&mut buffers, now)
        };
        let mut session = match created {
            Ok(s) => s,
            Err(_) => {
                broker::close();
                broker::yield_now();
                continue;
            }
        };
        let mut authenticated = false;
        loop {
            if !matches!(broker::poll(),Ok((true,e)) if e==epoch) {
                break;
            }
            let Some((now, _)) = broker::time() else {
                break;
            };
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
            let bytes = session.pending_tls();
            if !bytes.is_empty() {
                let n = bytes.len().min(PAYLOAD);
                match broker::request(OP_WRITE, &bytes[..n], &mut [], 0, [0; 3]) {
                    Ok((n, _)) => {
                        if session.consume_tls(n).is_err() {
                            break;
                        }
                    }
                    Err(AGAIN) => {}
                    Err(_) => break,
                }
            }
            if session.authenticated_peer().is_some() && !authenticated {
                broker::trace(3);
                let mut challenge = [0u8; 32];
                if broker::entropy(&mut challenge).is_err()
                    || driver.connect(challenge, now).is_err()
                {
                    break;
                }
                authenticated = true;
            }
            if authenticated {
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
                let pending = driver.outgoing();
                if !pending.is_empty() {
                    let count = pending.len().min(PLAINTEXT_BUFFER);
                    match session.send_plaintext(&pending[..count]) {
                        Ok(()) => driver.consume_outgoing(count),
                        Err(Error::WouldBlock) => {}
                        Err(_) => break,
                    }
                }
            }
            broker::yield_now();
        }
        driver.disconnect();
        session.abort();
        drop(session);
        broker::close();
        broker::trace(4);
        broker::yield_now();
    }
}
