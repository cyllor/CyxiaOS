//! One production TLS/Driver turn, shared by the native loop and host replay.
//! Broker calls stay at their original boundaries so controlled clocks and
//! partial IO exercise the same ordering instead of a parallel model.
use super::{BrokerTcp, feedback, timing};
use crate::{broker, driver::Driver};
use cyxia_cluster_transport::tls::Session;
use cyxia_prototype::domains::{Error as DomainError, ObjectKey, platform::AuthTicket};
use cyxia_prototype_cluster::{
    abi::{AGAIN, OP_READ},
    domain_ingress::{TlsEgress, TlsIngress},
    session_exit::{SessionExitReason, connection_result, domain_result, tls_result},
};

pub(crate) struct SessionState {
    epoch: u64,
    pub(super) handshake: Option<AuthTicket>,
    pub(super) authenticated: Option<(ObjectKey, AuthTicket)>,
    pub(super) timing: timing::Tracker,
}
impl SessionState {
    pub(crate) fn new(epoch: u64, ticket: AuthTicket) -> Self {
        Self {
            epoch,
            handshake: Some(ticket),
            authenticated: None,
            timing: timing::Tracker::new(broker::clock_ns()),
        }
    }
}

pub(crate) fn session_turn(
    driver: &mut Driver,
    session: &mut Session<'_>,
    ingress: &mut TlsIngress,
    outgoing: &mut TlsEgress,
    input: &mut [u8],
    state: &mut SessionState,
) -> Result<(), (SessionExitReason, u64)> {
    state.timing.begin_loop(broker::clock_ns());
    if let Some(result) = connection_result(broker::poll(), state.epoch) {
        return Err((SessionExitReason::ConnectionLost, result));
    }
    let Some((now, _)) = broker::time() else {
        return Err((SessionExitReason::ClockUnavailable, 0));
    };
    let now_ns = broker::clock_ns();
    let policies = broker::domains();
    let _ = ingress.install_at(policies.unauth, now_ns);
    let _ = outgoing.install_at(policies.tx, now_ns);
    if driver.domain_tick(now_ns).is_err() {
        return Err((SessionExitReason::DomainTick, 0x4000));
    }
    let receive_started = broker::clock_ns();
    let read_capacity = session.receive_capacity().min(input.len());
    if read_capacity != 0 {
        match broker::request(OP_READ, &[], &mut input[..read_capacity], 0, [0; 3]) {
            Ok((n, _)) => {
                if n > 0 {
                    match session.receive_tls(&input[..n]) {
                        Ok(accepted) if accepted == n => (),
                        Ok(_) => return Err((SessionExitReason::TlsReceive, 0x4003)),
                        Err(e) => return Err((SessionExitReason::TlsReceive, tls_result(&e))),
                    }
                }
            }
            Err(AGAIN) => {}
            Err(e) => return Err((SessionExitReason::TcpRead, 0x3000 + e)),
        }
    }
    state.timing.receive(receive_started, broker::clock_ns());
    if let Err(e) = session.pump(now) {
        return Err((SessionExitReason::TlsPump, tls_result(&e)));
    }
    if session.authenticated_peer().is_some() && state.authenticated.is_none() {
        let Some(ticket) = state.handshake.take() else {
            return Err((SessionExitReason::HandshakeTicket, 0));
        };
        if let Err(e) = ingress.finish_at(ticket, true, broker::clock_ns()) {
            return Err((SessionExitReason::HandshakeFinish, domain_result(e)));
        }
        let identity = ObjectKey {
            id: 1,
            generation: state.epoch,
        };
        match ingress.enter_authenticated_at(identity, broker::clock_ns(), || {
            let mut challenge = [0; 32];
            broker::entropy(&mut challenge).map_err(|_| DomainError::Again)?;
            driver.connect(challenge, now).map_err(|_| DomainError::Io)
        }) {
            Ok((ticket, ())) => {
                state.authenticated = Some((identity, ticket));
                driver.replay_authenticated(state.epoch, broker::clock_ns());
                broker::trace(3);
            }
            Err(e) => return Err((SessionExitReason::EnterAuthenticated, domain_result(e))),
        }
    }
    if state.authenticated.is_some() {
        if !session.plaintext().is_empty() {
            let ingest_started = broker::clock_ns();
            let ingested = driver.ingest(session.plaintext(), now);
            let ingest_finished = broker::clock_ns();
            state
                .timing
                .ingest(ingest_started, ingest_finished, driver.take_ingest_timing());
            let accepted = match ingested {
                Ok(n) => n,
                Err(_) => return Err((SessionExitReason::PlaintextIngest, 0x4000)),
            };
            if let Err(e) = session.consume_plaintext(accepted) {
                return Err((SessionExitReason::PlaintextConsume, tls_result(&e)));
            }
        }
        let tick_started = broker::clock_ns();
        let ticked = driver.tick(now);
        state.timing.tick(tick_started, broker::clock_ns());
        if ticked.is_err() {
            return Err((SessionExitReason::DriverTick, 0x4000));
        }
        if driver.replay_wants_reconnect(state.epoch) {
            return Err((SessionExitReason::ReplayReconnect, 0));
        }
    }
    let egress_started = broker::clock_ns();
    let egress_result = outgoing.service_at(session, driver, broker::clock_ns(), &mut BrokerTcp);
    state.timing.egress(egress_started, broker::clock_ns());
    if let Err(e) = egress_result {
        return Err((SessionExitReason::TlsEgress, domain_result(e)));
    }
    feedback(
        driver,
        ingress,
        Some(outgoing),
        broker::clock_ns(),
        !session.pending_tls().is_empty(),
    );
    state.timing.finish_loop(broker::clock_ns());
    Ok(())
}
