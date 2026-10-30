//! TLS-facing admission and bounded transmission adapters. The tests drive real
//! mutual TLS sessions through these same executors and partial-write paths.
use crate::abi::*;
use cyxia_cluster_transport::tls::{Error as TlsError, PLAINTEXT_BUFFER, Session};
use cyxia_prototype::{
    cluster::wire::Header,
    domains::{Action, Error, ObjectKey, PolicyStamp, platform::*},
};
fn ns(ms: u64) -> Result<u64, Error> {
    ms.checked_mul(1_000_000).ok_or(Error::Overflow)
}
pub fn policy_stamp(p: PolicyWire) -> Result<PolicyStamp, Error> {
    if p.version == 0
        || p.controller_epoch == 0
        || p.plan_seq == 0
        || p.action_index > u16::MAX as u64
    {
        return Err(Error::Format);
    }
    Ok(PolicyStamp {
        version: p.version,
        snapshot_ns: p.snapshot_ns,
        installed_until_ns: p.installed_until_ns,
    })
}
/// Placement is an invocation, not an installed setting. Its immutable wire
/// lease is zero; admission freshness and exact retries still use the stamp.
pub fn accept_placement_policy(
    previous: PolicyWire,
    next: PolicyWire,
    now_ns: u64,
) -> Result<PolicyStamp, Error> {
    let value = u16::try_from(next.value).map_err(|_| Error::Range)?;
    if value > 2 {
        return Err(Error::Range);
    }
    if previous.version == next.version && previous != next {
        return Err(Error::Conflict);
    }
    let old = if previous.version == 0 {
        PolicyStamp::default()
    } else {
        policy_stamp(previous)?
    };
    let stamp = policy_stamp(next)?;
    old.accepts_action(Action::Placement(value), stamp, now_ns)?;
    Ok(stamp)
}
pub fn receipt(
    p: PolicyWire,
    outcome: u64,
    actual: u64,
    key: Option<ObjectKey>,
) -> PolicyReceiptWire {
    PolicyReceiptWire {
        version: p.version,
        actual,
        outcome,
        plan_seq: p.plan_seq,
        controller_epoch: p.controller_epoch,
        action_index: p.action_index,
        request_id: key.map_or(0, |k| k.id),
        request_generation: key.map_or(0, |k| k.generation),
    }
}
pub struct TlsIngress {
    pub security: SecurityIngress,
    policy: PolicyWire,
    pub receipt: PolicyReceiptWire,
    window_ms: u64,
    previous: [u64; 3],
    observation: Option<[u64; 4]>,
}
impl TlsIngress {
    pub fn new(now_ms: u64) -> Result<Self, Error> {
        Ok(Self {
            security: SecurityIngress::new(ns(now_ms)?),
            policy: PolicyWire::default(),
            receipt: PolicyReceiptWire::default(),
            window_ms: now_ms,
            previous: [0; 3],
            observation: None,
        })
    }
    pub fn install(&mut self, p: PolicyWire, now_ms: u64) -> Result<(), Error> {
        self.install_at(p, ns(now_ms)?)
    }
    pub fn install_at(&mut self, p: PolicyWire, now: u64) -> Result<(), Error> {
        if p.version == 0 {
            return Ok(());
        }
        if p.version == self.policy.version {
            return if p == self.policy {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let result = (|| {
            self.security.install(
                policy_stamp(p)?,
                u16::try_from(p.value).map_err(|_| Error::Range)?,
                now,
            )
        })();
        self.receipt = receipt(
            p,
            if result.is_ok() {
                DOMAIN_PENDING
            } else {
                DOMAIN_REJECTED
            },
            p.value,
            Some(ObjectKey {
                id: UNAUTH_SERVICE_ID,
                generation: 1,
            }),
        );
        if result.is_ok() {
            self.policy = p;
        }
        result
    }
    pub fn begin<T>(
        &mut self,
        ip: [u8; 4],
        now_ms: u64,
        construct: impl FnOnce() -> Result<T, Error>,
    ) -> Result<(AuthTicket, T), Error> {
        self.begin_at(ip, ns(now_ms)?, construct)
    }
    pub fn begin_at<T>(
        &mut self,
        ip: [u8; 4],
        now: u64,
        construct: impl FnOnce() -> Result<T, Error>,
    ) -> Result<(AuthTicket, T), Error> {
        let admitted = self.security.begin(ip, now);
        if self.policy.version != 0
            && self.receipt.version == self.policy.version
            && self.receipt.outcome == DOMAIN_PENDING
        {
            self.receipt = receipt(
                self.policy,
                if policy_stamp(self.policy)?.live(now) {
                    DOMAIN_APPLIED
                } else {
                    DOMAIN_EXPIRED
                },
                u64::from(self.security.effective_rate(now)?),
                Some(ObjectKey {
                    id: UNAUTH_SERVICE_ID,
                    generation: 1,
                }),
            );
        }
        let ticket = admitted?;
        match construct() {
            Ok(value) => Ok((ticket, value)),
            Err(error) => {
                self.security.finish(ticket, false, now)?;
                Err(error)
            }
        }
    }
    pub fn finish(&mut self, ticket: AuthTicket, valid: bool, now_ms: u64) -> Result<(), Error> {
        self.finish_at(ticket, valid, ns(now_ms)?)
    }
    pub fn finish_at(&mut self, ticket: AuthTicket, valid: bool, now: u64) -> Result<(), Error> {
        self.security.finish(ticket, valid, now)
    }
    pub fn enter_authenticated_at<T>(
        &mut self,
        session: ObjectKey,
        now: u64,
        start: impl FnOnce() -> Result<T, Error>,
    ) -> Result<(AuthTicket, T), Error> {
        self.security.authorize_recovery_session(session)?;
        let ticket = self.security.begin_recovery(session, now)?;
        match start() {
            Ok(value) => Ok((ticket, value)),
            Err(e) => {
                self.security.revoke_recovery_session(session)?;
                self.security.finish(ticket, false, now)?;
                Err(e)
            }
        }
    }
    pub fn leave_authenticated_at(
        &mut self,
        session: ObjectKey,
        ticket: AuthTicket,
        now: u64,
    ) -> Result<(), Error> {
        self.security.revoke_recovery_session(session)?;
        self.security.finish(ticket, true, now)
    }
    pub fn observe(&mut self, now_ms: u64) -> Result<Option<[u64; 4]>, Error> {
        if self.receipt.outcome == DOMAIN_PENDING
            && self.policy.version != 0
            && ns(now_ms)? >= self.policy.installed_until_ns
        {
            self.receipt = receipt(
                self.policy,
                DOMAIN_EXPIRED,
                16,
                Some(ObjectKey {
                    id: UNAUTH_SERVICE_ID,
                    generation: 1,
                }),
            );
        }
        let elapsed = now_ms.checked_sub(self.window_ms).ok_or(Error::Stale)?;
        let counters = self.security.counters;
        if elapsed >= 1000 {
            let values = [counters.attempts, counters.failures, counters.rejected];
            let rates: [u64; 3] = core::array::from_fn(|i| {
                ((u128::from(values[i].saturating_sub(self.previous[i])) * 1000)
                    / u128::from(elapsed))
                .min(u128::from(u64::MAX)) as u64
            });
            self.observation = Some([
                rates[0],
                rates[1],
                self.security.active().0 as u64,
                rates[2],
            ]);
            self.previous = values;
            self.window_ms = now_ms;
        }
        Ok(self.observation.map(|mut fields| {
            fields[2] = self.security.active().0 as u64;
            fields
        }))
    }
}

pub trait RpcOutbox {
    fn outgoing(&self) -> &[u8];
    fn consume(&mut self, bytes: usize);
}
pub trait TlsTransport {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Error>;
    fn write_reserved(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.write(bytes)
    }
}
pub fn reserved_rpc(kind: u16) -> bool {
    // Membership/heartbeat, durable result acknowledgement/closure, and
    // reconciliation have bounded progress credit. Bulk quotation/preparation
    // responses do not acquire that credit merely by setting the response bit.
    matches!(kind & 0x7fff, 1..=6 | 20..=22 | 32..=33)
}
pub struct TlsEgress {
    scheduler: NetworkScheduler,
    connection: ObjectKey,
    policy: PolicyWire,
    pub receipt: PolicyReceiptWire,
    frame_remaining: usize,
    frame_reserved: bool,
    encrypted_reserved: bool,
    owned_reserved: Option<bool>,
    last_round: TxRound,
}
impl TlsEgress {
    pub fn new(epoch: u64) -> Result<Self, Error> {
        let connection = ObjectKey {
            id: 1,
            generation: epoch,
        };
        let mut scheduler = NetworkScheduler::new();
        scheduler.register(connection)?;
        Ok(Self {
            scheduler,
            connection,
            policy: PolicyWire::default(),
            receipt: PolicyReceiptWire::default(),
            frame_remaining: 0,
            frame_reserved: true,
            encrypted_reserved: true,
            owned_reserved: None,
            last_round: TxRound::default(),
        })
    }
    pub fn install(&mut self, p: PolicyWire, now_ms: u64) -> Result<(), Error> {
        self.install_at(p, ns(now_ms)?)
    }
    pub fn install_at(&mut self, p: PolicyWire, now: u64) -> Result<(), Error> {
        if p.version == 0 {
            return Ok(());
        }
        if p.version == self.policy.version {
            return if p == self.policy {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let result = (|| {
            self.scheduler.install(
                policy_stamp(p)?,
                u8::try_from(p.value).map_err(|_| Error::Range)?,
                now,
            )
        })();
        self.receipt = receipt(
            p,
            if result.is_ok() {
                DOMAIN_PENDING
            } else {
                DOMAIN_REJECTED
            },
            p.value,
            Some(ObjectKey {
                id: TX_SERVICE_ID,
                generation: 1,
            }),
        );
        if result.is_ok() {
            self.policy = p;
        }
        result
    }
    pub fn service<O: RpcOutbox, T: TlsTransport>(
        &mut self,
        session: &mut Session<'_>,
        outbox: &mut O,
        now_ms: u64,
        transport: &mut T,
    ) -> Result<TxRound, Error> {
        self.service_at(session, outbox, ns(now_ms)?, transport)
    }
    pub fn service_at<O: RpcOutbox, T: TlsTransport>(
        &mut self,
        session: &mut Session<'_>,
        outbox: &mut O,
        now: u64,
        transport: &mut T,
    ) -> Result<TxRound, Error> {
        if !outbox.outgoing().is_empty()
            || !session.pending_tls().is_empty()
            || session.has_pending_plaintext()
        {
            self.scheduler.mark_ready(self.connection)?;
        }
        let mut turn = SendTurn {
            session,
            outbox,
            transport,
            now_ms: now / 1_000_000,
            frame_remaining: &mut self.frame_remaining,
            frame_reserved: &mut self.frame_reserved,
            encrypted_reserved: &mut self.encrypted_reserved,
            owned_reserved: &mut self.owned_reserved,
        };
        let round = self.scheduler.service(now, &mut turn)?;
        self.last_round = round;
        if self.policy.version != 0
            && self.receipt.version == self.policy.version
            && self.receipt.outcome == DOMAIN_PENDING
        {
            let live = policy_stamp(self.policy)?.live(now);
            if round.ordinary != 0 || !live {
                self.receipt = receipt(
                    self.policy,
                    if live { DOMAIN_APPLIED } else { DOMAIN_EXPIRED },
                    if live { self.policy.value } else { 4 },
                    Some(ObjectKey {
                        id: TX_SERVICE_ID,
                        generation: 1,
                    }),
                );
            }
        }
        Ok(round)
    }
    pub fn counts(&self) -> (u64, u64) {
        (self.scheduler.sent, self.scheduler.reserved_sent)
    }
    pub fn expire_at(&mut self, now: u64) {
        if self.policy.version != 0
            && self.receipt.outcome == DOMAIN_PENDING
            && now >= self.policy.installed_until_ns
        {
            self.receipt = receipt(
                self.policy,
                DOMAIN_EXPIRED,
                4,
                Some(ObjectKey {
                    id: TX_SERVICE_ID,
                    generation: 1,
                }),
            );
        }
    }
    pub fn last_round(&self) -> TxRound {
        self.last_round
    }
    pub fn reset_session(&mut self) {
        self.frame_remaining = 0;
        self.frame_reserved = true;
        self.encrypted_reserved = true;
        self.owned_reserved = None;
    }
    /// The caller has closed and dropped the previous TLS/TCP generation.
    pub fn begin_session(&mut self, epoch: u64) -> Result<(), Error> {
        if epoch == 0 {
            return Err(Error::Format);
        }
        self.scheduler.retire_closed(self.connection)?;
        self.connection = ObjectKey {
            id: 1,
            generation: epoch,
        };
        self.scheduler.register(self.connection)?;
        self.reset_session();
        Ok(())
    }
}
struct SendTurn<'s, 'b, O, T> {
    session: &'s mut Session<'b>,
    outbox: &'s mut O,
    transport: &'s mut T,
    now_ms: u64,
    frame_remaining: &'s mut usize,
    frame_reserved: &'s mut bool,
    encrypted_reserved: &'s mut bool,
    owned_reserved: &'s mut Option<bool>,
}
impl<O: RpcOutbox, T: TlsTransport> SendTurn<'_, '_, O, T> {
    fn head(&mut self) -> Result<Option<bool>, Error> {
        if self.outbox.outgoing().is_empty() {
            return Ok(None);
        }
        if *self.frame_remaining == 0 {
            let bytes = self.outbox.outgoing();
            if bytes.len() < 96 {
                return Err(Error::Format);
            }
            let header = Header::decode(&bytes[..96]).map_err(|_| Error::Format)?;
            *self.frame_remaining = 96 + header.body_len as usize;
            *self.frame_reserved = reserved_rpc(header.kind);
        }
        Ok(Some(*self.frame_reserved))
    }
    fn send(&mut self, reserved: bool) -> Result<TxStep, Error> {
        if self.session.pending_tls().is_empty() && self.session.authenticated_peer().is_some() {
            if !self.session.has_pending_plaintext() {
                if self.head()? != Some(reserved) {
                    return Ok(TxStep {
                        sent: false,
                        still_ready: !self.outbox.outgoing().is_empty(),
                    });
                }
                let count = self
                    .outbox
                    .outgoing()
                    .len()
                    .min(*self.frame_remaining)
                    .min(PLAINTEXT_BUFFER);
                match self
                    .session
                    .send_plaintext(&self.outbox.outgoing()[..count])
                {
                    Ok(()) => {
                        self.outbox.consume(count);
                        *self.frame_remaining -= count;
                        *self.owned_reserved = Some(reserved);
                    }
                    Err(TlsError::WouldBlock) => {
                        return Ok(TxStep {
                            sent: false,
                            still_ready: true,
                        });
                    }
                    Err(_) => return Err(Error::Io),
                }
            }
            self.session.pump(self.now_ms).map_err(|_| Error::Io)?;
        }
        if !self.session.pending_tls().is_empty() {
            if self.session.has_pending_plaintext() {
                // Protocol output precedes the accepted application prefix.
                *self.encrypted_reserved = true;
            } else if let Some(class) = self.owned_reserved.take() {
                *self.encrypted_reserved = class;
            }
        }
        if self.session.pending_tls().is_empty() || *self.encrypted_reserved != reserved {
            return Ok(TxStep {
                sent: false,
                still_ready: !self.outbox.outgoing().is_empty()
                    || !self.session.pending_tls().is_empty()
                    || self.session.has_pending_plaintext(),
            });
        }
        let count = self.session.pending_tls().len().min(PAYLOAD);
        let written = if reserved {
            self.transport
                .write_reserved(&self.session.pending_tls()[..count])
        } else {
            self.transport.write(&self.session.pending_tls()[..count])
        };
        let sent = match written {
            Ok(n) if n <= count => n,
            Ok(_) => return Err(Error::Range),
            Err(Error::Again) => 0,
            Err(e) => return Err(e),
        };
        self.session.consume_tls(sent).map_err(|_| Error::Io)?;
        if self.session.pending_tls().is_empty() {
            *self.encrypted_reserved = true;
        }
        Ok(TxStep {
            sent: sent != 0,
            still_ready: !self.session.pending_tls().is_empty()
                || !self.outbox.outgoing().is_empty()
                || self.session.has_pending_plaintext(),
        })
    }
}
impl<O: RpcOutbox, T: TlsTransport> NetworkTx for SendTurn<'_, '_, O, T> {
    fn reserved(&mut self) -> Result<TxStep, Error> {
        self.send(true)
    }
    fn send_ready(&mut self, _: ObjectKey) -> Result<TxStep, Error> {
        self.send(false)
    }
}
