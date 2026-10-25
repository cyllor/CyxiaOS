//! Protected custody of an asynchronous real quote-owner stop. The request's
//! first snapshot/deadline never move while EL0 is busy, and no elapsed-time
//! inference is accepted as a stop receipt.
use super::abi::{self, QuoteStopReceiptWire, QuoteStopWire};
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    policy::Snapshot,
};

const HISTORY: usize = 64;
pub(super) const TARGET: ObjectKey = ObjectKey {
    id: abi::OFFER_SERVICE_ID,
    generation: 1,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub boot: u64,
    pub replay: u64,
    pub owner: ObjectKey,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub command: QuoteStopWire,
    pub snapshot: Snapshot,
    pub accepted_ns: u64,
    pub receipt: Option<QuoteStopReceiptWire>,
}
pub(crate) struct Journal<const N: usize = HISTORY> {
    records: [Option<Record>; N],
    used: usize,
    delivered: Option<usize>,
}
impl<const N: usize> Journal<N> {
    pub(crate) const fn new() -> Self {
        Self {
            records: [None; N],
            used: 0,
            delivered: None,
        }
    }
    fn validate_identity(id: Identity, snapshot: Snapshot, now: u64) -> Result<(), Error> {
        if id.boot == 0
            || id.replay == 0
            || id.owner.id == 0
            || id.owner.generation == 0
            || snapshot.sequence == 0
            || snapshot.core_generation == 0
            || snapshot.ledger_generation == 0
            || snapshot.taken_ns > now
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Absence is conclusive only while no different command still owns the
    /// outbox. Retained requests count as custody before EL0 has acknowledged
    /// them; neither elapsed time nor a failed receipt erases that fact.
    pub(crate) fn custody(
        &self,
        id: Identity,
        snapshot: Snapshot,
        now: u64,
    ) -> Result<bool, Error> {
        Self::validate_identity(id, snapshot, now)?;
        if let Some(old) = self.records[..self.used].iter().flatten().find(|r| {
            r.command.boot_epoch == id.boot
                && r.command.replay_id == id.replay
                && r.command.owner_id == id.owner.id
                && r.command.owner_generation == id.owner.generation
                && r.snapshot.sequence == snapshot.sequence
        }) {
            return if old.snapshot == snapshot {
                Ok(true)
            } else {
                Err(Error::Conflict)
            };
        }
        if self
            .delivered
            .and_then(|i| self.records[i])
            .is_some_and(|r| r.receipt.is_none())
        {
            return Err(Error::Busy);
        }
        Ok(false)
    }
    pub(crate) fn request(
        &mut self,
        id: Identity,
        snapshot: Snapshot,
        now: u64,
    ) -> Result<Record, Error> {
        Self::validate_identity(id, snapshot, now)?;
        if let Some(old) = self.records[..self.used].iter().flatten().find(|r| {
            r.command.boot_epoch == id.boot
                && r.command.replay_id == id.replay
                && r.command.owner_id == id.owner.id
                && r.command.owner_generation == id.owner.generation
                && r.snapshot.sequence == snapshot.sequence
        }) {
            return if old.snapshot == snapshot {
                Ok(*old)
            } else {
                Err(Error::Conflict)
            };
        }
        if self
            .delivered
            .and_then(|i| self.records[i])
            .is_some_and(|r| r.receipt.is_none())
        {
            return Err(Error::Busy);
        }
        if self.used == N {
            return Err(Error::Capacity);
        }
        let command = QuoteStopWire {
            boot_epoch: id.boot,
            replay_id: id.replay,
            owner_id: id.owner.id,
            owner_generation: id.owner.generation,
            sequence: (1u64 << 63) | self.used as u64 + 1,
            issued_ns: snapshot.taken_ns,
        };
        let record = Record {
            command,
            snapshot,
            accepted_ns: now,
            receipt: None,
        };
        self.records[self.used] = Some(record);
        self.delivered = Some(self.used);
        self.used += 1;
        Ok(record)
    }
    pub(crate) fn pending(&self, boot: u64) -> QuoteStopWire {
        self.delivered
            .and_then(|i| self.records[i])
            .filter(|r| r.command.boot_epoch == boot)
            .map_or(QuoteStopWire::EMPTY, |r| r.command)
    }
    pub(crate) fn observe(&mut self, receipt: QuoteStopReceiptWire, now: u64) -> Result<(), Error> {
        let row = self.records[..self.used]
            .iter_mut()
            .flatten()
            .find(|r| r.command == receipt.command)
            .ok_or(Error::Stale)?;
        if let Some(old) = row.receipt {
            return if old == receipt {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if !matches!(receipt.outcome, abi::DOMAIN_APPLIED | abi::DOMAIN_REJECTED)
            || receipt.started_ns < row.accepted_ns
            || receipt.finished_ns < receipt.started_ns
            || receipt.finished_ns > now
        {
            return Err(Error::Again);
        }
        row.receipt = Some(receipt);
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
mod native {
    use super::*;
    use crate::domain_control::replay::{Receipt, Token};
    use core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, Ordering},
    };
    use cyxia_prototype::{
        domains::{Action, ApplyId, PolicyStamp},
        policy::ExecutionState,
    };
    struct Cell(UnsafeCell<Journal>);
    unsafe impl Sync for Cell {}
    static JOURNAL: Cell = Cell(UnsafeCell::new(Journal::new()));
    static GATE: AtomicBool = AtomicBool::new(false);
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            GATE.store(false, Ordering::Release);
        }
    }
    fn with<R>(f: impl FnOnce(&mut Journal) -> Result<R, Error>) -> Result<R, Error> {
        GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        let _guard = Guard;
        f(unsafe { &mut *JOURNAL.0.get() })
    }
    pub fn input(boot: u64) -> QuoteStopWire {
        super::super::owner();
        with(|s| Ok(s.pending(boot))).unwrap_or(QuoteStopWire::EMPTY)
    }
    pub fn observe(receipt: QuoteStopReceiptWire) {
        super::super::owner();
        let _ = with(|s| s.observe(receipt, crate::domain_platform::now_ns()));
    }
    fn authorize_turn() -> Result<(), Error> {
        match cyxia_arch_aarch64::cpu::slot() {
            0 => crate::domain_tasks::authorize_service_turn(),
            1 => crate::smp::prototype_runtime::authorize_learning_turn(),
            _ => Err(Error::Auth),
        }
    }
    /// Called by the local root's no-publication gate while it already holds
    /// the root lock. Only the exact journal can prove this command was never
    /// issued; this read must not re-enter root or infer completion from time.
    pub fn baseline_stop_custody(
        token: Token,
        target: ObjectKey,
        snapshot: Snapshot,
    ) -> Result<bool, Error> {
        if target != TARGET || token.owner != crate::learning_workload::OWNER {
            return Err(Error::Auth);
        }
        authorize_turn()?;
        with(|s| {
            s.custody(
                Identity {
                    boot: token.boot_epoch,
                    replay: token.id,
                    owner: token.owner,
                },
                snapshot,
                crate::domain_platform::now_ns(),
            )
        })
    }
    /// Registered root-only callback. CPU identity alone is insufficient: the
    /// invocation must own an actual service or optional control credit.
    pub fn baseline_stop_quotes(
        token: Token,
        target: ObjectKey,
        snapshot: Snapshot,
    ) -> Result<Receipt, Error> {
        if target != TARGET
            || token.owner != crate::learning_workload::OWNER
                && !crate::peer_replay::fixture_stop_authorized(token)
        {
            return Err(Error::Auth);
        }
        authorize_turn()?;
        let row = with(|s| {
            s.request(
                Identity {
                    boot: token.boot_epoch,
                    replay: token.id,
                    owner: token.owner,
                },
                snapshot,
                crate::domain_platform::now_ns(),
            )
        })?;
        let actual = row.receipt.ok_or(Error::Again)?;
        if actual.outcome != abi::DOMAIN_APPLIED {
            return Err(Error::Again);
        }
        Ok(Receipt {
            action: Action::OfferCpu(0),
            apply: ApplyId {
                boot_epoch: token.boot_epoch,
                controller_epoch: token.id,
                plan_seq: row.command.sequence,
                action_index: 0,
                target,
            },
            stamp: PolicyStamp {
                version: row.command.sequence,
                snapshot_ns: snapshot.taken_ns,
                installed_until_ns: 0,
            },
            snapshot,
            state: ExecutionState::Applied,
            executor_generation: target.generation,
            issued_ns: snapshot.taken_ns,
            accepted_ns: row.accepted_ns,
            started_ns: Some(actual.started_ns),
            observed_ns: actual.finished_ns,
            approved_deadline_ns: row
                .accepted_ns
                .checked_add(50_000_000)
                .ok_or(Error::Overflow)?,
        })
    }
}
#[cfg(target_arch = "aarch64")]
pub use native::{baseline_stop_custody, baseline_stop_quotes, input, observe};
