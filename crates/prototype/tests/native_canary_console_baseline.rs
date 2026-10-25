//! Host regression of the production D15 registration, Governance and real
//! ConsolePump executor. Clock, UART and protected callback ownership are
//! explicit fixtures; this does not claim native A16 execution evidence.
#[path = "../../../kernel/src/domain_services/console_baseline.rs"]
mod console_baseline;
#[path = "support/learning.rs"]
mod support;

use cyxia_prototype::{
    domains::{
        Action, ApplyId, Error as DomainError, ObjectKey, PolicyStamp,
        maintenance::{ConsoleHardware, ConsolePump},
    },
    features::RawFeatures,
    learning::{Error, Family, governance::*, reward::WorkRequest},
    policy::{Candidate, CandidateSet, ExecutionState, ModelBinding, Snapshot},
};
use std::cell::{Cell, RefCell};

const KEY: ObjectKey = ObjectKey {
    id: 0x0900_0000,
    generation: 11,
};

struct Uart {
    now: u64,
    writes: Vec<u8>,
    fail: bool,
}
impl ConsoleHardware for Uart {
    fn try_write(&mut self, byte: u8) -> Result<bool, DomainError> {
        if self.fail {
            return Err(DomainError::Io);
        }
        self.writes.push(byte);
        self.now += 100;
        Ok(true)
    }
    fn now_ns(&mut self) -> u64 {
        self.now
    }
}

struct Owner {
    pump: RefCell<ConsolePump>,
    receipt: Cell<Option<CanaryReceipt>>,
    restoration: Cell<Option<(RestorationRequest, RestorationReceipt)>>,
}
impl Owner {
    fn new() -> Self {
        Self {
            pump: RefCell::new(ConsolePump::new()),
            receipt: Cell::new(None),
            restoration: Cell::new(None),
        }
    }
    fn registration(&self) -> TargetRegistration {
        console_baseline::registration(KEY, self.pump.borrow().poisoned()).unwrap()
    }
    fn write_batch(&self, stamp: PolicyStamp, chars: u16, at: u64) -> u64 {
        self.legal_console(KEY, Action::ConsoleBatch(chars), at)
            .unwrap();
        let mut pump = self.pump.borrow_mut();
        pump.install(stamp, chars, at).unwrap();
        pump.enqueue(&[b'x'; 128], at).unwrap();
        let mut uart = Uart {
            now: at,
            writes: Vec::new(),
            fail: false,
        };
        let result = pump.pump(at, &mut uart).unwrap();
        assert_eq!(result.policy_version, stamp.version);
        assert_eq!(result.chars, chars);
        assert_eq!(uart.writes.len(), usize::from(chars));
        uart.now
    }
    fn execute(&self, submission: Submission, at: u64) -> CanaryReceipt {
        let Action::ConsoleBatch(chars) = submission.action else {
            panic!("D15 action")
        };
        let finished_ns = self.write_batch(submission.stamp, chars, at);
        let receipt = CanaryReceipt {
            apply: submission.apply,
            plan_version: submission.stamp.version,
            executor_generation: KEY.generation,
            model: submission.model,
            state: ExecutionState::Applied,
            actual: Some(submission.action),
            started_ns: at,
            finished_ns,
            installed_until_ns: submission.stamp.installed_until_ns,
            evidence_hash: [3; 32],
        };
        self.receipt.set(Some(receipt));
        receipt
    }
    fn restore(&self, request: RestorationRequest, at: u64) -> RestorationReceipt {
        assert_eq!(request.target, self.registration());
        let Action::ConsoleBatch(chars) = request.target.baseline else {
            panic!("D15 baseline")
        };
        let stamp = PolicyStamp::new(3, at, at).unwrap();
        self.write_batch(stamp, chars, at);
        let receipt = RestorationReceipt {
            boot_epoch: request.boot_epoch,
            restoration_id: request.id,
            target: request.target.key,
            actual: request.target.baseline,
            actual_version: stamp.version,
            executor_generation: KEY.generation,
            state: ExecutionState::Applied,
            evidence_hash: [4; 32],
        };
        self.restoration.set(Some((request, receipt)));
        receipt
    }
}
impl ControlAuthority for Owner {
    fn authorize(&self, _: Role, cpu: u16, generation: u64, bytes: u32) -> Result<(), Error> {
        if cpu == 1 && generation == 1 && bytes <= 1024 * 1024 {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
}
impl GovernanceAuthority for Owner {
    fn registered_noncritical_console(&self, target: TargetRegistration) -> Result<(), Error> {
        if target == self.registration() {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn legal_console(&self, target: ObjectKey, action: Action, _: u64) -> Result<(), Error> {
        if target != KEY
            || self.pump.borrow().poisoned()
            || !matches!(action, Action::ConsoleBatch(_))
        {
            return Err(Error::Safety);
        }
        action.validate().map_err(|_| Error::Safety)
    }
    fn verify_receipt(&self, receipt: &CanaryReceipt) -> Result<(), Error> {
        if self.receipt.get() == Some(*receipt) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn verify_measurement(
        &self,
        _: CanaryPermit,
        _: u16,
        _: &[WorkRequest],
        _: &[WorkRequest],
        _: [u8; 32],
    ) -> Result<(), Error> {
        Err(Error::DataIncomplete)
    }
    fn authorize_extension(
        &self,
        _: [u8; 32],
        _: CanaryPermit,
        _: u64,
        _: u16,
    ) -> Result<(), Error> {
        Err(Error::Evidence)
    }
    fn verify_restoration(
        &self,
        request: RestorationRequest,
        receipt: &RestorationReceipt,
    ) -> Result<(), Error> {
        if self.restoration.get() == Some((request, *receipt)) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
}

fn candidates(actions: &[Action], model: ModelBinding, at: u64) -> CandidateSet {
    let choices: Vec<_> = actions
        .iter()
        .copied()
        .map(|action| Candidate {
            action,
            features: RawFeatures {
                control_capacity: Some(1000),
                ..RawFeatures::default()
            },
        })
        .collect();
    CandidateSet::new(
        Snapshot {
            sequence: 1,
            taken_ns: at,
            ledger_generation: 1,
            core_generation: 1,
        },
        KEY,
        model,
        &choices,
        Some(actions[0]),
    )
    .unwrap()
}
fn shadow(g: &mut Governance<'_, '_>, gate: &CommitGate, budget: &mut ExtraBudget, owner: &Owner) {
    for window in 0..10 {
        let families: &[Family] = if window == 0 {
            &support::FAMILIES
        } else {
            &support::FAMILIES[..1]
        };
        for (index, family) in families.iter().enumerate() {
            let now = window * WINDOW_NS + index as u64 * 2_000;
            let credit = budget
                .reserve(Role::Shadow, 1, 1, 1024 * 1024, now, 2_000, owner)
                .unwrap();
            let proof = g
                .score_shadow(
                    &candidates(&support::choices(*family), gate.active(), now),
                    &credit,
                )
                .unwrap();
            let cost = budget.settle(credit, 1_000, now + 1_000).unwrap();
            g.record_shadow(proof, cost).unwrap();
        }
        g.close_shadow_window((window + 1) * WINDOW_NS).unwrap();
    }
    assert_eq!(g.stage(), Stage::Ready);
}
fn publish(
    g: &mut Governance<'_, '_>,
    gate: &mut CommitGate,
    budget: &mut ExtraBudget,
    owner: &Owner,
    at: u64,
) -> Submission {
    let model = ModelBinding {
        model_hash: gate.permit().unwrap().candidate_hash,
        ..gate.active()
    };
    let credit = budget
        .reserve(Role::Canary, 1, 1, 1024 * 1024, at, 2_000, owner)
        .unwrap();
    let proof = g
        .score_canary(&candidates(&[Action::ConsoleBatch(64)], model, at), &credit)
        .unwrap();
    let cost = budget.settle(credit, 1_000, at + 1_000).unwrap();
    g.publish(
        gate,
        at + 1_000,
        proof,
        cost,
        ApplyId {
            boot_epoch: KEY.generation,
            controller_epoch: 3,
            plan_seq: 2,
            action_index: 0,
            target: KEY,
        },
        PolicyStamp::new(2, at, at + 1_000).unwrap(),
        owner,
    )
    .unwrap();
    g.submissions().next().unwrap()
}

fn exercise(expiry: bool) {
    support::with_candidate(|candidate, old| {
        let active = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let mut gate = CommitGate::new(KEY.generation, active).unwrap();
        let mut g = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        let owner = Owner::new();
        shadow(&mut g, &gate, &mut budget, &owner);

        // The production registration must not snapshot this still-live AI64
        // lease as the baseline, even after real UART writes prove it applied.
        let old_at = 10 * WINDOW_NS;
        let old_stamp = PolicyStamp::new(1, old_at, old_at).unwrap();
        owner.write_batch(old_stamp, 64, old_at);
        let registration_at = old_at + 10_000;
        assert!(old_stamp.live(registration_at));
        assert_eq!(owner.pump.borrow().current(registration_at), 64);
        let target = owner.registration();
        assert_eq!(target.key, KEY);
        assert_eq!(target.baseline, Action::ConsoleBatch(8));
        let permit = g
            .begin_canary(&mut gate, target, registration_at, &owner)
            .unwrap();
        let at = if expiry {
            permit.expires_ns - 10_000_000
        } else {
            permit.start_ns + 1_000
        };
        let submitted = publish(&mut g, &mut gate, &mut budget, &owner, at);

        let restoration_at = if expiry {
            let receipt = owner.execute(submitted, at + 2_000);
            g.reconcile(&mut gate, receipt, &owner).unwrap();
            g.tick(&mut gate, permit.expires_ns);
            assert_eq!(g.stage(), Stage::Frozen);
            assert_eq!(gate.permit(), None);
            assert_eq!(gate.closing(), Some(permit));
            // No measurements authorize promotion; closing expiry creates
            // the same ordinary restoration obligation without renewing TTL.
            let deadline = permit.expires_ns + CLOSING_NS + 1;
            g.tick(&mut gate, deadline);
            deadline + 1_000
        } else {
            let unknown = CanaryReceipt {
                apply: submitted.apply,
                plan_version: submitted.stamp.version,
                executor_generation: KEY.generation,
                model: submitted.model,
                state: ExecutionState::Unknown,
                actual: None,
                started_ns: at + 2_000,
                finished_ns: at + 2_000,
                installed_until_ns: submitted.stamp.installed_until_ns,
                evidence_hash: [3; 32],
            };
            owner.receipt.set(Some(unknown));
            g.reconcile(&mut gate, unknown, &owner).unwrap();
            g.abort(&mut gate, Error::Validation);
            let request = gate.restoration_request().unwrap();
            let premature = RestorationReceipt {
                boot_epoch: request.boot_epoch,
                restoration_id: request.id,
                target: KEY,
                actual: Action::ConsoleBatch(8),
                actual_version: 3,
                executor_generation: KEY.generation,
                state: ExecutionState::Applied,
                evidence_hash: [4; 32],
            };
            assert_eq!(
                g.restored(&mut gate, premature, &owner),
                Err(Error::Unknown)
            );
            assert_eq!(gate.restoration_request(), Some(request));
            // Only the exact terminal receipt can end the old obligation.
            let receipt = owner.execute(submitted, at + 3_000);
            g.reconcile(&mut gate, receipt, &owner).unwrap();
            at + 20_000
        };

        assert_eq!(g.stage(), Stage::Restoring);
        assert_eq!(gate.active(), active);
        assert_eq!(gate.permit(), None);
        assert!(submitted.stamp.live(restoration_at));
        assert_eq!(owner.pump.borrow().current(restoration_at), 64);
        let request = gate.restoration_request().unwrap();
        assert_eq!(request.target.baseline, Action::ConsoleBatch(8));
        assert_eq!(
            gate.check_active_publication(active, KEY),
            Err(Error::State)
        );
        let receipt = owner.restore(request, restoration_at);
        assert_eq!(receipt.actual, Action::ConsoleBatch(8));
        let mut wrong = receipt;
        wrong.restoration_id += 1;
        assert_eq!(g.restored(&mut gate, wrong, &owner), Err(Error::Evidence));
        assert_eq!(gate.restoration_request(), Some(request));
        g.restored(&mut gate, receipt, &owner).unwrap();
        assert_eq!(g.stage(), Stage::Rejected);
        assert_eq!(owner.pump.borrow().current(restoration_at + 1_000), 8);
        assert_eq!(gate.restoration_pending(), None);
        assert_eq!(gate.active(), active);
    });
}

#[test]
fn failed_canary_restores_eight_after_unknown_work_closes_despite_live_active_sixty_four() {
    exercise(false);
}
#[test]
fn expired_canary_restores_eight_while_its_sixty_four_lease_is_still_live() {
    exercise(true);
}
#[test]
fn deterministic_registration_keeps_poisoned_output_isolated() {
    let mut pump = ConsolePump::new();
    pump.enqueue(b"x", 0).unwrap();
    assert_eq!(
        pump.pump(
            0,
            &mut Uart {
                now: 0,
                writes: Vec::new(),
                fail: true
            }
        ),
        Err(DomainError::Io)
    );
    assert!(pump.poisoned());
    assert_eq!(
        console_baseline::registration(KEY, pump.poisoned()),
        Err(DomainError::Io)
    );
}
