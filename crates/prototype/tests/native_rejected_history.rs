//! Host fixtures exercise the actual Registry and negative-history encoder.
//! Their clock/authority are synthetic and never supply native learning labels.
#[path = "../../../kernel/src/learning_history/rejection.rs"]
mod rejection;

use cyxia_prototype::{
    domains::{Action, Error, ObjectKey, POLICY_NS, WINDOW_NS},
    policy::{
        Clock, ExecutionState, Executor, ModelBinding, Publisher, RegisteredSet, Registry, Snapshot,
    },
    policy_wire::{self, Decision, Envelope, Plan, PlanHeader},
};
use sha2::{Digest, Sha256};

struct FixedClock(u64);
impl Clock for FixedClock {
    fn now_ns(&mut self) -> u64 {
        self.0
    }
}
#[derive(Default)]
struct BusyOwner {
    checks: usize,
    publications: usize,
}
impl Executor for BusyOwner {
    fn authorize_baseline(
        &mut self,
        _: ModelBinding,
        set: &RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        assert_eq!(set.baseline_action(), Some(Action::CpuWeight(1)));
        Ok(())
    }
    fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        self.checks += 1;
        Err(Error::Busy)
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        panic!("rejected before PREPARE")
    }
    fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        panic!("rejected before revalidation")
    }
    fn publish(&mut self, _: &Plan, _: u64, _: u64) -> Result<(), Error> {
        self.publications += 1;
        panic!("rejected before PUBLISH")
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        panic!("nothing was prepared")
    }
}

fn rejected(sequence: u64) -> (rejection::Facts, Vec<u8>) {
    let publisher = Publisher {
        object: ObjectKey {
            id: 2,
            generation: 1,
        },
        controller_epoch: 3,
    };
    let model = ModelBinding {
        generation: 4,
        model_hash: [5; 32],
        schema_hash: [6; 32],
    };
    let target = ObjectKey {
        id: 12,
        generation: 2,
    };
    let snapshot = Snapshot {
        sequence: 7,
        taken_ns: 1_000_000_000,
        ledger_generation: 8,
        core_generation: 9,
    };
    let mut registry = Registry::new(10, publisher, model).unwrap();
    let hash = registry
        .register_baseline(publisher, snapshot, target, model, Action::CpuWeight(1))
        .unwrap();
    let header = PlanHeader {
        plan_seq: sequence,
        base_plan_version: 0,
        active_model_generation: model.generation,
        controller_epoch: publisher.controller_epoch,
        snapshot_seq: snapshot.sequence,
        active_until_local_ns: snapshot.taken_ns + POLICY_NS,
    };
    let decision = Decision {
        action: Action::CpuWeight(1),
        candidate_index: 0,
        envelope: Envelope {
            controller_epoch: publisher.controller_epoch,
            decision_seq: sequence,
            snapshot_seq: snapshot.sequence,
            target,
            ledger_generation: snapshot.ledger_generation,
            core_generation: snapshot.core_generation,
            expires_local_ns: snapshot.taken_ns + WINDOW_NS,
            model_hash: model.model_hash,
            candidate_set_hash: hash,
        },
    };
    let mut wire = vec![0; 384];
    let count = policy_wire::encode_plan(header, &[decision], &mut wire).unwrap();
    wire.truncate(count);
    let received = snapshot.taken_ns + 800;
    let deadline = snapshot.taken_ns + 50_000_000;
    let mut clock = FixedClock(snapshot.taken_ns + 1_000);
    let mut owner = BusyOwner::default();
    let receipt = registry
        .submit_job(publisher, &wire, received, deadline, &mut clock, &mut owner)
        .unwrap();
    assert_eq!(receipt.version, 0);
    assert_eq!(receipt.state(), ExecutionState::Failed(Error::Busy));
    assert_eq!(receipt.published_ns, 0);
    assert_eq!((owner.checks, owner.publications), (1, 0));
    // Registry itself retains this terminal rejection. A retry does not ask
    // the owner to execute it again or turn Busy into a later publication.
    assert_eq!(
        registry.submit_job(publisher, &wire, received, deadline, &mut clock, &mut owner),
        Ok(receipt)
    );
    assert_eq!((owner.checks, owner.publications), (1, 0));
    (
        rejection::Facts {
            receipt,
            snapshot,
            header,
            decision,
            model,
            received_ns: received,
            observed_ns: clock.0,
            wall_deadline_ns: deadline,
            plan_hash: Sha256::digest(&wire).into(),
        },
        wire,
    )
}
fn word(row: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(row[offset..offset + 8].try_into().unwrap())
}

#[test]
fn actual_terminal_registry_rejection_exports_original_plan_without_adoption_flags() {
    let (facts, wire) = rejected(11);
    let mut rows = vec![0xA5; 2 * rejection::SLOT_BYTES];
    let mut used = 0;
    assert_eq!(rejection::append(&mut rows, &mut used, &facts), Ok(true));
    assert_eq!(used, 1);
    let row = &rows[..rejection::SLOT_BYTES];
    assert_eq!(word(row, 0), rejection::FLAG);
    assert_eq!(
        word(row, 0) & (1 | 2 | 4 | 8 | 16 | 32 | 64),
        0,
        "a rejection is neither a proposal, PUBLISH, execution nor baseline adoption"
    );
    assert_eq!(&row[296..304], b"CYREJCT1");
    assert_eq!(
        (word(row, 272), word(row, 280), word(row, 288)),
        (
            facts.receipt.id.boot_epoch,
            facts.receipt.id.controller_epoch,
            facts.receipt.id.plan_seq
        )
    );
    assert_eq!(
        word(row, 152),
        7,
        "retain the original snapshot sequence separately from PlanId"
    );
    assert_eq!(word(row, 312), wire.len() as u64);
    assert_eq!(
        &row[rejection::PLAN_OFFSET..rejection::PLAN_OFFSET + wire.len()],
        wire.as_slice()
    );
    let decoded =
        policy_wire::decode_plan(&row[rejection::PLAN_OFFSET..rejection::PLAN_OFFSET + wire.len()])
            .unwrap();
    assert_eq!(decoded.header, facts.header);
    assert_eq!(decoded.action(0), Some(facts.decision));
    assert_eq!(&row[48..80], &facts.plan_hash);
    assert_eq!((word(row, 320), word(row, 328)), (0, 0));
    assert_eq!(
        (word(row, 336), word(row, 344), word(row, 352)),
        (facts.observed_ns, facts.wall_deadline_ns, facts.received_ns)
    );
    assert_eq!((word(row, 424), word(row, 432)), (3, Error::Busy as u64));
    assert_eq!((word(row, 512), word(row, 520)), (3, Error::Busy as u64));
    assert!(
        row[528..768].iter().all(|v| *v == 0),
        "unused actual Pending slots retained"
    );
    assert!(
        row[208..272].iter().all(|v| *v == 0),
        "no invented model scores"
    );
    assert!(rows[rejection::SLOT_BYTES..].iter().all(|v| *v == 0xA5));
    let saved = rows.clone();
    assert_eq!(rejection::append(&mut rows, &mut used, &facts), Ok(false));
    assert_eq!((used, &rows), (1, &saved));
    let mut changed = facts;
    changed.observed_ns += 1;
    assert_eq!(
        rejection::append(&mut rows, &mut used, &changed),
        Err(Error::Conflict)
    );
    changed = facts;
    changed.receipt.actions[0] = ExecutionState::Failed(Error::Stale);
    assert_eq!(
        rejection::append(&mut rows, &mut used, &changed),
        Err(Error::Conflict)
    );
    assert_eq!((used, &rows), (1, &saved));
}

#[test]
fn pending_unknown_published_and_tampered_receipts_cannot_be_archived_as_rejections() {
    let (facts, _) = rejected(11);
    let mut rows = vec![0xA5; rejection::SLOT_BYTES];
    let saved = rows.clone();
    let mut used = 0;
    for state in [
        ExecutionState::Pending,
        ExecutionState::Unknown,
        ExecutionState::Applied,
    ] {
        let mut changed = facts;
        changed.receipt.actions[0] = state;
        assert_eq!(
            rejection::append(&mut rows, &mut used, &changed),
            Err(Error::Conflict)
        );
    }
    let mut changed = facts;
    changed.receipt.version = 1;
    assert_eq!(
        rejection::append(&mut rows, &mut used, &changed),
        Err(Error::Conflict)
    );
    changed = facts;
    changed.header.base_plan_version = 1;
    assert_eq!(
        rejection::append(&mut rows, &mut used, &changed),
        Err(Error::Conflict)
    );
    changed = facts;
    changed.snapshot.ledger_generation += 1;
    assert_eq!(
        rejection::append(&mut rows, &mut used, &changed),
        Err(Error::Conflict)
    );
    assert_eq!((used, &rows), (0, &saved));
    assert_eq!(rejection::append(&mut rows, &mut used, &facts), Ok(true));
    let saved = rows.clone();
    let (next, _) = rejected(12);
    assert_eq!(
        rejection::append(&mut rows, &mut used, &next),
        Err(Error::Capacity)
    );
    assert_eq!(rejection::append(&mut rows, &mut used, &facts), Ok(false));
    assert_eq!((used, &rows), (1, &saved));
}

#[test]
fn terminal_rejection_uses_reserved_last_slot_without_rewriting_ordinary_rows() {
    let (facts, wire) = rejected(11);
    let mut rows = vec![0xA5; 64 * rejection::SLOT_BYTES];
    // Explicit ordinary-row fixtures: proposal flag 1 is disjoint from the
    // rejection flag. The actual 63-proposal bound is separately exercised
    // by learning_native_history against the production protected history.
    for (index, row) in rows[..63 * rejection::SLOT_BYTES]
        .chunks_exact_mut(rejection::SLOT_BYTES)
        .enumerate()
    {
        row.fill((index as u8).wrapping_mul(17));
        row[..8].copy_from_slice(&1_u64.to_le_bytes());
        row[8..16].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    }
    let ordinary = rows[..63 * rejection::SLOT_BYTES].to_vec();
    let mut used = 63;
    assert_eq!(rejection::append(&mut rows, &mut used, &facts), Ok(true));
    assert_eq!(used, 64);
    assert_eq!(&rows[..63 * rejection::SLOT_BYTES], ordinary.as_slice());
    let last = &rows[63 * rejection::SLOT_BYTES..];
    assert_eq!(word(last, 0), rejection::FLAG);
    assert_eq!((word(last, 320), word(last, 328)), (0, 0));
    assert_eq!((word(last, 424), word(last, 432)), (3, Error::Busy as u64));
    assert_eq!(
        &last[rejection::PLAN_OFFSET..rejection::PLAN_OFFSET + wire.len()],
        wire.as_slice()
    );
    let saved = rows.clone();
    assert_eq!(rejection::append(&mut rows, &mut used, &facts), Ok(false));
    let (next, _) = rejected(12);
    assert_eq!(
        rejection::append(&mut rows, &mut used, &next),
        Err(Error::Capacity)
    );
    assert_eq!((used, &rows), (64, &saved));
}
