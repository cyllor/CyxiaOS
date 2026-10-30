#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use cyxia_prototype::{domains::{Action, Error, ObjectKey, PolicyStamp, POLICY_NS, WINDOW_NS},
    policy::{self, ModelBinding, PublicationTime, CpuTime}, policy_wire::{self, Plan, Decision, Envelope, PlanHeader}};
static WALL: AtomicU64 = AtomicU64::new(100_000_000);
static WORK: AtomicU64 = AtomicU64::new(1_000);
static CORE: AtomicUsize = AtomicUsize::new(0);
pub mod cpu { pub fn slot() -> usize { super::CORE.load(super::Ordering::Acquire) } }
mod timer {
    pub fn cpu_ticks() -> u64 { super::WORK.load(super::Ordering::Acquire) }
    pub fn cpu_ns(ticks: u64) -> u64 { ticks }
}
fn now() -> u64 { WALL.load(Ordering::Acquire) }
struct NativeClock;
// NATIVE_CLOCK
#[derive(Clone, Copy)]
struct Family;
struct Owner { prepared_count: usize, families: [Option<Family>; 1] }
fn family_index(_: u16, _: u16) -> Result<usize, Error> { Ok(0) }
struct Scope { cpu_cost: u64, wall_cost: u64 }
impl Scope {
    fn authorize_executor(&self, _: &Owner) -> Result<(), Error> { Ok(()) }
    fn selection(&self, _: &Owner, _: Family, _: Action, _: ObjectKey, _: u64) -> Result<(), Error> {
        WORK.fetch_add(self.cpu_cost, Ordering::AcqRel);
        WALL.fetch_add(self.wall_cost, Ordering::AcqRel);
        Ok(())
    }
}
// SUBMISSION_TRACE_MODULE
struct Executor {
    owner: &'static mut Owner, scope: Scope, model: ModelBinding, publication_started: PublicationTime,
    publication_debit: CpuTime, wall_deadline: u64, published: usize,provenance:submission::Facts,
}
impl Executor {
    // NATIVE_PRECOMMIT
}
fn fixture(cpu_cost: u64, wall_cost: u64) -> (Executor, Vec<u8>) {
    WALL.store(100_000_010, Ordering::Release); WORK.store(1_000, Ordering::Release);
    CORE.store(0, Ordering::Release);
    let model = ModelBinding { generation: 1, model_hash: [3; 32], schema_hash: [4; 32] };
    let d = Decision { action: Action::CpuWeight(1), candidate_index: 0,
        envelope: Envelope { controller_epoch: 1, decision_seq: 1, snapshot_seq: 1,
            target: ObjectKey { id: 1, generation: 1 }, ledger_generation: 1, core_generation: 1,
            expires_local_ns: 100_000_000 + WINDOW_NS, model_hash: model.model_hash, candidate_set_hash: [5; 32] } };
    let header = PlanHeader { plan_seq: 1, base_plan_version: 0, active_model_generation: 1,
        controller_epoch: 1, snapshot_seq: 1, active_until_local_ns: 100_000_000 + POLICY_NS };
    let mut wire = vec![0; 384]; let used = policy_wire::encode_plan(header, &[d], &mut wire).unwrap(); wire.truncate(used);
    (Executor { owner: Box::leak(Box::new(Owner { prepared_count: 1, families: [Some(Family)] })), scope: Scope { cpu_cost, wall_cost },
        model, publication_started: PublicationTime { wall_ns: 100_000_000, cpu: CpuTime { cpu: 0, ns: 1_000 } },
        publication_debit: CpuTime { cpu: 0, ns: 0 },
        wall_deadline: 150_000_000, published: 0,provenance:submission::Facts::disabled() }, wire)
}
#[test]
fn wall_pause_does_not_consume_native_publication_cpu() {
    let (mut executor, wire) = fixture(100, 2_000_000);
    assert_eq!(executor.publish(&policy_wire::decode_plan(&wire).unwrap(), 1, 100_000_010), Ok(()),
        "native final gate charged descheduling as CPU");
    assert_eq!(executor.published, 1);
}
#[test]
fn last_callback_cannot_hide_cpu_overrun() {
    for cost in [500_000, 500_001] {
        let (mut executor, wire) = fixture(cost, 1);
        let result = executor.publish(&policy_wire::decode_plan(&wire).unwrap(), 1, 100_000_010);
        if cost == 500_000 { assert_eq!(result, Ok(())); }
        else { assert_eq!(result, Err(Error::Budget), "last callback CPU overrun reached commit");
            assert_eq!(executor.published, 0); }
    }
}
#[test]
fn native_wall_deadline_is_not_replaced_with_cpu_time() {
    let (mut executor, wire) = fixture(100, 50_000_000);
    assert_eq!(executor.publish(&policy_wire::decode_plan(&wire).unwrap(), 1, 100_000_010), Err(Error::Expired));
    assert_eq!(executor.published, 0);
}
#[test]
fn native_cpu_identity_and_regression_are_rejected() {
    for error in [Error::Auth, Error::Range] {
        let (mut executor, wire) = fixture(0, 0);
        if error == Error::Auth { CORE.store(1, Ordering::Release); } else { WORK.store(999, Ordering::Release); }
        assert_eq!(executor.publish(&policy_wire::decode_plan(&wire).unwrap(), 1, 100_000_010), Err(error));
        assert_eq!(executor.published, 0);
    }
}
