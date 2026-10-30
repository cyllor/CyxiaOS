#![allow(dead_code, unused_imports)]
use std::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::domains::{Error, ObjectKey};
use cyxia_prototype::domains::tasks::{Scheduler, SpawnAdmission, SpawnRequest, SpawnState,
    TaskBackend, CreateOutcome, CpuLayout, ThreadSpec, ThreadReservation};
const fn key(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
const GROUP: ObjectKey = key(14);
const PACKAGE: ObjectKey = key(1);
const CLIENT_PACKAGE: ObjectKey = key(2);
const KERNEL_CALLER: ObjectKey = key(u64::MAX);
const CLUSTER_CALLER: ObjectKey = key(u64::MAX - 3);
const PARENT: ObjectKey = key(0x1000);
const ZERO: ObjectKey = ObjectKey { id: 0, generation: 0 };
const SELFTEST_ENABLED: bool = true;
const TASKS: usize = 6;
const ORDINARY_TASKS: usize = 4;
const LAYOUT: CpuLayout = CpuLayout { business_mask: 13, healthy_mask: 15, generation: 7 };
static NOW: AtomicU64 = AtomicU64::new(100_000_000);
fn now_ns() -> u64 { NOW.load(Ordering::Acquire) }
fn group(id: u64) -> ObjectKey { key(id) }
#[derive(Clone, Copy, Eq, PartialEq)] enum Life { Free, Ready, Exiting }
#[derive(Clone, Copy)] struct Task { key: ObjectKey, group: ObjectKey, package: ObjectKey,
    life: Life, recipe: u16, closed: bool, cpu: u16, failure: Option<Error> }
impl Task { const EMPTY: Self = Self { key: ZERO, group: ZERO, package: ZERO,
    life: Life::Free, recipe: 0, closed: false, cpu: 3, failure: None }; }
#[derive(Clone, Copy)] struct Launch { request: SpawnRequest, cpu: u16, deadline: u64,
    recipe: u16, len: usize, input: [u8; 32] }
struct BuildTrace { enabled: bool, stage: u64, entered_ns: u64 }
impl BuildTrace {
    fn new(enabled: bool) -> Self { Self { enabled, stage: 0, entered_ns: 0 } }
    fn step(&mut self, stage: u64) { if self.enabled { self.stage = stage; self.entered_ns = now_ns(); } }
}
mod replay {
    use super::*;
    pub const CALLER_ID: u64 = u64::MAX - 10;
    pub fn authorize_request(_: &SpawnRequest, _: &[u8], _: u16, _: u64, _: u16) -> Result<(), Error> { Err(Error::Auth) }
    pub fn work_measured() -> bool { false }
    pub fn work_source(_: ObjectKey, _: u64, _: u16) -> Option<ObjectKey> { None }
}
mod learning_evidence {
    pub mod execution_trace {
        pub struct Child { pub group: super::super::ObjectKey, pub child: super::super::ObjectKey,
            pub parent: super::super::ObjectKey, pub request_id: u64, pub at: u64 }
        pub fn created(_: Child) {}
    }
    pub fn measure<T>(_: (), _: cyxia_prototype::learning::reward::CpuClass, body: impl FnOnce() -> T) -> T { body() }
}
// THREAD_SPEC
struct Creator<'a> {
    tasks: &'a mut [Task; TASKS], launches: [Launch; 1], scheduler: Scheduler, layout: CpuLayout,
    generation: &'a mut u64, local_failure: Option<()>, builds: u64, rollbacks: u64,
}
fn task_index(tasks: &[Task; TASKS], owner: ObjectKey) -> Result<usize, Error> {
    tasks.iter().position(|t| t.key == owner && t.life != Life::Free).ok_or(Error::Stale)
}
impl Creator<'_> {
    fn launch(&self, r: &SpawnRequest) -> Result<usize, Error> {
        self.launches.iter().position(|l| l.request == *r).ok_or(Error::Stale)
    }
    fn failure_facts(&self, _: &SpawnRequest, _: ObjectKey, _: u64, _: u64, _: Error) -> Option<()> { None }
    fn build(&mut self, r: &SpawnRequest, slot: usize, key: ObjectKey,
        reservation: Option<ThreadReservation>, trace: &mut BuildTrace) -> Result<(), Error> {
        self.builds += 1;
        let launch = &self.launches[self.launch(r)?];
        let local = r.caller == CLUSTER_CALLER;
        // PTE/page/cap effects are counted, while real reservation validation
        // and the old/new final admission path run unchanged below.
        // BUILD_CHECKS
        self.tasks[slot] = Task { key, group: r.group, package: r.package,
            life: Life::Ready, recipe: launch.recipe, closed: false, cpu: launch.cpu, failure: None };
        // LATE_ADMISSION
        Ok(())
    }
    fn rollback(&mut self, slot: usize, key: ObjectKey) -> Result<(), Error> {
        self.rollbacks += 1;
        match self.scheduler.remove(key) { Ok(()) | Err(Error::Stale) => {}, Err(e) => return Err(e) }
        self.tasks[slot] = Task::EMPTY; Ok(())
    }
}
impl TaskBackend for Creator<'_> {
    // ACTUAL_CREATOR
}
fn request(recovery: bool) -> SpawnRequest {
    SpawnRequest { caller: if recovery { KERNEL_CALLER } else { PARENT }, request_id: 0x5151,
        package: PACKAGE, group: GROUP, payload_hash: [0x51; 32], recovery }
}
fn fixture<'a>(generation: &'a mut u64, r: SpawnRequest) -> (Creator<'a>, SpawnAdmission) {
    NOW.store(100_000_000, Ordering::Release);
    let mut scheduler = Scheduler::new(); scheduler.register_group(GROUP).unwrap();
    for (id, budget) in [(100, 30_000_000), (101, 30_000_000), (102, 10_000_000), (103, 20_000_000)] {
        scheduler.admit(ThreadSpec { key: key(id), group: GROUP, cpu: 3, allowed_mask: 12,
            minimum_ns: 0, budget_ns: budget }, LAYOUT, now_ns()).unwrap();
    }
    let mut tasks = [Task::EMPTY; TASKS];
    tasks[0] = Task { key: PARENT, group: GROUP, package: CLIENT_PACKAGE, life: Life::Ready,
        recipe: 0, closed: false, cpu: 3, failure: None };
    let creator = Creator { tasks: Box::leak(Box::new(tasks)), launches: [Launch { request: r, cpu: 3,
        deadline: 4_100_000_000, recipe: 0, len: 32, input: [1; 32] }],
        scheduler, layout: LAYOUT, generation, local_failure: None, builds: 0, rollbacks: 0 };
    let mut q = SpawnAdmission::new(); q.register_group(GROUP).unwrap();
    (creator, q)
}
#[test]
fn ordinary_child_waits_without_effects_then_creates_once_after_real_capacity_release() {
    let mut generation = 10; let r = request(false); let (mut c, mut q) = fixture(&mut generation, r);
    assert_eq!(q.submit(r, now_ns(), &mut c), Ok(SpawnState::Queued));
    assert_eq!(q.service_one(now_ns(), &mut c), Ok(Some((r, SpawnState::Queued))),
        "ordinary creator converted temporary committed capacity into permanent failure");
    assert_eq!((c.builds, c.rollbacks, *c.generation), (0, 0, 10));
    assert_eq!(c.scheduler.committed_ns(3), 90_000_000);
    assert_eq!(c.scheduler.committed_ns(2), 0, "explicit target CPU must not silently change");
    assert_eq!(q.submit(r, now_ns(), &mut c), Ok(SpawnState::Queued));
    NOW.store(101_000_000, Ordering::Release); c.scheduler.remove(key(103)).unwrap();
    let created = q.service_one(now_ns(), &mut c).unwrap().unwrap();
    let SpawnState::Created(child) = created.1 else { panic!("original spawn did not create after release"); };
    assert_eq!(created.0, r); assert_eq!(c.builds, 1); assert_eq!(*c.generation, 11);
    assert_eq!(c.scheduler.committed_ns(3), 71_000_000); assert_eq!(c.scheduler.committed_ns(2), 0);
    assert_eq!(q.submit(r, now_ns(), &mut c), Ok(SpawnState::Created(child)));
    assert!(q.service_one(now_ns(), &mut c).unwrap().is_none()); assert_eq!(c.builds, 1);
    assert_eq!(c.launches[0].deadline, 4_100_000_000);
}
#[test]
fn pressure_never_refreshes_the_original_deadline_or_leaks_construction() {
    let mut generation = 10; let r = request(false); let (mut c, mut q) = fixture(&mut generation, r);
    q.submit(r, now_ns(), &mut c).unwrap();
    assert_eq!(q.service_one(now_ns(), &mut c), Ok(Some((r, SpawnState::Queued))));
    NOW.store(4_100_000_000, Ordering::Release);
    assert_eq!(q.service_one(now_ns(), &mut c), Ok(Some((r, SpawnState::Failed(Error::Expired)))));
    assert_eq!((c.builds, *c.generation), (0, 10)); assert_eq!(c.scheduler.committed_ns(3), 90_000_000);
}
#[test]
fn permanent_authority_failure_is_not_hidden_by_resource_pressure() {
    let mut generation = 10; let r = request(false); let (mut c, mut q) = fixture(&mut generation, r);
    let mut invalid = r; invalid.package = key(999);
    assert_eq!(q.submit(invalid, now_ns(), &mut c), Err(Error::Auth)); assert_eq!(c.builds, 0);
}
#[test]
fn existing_recovery_path_keeps_its_original_admission_behavior() {
    let mut generation = 10; let r = request(true); let (mut c, mut q) = fixture(&mut generation, r);
    q.submit(r, now_ns(), &mut c).unwrap();
    assert_eq!(q.service_one(now_ns(), &mut c), Ok(Some((r, SpawnState::Failed(Error::Capacity)))));
    assert_eq!((c.builds, c.rollbacks), (1, 1));
}
