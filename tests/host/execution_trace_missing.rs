#![allow(dead_code)]
use cyxia_prototype::{domains::{Action, ApplyId, ObjectKey, PolicyStamp, Error, tasks::Dispatch}, learning::{Family, capture::RunKey}, policy::ExecutionState};
pub struct ControlEvent { pub action: Action, pub apply: ApplyId, pub stamp: PolicyStamp, pub was_started: bool, pub entered_ns: u64, pub finished_ns: u64, pub cpu_ns: u64, pub published_ns: u64, pub result: Result<ExecutionState, Error> }
pub struct Settlement { pub dispatch: Dispatch, pub actual_ns: u64, pub physical_finished_ns: u64, pub settled_ns: u64, pub before_version: Result<u64, Error>, pub after_version: Result<u64, Error>, pub still_active: bool, pub result: Result<(), Error> }
pub struct Reconciliation { pub target: ObjectKey, pub stamp: PolicyStamp, pub version: u64, pub in_flight: bool, pub state: ExecutionState, pub at: u64 }
pub struct Child { pub group: ObjectKey, pub child: ObjectKey, pub parent: ObjectKey, pub request_id: u64, pub at: u64 }
pub enum WorkEvent { Activated, Poll, WarmCreated { id: u64, deadline: u64 }, WarmSubmit { id: u64, entered_ns: u64, result: Result<(), Error> }, WarmOutcome { id: u64, result: Result<u64, Error> } }
pub fn begin(_: RunKey, _: Family, _: ObjectKey, _: u64) {}
pub fn close(_: RunKey, _: u64) {}
pub fn control(_: ControlEvent) {}
pub fn installed(_: ObjectKey, _: PolicyStamp, _: u64) {}
pub fn selected(_: Dispatch) {}
pub fn cancelled(_: Dispatch, _: u64) {}
pub fn settled(_: Settlement) {}
pub fn reconciled(_: Reconciliation) {}
pub fn created(_: Child) {}
pub fn work(_: RunKey, _: WorkEvent, _: u64) {}
pub fn snapshots() -> ([u64; 224], [u64; 128], [u64; 64]) { ([0;224],[0;128],[0;64]) }
