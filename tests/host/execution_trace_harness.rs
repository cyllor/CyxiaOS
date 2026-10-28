#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use cyxia_prototype::{domains::{Action, ApplyId, ObjectKey, PolicyStamp, Error, tasks::*}, learning::{Family, capture::RunKey}, policy::ExecutionState};
pub mod cpu {
    use std::cell::Cell;
    std::thread_local! { static CPU: Cell<usize> = const { Cell::new(0) }; }
    pub fn slot() -> usize { CPU.with(Cell::get) }
    pub fn at(value: usize) { CPU.with(|v| v.set(value)); }
}
// TRACE_MODULE
const fn key(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
const RUN: RunKey = RunKey { boot_epoch: 7, trial_id: 9, generation: 3 };
const STAMP: PolicyStamp = PolicyStamp { version: 41, snapshot_ns: 100_000_000, installed_until_ns: 10_100_000_000 };
fn apply(seq: u64) -> ApplyId { ApplyId { boot_epoch: 7, controller_epoch: 2, plan_seq: seq, action_index: 0, target: key(12) } }
fn event(seq: u64, started: bool, result: Result<ExecutionState, Error>, entered: u64, cpu: u64) -> trace::ControlEvent {
    trace::ControlEvent { action: Action::CpuWeight(2), apply: apply(seq), stamp: STAMP,
        was_started: started, entered_ns: entered, finished_ns: entered + 1_000,
        cpu_ns: cpu, published_ns: 100_000_500, result }
}
#[test]
fn first_scope_preserves_each_stage_and_later_trials_cannot_replace_it() {
    trace::begin(RUN, Family { domain: 1, kind: 1 }, key(12), 100_000_000);
    trace::installed(key(12), STAMP, 100_001_000);
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(12)).unwrap();
    let layout = CpuLayout { business_mask: 9, healthy_mask: 15, generation: 1 };
    scheduler.admit(ThreadSpec { key: key(99), group: key(12), cpu: 3,
        allowed_mask: 8, minimum_ns: 0, budget_ns: 20_000_000 }, layout, 100_001_000).unwrap();
    scheduler.install_weight(key(12), 2, STAMP, 100_001_000).unwrap();
    trace::control(event(51, false, Ok(ExecutionState::Pending), 100_001_000, 2_000));
    trace::control(event(51, true, Err(Error::Busy), 100_003_000, 3_000));
    trace::work(RUN, trace::WorkEvent::Activated, 100_004_000);
    trace::work(RUN, trace::WorkEvent::Poll, 100_005_000);
    trace::work(RUN, trace::WorkEvent::WarmCreated { id: 77, deadline: 200_000_000 }, 100_005_100);
    trace::work(RUN, trace::WorkEvent::WarmSubmit { id: 77, entered_ns: 100_006_000, result: Err(Error::Busy) }, 100_006_500);
    trace::work(RUN, trace::WorkEvent::WarmSubmit { id: 77, entered_ns: 100_006_900, result: Ok(()) }, 100_007_000);
    trace::created(trace::Child { group: key(12), child: key(99), parent: key(88), request_id: 77, at: 100_008_000 });
    // Existing task-owner exclusion serializes this fixture's CPU0/CPU3
    // metadata updates; clocks represent observations, not native timings.
    let gate = std::sync::Mutex::new(());
    cpu::at(3);
    let _owner = gate.lock().unwrap();
    let d = scheduler.dispatch_with_window_headroom(3, layout, 100_010_000, 2_000_000, 20_000_000).unwrap().unwrap();
    trace::selected(d);
    let before = scheduler.policy_receipt(key(12)).unwrap();
    scheduler.complete(d, 20_000, RunState::Runnable, 100_030_000).unwrap();
    trace::settled(trace::Settlement { dispatch: d, actual_ns: 20_000,
        physical_finished_ns: 100_030_000, settled_ns: 100_500_000,
        before_version: Ok(before), after_version: scheduler.policy_receipt(key(12)),
        still_active: false, result: Ok(()) });
    drop(_owner);
    cpu::at(0);
    trace::reconciled(trace::Reconciliation { target: key(12), stamp: STAMP, version: 41,
        in_flight: false, state: ExecutionState::Applied, at: 101_000_000 });
    trace::control(event(51, true, Ok(ExecutionState::Applied), 101_000_000, 4_000));
    trace::work(RUN, trace::WorkEvent::WarmOutcome { id: 77, result: Ok(100_030_000) }, 101_001_000);
    let (control, task, work) = trace::snapshots();
    assert_eq!(control[8], 1, "executed control attempts were not retained under their ApplyId");
    assert_eq!(&control[16..23], &[7,2,51,0,12,1,41]);
    assert_eq!(&control[27..29], &[1,2]);
    assert_eq!(control[31], 101_001_000);
    assert_eq!(control[32], 9_000);
    assert_eq!(task[5], 41);
    assert_eq!(task[16], d.sequence);
    assert_eq!(task[37], 100_030_000, "physical completion was replaced by settlement time");
    assert_eq!(task[43], 100_500_000, "settlement observation was replaced by control observation");
    assert_eq!(task[56], 101_000_000);
    assert_eq!(task[64], 99);
    assert_eq!(&work[10..14], &[1,77,100_005_100,200_000_000]);
    assert_eq!(&work[14..20], &[2,77,100_006_000,5 + ((Error::Busy as u64 + 1) << 8),100_007_000,77]);
    assert_eq!(work[20], 101_001_000);
    assert_eq!(work[29], 100_006_500);
    assert_eq!(work[30], 100_030_000, "warm completion was replaced by its later observation");
    assert_eq!(control[37], 0x0002_0000, "canonical action payload was not retained");
    assert_eq!(control[39], 4, "canonical action length was not retained");
    let mut collision = event(51, true, Ok(ExecutionState::Pending), 101_002_000, 1);
    collision.action = Action::CpuWeight(4);
    trace::control(collision);
    let (conflict, _, _) = trace::snapshots();
    assert_eq!(conflict[28], 2, "same identity with different action polluted the original counters");
    assert_eq!(conflict[14], 1);
    cpu::at(3);
    trace::settled(trace::Settlement { dispatch: d, actual_ns: 20_000,
        physical_finished_ns: 100_030_000, settled_ns: 101_003_000,
        before_version: Err(Error::Stale), after_version: Ok(41), still_active: false, result: Ok(()) });
    let (_, query_error, _) = trace::snapshots();
    assert_eq!(query_error[15], 1, "failed policy receipt query disappeared from settlement diagnostics");
    assert_eq!(&query_error[80..84], &[101_003_000,d.sequence,Error::Stale as u64 + 1,0]);
    assert_eq!(query_error[11], 1);
    cpu::at(0);
    // Separate publication identities remain distinct even for one target.
    for sequence in 52..60 { trace::control(event(sequence, false, Ok(ExecutionState::Pending), 102_000_000, 1)); }
    let (full, _, _) = trace::snapshots();
    assert_eq!(full[8], 8);
    assert_eq!(full[9], 1, "diagnostic overflow silently replaced a retained identity");
    assert_eq!(full[18], 51);
    // The closing policy has a different snapshot/version from the first
    // baseline. Its own demand, bill and observation chain must stay distinct.
    let closing_stamp=PolicyStamp {version:42,snapshot_ns:103_000_000,installed_until_ns:10_103_000_000};
    let closing_apply=ApplyId {plan_seq:60,..event(51,false,Ok(ExecutionState::Pending),103_000_000,1).apply};
    trace::closing(key(12),99_000_000,closing_apply,closing_stamp,103_001_000,153_001_000,103_002_000);
    trace::closing(key(12),100_000_000,ApplyId {target:key(13),..closing_apply},closing_stamp,103_001_000,153_001_000,103_002_000);
    assert_eq!(trace::snapshots().2[37],0,"mismatched closing identity armed the task chain");
    trace::closing(key(12),100_000_000,closing_apply,closing_stamp,103_001_000,153_001_000,103_002_000);
    assert_eq!(trace::snapshots().2[37],42,"closing policy identity was not armed");
    trace::closing(key(12),100_000_000,ApplyId{plan_seq:61,..closing_apply},closing_stamp,103_001_000,153_001_000,103_002_000);
    assert_eq!(trace::admission_snapshot()[58],1,"conflicting closing identity was silently ignored");
    trace::closing_work(RUN,trace::ClosingWork::DrainStart,103_003_000);
    trace::closing_work(RUN,trace::ClosingWork::PollReturned{result:Err(Error::Busy)},103_004_000);
    trace::closing_work(RUN,trace::ClosingWork::PollOrigin{stage:2,code:0x1007},103_004_000);
    trace::closing_work(RUN,trace::ClosingWork::ProbeCreated{version:42,id:251,deadline:5_103_005_000},103_005_000);
    trace::closing_work(RUN,trace::ClosingWork::ProbeSubmit{id:251,entered_ns:103_006_000,result:Err(Error::Busy)},103_007_000);
    trace::closing_work(RUN,trace::ClosingWork::ProbeSubmit{id:251,entered_ns:103_008_000,result:Ok(())},103_009_000);
    trace::admission_opportunity(true,true,103_010_000);
    trace::admission_body(901,103_011_000);
    let request=cyxia_prototype::domains::tasks::SpawnRequest {caller:key(0x5245504c4341),request_id:251,
        package:key(7),group:key(12),payload_hash:[7;32],recovery:false};
    trace::probe_caller(RUN,251,request.caller,103_010_000);
    let foreign=cyxia_prototype::domains::tasks::SpawnRequest {caller:key(88),..request};
    trace::admitted(&foreign,cyxia_prototype::domains::tasks::SpawnState::Queued,103_011_000,900);
    trace::created(trace::Child{group:key(12),child:key(100),parent:foreign.caller,request_id:251,at:103_011_000});
    assert_eq!(trace::snapshots().1[72],0,"foreign caller occupied closing probe child record");
    trace::admitted(&request,cyxia_prototype::domains::tasks::SpawnState::Queued,103_012_000,901);
    trace::created(trace::Child{group:key(12),child:key(101),parent:request.caller,request_id:251,at:103_012_500});
    assert_eq!(trace::snapshots().1[72],101,"exact closing probe child was not retained");
    trace::admission_result(true,103_013_000);
    cpu::at(3);
    trace::installed(key(12),PolicyStamp {snapshot_ns:99_000_000,..closing_stamp},103_014_000);
    assert_eq!(trace::snapshots().1[88],0,"closing task accepted a mismatched snapshot");
    trace::installed(key(12),closing_stamp,103_014_000);
    scheduler.install_weight(key(12),1,closing_stamp,103_014_000).unwrap();
    let close_dispatch=scheduler.dispatch(3,layout,103_015_000,20_000).unwrap().unwrap();
    trace::selected(close_dispatch);
    scheduler.complete(close_dispatch,10_000,RunState::Runnable,103_025_000).unwrap();
    trace::settled(trace::Settlement {dispatch:close_dispatch,actual_ns:10_000,physical_finished_ns:103_025_000,
        settled_ns:104_000_000,before_version:Ok(41),after_version:Ok(42),still_active:false,result:Ok(())});
    cpu::at(0);
    trace::reconciled(trace::Reconciliation {target:key(12),stamp:closing_stamp,version:42,in_flight:false,
        state:ExecutionState::Applied,at:104_001_000});
    trace::closing_work(RUN,trace::ClosingWork::ClosingObserved{version:42,state:ExecutionState::Applied},104_002_000);
    trace::closing_work(RUN,trace::ClosingWork::ProbeOutcome{id:251,result:Ok(103_025_000)},104_003_000);
    trace::closing_work(RUN,trace::ClosingWork::Block{reason:1},104_004_000);
    trace::task_block(RUN,2,[251,7,1,12,1,0],104_005_000);
    trace::closing_work(RUN,trace::ClosingWork::Drained,104_006_000);
    let (_,closed_task,closed_work)=trace::snapshots();
    assert_eq!(&closed_work[34..39],&[1,Error::Busy as u64+1,103_004_000,42,60]);
    assert_eq!(&closed_work[40..47],&[251,5_103_005_000,103_005_000,103_006_000,103_007_000,
        5|((Error::Busy as u64+1)<<8),103_009_000]);
    assert_eq!(&closed_work[47..50],&[104_003_000,103_025_000,2]);
    assert_eq!(closed_task[88],42);assert_eq!(closed_task[96],close_dispatch.sequence);
    assert_eq!(closed_task[109],103_025_000,"closing physical time was replaced by settlement");
    assert_eq!(closed_task[111],104_000_000);assert_eq!(closed_task[120],104_001_000);
    let admission=trace::admission_snapshot();
    assert_eq!(&admission[8..15],&[closing_apply.boot_epoch,closing_apply.controller_epoch,60,0,12,1,42]);
    assert_eq!(&admission[25..30],&[251,foreign.caller.id,1,1,103_011_000]);
    assert_eq!(&admission[30..35],&[251,request.caller.id,1,1,103_012_000]);
    assert_eq!(admission[59],900);assert_eq!(admission[60],901);
    assert_eq!(&closed_work[59..63],&[1,1,103_012_000,901]);
    assert_eq!(&admission[40..48],&[104_005_000,2,251,7,1,12,1,0]);
    assert_eq!(&admission[52..56],&[2,0x1007,103_004_000,1]);
    trace::close(RUN, 110_000_000);
    let admission_frozen=trace::admission_snapshot();
    let frozen = trace::snapshots();
    trace::begin(RunKey { trial_id: 10, generation: 4, ..RUN }, Family { domain: 1, kind: 1 }, key(12), 200_000_000);
    trace::control(event(90, false, Ok(ExecutionState::Pending), 200_000_000, 1));
    trace::work(RunKey { trial_id: 10, ..RUN }, trace::WorkEvent::Poll, 200_001_000);
    trace::installed(key(12), PolicyStamp { version: 42, ..STAMP }, 200_001_000);
    trace::admission_body(999,200_002_000);
    trace::task_block(RUN,9,[9;6],200_002_000);
    assert_eq!(trace::admission_snapshot(),admission_frozen,"later trial replaced closing diagnostics");
    assert_eq!(trace::snapshots(), frozen, "later trial replaced first-publication diagnostics");
    assert_eq!(frozen.0[223] & 1, 0); assert_eq!(frozen.1[127] & 1, 0); assert_eq!(frozen.2[63] & 1, 0);
}
