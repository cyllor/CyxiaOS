"""Real paid helper, selector, cleanup and receipt consumption over real owners.

Reuses the existing billing fixture's clock/Root boundary. Hardware pages,
file close, context return and TLB completion remain controlled boundaries.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from test_governance_billing_priority import function


def program():
    task=(ROOT/'kernel/src/domain_tasks.rs').read_text()
    execution=(ROOT/'kernel/src/domain_tasks/execution.rs').read_text()
    owner=(ROOT/'kernel/src/learning_replay/owner.rs').read_text()
    replay=(ROOT/'kernel/src/domain_tasks/replay.rs').read_text()
    facade=(ROOT/'kernel/src/learning_replay.rs').read_text()
    unified=(ROOT/'kernel/src/unified.rs').read_text()
    code=(ROOT/'tests/host/baseline_progress_harness.rs').read_text().split('#[test]',1)[0]
    def replace(old,new,count=1):
        nonlocal code
        assert code.count(old)==count,(old,code.count(old))
        code=code.replace(old,new)
    # Only the fixture State changes: the compiled production bodies below
    # retain their actual control flow, gates, selectors and cleanup ordering.
    replace('use cyxia_prototype::domains::{Error, ObjectKey, WINDOW_NS};','use cyxia_prototype::domains::{Error, ObjectKey, ApplyId, WINDOW_NS};')
    code=code.replace('[Option<Active>; 1]','[Option<Active>; 4]').replace('active: [None]','active: [None;4]').replace('s.active = [None]','s.active = [None;4]')
    code=code.replace('[AtomicU64; 1] = [AtomicU64::new(0)]','[AtomicU64; 4] = [const {AtomicU64::new(0)};4]').replace('[AtomicBool; 1] = [AtomicBool::new(false)]','[AtomicBool; 4] = [const {AtomicBool::new(false)};4]')
    replace('admission: SpawnAdmission, tasks: (), launches:', 'admission: SpawnAdmission, tasks: [Task;TASKS], launches:')
    assert code.count('memory: (), services: (), ipc: (),')==2
    code=code.replace('memory: (), services: (), ipc: (),','memory: Memory<256,16>, services: ServiceBatch, ipc: Ipc<64>,',1)
    replace('remote: (), generation: u64, facts: Facts, launch_cursor: usize,','remote: (), generation: u64, facts: Facts, launch_cursor: usize,\n    lifecycle_cursor:usize, exits:[Option<ExitRecord>;16], vectors:[Option<()>;TASKS],wake:u64,probe_key:Option<ObjectKey>,probe_exit:Option<u64>,')
    replace('admission: SpawnAdmission::new(), tasks: (), launches:', 'admission: SpawnAdmission::new(), tasks: [Task::EMPTY;TASKS], launches:')
    replace('memory: (), services: (), ipc: (), remote: (), generation: 1, facts: Facts { rejected: 0 }, launch_cursor: 0', 'memory: Memory::new(), services: ServiceBatch::new(), ipc: Ipc::new(), remote: (), generation: 1, facts: Facts { rejected: 0 }, launch_cursor: 0, lifecycle_cursor:0,exits:[None;16],vectors:[None;TASKS],wake:0,probe_key:None,probe_exit:None')
    replace("tasks: &'a mut (), launches:","tasks: &'a mut [Task;TASKS], launches:")
    replace("memory: &'a mut (),","memory: &'a mut Memory<256,16>,")
    replace("services: &'a mut (), ipc: &'a mut (),","services: &'a mut ServiceBatch, ipc: &'a mut Ipc<64>,")
    replace('struct Facts { rejected: u64 }','struct Facts { rejected: u64, cpu:[Counter;16] }')
    replace('facts: Facts { rejected: 0 }','facts: Facts { rejected: 0, cpu:[const{Counter};16] }')
    replace('work(80_000);','work(CTOR_COST.load(Ordering::Acquire));\n        if DENY_ON_CTOR.load(Ordering::Acquire){DENY_SETTLE.store(true,Ordering::Release);}\n        if CLEAR_DRAIN_ON_CTOR.load(Ordering::Acquire){learning_replay::change_phase(1);}')
    replace('mod local_evidence { pub fn retain(_: ()) {} }','''mod local_evidence {
      pub struct Event{pub stage:u64,pub error:super::Error,pub observed_ns:u64,pub spawn_id:u64,pub deadline_ns:u64,pub task:super::ObjectKey,pub cpu:u16,pub group:super::ObjectKey,pub layout:super::CpuLayout,pub entered_ns:u64}
      pub struct Failure;impl Failure{pub fn capture(_:Event,_:&super::Scheduler){}}
      pub fn retain(_: ()) {}
    }''')
    replace('mod replay { pub fn service_admitted() {} }','// TASK_REPLAY')
    replace('mod learning_evidence {','mod learning_evidence { pub fn measure<R>(_:super::ObjectKey,_:cyxia_prototype::learning::reward::CpuClass,body:impl FnOnce()->R)->R{body()}')
    code=code.replace('mod learning_evidence {','mod learning_evidence {'+
        (ROOT/'tests/host/capture_identity_facade.rs').read_text())
    replace('fn complete_locked(s: &mut State, _: usize) -> Result<(), Error> {', 'fn complete_locked(s: &mut State, slot: usize) -> Result<(), Error> {')
    old=function(code,'fn complete_locked(')
    replace(old,'''fn complete_locked(s:&mut State,slot:usize)->Result<(),Error>{
      if slot==0 && DENY_SETTLE.load(Ordering::Acquire){return Err(Error::Busy)}
      let bill=s.active[slot].map(|a|(a.dispatch.sequence,COMPLETE_ACTUAL[slot].load(Ordering::Acquire),COMPLETE_AT[slot].load(Ordering::Acquire)));
      let result=complete_actual_locked(s,slot);
      if slot==0 && s.active[slot].is_none(){if let Some(bill)=bill{s.bills.push(bill);}}
      result
    }''')
    # Root's body is already a controlled boundary. Keep owned Drain until the
    # test explicitly clears it; the old launch-only completion spy is unrelated.
    replace(function(code,'if s.phase==Phase::Drain && locked('),'')
    reader=function(facade,'pub fn baseline_activation_pending(')
    owned=function(facade,'pub fn owned_drain_pending(') if 'pub fn owned_drain_pending(' in facade else 'pub fn owned_drain_pending()->bool{false}'
    replace('// REPLAY_HINT_READER',reader+'\n'+owned)
    owner_bodies='struct Guard;\n'+'\n'.join(function(owner,s) for s in ['impl Drop for Guard','fn lock()','fn with<T>','pub fn service_step()','fn publish_drain_hint(','pub(super) fn drain_pending('])
    owner_bodies+='\n'+re.search(r'^static DRAIN_PENDING:.*;$',owner,re.M)[0]
    replace('// REPLAY_BODIES',owner_bodies)
    pieces=['static LOCK: ResettableGate = ResettableGate(core::cell::UnsafeCell::new(owner_gate::Gate::new()));']
    pieces += [function(task,s) for s in ['struct Guard','impl Guard','impl Drop for Guard','fn acquire_guard()','fn locked<R>','fn locked_with_guard<R>','pub struct Credit','fn admit_service(','pub fn begin_service_segment()','fn revalidate_unstarted(','pub fn revalidate_service_segment()','pub(crate) struct PaidServiceWitness','fn service_witness_locked(','pub fn authorize_service_turn()','pub fn complete_builtin(','pub fn complete_service(','pub fn service_segment<R>']]
    pieces.append(function(task,'fn complete_locked(').replace('fn complete_locked(','fn complete_actual_locked(',1))
    pieces += [function(execution,s).replace('super::deadline::','deadline::') for s in ['pub fn service_io_piece<R>','fn service_baseline_activation(','pub fn service_baseline_progress(','struct BaselineRetryGuard','impl Drop for BaselineRetryGuard','fn enter_baseline_retry(','fn service_baseline_activation_at(','fn advance_admission_bounded(','fn submit_package(','fn lifecycle_piece(','fn capture_task_identity(','fn cleanup(','fn cleanup_inner(']]
    pieces.append(re.search(r'^static BASELINE_RETRY_ACTIVE:.*;$',execution,re.M)[0])
    if 'fn lifecycle_turn(' in execution:
        pieces.append(function(execution,'fn lifecycle_turn('))
    else:
        # Exact old phase-0 body: this makes the RED behavioral (no targeted
        # call), while retaining the production selector and completion order.
        phase=function(function(execution,'pub fn service('),'0 =>')
        pieces.append('fn lifecycle_turn(s:&mut State){'+phase[phase.index('{')+1:-1]+'}')
    pieces += [function(unified,s) for s in ['fn mechanism_progress(','fn progress(','fn finish_service(','fn service_work<R>','fn service_start(']]
    pieces += ['#[derive(Clone,Copy,PartialEq,Eq)]'+function(task,'enum Life'), '#[derive(Clone,Copy)]'+function(task,'struct Task {'),function(task,'impl Task'),'#[derive(Clone,Copy)]'+function(task,'struct ExitRecord')]
    for name in ['owner_gate.rs','service_authority.rs','deadline.rs','lifecycle.rs']:
        pieces.append('#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks'/name))+'] mod '+name[:-3]+';')
    replace('// PRODUCTION_BODIES','\n'.join(pieces))
    query=function(replay,'pub fn spawn_result(')
    # Namespace-only relocation into the fixture's task-replay module.
    task_replay='mod replay{use super::*;\n'+(ROOT/'tests/host/paid_lifecycle_replay.rs').read_text()+'\n'+query+'\n}'
    replace('// TASK_REPLAY',task_replay)
    return code+'\n'+(ROOT/'tests/host/paid_lifecycle_support.rs').read_text()


class PaidLifecycleProgress(unittest.TestCase):
    def test_actual_paid_lifecycle_releases_real_resources_before_delivery(self):
        code=program()
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            rust=directory/'harness.rs';rust.write_text(code)
            (directory/'Cargo.toml').write_text('[package]\nname="paid-lifecycle"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'test','--offline','--lib','--manifest-path',str(directory/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-paid-lifecycle'),'--','--test-threads=1']
            def run(source,name=None):
                rust.write_text(source)
                return subprocess.run(command+(['--exact',name] if name else []),cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            result=run(code)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('7 passed; 0 failed',result.stdout)
            hook='lifecycle_turn(s);'
            self.assertEqual(code.count(hook),1)
            for replacement,name,failure in [
                ('','paid_lifecycle_three_separate_bills_and_one_original_delivery','owned Exiting child never reached actual cleanup'),
                ('lifecycle_turn(s); lifecycle_turn(s);','paid_lifecycle_selects_only_one_and_rotates_past_busy','one paid lifecycle piece processed two items'),
            ]:
                negative=run(code.replace(hook,replacement),'%s'%name)
                self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
                self.assertIn(failure,negative.stdout+negative.stderr)
            owned=function(code,'pub fn owned_drain_pending(')
            negative=run(code.replace(owned,'pub fn owned_drain_pending()->bool {baseline_activation_pending()}'),
                         'paid_lifecycle_requires_owned_drain_and_allowed_root_result')
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('unowned or disallowed Root result ran lifecycle',negative.stdout+negative.stderr)
            entry='    let Some(_entry) = enter_baseline_retry() else {\n        return;\n    };'
            self.assertEqual(code.count(entry),1)
            negative=run(code.replace(entry,''),'paid_lifecycle_three_separate_bills_and_one_original_delivery')
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('lifecycle progress recursively replaced the outer ticket',negative.stdout+negative.stderr)


if __name__=='__main__':unittest.main()
