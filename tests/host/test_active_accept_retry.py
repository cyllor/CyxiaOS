"""Complete production accept/abort/root_return with real Registry, reply and Task Gate.

Native CPU/clock, model/Root/resource scope and delivery are explicit controlled
boundaries. Scheduler/selection/ADMISSION composition has its separate fixture.
"""
import json
from pathlib import Path
import subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from test_governance_billing_priority import function
from test_native_submission_provenance import native_program

def program():
 c=(ROOT/'kernel/src/domain_control.rs').read_text()
 p=native_program().split('fn setup(mode:')[0]
 p=p.replace('#![allow(dead_code)]','#![allow(dead_code,unused_imports)]')
 p=p.replace('fn publisher() -> Publisher','fn publisher_fixture() -> Publisher')
 p=p.replace('pub fn cpu_ns(v:u64)->u64{v}', 'pub fn cpu_ns(v:u64)->u64{v}pub fn cpu_elapsed_ns(v:u64)->u64{cpu_ticks()-v}pub fn ticks()->u64{super::WALL.load(super::Ordering::Acquire)}pub fn frequency()->u64{1_000_000_000}')
 p=p.replace('CPU.fetch_add(1,Ordering::AcqRel);','pay(1);').replace('7 if n==4=>{CPU.fetch_add(500001','7 if n==4=>{CPU.fetch_add(250000')
 p=p.replace('struct Owner{context:Context,', 'struct Owner{dependencies:[Option<fn(ObjectKey)->Result<[Option<Prerequisite>;2],Error>>;16],dependency_binders:[Option<fn(ObjectKey,u64)->Result<[Option<BoundDependency>;2],Error>>;16],context:Context,')
 h=(ROOT/'tests/host/active_accept_retry_harness.rs').read_text()
 for marker,signature in [('JOB','struct Job {'),('COMPLETION','struct JobCompletion {')]:h=h.replace('// ACTUAL_'+marker,'#[derive(Clone,Copy)]'+function(c,signature))
 for marker,signature in [('ACCEPT','pub fn accept('),('ABORT','pub fn abort('),('FINISH_JOB','fn finish_job('),('PENDING_JOB','pub fn pending_job(')]:h=h.replace('// ACTUAL_'+marker,function(c,signature))
 native=(ROOT/'kernel/src/prototype_runtime/native.rs').read_text();h=h.replace('// ACTUAL_ROOT_RETURN',function(native,'fn root_return('))
 h=h.replace('// REPLY_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/domain_control/reply.rs'))+'] mod actual_reply;')
 h=h.replace('// OWNER_GATE_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks/owner_gate.rs'))+'] mod owner_gate;')
 h=h.replace('// JOB_DEBIT_INIT','publication_debit:policy::CpuTime{cpu:1,ns:0},' if 'publication_debit:' in function(c,'struct Job {') else '')
 h=h.replace('// FAULT_TESTS',r'''
#[test]fn active_accept_counter_identity_rollback_and_overflow_fail_closed(){for fault in 0..3{let out=setup(0);if fault==0{with(|s|{s.job.as_mut().unwrap().publication_debit.cpu=2;Ok(())}).unwrap();}else{CPU.store(1000,Ordering::Release);FAULT.store(fault,Ordering::Release);if fault==2{with(|s|{s.job.as_mut().unwrap().publication_debit.ns=100_000;Ok(())}).unwrap();}}let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();let r=accept(&out,10);held.release(WALL.load(Ordering::Acquire));assert_eq!(r,Err(match fault{0=>Error::Auth,1=>Error::Range,_=>Error::Overflow}));assert!(!pending_job().unwrap());assert!(with(|s|Ok(s.registry.optimization_stopped())).unwrap());assert_eq!(EFFECTS.load(Ordering::Acquire),0);}}
''' if 'publication_debit:' in function(c,'struct Job {') else '')
 h=h.replace('// GET_DEBIT','j.publication_debit.ns' if 'publication_debit:' in function(c,'struct Job {') else '0')
 return p+'\n'+h

class ActiveAcceptRetry(unittest.TestCase):
 def test_actual_accept_retains_only_acquisition_busy_and_all_cpu_costs(self):
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);source=d/'harness.rs';original=program();source.write_text(original);(d/'Cargo.toml').write_text('[package]\nname="active-accept-retry"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-active-accept-retry'),'--','--test-threads=1','active_accept_']
   e=env();e['RUST_MIN_STACK']='16777216';r=subprocess.run(command,cwd=ROOT,env=e,capture_output=True,text=True,timeout=120)
   self.assertEqual(r.returncode,0,r.stdout+r.stderr)
   self.assertIn('17 passed; 0 failed',r.stdout)
   mutants=[
    ('.checked_add(publication_started.cpu_elapsed(observed)?)','.checked_add(0)','active_accept_busy_twice','failed preflight actual CPU was lost'),
    ('                budget,\n                job.started.checked_add','                policy::PublicationBudget::fresh(publication_started),\n                job.started.checked_add','active_accept_registry_budget','Registry initial cap ignored carried CPU'),
    ('carried: self.publication_debit,','carried: policy::CpuTime{cpu:self.publication_started.cpu.cpu,ns:0},','active_accept_native_precommit','Native precommit forgot same Job debit'),
    ('elapsed_ns: job.publication_debit.ns,','elapsed_ns: 0,','active_accept_abort_keeps','abort dropped prior actual publication CPU'),
    ('budget.check(observed)','policy::PublicationBudget::fresh(publication_started).check(observed)','active_accept_release_cap_includes','release cap forgot earlier actual CPU'),
    ('if local_stop {','if false {','active_accept_release_overrun','release CPU escaped final publication cap'),
    ('if acquisition_busy {','if acquisition_busy || result == Err(Error::Busy) {','active_accept_only_acquisition','completed resource/model/Root/selection Busy was retried'),
    ('drop(task_publication);','core::mem::forget(task_publication);','active_accept_guard_releases','delivery retained Task guard'),
    ('if observed.wall_ns > job.started.checked_add(50_000_000).ok_or(Error::Overflow)? {','if false {','active_accept_release_wall_overrun','release escaped original wall deadline'),
    ('if !registry_completed','if true','active_accept_release_overrun','left: Err(Budget)'),
    ('if crate::domain_tasks::scheduler_publication_matches(','if true || crate::domain_tasks::scheduler_publication_matches(','active_accept_contract_fallback','unmatched registration acquired Task guard'),
    ('is_some_and(|job| job.completion.is_some())','is_some_and(|_| false)','active_accept_delivery_busy','delivery retried completed publication'),
   ]
   for old,new,name,message in mutants:
    # The original checkpoint and enclosing charged cap must both lose the
    # same guard for these controls; the retry shares that original guard.
    count=3 if old in ('budget.check(observed)','if observed.wall_ns > job.started.checked_add(50_000_000).ok_or(Error::Overflow)? {') else 1
    self.assertEqual(original.count(old),count,'mutation anchor: '+old)
    source.write_text(original.replace(old,new))
    negative=subprocess.run(command[:-1]+[name],cwd=ROOT,env=e,capture_output=True,text=True,timeout=60)
    self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
    self.assertIn(message,negative.stdout+negative.stderr)
if __name__=='__main__':unittest.main()
