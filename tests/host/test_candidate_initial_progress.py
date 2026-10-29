"""Submitted initial custody, real Control poll/Task settlement, exact Activate arm.

Registry/resource/hardware/capture boundaries are explicit; host timing is not WCET.
"""
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from test_governance_billing_priority import function


def root_support(observe_stale=False):
    replay=(ROOT/'kernel/src/domain_control/replay.rs').read_text()
    control=(ROOT/'kernel/src/domain_control.rs').read_text()
    support=(ROOT/'tests/host/candidate_initial_support.rs').read_text()
    initial='#[derive(Clone,Copy)] struct CandidatePublication;'
    if 'struct CandidatePublication' in replay:
        initial='#[derive(Clone,Copy)]\n'+function(replay,'struct CandidatePublication')
    hook='pub(super) fn candidate_execution(_:ApplyId,_:PolicyStamp,_:ExecutionState) {}'
    if 'fn candidate_execution(' in replay: hook=function(replay,'pub(super) fn candidate_execution(')
    support=support.replace('// CANDIDATE_GUARD',function(control,'impl Drop for Guard').replace('impl Drop for Guard','struct Guard;\nimpl Drop for Guard'))
    support=support.replace('// CANDIDATE_TOKEN','#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'+function(replay,'pub struct Token'))
    support=support.replace('// CANDIDATE_INITIAL_TYPE',initial)
    support=support.replace('// CANDIDATE_ROOT_BODIES','\n'.join([
        re.search(r'^static BASELINE_ACTIVATION_PENDING:.*;$',replay,re.M)[0],
        function(replay,'pub(super) fn publish_baseline_activation_hint('),
        function(replay,'pub fn baseline_activation_pending('),function(replay,'pub(super) fn published('),hook]))
    stale='pub(super) fn candidate_stale<T>(_: &T) {}'
    if observe_stale and 'fn candidate_stale(' in replay:stale=function(replay,'pub(super) fn candidate_stale(')
    support=support.replace('// CANDIDATE_STALE_HOOK',stale)
    support=support.replace('// CANDIDATE_STALE_CASE',(ROOT/'tests/host/candidate_stale_support.rs').read_text() if observe_stale else '')
    extra=', stamp' if 'first_stamp: Option<PolicyStamp>' in replay else ''
    return support.replace('// CANDIDATE_PUBLISHED_CALL',f'published(&plan,id.boot_epoch{extra})?;')


class CandidatePublicationProgress(unittest.TestCase):
    def test_actual_candidate_custody_uses_existing_paid_progress_pieces(self):
        task=(ROOT/'kernel/src/domain_tasks.rs').read_text()
        execution=(ROOT/'kernel/src/domain_tasks/execution.rs').read_text()
        unified=(ROOT/'kernel/src/unified.rs').read_text()
        owner=(ROOT/'kernel/src/learning_replay/owner.rs').read_text()
        control=(ROOT/'kernel/src/domain_control.rs').read_text()
        pieces=['static LOCK: ResettableGate = ResettableGate(core::cell::UnsafeCell::new(owner_gate::Gate::new()));']
        for sig in ['struct Guard','impl Guard','impl Drop for Guard','fn acquire_guard()',
            'fn locked<R>','fn locked_with_guard<R>','pub struct Credit','fn admit_service(',
            'pub fn begin_service_segment()','fn revalidate_unstarted(','pub fn revalidate_service_segment()',
            'pub(crate) struct PaidServiceWitness','fn service_witness_locked(','pub fn authorize_service_turn()',
            'pub fn complete_builtin(','pub fn complete_service(','pub fn service_segment<R>']:
            pieces.append(function(task,sig))
        for sig in ['pub fn service_io_piece<R>','fn service_baseline_activation(',
            'fn advance_admission_bounded(','fn submit_package(','pub fn service_baseline_progress(',
            'struct BaselineRetryGuard','impl Drop for BaselineRetryGuard','fn enter_baseline_retry(',
            'fn service_baseline_activation_at(']:
            pieces.append(function(execution,sig).replace('super::deadline::','deadline::'))
        pieces += [re.search(r'^static BASELINE_RETRY_ACTIVE:.*;$',execution,re.M)[0],
            '#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks/deadline.rs'))+'] mod deadline;',
            'fn lifecycle_turn(_: &mut State) {panic!("lifecycle outside candidate fixture")}']
        pieces += [function(unified,sig) for sig in ['fn mechanism_progress(','fn progress(',
            'fn finish_service(','fn service_work<R>','fn service_start(']]
        modules='\n'.join('#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks'/name))+'] mod '+name[:-3]+';' for name in ['owner_gate.rs','service_authority.rs'])
        program=(ROOT/'tests/host/baseline_progress_harness.rs').read_text().replace('// PRODUCTION_BODIES',modules+'\n'+'\n'.join(pieces))
        replay='struct Guard;\n'+'\n'.join(function(owner,sig) for sig in ['impl Drop for Guard','fn lock()','fn with<T>','pub fn service_step()','fn publish_drain_hint(','pub(super) fn drain_pending('])
        replay+='\n'+re.search(r'^static DRAIN_PENDING:.*;$',owner,re.M)[0]
        program=program.replace('// REPLAY_BODIES',replay)
        facade=(ROOT/'kernel/src/learning_replay.rs').read_text()
        program=program.replace('// REPLAY_HINT_READER',function(facade,'pub fn baseline_activation_pending(')+'\npub fn owned_drain_pending()->bool{false}')
        reader=function(program,'mod domain_control {')
        program=program.replace(reader,'''mod domain_control {pub mod replay {pub fn baseline_activation_pending()->bool{
            if super::super::CANDIDATE_MODE.load(super::super::Ordering::Acquire){super::super::candidate::pending()}
            else{super::super::HINT.load(super::super::Ordering::Acquire)}}}}''')
        # The service body is the explicit owner/capture facade; real warm and
        # all paid wrappers execute after this branch, outside Root's gate.
        program=program.replace('            HINT.store(KEEP_HINT.load(Ordering::Acquire), Ordering::Release); Ok(true)',
            '            if CANDIDATE_MODE.load(Ordering::Acquire){candidate_warm::advance()?;}\n            HINT.store(KEEP_HINT.load(Ordering::Acquire), Ordering::Release); Ok(true)')
        support=(ROOT/'tests/host/candidate_paid_support.rs').read_text()
        support=support.replace('// PAID_CONTROL_WITH',function(control,'fn with<T>'))
        support=support.replace('// PAID_ROOT_SUPPORT',root_support().split('pub fn candidate_poll_scenario()',1)[0])
        warm=function((ROOT/'kernel/src/learning_workload/owner.rs').read_text(),'fn warm(')
        support=support.replace('// PAID_REAL_WARM',warm)
        # Use a const key in the fixture's static ID, never alter real ApplyId.
        support=support.replace('action_index:0,target:group(12)','action_index:0,target:key(12)')
        program+='\n#[path='+json.dumps(str(ROOT/'kernel/src/learning_evidence/execution_trace.rs'))+'] pub(crate) mod candidate_trace;\n'+support
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);source=d/'harness.rs';source.write_text(program)
            (d/'Cargo.toml').write_text('[package]\nname="candidate-paid-progress"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-candidate-paid-progress'),'--','--test-threads=1','candidate_']
            r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertIn('4 passed; 0 failed',r.stdout)
            for old,new,case,failure in [
                ('    crate::domain_tasks::service_baseline_progress();','',
                 'actual_candidate_publication_flows_through_fresh_helper_warm_admission_and_policy_receipt','candidate warm never reached real admission'),
                ('advance_admission_bounded(s, 1, 1)','advance_admission_bounded(s, 0, 1)',
                 'actual_candidate_publication_flows_through_fresh_helper_warm_admission_and_policy_receipt','candidate warm never reached real admission'),
                ('        return;\n    };\n    let hint = crate::learning_replay::baseline_activation_pending();',
                 '        return;\n    };\n    drop(_entry);\n    let hint = crate::learning_replay::baseline_activation_pending();',
                 'candidate_old_bill_credit_denial_and_recursive_entry_preserve_original_custody','recursive progress replaced the outer diagnostic ticket'),
            ]:
                self.assertEqual(program.count(old),1)
                source.write_text(program.replace(old,new))
                negative=subprocess.run(command[:-1]+['--exact',case],cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
                self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
                self.assertIn(failure,negative.stdout+negative.stderr)

    def test_submitted_identity_terminal_updates_and_prepublication_activate(self):
        task=(ROOT/'kernel/src/domain_tasks.rs').read_text()
        control=(ROOT/'kernel/src/domain_control.rs').read_text()
        owner=(ROOT/'kernel/src/learning_replay/owner.rs').read_text()
        template=(ROOT/'tests/host/execution_trace_hooks_harness.rs').read_text()
        pieces=[re.search(r'^static LOCK:.*;$',task,re.M)[0],
            '#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks/owner_gate.rs'))+'] mod owner_gate;']
        pieces += [function(task,s) for s in ['struct Guard','impl Guard','impl Drop for Guard',
            'fn acquire_guard()','fn locked<R>','fn locked_with_guard<R>','fn complete_locked(']]
        program=template[:template.index('mod warm {')]
        program=program.replace(function(program,'mod replay {'),'')
        program=program.replace('// TRACE_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/learning_evidence/execution_trace.rs'))+'] pub(crate) mod trace;')
        program=program.replace('// TASK_BODIES','\n'.join(pieces))
        program=program.replace('struct State {owner:Owner,registry:Registry}', 'pub struct State {owner:Owner,registry:Registry}')
        program=program.replace('struct Registry; impl Registry {','static REGISTRY_FAIL:AtomicBool=AtomicBool::new(false);\nstruct Registry; impl Registry {')
        program=program.replace('fn reconcile(&mut self,_:ApplyId,_:u64,_:ExecutionState)->Result<(),Error>{Ok(())}',
            'fn reconcile(&mut self,_:ApplyId,_:u64,_:ExecutionState)->Result<(),Error>{if REGISTRY_FAIL.load(Ordering::Acquire){Err(Error::Stale)}else{Ok(())}}')
        program=program.replace('// CONTROL_BODIES','\n'.join(function(control,s) for s in [
            'fn execution_blocks_replacement(','fn execution_limit(','pub fn poll('])+root_support(True))
        # Execute native precommit through the actual post-commit Root hook.
        # Desired writes after that hook remain the original Control fixture's
        # explicit publication boundary; commit itself is a counted facade.
        publication=(ROOT/'tests/host/native_publication_clock_harness.rs').read_text()
        publication=publication.replace('#![allow(dead_code)]','').replace('extern crate self as cyxia_arch_aarch64;','')
        publication=publication.replace('use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};',
            'use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};\nuse super::replay;')
        publication=publication.replace('// NATIVE_CLOCK',function(control,'impl policy::Clock for NativeClock'))
        publication=publication.replace('// SUBMISSION_TRACE_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/domain_control/submission.rs'))+'] mod submission;')
        publish=function(control,'fn publish(&mut self, plan: &Plan, version: u64, at: u64)')
        cutoff=publish.index('        for (index, d) in plan.iter().enumerate() {',publish.index('self.scope.commit('));cutoff=publish.rfind('\n',0,cutoff)+1
        suffix=publish[publish.rfind('\n        })();'):] if 'let result = (|| {' in publish else '\n}'
        publish=publish[:cutoff]+'self.published+=1;Ok(())'+suffix
        publication=publication.replace('// NATIVE_PRECOMMIT',publish)
        publication=publication.replace('wall_deadline: u64, published: usize,','wall_deadline: u64, published: usize,boot:u64,')
        publication=publication.replace('wall_deadline: 150_000_000, published: 0','wall_deadline: 150_000_000, published: 0,boot:7')
        publication=publication.replace('id: 1, generation: 1','id: 12, generation: 1').replace('plan_seq: 1,','plan_seq: 51,')
        publication=publication.replace('controller_epoch: 1,','controller_epoch: 2,').replace('snapshot_seq: 1,','snapshot_seq: 51,')
        publication+='''
impl Scope {fn commit(&self,_:&Owner,_:ModelBinding,_:&Plan,stamps:&[PolicyStamp],boot:u64,_:u64)->Result<(),Error>{
    assert_eq!(boot,7);assert_eq!(stamps.first().copied(),Some(super::STAMP));
    assert!(!replay::baseline_activation_pending(),"initial hint preceded commit");Ok(())}}
pub fn scenario(){replay::reset();let(mut executor,wire)=fixture(100,1);
    super::with(|_|executor.publish(&policy_wire::decode_plan(&wire).unwrap(),41,100_000_010)).unwrap();
    assert!(replay::baseline_activation_pending(),"native publication did not bind its actual initial stamp");
    println!("candidate native publication bridge passed");}
'''
        program=program.replace('    pub fn observe(){poll(now()).unwrap();}',
            '    pub fn observe(){poll(now()).unwrap();}\n pub mod publication{'+publication+'}\n')
        program=program.replace(function(program,'mod domain_evidence {'),'// ACTUAL_DOMAIN_EVIDENCE')
        program+='\nmod domain_platform {pub fn now_ns()->u64{super::now()}}\n'
        program=program.replace('fn bind_dependencies(_: &Owner,_:Action,_:ObjectKey,_:u64)->Result<[Option<u8>;2],Error>{Ok([None;2])}',
            'static BIND_MODE:AtomicU64=AtomicU64::new(0);\nfn bind_dependencies(_: &Owner,_:Action,_:ObjectKey,_:u64)->Result<[Option<u8>;2],Error>{match BIND_MODE.load(Ordering::Acquire){2=>Err(Error::Stale),4=>Ok([Some(1),None]),_=>Ok([None;2])}}')
        old='fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{let mut guard=STATE.try_lock().map_err(|_|Error::Busy)?;f(&mut guard)}'
        program=program.replace(old,'''pub fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{
            let mut guard=STATE.try_lock().map_err(|_|Error::Busy)?;
            CLAIMED.store(true,Ordering::Release);let _root_guard=Guard;f(&mut guard)}''')
        arm=function(owner,'Phase::Activate =>')
        program+=(ROOT/'tests/host/candidate_activate_support.rs').read_text().replace('// CANDIDATE_ACTIVATE_ARM',arm)
        program+='\nfn main(){trace::begin(RUN,Family{domain:1,kind:1},key(12),STAMP.snapshot_ns);task::initialize();match std::env::args().nth(1).unwrap_or_default().as_str(){"denial_scope"=>control::replay::stale_scope_scenario(),"root"=>control::replay::scenario(),"renewal"=>control::replay::renewal_scenario(),"publish"=>control::publication::scenario(),"activate"=>candidate_owner::scenario(),_=>control::candidate_poll_scenario()}}\n'
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);evidence=d/'evidence.rs'
            evidence.write_text((ROOT/'kernel/src/domain_evidence.rs').read_text()+'\npub fn candidate_stale_header()->[u64;36]{core::array::from_fn(|i|get(220+i))}\n')
            program=program.replace('// ACTUAL_DOMAIN_EVIDENCE','#[path='+json.dumps(str(evidence))+'] mod domain_evidence;')
            source=d/'harness.rs';source.write_text(program)
            (d/'Cargo.toml').write_text('[package]\nname="candidate-initial"\nversion="0.1.0"\nedition="2024"\n[[bin]]\nname="initial"\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'run','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-candidate-initial')]
            failures=[]
            for case in ['denial_scope','denial_core','denial_ledger','denial_binder','denial_binding','denial_executor','root','renewal','renewal_stale','publish','activate','stale','failed','busy','deadline','unknown','applied','registry']:
                r=subprocess.run(command+['--',case],cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
                if r.returncode: failures.append(case+'\n'+r.stdout+r.stderr)
            self.assertFalse(failures,'\n'.join(failures))
            hook='            replay::candidate_execution(d.apply, d.stamp, d.state);'
            mutants=[
                (program.replace('        replay::published(plan, self.boot, stamps[..plan.len()].first().copied())?;',''),
                 'publish','native publication did not bind its actual initial stamp'),
                (program.replace('replay::published(plan, self.boot, stamps[..plan.len()].first().copied())?',
                    'replay::published(plan, self.boot, None)?'),
                 'publish','native publication did not bind its actual initial stamp'),
                (program.replace(hook,''),'stale','real final Control state did not update the initial hint'),
                (program.replace('                replay::candidate_stale(&denial);',''),'denial_ledger','actual candidate pre-executor Stale lost its original denial facts'),
                (program.replace(function(program,'pub(super) fn candidate_stale('),'pub(super) fn candidate_stale<T>(_:&T){}'),'denial_core','actual candidate pre-executor Stale lost its original denial facts'),
                (program.replace('e.current_ledger,','e.expected_ledger,'),'denial_ledger','assertion `left == right` failed'),

                (program.replace(hook,'if d.apply.plan_seq==51{'+hook+'}'),'renewal_stale','real final Control state did not update the initial hint'),
                (program.replace('old.state.terminal()','true'),'renewal','new publication replaced an unresolved renewal'),
                (program.replace('first.plan_seq <= apply.plan_seq','first.plan_seq == apply.plan_seq'),'renewal','terminal actual renewal retained priority'),
                (program.replace('initial.apply.plan_seq > first_apply.plan_seq','false'),'renewal','actual candidate renewal lost its paid progress opportunity'),
                (program.replace('        if first {','        if true {'),'renewal','renewal replaced the original captured first identity'),

                (program.replace(hook,'if executor_trace.is_some(){'+hook+'}'),'stale','real final Control state did not update the initial hint'),
                (program.replace(hook,'').replace('            d.observed_ns = observed;',hook+'\n            d.observed_ns = observed;'),
                 'deadline','real final Control state did not update the initial hint'),
                (program.replace('&& !initial.state.terminal()',''),'root','terminal initial was resurrected by a delayed update'),
                (program.replace('        replay::publish_baseline_activation_hint();',''),'root','submitted candidate initial lost its progress opportunity'),
                (program.replace('if !root::publication_started(token)? {','if false {'),'activate','candidate business started before publication committed'),
            ]
            for mutant,case,failure in mutants:
                self.assertNotEqual(mutant,program)
                source.write_text(mutant)
                negative=subprocess.run(command+['--',case],cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
                self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
                self.assertIn(failure,negative.stdout+negative.stderr)
            original_evidence=evidence.read_text();self.assertIn('if get(223) == 0 {',original_evidence)
            evidence.write_text(original_evidence.replace('if get(223) == 0 {','if true {'))
            source.write_text(program)
            negative=subprocess.run(command+['--','denial_scope'],cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('first candidate stale facts were overwritten',negative.stdout+negative.stderr)


if __name__=='__main__':unittest.main()
