"""Actual control/prepare predicates; diagnostics never add owner queries."""
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


class PreexecutionPreparationTrace(unittest.TestCase):
    def test_actual_denials_and_prepare_waits_keep_original_work_and_identity(self):
        control=(ROOT/'kernel/src/domain_control.rs').read_text()
        root=(ROOT/'kernel/src/domain_control/replay.rs').read_text()
        owner=(ROOT/'kernel/src/learning_replay/owner.rs').read_text()
        task=(ROOT/'kernel/src/domain_tasks.rs').read_text()
        trace=(ROOT/'kernel/src/learning_evidence/execution_trace.rs').read_text()
        code=(ROOT/'tests/host/execution_trace_hooks_harness.rs').read_text().split('fn main()',1)[0]
        code=code.replace('// WARM_BODY',function((ROOT/'kernel/src/learning_workload/owner.rs').read_text(),'fn warm('))
        pieces=[re.search(r'^static LOCK:.*;$',task,re.M)[0], '#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks/owner_gate.rs'))+'] mod owner_gate;']
        pieces += [function(task,s) for s in ['struct Guard','impl Guard','impl Drop for Guard','fn acquire_guard()','fn locked<R>','fn locked_with_guard<R>','fn complete_locked(']]
        code=code.replace('// TASK_BODIES','\n'.join(pieces))
        predicate=function(control,'fn execution_blocks_replacement(').replace('fn execution_blocks_replacement(','fn real_execution_blocks_replacement(',1)
        pieces=[predicate,'fn execution_blocks_replacement(d:&Desired)->bool {PREP_CHECKS.fetch_add(1,Ordering::Relaxed);real_execution_blocks_replacement(d)}',function(control,'fn execution_limit('),function(control,'pub fn poll(')]
        code=code.replace('// CONTROL_BODIES','\n'.join(pieces)+'\n'+(ROOT/'tests/host/preexecution_preparation_support.rs').read_text())
        code=code.replace('struct State {owner:Owner,registry:Registry}','struct State {owner:Owner,registry:Registry,job:Option<()>}')
        code=code.replace('poll_cursor:usize,context:Context }','poll_cursor:usize,context:Context,prepared_count:usize }')
        code=code.replace('execution_observed:false})],','execution_observed:false})],')
        code=code.replace('context:Context {core_generation:1,ledger_generation:1}},registry:Registry});','context:Context {core_generation:1,ledger_generation:1},prepared_count:0},registry:Registry,job:None});')
        binding=function(code,'fn bind_dependencies(')
        code=code.replace(binding,'''fn bind_dependencies(_: &Owner,_:Action,_:ObjectKey,_:u64)->Result<[Option<u8>;2],Error>{
            BINDS.fetch_add(1,Ordering::Relaxed);match BIND_MODE.load(Ordering::Relaxed){1=>Err(Error::Busy),2=>Ok([Some(1),None]),_=>Ok([None;2])}
        }''')
        code=code.replace('fn apply(_:Action,_:ApplyId,_:PolicyStamp,_:u64)->Result<ExecutionState,Error>{','fn apply(_:Action,_:ApplyId,_:PolicyStamp,_:u64)->Result<ExecutionState,Error>{ APPLY_CALLS.fetch_add(1,Ordering::Relaxed);')
        # Root preparation scans a 16-slot owner, with the same actual Desired
        # type used above. The control poll still processes stability_high=1.
        code=code.replace('desired:[Option<Desired>;1]','desired:[Option<Desired>;16]')
        start=code.index('desired:[Some(Desired ')
        end=code.index('],\n        stability:',start)
        original=code[start+len('desired:['):end]
        code=code[:start]+'desired:{let mut rows=[None;16];rows[0]='+original+';rows}'+code[end+1:]
        poll=function(root,'pub fn poll_preparation(')
        prep_support=(ROOT/'tests/host/root_preparation_trace_support.rs').read_text()
        if 'service_entry_ns' in poll.split('{',1)[0]:
            prep_support=prep_support.replace('// POLL_CALL','poll_preparation(p,at)')
        else:
            prep_support=prep_support.replace('// POLL_CALL','{let _=at;poll_preparation(p)}')
        prep_support=prep_support.replace('// ROOT_PREPARATION',poll)
        # Trace identity is a pure copy of the actual preparation fields.
        if 'fn trace_preparation(' in root:
            prep_support=prep_support.replace('// PREP_IDENTITY',function(root,'fn trace_preparation('))
        else:
            prep_support=prep_support.replace('// PREP_IDENTITY','')
        code=code.replace('// ROOT_PREP_SUPPORT',prep_support)
        owner_support=(ROOT/'tests/host/owner_preparation_trace_support.rs').read_text()
        if 'fn prepare_step(' in owner:
            step=function(owner,'fn prepare_step(')
        else:
            arm=function(function(owner,'fn service('),'Phase::Prepare =>')
            step='fn prepare_step(trace:&mut diagnostic::Attempt)->Result<bool,DomainError>{'+arm[arm.index('{')+1:-1]+'\nOk(true)}'
        owner_support=owner_support.replace('// OWNER_PREP_STEP',step)
        dispatch=function(function(owner,'fn service('),'Phase::Prepare =>')
        owner_support=owner_support.replace('// OWNER_DISPATCH',dispatch)
        if 'fn trace_preparation(' in owner:
            owner_support=owner_support.replace('// PREP_IDENTITY',function(owner,'fn trace_preparation('))
        else:
            owner_support=owner_support.replace('// PREP_IDENTITY','')
        code+='\n'+owner_support
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            module=directory/'trace.rs'
            if 'pub struct ControlDenial' not in trace:
                trace+=(ROOT/'tests/host/preexecution_preparation_missing.rs').read_text()
            module.write_text(trace+'''
pub fn test_snapshots()->([u64;224],[u64;64],[u64;64]){
 (core::array::from_fn(|i|TRACE_CONTROL_EVIDENCE.get(i)),core::array::from_fn(|i|TRACE_PREPARATION_ROOT_EVIDENCE.get(i)),core::array::from_fn(|i|TRACE_PREPARATION_OWNER_EVIDENCE.get(i)))
}
pub fn test_reset(){
 for v in &TRACE_CONTROL_EVIDENCE.words{v.store(0,Ordering::Relaxed);}
 for v in &TRACE_PREPARATION_ROOT_EVIDENCE.words{v.store(0,Ordering::Relaxed);}
 for v in &TRACE_PREPARATION_OWNER_EVIDENCE.words{v.store(0,Ordering::Relaxed);}
}
''')
            code=code.replace('// TRACE_MODULE','#[path='+json.dumps(str(module))+'] pub(crate) mod trace;')
            code+='\nfn main(){let case=std::env::args().nth(1).unwrap_or("all".into());task::initialize();if case=="all"||case=="denial"{control::denial_scenarios();}if case=="all"||case=="root"{control::prep::scenarios();}if case=="all"||case=="owner"{owner_prepare::scenarios();}println!("preexecution and preparation facts passed");}\n'
            rust=directory/'harness.rs';rust.write_text(code)
            (directory/'Cargo.toml').write_text('[package]\nname="preexecution-preparation"\nversion="0.1.0"\nedition="2024"\n[[bin]]\nname="facts"\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'run','--offline','--manifest-path',str(directory/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-preexecution-preparation'),'--bin','facts']
            def run(source,case='all'):
                rust.write_text(source)
                return subprocess.run(command+['--',case],cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            results=[run(code,case) for case in ['denial','root','owner']]
            self.assertTrue(all(result.returncode==0 for result in results), '\n'.join(result.stdout+result.stderr for result in results))
            for result in results:self.assertIn('preexecution and preparation facts passed',result.stdout)
            for signature,failure in [('crate::learning_evidence::execution_trace::control_denied(','pre-executor rejection was not retained'),('crate::learning_evidence::execution_trace::preparation_root(','actual preparation blocker was not retained'),('capture::execution_trace::preparation_owner(','outer preparation result was not retained')]:
                start=code.index(signature);depth=1;end=start+len(signature)
                while depth:
                    if code[end]=='(':depth+=1
                    elif code[end]==')':depth-=1
                    end+=1
                self.assertEqual(code[end],';')
                negative=run(code[:start]+code[end+1:])
                self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
                self.assertIn(failure,negative.stdout+negative.stderr)
            self.assertEqual(code.count('return prepare_step(trace);'),1)
            negative=run(code.replace('return prepare_step(trace);','return Ok(false);'),'owner')
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('outer preparation result was not retained',negative.stdout+negative.stderr)


if __name__=='__main__':unittest.main()
