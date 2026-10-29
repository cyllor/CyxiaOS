"""Actual Work poll, Task query and lifecycle hooks; hardware is controlled."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class DrainCustodyTrace(unittest.TestCase):
    def test_actual_custody_boundaries_publish_without_changing_results(self):
        work = (ROOT/'kernel/src/learning_workload/owner.rs').read_text()
        replay = (ROOT/'kernel/src/domain_tasks/replay.rs').read_text()
        execution = (ROOT/'kernel/src/domain_tasks/execution.rs').read_text()
        task = (ROOT/'kernel/src/domain_tasks.rs').read_text()
        trace = (ROOT/'kernel/src/learning_evidence/execution_trace.rs').read_text()
        template = (ROOT/'tests/host/drain_custody_trace_harness.rs').read_text()
        work_body = function(work, 'pub fn poll(').replace('#[cfg(not(test))]', '')
        query_body = function(replay, 'pub fn spawn_result(').replace('#[cfg(not(test))]', '')
        helper = function(replay, 'pub(super) fn drain_task_facts(').replace('#[cfg(not(test))]', '') if 'fn drain_task_facts(' in replay else 'pub(super) fn drain_task_facts(_: &State,_:usize)->Option<crate::trace::DrainTask>{None}'
        bodies = '\n'.join(function(execution, s).replace('#[cfg(not(test))]', '') for s in ['fn cleanup(', 'fn lifecycle_piece('])
        task_bodies = '\n'.join(function(task, s) for s in ['struct Guard','impl Guard','impl Drop for Guard','fn acquire_guard()', 'fn locked<R>','fn locked_with_guard<R>'])
        task_bodies = 'static LOCK: owner_gate::Gate = owner_gate::Gate::new();\n' + task_bodies
        template = template.replace('// OWNER_GATE', '#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks/owner_gate.rs'))+'] mod owner_gate;')
        template = template.replace('// WORK_POLL', work_body).replace('// SPAWN_QUERY', query_body+'\n'+helper)
        template = template.replace('// TASK_BODIES', task_bodies+'\n'+bodies)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            module = directory/'trace.rs'
            if 'pub struct WorkWait' not in trace:
                trace += (ROOT/'tests/host/drain_trace_missing.rs').read_text()
            module.write_text(trace+'''
pub fn drain_snapshots()->([u64;64],[u64;128]) {
 (core::array::from_fn(|i|TRACE_DRAIN_WORK_EVIDENCE.words[i].load(Ordering::Acquire)),
  core::array::from_fn(|i|TRACE_DRAIN_TASK_EVIDENCE.words[i].load(Ordering::Acquire)))
}
pub fn reset_for_host() {
 for v in &TRACE_CONTROL_EVIDENCE.words {v.store(0,Ordering::Relaxed);}
 for v in &TRACE_CLOSING_EVIDENCE.words {v.store(0,Ordering::Relaxed);}
 for v in &TRACE_WORK_EVIDENCE.words {v.store(0,Ordering::Relaxed);}
 for v in &TRACE_TASK_EVIDENCE.words {v.store(0,Ordering::Relaxed);}
 for v in &TRACE_DRAIN_WORK_EVIDENCE.words {v.store(0,Ordering::Relaxed);}
 for v in &TRACE_DRAIN_TASK_EVIDENCE.words {v.store(0,Ordering::Relaxed);}
}
pub fn closing_identity_for_host()->(u64,u64) {
 (TRACE_CLOSING_EVIDENCE.get(14),TRACE_WORK_EVIDENCE.get(37))
}
pub fn interrupted_work_publication(odd:bool) {
 TRACE_DRAIN_WORK_EVIDENCE.words[63].fetch_add(1,Ordering::AcqRel);
 assert_eq!(TRACE_DRAIN_WORK_EVIDENCE.get(63)&1,u64::from(odd));
}
''')
            template = template.replace('// TRACE_MODULE', '#[path='+json.dumps(str(module))+'] mod trace;')
            rust = directory/'harness.rs'
            rust.write_text(template)
            (directory/'Cargo.toml').write_text('[package]\nname="drain-custody-trace"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
            command = [str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(directory/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-drain-custody-trace'),'--','--test-threads=1']
            def run(code, name=None):
                rust.write_text(code)
                return subprocess.run(command+(['--exact',name] if name else []),cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            result = run(template)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('4 passed; 0 failed',result.stdout)
            for signature,name,failure in [
                ('evidence::execution_trace::drain_work(', 'work_poll_distinguishes_request_and_warm_custody', 'actual Work wait facts were absent'),
                ('crate::learning_evidence::execution_trace::drain_query(', 'actual_spawn_query_keeps_identity_and_never_consumes_an_extra_outcome', 'actual spawn query facts were absent'),
                ('crate::learning_evidence::execution_trace::drain_lifecycle(', 'actual_lifecycle_and_cleanup_keep_the_original_child', 'actual lifecycle selection facts were absent'),
                ('crate::learning_evidence::execution_trace::drain_cleanup(', 'actual_lifecycle_and_cleanup_keep_the_original_child', 'actual cleanup result facts were absent'),
            ]:
                # Remove exactly the actual reporting statement, retaining all
                # business operations and external controlled boundaries.
                start=template.index(signature)
                depth=0; end=start
                for end in range(start+len(signature)-1,len(template)):
                    if template[end]=='(': depth+=1
                    elif template[end]==')':
                        depth-=1
                        if depth==0: break
                self.assertEqual(template[end+1],';')
                negative=run(template[:start]+template[end+2:],name)
                self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
                self.assertIn(failure,negative.stdout+negative.stderr)


if __name__ == '__main__':
    unittest.main()
