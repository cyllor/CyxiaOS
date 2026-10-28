"""Bounded first-trial timing facts, distinct from execution authority."""
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class ExecutionTrace(unittest.TestCase):
    def test_production_poll_warm_and_task_gate_settlement_emit_the_actual_times(self):
        task = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        control = (ROOT / 'kernel/src/domain_control.rs').read_text()
        work = (ROOT / 'kernel/src/learning_workload/owner.rs').read_text()
        pieces = [re.search(r'^static LOCK:.*;$', task, re.M)[0]]
        pieces.append('#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs')) + '] mod owner_gate;')
        pieces += [function(task, s) for s in ['struct Guard', 'impl Guard', 'impl Drop for Guard',
            'fn acquire_guard()', 'fn locked<R>', 'fn locked_with_guard<R>', 'fn complete_locked(']]
        program = (ROOT / 'tests/host/execution_trace_hooks_harness.rs').read_text().replace(
            '// TASK_BODIES', '\n'.join(pieces)).replace('// CONTROL_BODIES', '\n'.join(
                function(control, s) for s in ['fn execution_blocks_replacement(', 'fn execution_limit(', 'pub fn poll('])).replace(
            '// WARM_BODY', function(work, 'fn warm('))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            trace = directory / 'trace.rs'
            trace.write_text((ROOT / 'kernel/src/learning_evidence/execution_trace.rs').read_text() + '''
pub fn snapshots() -> ([u64;224],[u64;128],[u64;64]) {
    (core::array::from_fn(|i|TRACE_CONTROL_EVIDENCE.words[i].load(Ordering::Acquire)),
     core::array::from_fn(|i|TRACE_TASK_EVIDENCE.words[i].load(Ordering::Acquire)),
     core::array::from_fn(|i|TRACE_WORK_EVIDENCE.words[i].load(Ordering::Acquire)))
}
''')
            program = program.replace('// TRACE_MODULE', '#[path=' + json.dumps(str(trace)) + '] pub(crate) mod trace;')
            rust = directory / 'harness.rs'
            rust.write_text(program)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="execution-trace-hooks"\nversion="0.1.0"\nedition="2024"\n'
                '[[bin]]\nname="hooks"\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'run', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-execution-trace-hooks'), '--bin', 'hooks']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('production execution hooks passed', result.stdout)
            for signature, failure in [
                ('if let Some(before_version) = before_version', 'actual settlement hook lost physical or observed time'),
                ('if let Some(scope) = s.scope', 'actual warm submit hook was absent'),
                ('if let (Some(scope), Ok(Some(result)))', 'actual warm outcome hook lost completion/observation distinction'),
                ('if let Some((entered_ns, cpu_ns)) = executor_trace', 'actual control poll did not retain its execution hook'),
            ]:
                body = function(program, signature)
                rust.write_text(program.replace(body, 'if false {}', 1))
                negative = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
                self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
                self.assertIn(failure, negative.stdout + negative.stderr)
            rust.write_text(program)
            trace_original=trace.read_text()
            qualification=function(trace_original,'pub fn tracks_dispatch(')
            trace.write_text(trace_original.replace(qualification,
                'pub fn tracks_dispatch(d: Dispatch) -> bool { first_dispatch(d) }'))
            negative=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('production closing settlement hook was gated out',negative.stdout+negative.stderr)

    def test_first_trial_keeps_execution_settlement_and_observation_distinct(self):
        source = ROOT / 'kernel/src/learning_evidence/execution_trace.rs'
        template = (ROOT / 'tests/host/execution_trace_harness.rs').read_text()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            module = directory / 'trace.rs'
            if source.exists():
                closing = (ROOT / 'tests/host/closing_trace_missing.rs').read_text() if (
                    'pub fn closing(' not in source.read_text()) else '''
pub fn admission_snapshot() -> [u64;64] {
    core::array::from_fn(|i|TRACE_CLOSING_EVIDENCE.words[i].load(Ordering::Acquire))
}
'''
                if 'pub fn probe_caller(' not in source.read_text():
                    closing += 'pub fn probe_caller(_:RunKey,_:u64,_:ObjectKey,_:u64) {}\n'
                module.write_text(source.read_text() + closing + '''
pub fn snapshots() -> ([u64; 224], [u64; 128], [u64; 64]) {
    (core::array::from_fn(|i| TRACE_CONTROL_EVIDENCE.words[i].load(Ordering::Acquire)),
     core::array::from_fn(|i| TRACE_TASK_EVIDENCE.words[i].load(Ordering::Acquire)),
     core::array::from_fn(|i| TRACE_WORK_EVIDENCE.words[i].load(Ordering::Acquire)))
}
''')
            else:
                # A no-observation adapter keeps pre-feature code executable:
                # the RED is the missing fact, not an unresolved symbol.
                module.write_text((ROOT / 'tests/host/execution_trace_missing.rs').read_text())
            (directory / 'harness.rs').write_text(template.replace('// TRACE_MODULE',
                '#[path=' + json.dumps(str(module)) + '] mod trace;'))
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="execution-trace"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-execution-trace'), '--lib', '--', '--test-threads=1']
            result = subprocess.run(command,
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('1 passed; 0 failed', result.stdout)
            original = module.read_text()
            self.assertIn('e.physical_finished_ns,', original)
            module.write_text(original.replace('e.physical_finished_ns,', 'e.settled_ns,'))
            negative = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                      text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('physical completion was replaced by settlement time',
                          negative.stdout + negative.stderr)
            matching=function(original,'fn probe_matches(')
            module.write_text(original.replace(matching,'''fn probe_matches(group:ObjectKey,_caller:ObjectKey,id:u64)->bool {
    closing_active() && TRACE_WORK_EVIDENCE.get(40)==id && target_matches(group)
}'''))
            negative=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('foreign caller occupied closing probe child record',negative.stdout+negative.stderr)


if __name__ == '__main__':
    unittest.main()
