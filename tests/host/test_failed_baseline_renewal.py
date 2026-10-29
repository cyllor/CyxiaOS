"""Actual Control poll, Root receipt refresh arm and baseline_apply.

Registry publication, authorization, configuration scanning and hardware are
explicit counted boundaries. This fixture does not establish their native WCET.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class FailedBaselineRenewal(unittest.TestCase):
    def test_failed_unstarted_renewal_is_not_an_installed_lease(self):
        template = (ROOT / 'tests/host/execution_trace_hooks_harness.rs').read_text()
        control = (ROOT / 'kernel/src/domain_control.rs').read_text()
        replay = (ROOT / 'kernel/src/domain_control/replay.rs').read_text()
        prefix = template[:template.index('mod task {')]
        body = function(template, 'mod control {')
        body = body.replace(function(body, 'fn apply('), '''fn apply(_:Action,_:ApplyId,_:PolicyStamp,_:u64)->Result<ExecutionState,Error>{
            APPLY_CALLS.fetch_add(1,Ordering::Relaxed); match APPLY_MODE.load(Ordering::Relaxed){1=>Ok(ExecutionState::Pending),2=>Err(Error::NotReady),3=>Err(Error::Stale),_=>Ok(ExecutionState::Applied)}
        }''')
        body = body.replace(function(body, 'fn reconcile(_:Action'), '''fn reconcile(_:Action,_:ApplyId,_:PolicyStamp,_:u64)->Result<ExecutionState,Error>{
            RECONCILE_CALLS.fetch_add(1,Ordering::Relaxed); Ok(ExecutionState::Applied)
        }''')
        body = body.replace('struct Context {core_generation:u64,ledger_generation:u64}',
            '#[derive(Clone,Copy)] struct Context {core_generation:u64,ledger_generation:u64,control_mask:u64,business_mask:u64}')
        body = body.replace('context:Context {core_generation:1,ledger_generation:1}',
            'context:Context {core_generation:1,ledger_generation:1,control_mask:6,business_mask:9}')
        body = body.replace('struct State {owner:Owner,registry:Registry}',
            'struct State {owner:Owner,registry:Registry,job:Option<()>}')
        body = body.replace('poll_cursor:usize,context:Context }',
            'poll_cursor:usize,context:Context,prepared_count:usize }')
        body = body.replace('business_mask:9}},registry:Registry});',
            'business_mask:9},prepared_count:0},registry:Registry,job:None});')
        body = body.replace('// CONTROL_BODIES', '\n'.join(function(control, sig) for sig in [
            'fn execution_blocks_replacement(', 'fn execution_limit(', 'pub fn publish_context(', 'pub fn poll('])
            + '\n' + (ROOT / 'tests/host/failed_baseline_renewal_support.rs').read_text())
        # Execute the unchanged real running/restoring arm, including receipt
        # refresh and closing completion, instead of assigning cached failures.
        arm = function(function(replay, 'pub fn poll(token:'),
            'Phase::Frozen | Phase::Running | Phase::Restoring =>')
        body = body.replace('// ROOT_RUNNING_ARM', arm)
        body = body.replace('// ROOT_BODIES', '\n'.join(function(replay, sig) for sig in [
            'fn receipt(\n', 'fn latest(', 'impl Receipt {', 'pub fn baseline_apply(', 'pub fn restore(']))
        trace = ROOT / 'kernel/src/learning_evidence/execution_trace.rs'
        prefix = prefix.replace('// TRACE_MODULE', '#[path=' + json.dumps(str(trace)) + '] mod trace;')
        code = prefix + body + '\nfn main(){control::renewal::scenarios();}\n'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / 'harness.rs'
            source.write_text(code)
            (directory / 'Cargo.toml').write_text('[package]\nname="failed-baseline-renewal"\nversion="0.1.0"\nedition="2024"\n[[bin]]\nname="renewal"\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path=' + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'run', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-failed-baseline-renewal')]
            results = [subprocess.run(command + ['--', case], cwd=ROOT, env=env(),
                capture_output=True, text=True, timeout=120) for case in ['renewal', 'guards', 'capacity']]
            self.assertTrue(all(result.returncode == 0 for result in results),
                '\n'.join(result.stdout + result.stderr for result in results))
            for result in results:
                self.assertIn('failed renewal custody scenarios passed', result.stdout)
            mutants = [
                (re.sub(r'let unstarted_failed_renewal =.*?;',
                    'let unstarted_failed_renewal = false;', code, count=1, flags=re.S),
                    'renewal', 'failed renewal future stamp blocked an independent successor'),
                (code.replace('&& old.started_ns.is_none()', ''), 'guards',
                    'pending, unknown or started failure lost custody'),
                (code.replace('prior.stamp.live(at)', 'true'), 'guards',
                    'expired earlier installation authorized recovery of a coverage gap'),
                (code.replace('&& prior.apply.target == old.apply.target', ''), 'guards',
                    'unrelated installation authorized renewal'),
                (re.sub(r'r.baseline\[i\] =\s*Some\(receipt\(s, old.apply, old.stamp, old.snapshot, old.action\)\?\);',
                    'let next=receipt(s, old.apply, old.stamp, old.snapshot, old.action)?; if !matches!(next.state,ExecutionState::Failed(_)){r.baseline[i]=Some(next);}',
                    code, count=1), 'renewal', 'Root poll did not synchronize the real denial'),
                (code.replace('return Err(Error::Capacity);', '/* removed capacity denial */'),
                    'capacity', 'full receipt cache reached publication'),
                (code.replace('r.baseline[r.baseline_count] = Some(value);',
                    'r.baseline[if r.baseline_count<2 {r.baseline_count} else {r.baseline_count-1}] = Some(value);'),
                    'renewal', 'successor overwrote retained failed receipt'),
            ]
            for mutant, case, failure in mutants:
                self.assertNotEqual(mutant, code, failure)
                source.write_text(mutant)
                negative = subprocess.run(command + ['--', case], cwd=ROOT, env=env(),
                    capture_output=True, text=True, timeout=120)
                self.assertNotEqual(negative.returncode, 0, failure)
                self.assertIn(failure, negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
