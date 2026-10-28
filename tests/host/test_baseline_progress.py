"""Actual progress boundary and suspended service ownership over real Scheduler.

Root body/hardware/capture are controlled facades; production admission,
authorization, completion publication, replay exclusion and I/O wrappers run.
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


class BaselineProgress(unittest.TestCase):
    def test_real_progress_boundary_retains_bills_and_prevents_recursive_entry(self):
        task = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        execution = (ROOT / 'kernel/src/domain_tasks/execution.rs').read_text()
        unified = (ROOT / 'kernel/src/unified.rs').read_text()
        owner = (ROOT / 'kernel/src/learning_replay/owner.rs').read_text()
        pieces = ['static LOCK: ResettableGate = ResettableGate(core::cell::UnsafeCell::new(owner_gate::Gate::new()));']
        for signature in ['struct Guard', 'impl Guard', 'impl Drop for Guard', 'fn acquire_guard()',
                          'fn locked<R>', 'fn locked_with_guard<R>', 'pub struct Credit',
                          'fn admit_service(', 'pub fn begin_service_segment()', 'fn revalidate_unstarted(',
                          'pub fn revalidate_service_segment()', 'pub(crate) struct PaidServiceWitness',
                          'fn service_witness_locked(', 'pub fn authorize_service_turn()',
                          'pub fn complete_builtin(', 'pub fn complete_service(', 'pub fn service_segment<R>']:
            pieces.append(function(task, signature))
        for signature in ['pub fn service_io_piece<R>', 'fn service_baseline_activation(',
                          'fn advance_admission_bounded(', 'fn submit_package(']:
            # The function moves from execution's child module into this host
            # root; only its namespace changes, not its deadline implementation.
            pieces.append(function(execution, signature).replace('super::deadline::','deadline::'))
        pieces.append('#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks/deadline.rs'))+'] mod deadline;')
        if 'fn service_baseline_progress(' in execution:
            pieces.append(function(execution, 'pub fn service_baseline_progress('))
        else:
            pieces.append('pub fn service_baseline_progress() {}')
        for signature in ['struct BaselineRetryGuard', 'impl Drop for BaselineRetryGuard',
                          'fn enter_baseline_retry(', 'fn service_baseline_activation_at(']:
            if signature in execution:
                pieces.append(function(execution, signature))
        active = re.search(r'^static BASELINE_RETRY_ACTIVE:.*;$', execution, re.M)
        if active:
            pieces.append(active[0])
        for signature in ['fn mechanism_progress(', 'fn progress(', 'fn finish_service(',
                          'fn service_work<R>', 'fn service_start(']:
            pieces.append(function(unified, signature))
        modules = '\n'.join('#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks' / name))
            + '] mod ' + name.removesuffix('.rs') + ';'
            for name in ['owner_gate.rs', 'service_authority.rs'])
        template = (ROOT / 'tests/host/baseline_progress_harness.rs').read_text()
        template = template.replace('// PRODUCTION_BODIES', modules + '\n' + '\n'.join(pieces))
        replay = 'struct Guard;\n' + '\n'.join(function(owner, signature) for signature in
            ['impl Drop for Guard', 'fn lock()', 'fn with<T>', 'pub fn service_step()'])
        projection=function(owner,'fn publish_drain_hint(') if 'fn publish_drain_hint(' in owner else 'fn publish_drain_hint() {}'
        pending=function(owner,'pub(super) fn drain_pending(') if 'fn drain_pending(' in owner else 'pub(super) fn drain_pending()->bool {false}'
        flag=re.search(r'^static DRAIN_PENDING:.*;$',owner,re.M)
        replay+='\n'+(flag[0] if flag else 'static DRAIN_PENDING:AtomicBool=AtomicBool::new(false);')+'\n'+projection+'\n'+pending
        facade=(ROOT/'kernel/src/learning_replay.rs').read_text()
        reader=function(facade,'pub fn baseline_activation_pending(') if 'pub fn baseline_activation_pending(' in facade else 'pub fn baseline_activation_pending()->bool {HINT.load(Ordering::Acquire)}'
        template=template.replace('// REPLAY_HINT_READER',reader)
        template = template.replace('// REPLAY_BODIES', replay)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rust = directory / 'harness.rs'
            rust.write_text(template)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="baseline-progress"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\nsha2="=0.10.9"\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-baseline-progress'),
                '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                    text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('19 passed; 0 failed', result.stdout)
            hook = '    crate::domain_tasks::service_baseline_progress();'
            self.assertEqual(template.count(hook), 1)
            rust.write_text(template.replace(hook, ''))
            negative = subprocess.run(command + ['--exact', 'progress_retries_before_returning_to_suspended_io'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('owned baseline did not run at the actual progress boundary',
                          negative.stdout + negative.stderr)
            entry = '    let Some(_entry) = enter_baseline_retry() else {\n        return;\n    };'
            self.assertEqual(template.count(entry), 1)
            rust.write_text(template.replace(entry, ''))
            negative = subprocess.run(command + ['--exact', 'recursive_progress_cannot_replace_a_live_diagnostic_ticket'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('recursive progress replaced the outer diagnostic ticket',
                          negative.stdout + negative.stderr)
            admission = 'advance_admission_bounded(s, 1, 1)'
            self.assertEqual(template.count(admission), 1)
            rust.write_text(template.replace(admission, 'Ok(())'))
            negative = subprocess.run(command + ['--exact',
                'pending_execution_constructs_one_original_queued_child_under_separate_credit'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('helper must construct exactly one queued child',
                          negative.stdout + negative.stderr)
            for original,replacement,name,failure in [
                ('if (root_ok || root_again) && pending {','if root_ok && pending {',
                 'launch_full_again_gets_one_fresh_construction_and_one_terminal_cleanup','Again suppressed independent queue progress'),
                (admission,'advance_admission_bounded(s, 1, 0)',
                 'launch_full_again_gets_one_fresh_construction_and_one_terminal_cleanup','Again did not retire one terminal launch slot'),
                ('        publish_drain_hint();','',
                 'actual_owner_guard_projects_only_owned_drain_on_success_and_error','owned drain lost priority when Root was complete'),
            ]:
                self.assertEqual(template.count(original),1)
                rust.write_text(template.replace(original,replacement))
                negative=subprocess.run(command+['--exact',name],cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
                self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
                self.assertIn(failure,negative.stdout+negative.stderr)
            no_drain,count=re.subn(r'\s*\|\|\s*owner::drain_pending\(\)','',template)
            self.assertEqual(count,1)
            rust.write_text(no_drain)
            negative=subprocess.run(command+['--exact','actual_driver_finishes_owned_drain_after_root_hint_clears'],
                cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('actual driver did not advance the owned drain debt',negative.stdout+negative.stderr)
            rust.write_text(template.replace(admission, admission.replace('(s, 1, 1)', '(s, 2, 1)')))
            negative = subprocess.run(command + ['--exact',
                'pending_execution_constructs_one_original_queued_child_under_separate_credit'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('helper must construct exactly one queued child',
                          negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
