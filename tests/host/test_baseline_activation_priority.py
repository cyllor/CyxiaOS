"""Actual root activation and control-gate release over retained snapshots.

Callbacks substitute owner contention/binding; real activate() must keep the
original token/snapshot through both paths. Hardware clocks are mocked.
"""
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


class BaselineActivationPriority(unittest.TestCase):
    def test_real_root_retains_partial_activation_and_projects_it_before_unlock(self):
        control = (ROOT / 'kernel/src/domain_control.rs').read_text()
        replay = (ROOT / 'kernel/src/domain_control/replay.rs').read_text()
        hint = 'static BASELINE_ACTIVATION_PENDING: AtomicBool = AtomicBool::new(false);'
        match = re.search(r'^static BASELINE_ACTIVATION_PENDING:.*;$', replay, re.M)
        if match:
            hint = match[0]
        reader = ('pub fn baseline_activation_pending() -> bool { '
                  'BASELINE_ACTIVATION_PENDING.load(Ordering::Acquire) }')
        if 'pub fn baseline_activation_pending()' in replay:
            reader = function(replay, 'pub fn baseline_activation_pending()')
        projection = 'pub(super) fn publish_baseline_activation_hint() {}'
        if 'pub(super) fn publish_baseline_activation_hint()' in replay:
            projection = function(replay, 'pub(super) fn publish_baseline_activation_hint()')
        bodies = '\n'.join(['struct Guard;', function(control, 'impl Drop for Guard'),
            function(control, 'fn with<T>')])
        template = (ROOT / 'tests/host/baseline_activation_priority_harness.rs').read_text()
        template = template.replace('r.initial = Some(2)', 'r.initial = Some(INITIAL)').replace('r.initial=Some(2)', 'r.initial=Some(INITIAL)')
        template = template.replace('// CONTROL_GATE_BODIES', bodies)
        template = template.replace('// ROOT_HINT_BODIES', '\n'.join([
            hint, reader, projection, function(replay, 'fn activate(')]))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rust = directory / 'harness.rs'
            rust.write_text(template)
            binary = directory / 'test'
            compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                str(rust), '-o', str(binary)], cwd=ROOT, env=env(), capture_output=True,
                text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('8 passed; 0 failed', result.stdout)
            hook = '        replay::publish_baseline_activation_hint();'
            self.assertEqual(template.count(hook), 1)
            rust.write_text(template.replace(hook, ''))
            compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                str(rust), '-o', str(binary)], cwd=ROOT, env=env(), capture_output=True,
                text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            negative = subprocess.run([str(binary), '--test-threads=1', '--exact',
                'busy_before_owner_gate_acquisition_still_retains_an_urgent_original_snapshot'],
                capture_output=True, text=True, timeout=30)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('partial first activation waits for general phase9',
                          negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
