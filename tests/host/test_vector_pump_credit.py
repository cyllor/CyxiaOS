"""Native pump control flow over real scheduler and read-only vector policy.

Unrelated general mechanisms are substituted by their rotating opportunity;
actual service(), service_vectors() and service_segment() bodies are executed.
This is a progress/accounting regression, not native timing evidence.
"""
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


class VectorPumpCredit(unittest.TestCase):
    def test_actual_pump_uses_separate_bounded_credit_without_changing_batch_policy(self):
        execution = (ROOT / 'kernel/src/domain_tasks/execution.rs').read_text()
        driver = function(execution, 'pub fn service(')
        general = function(driver, 'let _ = service_segment(|| {')
        # Preserve actual outer sequencing; general owner internals have their
        # own tests. The old phase-2 vector opportunity is retained in RED.
        old_vector_phase = 'vector_piece(s, i);' in general
        driver = driver.replace(general, 'let _ = service_segment(|| { general_turn(); }')
        activation = function(execution, 'fn service_baseline_activation(') if (
            'fn service_baseline_activation(' in execution) else 'fn service_baseline_activation() {}'
        template = (ROOT / 'tests/host/vector_pump_credit_harness.rs').read_text()
        template = template.replace('// OWNER_GATE_PATH',
            str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs'))
        template = template.replace('// PUMP_BODIES', '\n'.join([
            driver, activation, function(execution, 'fn service_vectors('),
            function((ROOT / 'kernel/src/domain_tasks.rs').read_text(), 'pub fn service_segment<R>')]))
        template = template.replace('// OLD_VECTOR_PHASE', str(old_vector_phase).lower())
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'harness.rs').write_text(template)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="vector-pump-credit"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-vector-pump-credit'), '--', '--test-threads=1']
            result = subprocess.run(command,
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('6 passed; 0 failed', result.stdout)
            self.assertEqual(template.count('    service_vectors();'), 1)
            (directory / 'harness.rs').write_text(template.replace('    service_vectors();', ''))
            negative = subprocess.run(command + ['--exact',
                'queued_query_does_not_wait_for_eleven_unrelated_phases'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('queued query still waits behind general service rotation',
                          negative.stdout + negative.stderr)
            self.assertIn(template.count('    service_baseline_activation();'), (1, 2))
            (directory / 'harness.rs').write_text(template.replace('    service_baseline_activation();', ''))
            negative = subprocess.run(command + ['--exact',
                'owned_baseline_retries_on_the_next_paid_pass_with_unchanged_snapshot'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('owned baseline missed the next prepaid service opportunity',
                          negative.stdout + negative.stderr)
            if 'let baseline_was_pending =' in driver:
                old_order = template.replace('if baseline_was_pending {', 'if false {').replace(
                    'if !baseline_was_pending {', 'if true {')
                (directory / 'harness.rs').write_text(old_order)
                negative = subprocess.run(command + ['--exact',
                    'owned_baseline_gets_the_live_owner_turn_before_general_work'],
                    cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
                self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
                self.assertIn("general work consumed the owned baseline's live task-owner turn",
                              negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
