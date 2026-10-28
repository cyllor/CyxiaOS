"""Execute the actual workload drain body across real request/retirement boundaries.

External owner gates, clocks and request outcomes are controlled spies; this
does not claim native execution or completion of a synthetic request.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class ClosingProgress(unittest.TestCase):
    def test_actual_drain_preserves_closing_custody_before_releasing_owners(self):
        source = (ROOT / 'kernel/src/learning_workload/owner.rs').read_text()
        body = function(source, 'pub fn drain(')
        template = (ROOT / 'tests/host/workload_closing_progress_harness.rs').read_text()
        with tempfile.TemporaryDirectory() as temporary:
            rust = Path(temporary) / 'harness.rs'
            binary = Path(temporary) / 'test'

            def run(code, name=None):
                rust.write_text(template.replace('// PRODUCTION_DRAIN', code))
                compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                    str(rust), '-o', str(binary)], cwd=ROOT, env=env(), capture_output=True,
                    text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                return subprocess.run([str(binary), '--test-threads=1'] +
                    (['--exact', name] if name else []), capture_output=True, text=True, timeout=30)

            result = run(body)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('6 passed; 0 failed', result.stdout)
            early = '    let poll_done = poll(run)?;'
            self.assertEqual(body.count(early), 1)
            negative = run(body.replace(early, early + '\n    if !poll_done { return Ok(false); }'),
                           'closing_probe_can_progress_before_measurement_wait_all')
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('closing demand blocked behind measurement wait-all', negative.stdout)
            barrier = '    if !poll_done\n        || !done'
            self.assertEqual(body.count(barrier), 1)
            negative = run(body.replace(barrier, '    if !done'),
                           'applied_receipt_does_not_retire_unfinished_probe_or_measurement')
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
