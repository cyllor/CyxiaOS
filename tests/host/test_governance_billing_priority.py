"""Execute the actual dispatch/settlement bodies against the real scheduler."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    for at in range(opening + 1, len(source)):
        depth += (source[at] == '{') - (source[at] == '}')
        if depth == 0:
            return source[start:at + 1]
    raise ValueError('unterminated production function')


class GovernanceBillingPriority(unittest.TestCase):
    def test_actual_native_step_releases_original_bill_before_ready_request(self):
        native = (ROOT / 'kernel/src/prototype_runtime/native.rs').read_text()
        governance = (ROOT / 'kernel/src/prototype_runtime/governance.rs').read_text()
        step = function(native, 'pub(super) fn step(worker: &mut Worker)')
        template = (ROOT / 'tests/host/governance_priority_harness.rs').read_text()
        template = template.replace('// GOVERNANCE_BILL_FUNCTION',
            function(governance, 'fn settle_runtime_bill(runtime: &mut Runtime)'))
        template = template.replace('// GOVERNANCE_SETTLE_FUNCTION',
            function(governance, 'pub(super) fn settle()'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'Cargo.toml').write_text(
                '[package]\nname="governance-priority-regression"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                       str(root / 'Cargo.toml'), '--target-dir',
                       str(ROOT / 'target/host-governance-priority'), '--', '--test-threads=1']
            # Execute the old ordering as a negative control, then the actual
            # production body. The test checks effects, never source presence.
            missing_hook = step.replace('        || !super::governance::settle()\n', '')
            delayed_startup = step.replace('        && worker.native.model.is_none()\n    {',
                '        && worker.native.model.is_none()\n'
                '        && (REQUEST.load(Ordering::Acquire) != 1 || TARGET.load(Ordering::Acquire) != slot as u64)\n    {')
            displaced_owner = step.replace('        && !worker.native.in_job\n', '')
            for body, failure in [
                (missing_hook, 'old governor bill was starved by mandatory REQUEST'),
                (delayed_startup, 'coordinator startup was bypassed by REQUEST'),
                (displaced_owner, 'already owned ordinary job was displaced'),
                (step, None),
            ]:
                (root / 'harness.rs').write_text(template.replace('// NATIVE_STEP_FUNCTION', body))
                result = subprocess.run(command, cwd=ROOT, env=env(),
                    capture_output=True, text=True, timeout=120)
                output = result.stdout + result.stderr
                if failure is None:
                    self.assertEqual(result.returncode, 0, output)
                    self.assertIn('3 passed; 0 failed', output)
                else:
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertIn(failure, output)


if __name__ == '__main__':
    unittest.main()
