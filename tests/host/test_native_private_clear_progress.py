"""Execute the actual clear state machine, substituting only ARM stores/barrier."""
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


class NativePrivateClearProgress(unittest.TestCase):
    def test_private_clear_finishes_under_normal_wake_cadence_without_skipping_paid_work(self):
        source = (ROOT / 'kernel/src/prototype_runtime/native.rs').read_text()
        constants = [re.search(rf'^const {name}:.*;$', source, re.M)[0] for name in
            ['PRIVATE_CLEAR_PAGES', 'PRIVATE_CLEAR_BYTES', 'PRIVATE_CLEAR_BARRIER', 'PRIVATE_CLEAR_SLICE_BYTES']]
        if 'const PRIVATE_CLEAR_TURN_BYTES:' in source:
            constants.append(re.search(r'^const PRIVATE_CLEAR_TURN_BYTES:.*;$', source, re.M)[0])
        body = function(source, 'fn continue_private_clear(')
        barrier = 'core::arch::asm!("dsb ish", options(nostack));'
        self.assertEqual(body.count(barrier), 1)
        body = body.replace(barrier, 'BARRIERS.fetch_add(1, Ordering::AcqRel); CPU_NS.fetch_add(500, Ordering::AcqRel);')
        template = (ROOT / 'tests/host/native_private_clear_harness.rs').read_text()
        template = template.replace('// NATIVE_CLEAR', '\n'.join(constants) + '\n' + body)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rust = directory / 'harness.rs'
            executable = directory / 'clear-test'
            rust.write_text(template)
            compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                str(rust), '-o', str(executable)], cwd=ROOT, env=env(),
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable), '--test-threads=1'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('5 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
