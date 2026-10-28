"""Exercise actual CPU0 syscall handoff ordering with production scheduling."""
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


class FileRetryCustody(unittest.TestCase):
    def test_no_effect_retry_and_delivered_receipt_have_different_custody(self):
        template = (ROOT / 'tests/host/file_retry_harness.rs').read_text()
        template = template.replace('// DISPATCH_RESULT', function(
            (ROOT / 'kernel/src/domain_file_abi.rs').read_text(), 'pub(crate) enum DispatchResult'))
        template = template.replace('// FILE_SERVICE_FUNCTION', function(
            (ROOT / 'kernel/src/domain_tasks/execution.rs').read_text(), 'fn service_file('))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="file-retry-custody"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            (directory / 'harness.rs').write_text(template)
            result = subprocess.run([str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-file-retry'), '--', '--test-threads=1'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('3 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
