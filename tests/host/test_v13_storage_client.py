"""Host ABI regression tests for the actual EL0 client, never native evidence."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StorageClient(unittest.TestCase):
    def test_actual_client_keeps_durable_versions_and_rejects_bad_observations(self):
        self.assertTrue((ROOT / 'user/prototype-client/storage_fault.rs').is_file(),
                        'ordinary EL0 storage fault workload missing')
        rustc = shutil.which('rustc') or str(Path.home() / '.cargo/bin/rustc')
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'storage-client-tests')
            result = subprocess.run([rustc, '--edition=2024', '--test',
                                     str(ROOT / 'tests/host/storage_client_harness.rs'), '-o', binary],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([binary, '--test-threads=1'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
