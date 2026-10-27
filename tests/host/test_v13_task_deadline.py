"""Host regression for native task admission deadline policy."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TaskDeadline(unittest.TestCase):
    def test_storage_profile_gets_only_its_exact_extended_window(self):
        rustc = shutil.which('rustc') or str(Path.home() / '.cargo/bin/rustc')
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'task-deadline-tests')
            result = subprocess.run([rustc, '--edition=2024', '--test',
                                     str(ROOT / 'tests/host/task_deadline_harness.rs'), '-o', binary],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('4 passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
