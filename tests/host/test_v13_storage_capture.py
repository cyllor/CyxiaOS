"""Run protected capture state with host Rust; this is not native acceptance."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class StorageCapture(unittest.TestCase):
    def test_actual_capture_rejects_bad_binding_and_preserves_bounded_publication(self):
        source = ROOT / 'kernel/src/storage_fault_capture/state.rs'
        self.assertTrue(source.is_file(), 'protected capture state missing')
        rustc = shutil.which('rustc') or str(Path.home() / '.cargo/bin/rustc')
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'capture-tests')
            built = subprocess.run([rustc, '--edition=2024', '--test', str(ROOT / 'tests/host/storage_capture_harness.rs'), '-o', binary], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
