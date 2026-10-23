"""Read-only prerequisite failure tests; no toolchain installation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import doctor


class DoctorFailureTests(unittest.TestCase):
    def test_missing_executable_is_not_a_traceback(self):
        self.assertEqual(doctor.run(['/nonexistent/cyxia-rustc']), '')

    def test_timeout_and_permission_errors_are_missing_facts(self):
        for error in (PermissionError('denied'), subprocess.TimeoutExpired(['rustc'], 30)):
            with self.subTest(error=type(error).__name__):
                with patch.object(doctor.subprocess, 'run', side_effect=error):
                    self.assertEqual(doctor.run(['rustc']), '')

    def test_nonzero_exit_is_not_accepted_as_version(self):
        with patch.object(doctor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'rustc 1.95.0')):
            self.assertEqual(doctor.run(['rustc']), '')

    def test_successful_stdout_is_stripped(self):
        with patch.object(doctor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'rustc 1.95.0\n')):
            self.assertEqual(doctor.run(['rustc']), 'rustc 1.95.0')

    def test_missing_tools_yield_serializable_negative_report(self):
        with patch.object(doctor, 'run', return_value=''), patch.object(doctor.shutil, 'which', return_value=None):
            report = doctor.inspect()
        self.assertFalse(report['ready'])
        self.assertIsNone(report['facts']['llvm_dir'])
        self.assertFalse(report['llvm']['ready'])
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_llvm_directory_never_falls_back_to_current_working_directory(self):
        with patch.object(doctor, 'run', side_effect=['', 'host: x86_64-unknown-linux-gnu']):
            with self.assertRaises(RuntimeError):
                doctor.llvm_dir()
        with patch.object(doctor, 'run', side_effect=['relative', 'host: x86_64-unknown-linux-gnu']):
            with self.assertRaises(RuntimeError):
                doctor.llvm_dir()

    def test_invalid_host_cannot_escape_sysroot(self):
        for host in ('', '../escape', '/absolute', '..', 'host with spaces'):
            with self.subTest(host=host), patch.object(doctor, 'run', side_effect=['/toolchain', 'host: ' + host]):
                with self.assertRaises(RuntimeError):
                    doctor.llvm_dir()

    def test_valid_metadata_preserves_existing_path_contract(self):
        with patch.object(doctor, 'run', side_effect=['/toolchain', 'rustc 1.95.0\nhost: aarch64-apple-darwin']):
            self.assertEqual(doctor.llvm_dir(), Path('/toolchain/lib/rustlib/aarch64-apple-darwin/bin'))

    def test_version_prefix_does_not_accept_different_release(self):
        for value in ('cargo 1.95.01', 'cargo 1.95.0-beta', 'cargo 1.95.0-nightly'):
            self.assertFalse(doctor.assess({'cargo': value})['cargo']['ready'])
        self.assertTrue(doctor.assess({'cargo': 'cargo 1.95.0 (abc 2026-10-01)'})['cargo']['ready'])

    def test_official_qemu_tag_suffix_is_allowed_but_other_builds_are_not(self):
        for line in ('QEMU emulator version 10.2.2',
                     'QEMU emulator version 10.2.2 (v10.2.2)'):
            self.assertTrue(doctor.assess({'qemu': line + '\nCopyright notice'})['qemu']['ready'])
        for line in ('QEMU emulator version 10.2.21', 'QEMU emulator version 10.2.3',
                     'QEMU emulator version 10.2.2 (v10.2.2-1-gabcdef)',
                     'QEMU emulator version 10.2.2 (v10.2.2-dirty)',
                     'QEMU emulator version 10.2.2-rc1', ''):
            self.assertFalse(doctor.assess({'qemu': line})['qemu']['ready'])

    def test_cargo_home_is_honored_without_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            environment = dict(os.environ, CARGO_HOME=temp, PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.check_output([sys.executable, '-B', '-c',
                'from tools.doctor import RUST_BIN; print(RUST_BIN)'], env=environment, cwd=doctor.ROOT, text=True)
            self.assertEqual(result.strip(), str(Path(temp).resolve() / 'bin'))
            self.assertEqual(list(Path(temp).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
