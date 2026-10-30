"""Patched A02 captures must use the same fixed-source gate as pair runs."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from verify_v13_a02 import verify_native_qemu


class NativeQemuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'qemu'
        self.binary.write_bytes(b'unit-test binary, not native evidence')
        self.built = self.root / 'build/qemu-system-aarch64'
        self.built.parent.mkdir()
        self.built.write_bytes(self.binary.read_bytes())
        self.identity = dict(qemu_version='QEMU emulator version 10.2.2 (v10.2.2-dirty)\n',
                             qemu_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                             qemu_pmu_patch_attested=True, qemu_source_commit='fixed-commit',
                             qemu_patch_sha256='fixed-patch', qemu_source_sha256={'cpu.c': 'fixed-source'})
        self.tools = dict(self.identity, qemu_source_directory=str(self.root))

    def test_patched_capture_is_rechecked_not_trusted_from_recorded_boolean(self):
        with patch('verify_unified.attest_qemu', return_value=self.identity) as check:
            verify_native_qemu(self.tools, self.binary, qemu_source=self.root)
        check.assert_called_once_with(self.built, self.root)

    def test_missing_flag_source_or_absolute_path_is_rejected(self):
        for field, value in [('qemu_pmu_patch_attested', False),
                             ('qemu_source_directory', None), ('qemu_source_directory', 'relative')]:
            with self.subTest(field=field, value=value), patch('verify_unified.attest_qemu') as check:
                with self.assertRaisesRegex(ValueError, 'attestation missing'):
                    verify_native_qemu(dict(self.tools, **{field: value}), self.binary, qemu_source=self.root)
                check.assert_not_called()

    def test_changed_binary_is_rejected_before_source_validation(self):
        self.binary.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'binary identity changed'):
            verify_native_qemu(self.tools, self.binary, qemu_source=self.root)

    def test_all_recorded_source_and_patch_fields_must_match(self):
        for field in ('qemu_version', 'qemu_source_commit', 'qemu_patch_sha256', 'qemu_source_sha256'):
            with self.subTest(field=field), patch('verify_unified.attest_qemu',
                    return_value=dict(self.identity, **{field: 'changed'})):
                with self.assertRaisesRegex(ValueError, 'attestation changed'):
                    verify_native_qemu(self.tools, self.binary, qemu_source=self.root)

    def test_attester_rejection_is_not_downgraded_to_stock(self):
        with patch('verify_unified.attest_qemu', side_effect=ValueError('wrong tracked diff')):
            with self.assertRaisesRegex(ValueError, 'wrong tracked diff'):
                verify_native_qemu(self.tools, self.binary, qemu_source=self.root)

    def test_archive_cannot_select_a_directory_for_git_execution(self):
        with patch('verify_unified.attest_qemu') as check:
            with self.assertRaisesRegex(ValueError, 'explicit trusted'):
                verify_native_qemu(self.tools, self.binary)
            check.assert_not_called()

    def test_receipt_selected_executable_is_not_run_before_trusted_build_binding(self):
        self.binary.write_bytes(b'untrusted executable bytes')
        changed = dict(self.tools, qemu_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest())
        with patch('verify_unified.attest_qemu') as check:
            with self.assertRaisesRegex(ValueError, 'differs from explicit trusted source build'):
                verify_native_qemu(changed, self.binary, qemu_source=self.root)
            check.assert_not_called()

    def test_stock_legacy_receipt_is_compatible_but_cannot_claim_pmu(self):
        stock = dict(qemu_version='QEMU emulator version 10.2.2\n',
                     qemu_sha256=self.identity['qemu_sha256'])
        with patch('verify_unified.attest_qemu') as check:
            verify_native_qemu(stock, self.binary)
            check.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'cannot claim'):
            verify_native_qemu(dict(stock, qemu_pmu_patch_attested=True), self.binary)


if __name__ == '__main__':
    unittest.main()
