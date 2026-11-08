"""Test fixed A10 adapter dispatch, never claim that a fixture ran natively."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_v13_evidence as checker


class A10NativeEnrollment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.receipt = self.root / 'run' / 'summary.json'
        self.receipt.parent.mkdir()
        self.receipt.write_text('{}\n')
        document = json.loads(checker.DEFAULT.read_text())
        self.row = copy.deepcopy(next(row for row in document['cases'] if row['id'] == 'A10'))
        self.row.update(status='PASS', evidence={
            'path': 'run/summary.json',
            'sha256': hashlib.sha256(self.receipt.read_bytes()).hexdigest()})
        self.build = self.root / 'trusted-build' / 'build-manifest.json'
        self.qemu = self.root / 'trusted-qemu'
        self.formatter = self.root / 'trusted-formatter'
        self.complete = dict(test_id='A10', native_acceptance_status='PASS',
                             native_execution_verified=True, raw_matrix_verified=True,
                             native_filesystem_fault_matrix_complete=True)

    def check(self, **options):
        return checker.check_rows([self.row], {'A10'}, 'case set', self.root,
                                  descriptions=True, **options)

    def options(self):
        return dict(qemu_source=self.qemu, a10_build_manifest=self.build,
                    a10_formatter=self.formatter)

    def test_native_dispatch_requires_all_explicit_trusted_inputs(self):
        with patch.object(checker, 'verify_a10_matrix_receipt', return_value={}), \
                patch.object(checker, 'verify_a10_native_matrix_receipt', create=True) as native:
            for missing in self.options():
                options = self.options()
                del options[missing]
                with self.subTest(missing=missing), self.assertRaisesRegex(
                        ValueError, 'explicit.*A10|A10.*explicit'):
                    self.check(**options)
            native.assert_not_called()

    def test_fixed_native_verifier_receives_only_caller_selected_paths(self):
        with patch.object(checker, 'verify_a10_matrix_receipt', return_value={}) as raw, \
                patch.object(checker, 'verify_a10_native_matrix_receipt', create=True,
                             return_value=self.complete) as native:
            self.assertEqual(self.check(**self.options()), {'PASS': 1, 'FAIL': 0, 'NOT_RUN': 0})
            raw.assert_called_once_with(self.receipt.parent, source_root=self.root)
            native.assert_called_once_with(self.receipt.parent, source_root=self.root,
                build_manifest=self.build, qemu_binary=self.qemu / 'build/qemu-system-aarch64',
                qemu_source=self.qemu, formatter_binary=self.formatter)

    def test_offline_or_incomplete_native_result_cannot_close_a10(self):
        for key, value in (('test_id', 'A02'), ('native_acceptance_status', 'NOT_RUN'),
                           ('native_execution_verified', False), ('raw_matrix_verified', False),
                           ('native_filesystem_fault_matrix_complete', False)):
            observed = dict(self.complete, **{key: value})
            with self.subTest(key=key), \
                    patch.object(checker, 'verify_a10_matrix_receipt', return_value={}), \
                    patch.object(checker, 'verify_a10_native_matrix_receipt', create=True,
                                 return_value=observed), \
                    self.assertRaisesRegex(ValueError, 'A10.*complete|complete.*A10'):
                self.check(**self.options())

    def test_native_validation_failure_is_not_converted_to_pass(self):
        with patch.object(checker, 'verify_a10_matrix_receipt', return_value={}), \
                patch.object(checker, 'verify_a10_native_matrix_receipt', create=True,
                             side_effect=ValueError('native launch witness changed')), \
                self.assertRaisesRegex(ValueError, 'native launch witness changed'):
            self.check(**self.options())

    def test_receipt_cannot_choose_a_native_checker_or_caller_context(self):
        for name in ('verifier', 'build_manifest', 'qemu_source', 'formatter'):
            with self.subTest(name=name), \
                    patch.object(checker, 'verify_a10_native_matrix_receipt', create=True) as native:
                self.row['evidence'][name] = '/archive/selected'
                with self.assertRaises(ValueError):
                    self.check(**self.options())
                native.assert_not_called()
                del self.row['evidence'][name]


if __name__ == '__main__':
    unittest.main()
