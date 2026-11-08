"""Dispatch contract only; mocked results are never native acceptance evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_v13_evidence as checker


class A01Enrollment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        receipt = self.root / 'summary.json'
        receipt.write_text('{}\n')
        document = json.loads(checker.DEFAULT.read_text())
        self.row = copy.deepcopy(next(row for row in document['cases'] if row['id'] == 'A01'))
        self.row.update(status='PASS', evidence={
            'path': receipt.name, 'sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()})
        self.qemu = self.root / 'explicit-trusted-qemu'
        self.complete = dict(test_id='A01', native_acceptance_status='PASS',
                             native_execution_verified=True, runtime_truth_attested=False,
                             reboot_chain_verified=True)

    def check(self, **options):
        return checker.check_rows([self.row], {'A01'}, 'case set', self.root,
                                  descriptions=True, **options)

    def test_fixed_adapter_uses_caller_source_and_trusted_qemu(self):
        with patch.object(checker, 'verify_a01_native_receipt', create=True,
                          return_value=self.complete) as replay:
            self.assertEqual(self.check(qemu_source=self.qemu),
                             {'PASS': 1, 'FAIL': 0, 'NOT_RUN': 0})
            replay.assert_called_once_with(self.root, source_root=self.root,
                                           qemu_source=self.qemu)

    def test_a01_requires_explicit_qemu_context(self):
        with patch.object(checker, 'verify_a01_native_receipt', create=True) as replay, \
                self.assertRaisesRegex(ValueError, 'A01.*explicit'):
            self.check()
        replay.assert_not_called()

    def test_old_regression_or_mislabelled_scope_cannot_close_a01(self):
        for key, value in (('test_id', 'A02'), ('native_acceptance_status', 'NOT_RUN'),
                           ('native_execution_verified', False), ('runtime_truth_attested', True),
                           ('reboot_chain_verified', False)):
            observed = dict(self.complete, **{key: value})
            with self.subTest(key=key), \
                    patch.object(checker, 'verify_a01_native_receipt', create=True,
                                 return_value=observed) as replay:
                with self.assertRaisesRegex(ValueError,
                        'A01 native receipt does not establish complete A01'):
                    self.check(qemu_source=self.qemu)
                replay.assert_called_once()

    def test_native_verifier_error_remains_an_error(self):
        with patch.object(checker, 'verify_a01_native_receipt', create=True,
                          side_effect=ValueError('formal key preceded durable epoch')), \
                self.assertRaisesRegex(ValueError, 'formal key preceded durable epoch'):
            self.check(qemu_source=self.qemu)


if __name__ == '__main__':
    unittest.main()
