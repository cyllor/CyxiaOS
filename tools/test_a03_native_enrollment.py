"""Fixed adapter routing contracts; mocked replies are not native evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_v13_evidence as checker


class A03Enrollment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        receipt = self.root / 'summary.json'
        receipt.write_text('{}\n')
        document = json.loads(checker.DEFAULT.read_text())
        self.row = copy.deepcopy(next(r for r in document['cases'] if r['id'] == 'A03'))
        self.row.update(status='PASS', evidence={'path': receipt.name,
            'sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()})
        self.qemu = self.root / 'trusted-qemu'
        self.complete = dict(test_id='A03', native_acceptance_status='PASS',
            native_execution_verified=True, runtime_truth_attested=False,
            control_sets=[2, 6, 2], model_replay=[
                dict(status='MODEL_REPLAY_VALID', full_integer_mlp=True),
                dict(status='MODEL_REPLAY_VALID', full_integer_mlp=True)])

    def check(self, **context):
        return checker.check_rows([self.row], {'A03'}, 'case set', self.root,
                                  descriptions=True, **context)

    def test_fixed_adapter_uses_explicit_source_and_qemu(self):
        with patch.object(checker, 'verify_a03_native_receipt', create=True,
                          return_value=self.complete) as replay:
            self.assertEqual(self.check(qemu_source=self.qemu),
                             {'PASS': 1, 'FAIL': 0, 'NOT_RUN': 0})
            replay.assert_called_once_with(self.root, source_root=self.root,
                                           qemu_source=self.qemu)

    def test_missing_explicit_context_is_rejected_before_replay(self):
        with patch.object(checker, 'verify_a03_native_receipt', create=True) as replay:
            with self.assertRaisesRegex(ValueError, 'A03.*explicit'):
                self.check()
            replay.assert_not_called()

    def test_partial_model_or_proposal_cannot_establish_a03(self):
        for key, value in [('test_id', 'A04'), ('native_acceptance_status', 'NOT_RUN'),
                ('native_execution_verified', False), ('runtime_truth_attested', True),
                ('control_sets', [2, 6]), ('model_replay', []),
                ('model_replay', [dict(status='MODEL_REPLAY_VALID', full_integer_mlp=False)] * 2)]:
            with self.subTest(key=key, value=value), patch.object(checker,
                    'verify_a03_native_receipt', create=True,
                    return_value=dict(self.complete, **{key: value})):
                with self.assertRaisesRegex(ValueError, 'complete A03'):
                    self.check(qemu_source=self.qemu)

    def test_replay_failure_is_not_promoted(self):
        with patch.object(checker, 'verify_a03_native_receipt', create=True,
                          side_effect=ValueError('actual owner differs from model')):
            with self.assertRaisesRegex(ValueError, 'actual owner differs'):
                self.check(qemu_source=self.qemu)


if __name__ == '__main__':
    unittest.main()
