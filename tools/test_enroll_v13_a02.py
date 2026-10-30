"""Enrolment plumbing tests; mocked receipts never establish native acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check_v13_evidence import DEFAULT, ROOT
from check_prototype_evidence import sha256
from enroll_v13_a02 import enroll


class A02Enrolment(unittest.TestCase):
    def setUp(self):
        (ROOT / 'artifacts').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'artifacts')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.manifest = self.folder / 'catalogue.json'
        document = json.loads(DEFAULT.read_text())
        for row in document['cases'] + document['action_families']:
            row.update(status='NOT_RUN', evidence=None)
        self.document = document
        self.manifest.write_text(json.dumps(document))
        self.receipt = self.folder / 'summary.json'
        self.receipt.write_text('{"status":"PASS"}')
        self.output = self.folder / 'enrolled.json'

    def verified(self, **changes):
        result = dict(test_id='A02', native_acceptance_status='PASS',
                      native_execution_verified=True, runtime_truth_attested=False)
        result.update(changes)
        return patch('check_v13_evidence.verify_native_receipt', return_value=result)

    def test_only_fixed_adapter_can_promote_a02_and_source_is_explicit(self):
        before = self.manifest.read_bytes()
        emulator = self.folder / 'trusted-emulator'
        with self.verified() as adapter:
            report = enroll(self.manifest, self.receipt, self.output,
                            source_root=ROOT, qemu_source=emulator)
        adapter.assert_called_once_with(self.folder, source_root=ROOT.resolve(),
                                        qemu_source=emulator)
        document = json.loads(self.output.read_text())
        expected = copy.deepcopy(self.document)
        row = next(r for r in expected['cases'] if r['id'] == 'A02')
        row.update(status='PASS', evidence={'path': self.receipt.relative_to(ROOT).as_posix(),
                                          'sha256': sha256(self.receipt)})
        self.assertEqual(document, expected)
        self.assertEqual(self.manifest.read_bytes(), before)
        self.assertEqual(report['case_groups']['A'], {'PASS': 1, 'FAIL': 0, 'NOT_RUN': 15})
        self.assertFalse(report['a_acceptance_complete'])
        self.assertFalse(report['functional_acceptance_complete'])

    def test_producer_pass_does_not_create_an_enrolled_manifest(self):
        with self.assertRaises(ValueError):
            enroll(self.manifest, self.receipt, self.output, source_root=ROOT)
        self.assertFalse(self.output.exists())

    def test_adapter_failure_leaves_no_output(self):
        for changes in ({'native_execution_verified': False},
                        {'native_acceptance_status': 'NOT_RUN'},
                        {'runtime_truth_attested': True}, {'test_id': 'A01'}):
            with self.subTest(changes=changes), self.verified(**changes):
                with self.assertRaises(ValueError):
                    enroll(self.manifest, self.receipt, self.output, source_root=ROOT)
            self.assertFalse(self.output.exists())

    def test_existing_output_cannot_be_replaced(self):
        self.output.write_text('original')
        with self.verified(), self.assertRaises(FileExistsError):
            enroll(self.manifest, self.receipt, self.output, source_root=ROOT)
        self.assertEqual(self.output.read_text(), 'original')

    def test_outside_or_symlinked_receipt_is_rejected(self):
        alias = self.folder / 'alias'
        alias.symlink_to(self.folder, target_is_directory=True)
        with self.assertRaises(ValueError):
            enroll(self.manifest, alias / 'summary.json', self.output, source_root=ROOT)
        with tempfile.TemporaryDirectory() as external:
            receipt = Path(external) / 'summary.json'
            receipt.write_text('{}')
            with self.assertRaises(ValueError):
                enroll(self.manifest, receipt, self.output, source_root=ROOT)
        self.assertFalse(self.output.exists())

    def test_invalid_other_case_cannot_be_hidden_by_a02_enrolment(self):
        self.document['cases'][-1]['status'] = 'HOST_PASS'
        self.manifest.write_text(json.dumps(self.document))
        with self.verified(), self.assertRaises(ValueError):
            enroll(self.manifest, self.receipt, self.output, source_root=ROOT)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
