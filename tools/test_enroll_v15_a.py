"""Catalogue mutation is conditional on all fixed native checks succeeding."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import enroll_v15_a as enrollment


class Enrollment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.receipt = self.root / 'summary.json'
        self.receipt.write_text('{}\n')
        self.document = json.loads(enrollment.DEFAULT.read_text())

    def test_failed_or_stale_native_check_does_not_mutate_input(self):
        original = copy.deepcopy(self.document)
        with patch.object(enrollment, 'validate', side_effect=ValueError('stale A02 source')):
            with self.assertRaisesRegex(ValueError, 'stale A02 source'):
                enrollment.enroll(self.document, 'A01', self.receipt, self.root)
        self.assertEqual(self.document, original)

    def test_all_existing_rows_are_revalidated_and_not_auto_promoted(self):
        # This mock verifies dispatch only, not that a native guest executed.
        with patch.object(enrollment, 'validate', return_value={'case_groups': {}}) as check:
            result, _ = enrollment.enroll(self.document, 'A01', self.receipt, self.root,
                                          qemu_source=self.root / 'trusted-qemu')
        self.assertEqual(len(result['cases']), 51)
        self.assertEqual([r['id'] for r in result['cases'] if r['status'] == 'PASS'], ['A01'])
        self.assertTrue(all(r['status'] == 'NOT_RUN' for r in self.document['cases']))
        check.assert_called_once_with(result, self.root, qemu_source=self.root / 'trusted-qemu')

    def test_outside_receipt_or_unregistered_case_never_reaches_verifier(self):
        with patch.object(enrollment, 'validate') as check:
            with tempfile.TemporaryDirectory() as outside:
                receipt = Path(outside) / 'summary.json'
                receipt.write_text('{}\n')
                with self.assertRaisesRegex(ValueError, 'inside'):
                    enrollment.enroll(self.document, 'A01', receipt, self.root)
            with self.assertRaisesRegex(ValueError, 'no fixed'):
                enrollment.enroll(self.document, 'A04', self.receipt, self.root)
            check.assert_not_called()

    def test_rejected_receipt_cannot_create_output_catalogue(self):
        output = self.root / 'result.json'
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps(self.document))
        with patch.object(enrollment, 'validate', side_effect=ValueError('native evidence rejected')):
            self.assertEqual(enrollment.main(['--manifest', str(manifest), '--case', 'A01',
                '--receipt', str(self.receipt), '--source-root', str(self.root),
                '--qemu-source', str(self.root), '--output', str(output)]), 1)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
