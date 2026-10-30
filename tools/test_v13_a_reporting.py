"""Report arithmetic and fail-closed routing; fixtures are not native evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from check_v13_evidence import DEFAULT, ROOT, validate


class AReporting(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(DEFAULT.read_text())

    def test_case_groups_are_separate_from_action_families(self):
        report = validate(self.document, ROOT)
        self.assertEqual(report['case_states'], {'PASS': 0, 'FAIL': 0, 'NOT_RUN': 51})
        self.assertEqual(report['action_states'], {'PASS': 0, 'FAIL': 0, 'NOT_RUN': 18})
        for group, total in (('A', 16), ('T', 20), ('E', 15)):
            self.assertEqual(report['case_groups'][group],
                             {'PASS': 0, 'FAIL': 0, 'NOT_RUN': total})
        self.assertFalse(report['a_acceptance_complete'])
        self.assertFalse(report['functional_acceptance_complete'])
        self.assertEqual(report['states']['NOT_RUN'], 69)  # Legacy field preserved.

    def test_a_cli_reports_only_a_completion_without_hiding_global_status(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/prototype.py'),
                                 'report', '--scope', 'A'], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['selected_scope'], 'A')
        self.assertFalse(report['selected_scope_complete'])
        self.assertFalse(report['a_acceptance_complete'])
        self.assertFalse(report['functional_acceptance_complete'])
        self.assertEqual(report['case_groups']['T']['NOT_RUN'], 20)

    def test_default_report_still_requires_complete_acceptance(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/prototype.py'),
                                 'report'], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['selected_scope'], 'all')

    def test_forged_a_pass_still_requires_native_receipt(self):
        document = copy.deepcopy(self.document)
        for row in document['cases']:
            if row['id'].startswith('A'):
                row['status'] = 'PASS'
        with self.assertRaisesRegex(ValueError, 'receipt'):
            validate(document, ROOT)

    def test_group_summary_does_not_ignore_t_or_e_corruption(self):
        for case in ('T20', 'E15'):
            document = copy.deepcopy(self.document)
            row = next(r for r in document['cases'] if r['id'] == case)
            row['status'] = 'PASS'
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, 'receipt'):
                validate(document, ROOT)

    def test_missing_a_case_cannot_shrink_denominator(self):
        document = copy.deepcopy(self.document)
        document['cases'] = [r for r in document['cases'] if r['id'] != 'A16']
        with self.assertRaisesRegex(ValueError, 'case set'):
            validate(document, ROOT)

    def test_plan_or_engineering_status_cannot_count_as_pass(self):
        for status in ('IMPLEMENTED', 'BLOCKED', 'HOST_PASS', 'RAW_CONTRACT_PASS'):
            document = copy.deepcopy(self.document)
            document['cases'][0]['status'] = status
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'test status'):
                validate(document, ROOT)


if __name__ == '__main__':
    unittest.main()
