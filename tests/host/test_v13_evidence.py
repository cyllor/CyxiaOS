"""Evidence catalogue tests; fixtures are not native runtime evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


class EvidenceCatalogue(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'tools/check_v13_evidence.py').is_file(),
                        '1.3 evidence checker is not implemented')
        import check_v13_evidence
        self.check = check_v13_evidence
        self.document = json.loads((ROOT / 'docs/implementation/v13-requirements.json').read_text())

    def test_unrun_catalogue_cannot_complete_functional_acceptance(self):
        result = self.check.validate(self.document, ROOT)
        self.assertEqual(result['mandatory_cases'], 51)
        self.assertEqual(result['action_families'], 18)
        self.assertEqual(result['states'], {'PASS': 0, 'FAIL': 0, 'NOT_RUN': 69})
        self.assertFalse(result['functional_acceptance_complete'])
        self.assertFalse(result['strict_spec_conformance'])
        self.assertFalse(result['runtime_truth_attested'])

    def test_cannot_delete_new_implementation_boundaries(self):
        self.document['cases'] = [r for r in self.document['cases'] if r['id'] != 'E15']
        with self.assertRaisesRegex(ValueError, 'case set'):
            self.check.validate(self.document, ROOT)

    def test_duplicate_does_not_replace_missing_case(self):
        self.document['cases'][-1] = copy.deepcopy(self.document['cases'][0])
        with self.assertRaisesRegex(ValueError, 'case set'):
            self.check.validate(self.document, ROOT)

    def test_legacy_spec_hash_rejected(self):
        self.document['spec']['sha256'] = '2df965ba7604a444acf08d519e430c65429aebdf757fe3de29969dc7b9e2a35a'
        with self.assertRaisesRegex(ValueError, 'specification'):
            self.check.validate(self.document, ROOT)

    def test_existing_id_cannot_hide_changed_requirement_meaning(self):
        self.document['cases'][0]['required_outcome'] = 'Only print PASS.'
        with self.assertRaisesRegex(ValueError, 'definitions'):
            self.check.validate(self.document, ROOT)

    def test_rust_deviation_cannot_be_hidden(self):
        self.document['deviations'] = []
        with self.assertRaisesRegex(ValueError, 'Rust deviation'):
            self.check.validate(self.document, ROOT)

    def test_blocked_is_engineering_status_not_test_result(self):
        self.document['cases'][0]['status'] = 'BLOCKED'
        with self.assertRaisesRegex(ValueError, 'test status'):
            self.check.validate(self.document, ROOT)

    def test_pass_without_runtime_receipt_rejected(self):
        self.document['cases'][0]['status'] = 'PASS'
        with self.assertRaisesRegex(ValueError, 'receipt'):
            self.check.validate(self.document, ROOT)

    def test_domain_names_do_not_hide_second_action_families(self):
        self.document['action_families'] = self.document['action_families'][:-1]
        with self.assertRaisesRegex(ValueError, 'action family set'):
            self.check.validate(self.document, ROOT)

    def test_false_filesystem_freeze_without_fault_matrix_rejected(self):
        self.document['filesystem_fault_matrix']['frozen'] = True
        with self.assertRaisesRegex(ValueError, 'filesystem'):
            self.check.validate(self.document, ROOT)

    def test_release_cli_fails_for_incomplete_catalogue_in_optimized_python(self):
        result = subprocess.run([sys.executable, '-O', str(ROOT / 'tools/check_v13_evidence.py'),
                                 '--release'], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(json.loads(result.stdout)['functional_acceptance_complete'])


if __name__ == '__main__':
    unittest.main()
