"""Evidence catalogue tests; fixtures are not native runtime evidence."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

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

    def test_a02_native_adapter_coverage_does_not_promote_unrun_cases(self):
        result = self.check.validate(self.document, ROOT)
        coverage = result.get('verifier_coverage', {})
        self.assertIn('raw_contracts', coverage, 'Raw verifier coverage is not reported')
        self.assertEqual(coverage['native_receipt_cases'], ['A02'])
        self.assertEqual(coverage['raw_contracts']['A02']['native_receipt_admitted'], True)
        self.assertEqual(coverage['raw_contracts']['A02']['native_verifier_version'], 'a02-native-v4')
        self.assertEqual(result['states']['NOT_RUN'], 69)

    def native_row(self, root, *, case='A02', filename='summary.json', status='PASS'):
        receipt = root / filename
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({'test_id': case, 'status': 'PASS',
                                       'native_execution_verified': True,
                                       'raw_contract_valid': True}))
        row = copy.deepcopy(next(r for r in self.document['cases'] if r['id'] == case))
        row.update(status=status, evidence={'path': filename,
                    'sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()})
        return row

    def check_native_row(self, row, root):
        return self.check.check_rows([row], {row['id']}, 'case set', root, descriptions=True)

    def test_a02_patched_emulator_source_comes_only_from_explicit_caller(self):
        # Mock tests adapter routing only, never execution or native acceptance.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root)
            source = root / 'trusted-emulator'
            with patch.object(self.check, 'verify_native_receipt', return_value={
                    'test_id': 'A02', 'native_acceptance_status': 'PASS',
                    'native_execution_verified': True, 'runtime_truth_attested': False}) as replay:
                self.check.check_rows([row], {'A02'}, 'case set', root,
                                      descriptions=True, qemu_source=source)
                replay.assert_called_once_with(root, source_root=root, qemu_source=source)
            row['evidence']['qemu_source'] = str(source)
            with patch.object(self.check, 'verify_native_receipt') as replay:
                with self.assertRaises(ValueError):
                    self.check_native_row(row, root)
                replay.assert_not_called()

    def test_a02_legacy_adapter_does_not_infer_an_emulator_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root)
            with patch.object(self.check, 'verify_native_receipt', return_value={
                    'test_id': 'A02', 'native_acceptance_status': 'PASS',
                    'native_execution_verified': True, 'runtime_truth_attested': False}) as replay:
                self.check_native_row(row, root)
                replay.assert_called_once_with(root, source_root=root)

    def test_raw_contract_or_producer_pass_boolean_cannot_close_a02(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root)
            with self.assertRaisesRegex(ValueError, 'incomplete native artifact inventory'):
                self.check_native_row(row, root)

    def test_a10_offline_adapter_is_reported_without_opening_native_admission(self):
        result = self.check.validate(self.document, ROOT)
        coverage = result['verifier_coverage']
        self.assertEqual(coverage['native_receipt_cases'], ['A02'])
        a10 = coverage['raw_contracts']['A10']
        self.assertFalse(a10['native_receipt_admitted'])
        self.assertEqual(a10['offline_verifier_version'], 'a10-offline-v1')
        self.assertTrue(a10['native_admission_blockers'])
        self.assertEqual(result['states']['NOT_RUN'], 69)

    def test_a10_producer_pass_without_raw_matrix_inventory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root, case='A10')
            with self.assertRaisesRegex(ValueError, 'matrix-input'):
                self.check_native_row(row, root)

    def test_a10_complete_raw_contract_does_not_imply_native_receipt_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root, case='A10')
            with patch.object(self.check, 'verify_a10_matrix_receipt', return_value={
                    'raw_matrix_verified': True, 'native_acceptance_status': 'PASS',
                    'native_execution_verified': True}) as replay:
                with self.assertRaisesRegex(ValueError, 'A10 native receipt admission remains closed'):
                    self.check_native_row(row, root)
                replay.assert_called_once_with(root, source_root=root)

    def test_a10_wrong_summary_name_and_fail_classification_remain_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, status, message in (
                    ('other.json', 'PASS', 'A10 receipt must name summary.json'),
                    ('summary.json', 'FAIL', 'A10 native FAIL classification is not registered')):
                row = self.native_row(root, case='A10', filename=filename, status=status)
                with self.subTest(filename=filename, status=status), self.assertRaisesRegex(ValueError, message):
                    self.check_native_row(row, root)

    def test_a02_adapter_requires_canonical_summary_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root, filename='receipt.json')
            with self.assertRaisesRegex(ValueError, 'A02 receipt must name summary.json'):
                self.check_native_row(row, root)

    def test_a02_adapter_cannot_certify_native_failure_from_checker_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root, status='FAIL')
            with self.assertRaisesRegex(ValueError, 'A02 native FAIL classification is not registered'):
                self.check_native_row(row, root)

    def test_a02_receipt_cannot_close_another_case_or_action_family(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root, case='A03')
            with self.assertRaisesRegex(ValueError, 'No complete 1.3 native receipt verifier'):
                self.check_native_row(row, root)
            row = {key: value for key, value in row.items() if key in ('id', 'status', 'evidence')}
            row['id'] = 'D01_CORESET'
            with self.assertRaisesRegex(ValueError, 'No complete 1.3 native receipt verifier'):
                self.check.check_rows([row], {'D01_CORESET'}, 'action family set', root, descriptions=False)

    def test_a02_receipt_rejects_bad_hash_and_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.native_row(root, filename='real/summary.json')
            row['evidence']['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                self.check_native_row(row, root)
            row = self.native_row(root, filename='real/summary.json')
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            row['evidence']['path'] = 'alias/summary.json'
            with self.assertRaisesRegex(ValueError, 'symlink'):
                self.check_native_row(row, root)

    def test_manifest_cannot_supply_a_checker_or_source_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key in ('checker', 'source_root'):
                row = self.native_row(root)
                row['evidence'][key] = '/tmp/arbitrary-code'
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.check_native_row(row, root)

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
