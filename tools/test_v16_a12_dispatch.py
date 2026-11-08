"""Portable A12 adapter dispatch tests; mocked verdicts are not native evidence."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_v13_evidence as checker
import enroll_v15_a as enrollment
import prototype


class A12Dispatch(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.document = json.loads(checker.DEFAULT.read_text())
        spec = self.document['spec']['path']
        (self.root / spec).write_bytes((checker.ROOT / spec).read_bytes())
        self.receipt = self.root / 'run' / 'summary.json'
        self.receipt.parent.mkdir()
        self.receipt.write_text('{"source_root":"/untrusted/archive"}\n')
        self.row = copy.deepcopy(next(r for r in self.document['cases'] if r['id'] == 'A12'))
        self.row.update(status='PASS', evidence={
            'path': 'run/summary.json',
            'sha256': hashlib.sha256(self.receipt.read_bytes()).hexdigest()})
        self.build = self.root / 'trusted-build.json'
        self.formatter = self.root / 'trusted-formatter'
        self.qemu = self.root / 'trusted-qemu'
        self.complete = dict(test_id='A12', native_acceptance_status='PASS',
                             native_execution_verified=True, full_a12_verified=True,
                             runtime_truth_attested=False)

    def options(self):
        return dict(qemu_source=self.qemu, a12_build_manifest=self.build,
                    a12_formatter=self.formatter)

    def check(self, **options):
        return checker.check_rows([self.row], {'A12'}, 'case set', self.root,
                                  descriptions=True, **options)

    def manifest(self, *, admitted=True):
        document = copy.deepcopy(self.document)
        if admitted:
            document['cases'][11] = copy.deepcopy(self.row)
        path = self.root / ('admitted.json' if admitted else 'base.json')
        path.write_text(json.dumps(document))
        return path

    def test_missing_adapter_requires_explicit_context(self):
        # Existing check_rows API: the initial RED is missing A12 registration,
        # not an absent keyword or fabricated native capture.
        with patch.object(checker, 'verify_a12_native_receipt', create=True) as replay:
            with self.assertRaisesRegex(ValueError, 'A12.*explicit'):
                self.check(qemu_source=self.qemu)
            replay.assert_not_called()

    def test_each_trusted_context_is_required_before_replay(self):
        for missing in self.options():
            options = self.options()
            del options[missing]
            with self.subTest(missing=missing), \
                    patch.object(checker, 'verify_a12_native_receipt') as replay:
                with self.assertRaisesRegex(ValueError, 'A12.*explicit'):
                    self.check(**options)
                replay.assert_not_called()

    def test_fixed_adapter_receives_only_caller_selected_paths(self):
        with patch.object(checker, 'verify_a12_native_receipt',
                          return_value=self.complete) as replay:
            self.assertEqual(self.check(**self.options()), {'PASS': 1, 'FAIL': 0, 'NOT_RUN': 0})
            replay.assert_called_once_with(self.receipt.parent, source_root=self.root,
                build_manifest=self.build, formatter=self.formatter, qemu_source=self.qemu)

    def test_validate_requires_explicit_source_even_with_other_context(self):
        document = json.loads(self.manifest().read_text())
        with patch.object(checker, 'verify_a12_native_receipt') as replay:
            with self.assertRaisesRegex(ValueError, 'A12.*explicit.*source'):
                checker.validate(document, **self.options())
            replay.assert_not_called()

    def test_partial_wrong_case_and_non_boolean_flags_are_rejected(self):
        changes = [('test_id', 'A13'), ('native_acceptance_status', 'NOT_RUN'),
                   ('full_a12_verified', False), ('full_a12_verified', 1),
                   ('native_execution_verified', False), ('native_execution_verified', 1),
                   ('runtime_truth_attested', True), ('runtime_truth_attested', 0)]
        invalid = [dict(self.complete, **{key: value}) for key, value in changes]
        invalid += [None, [], {}, {'native_acceptance_status': 'PASS'}]
        for key in self.complete:
            invalid.append({k: v for k, v in self.complete.items() if k != key})
        for observed in invalid:
            with self.subTest(observed=observed), patch.object(checker,
                    'verify_a12_native_receipt', return_value=observed):
                with self.assertRaisesRegex(ValueError, 'complete A12'):
                    self.check(**self.options())

    def test_verifier_error_is_not_converted_to_pass(self):
        with patch.object(checker, 'verify_a12_native_receipt',
                          side_effect=ValueError('same configuration proof differs')):
            with self.assertRaisesRegex(ValueError, 'same configuration proof differs'):
                self.check(**self.options())

    def test_fail_classification_is_not_registered(self):
        self.row['status'] = 'FAIL'
        with patch.object(checker, 'verify_a12_native_receipt') as replay:
            with self.assertRaisesRegex(ValueError, 'A12 native FAIL classification'):
                self.check(**self.options())
            replay.assert_not_called()

    def test_invalid_receipt_identity_never_reaches_adapter(self):
        other = self.receipt.with_name('producer.json')
        other.write_bytes(self.receipt.read_bytes())
        original = copy.deepcopy(self.row['evidence'])
        for evidence in [dict(original, path='run/producer.json'),
                         dict(original, path=str(self.receipt)),
                         dict(original, path='../summary.json'),
                         dict(original, sha256='00' * 32)]:
            self.row['evidence'] = evidence
            with self.subTest(evidence=evidence), \
                    patch.object(checker, 'verify_a12_native_receipt') as replay:
                with self.assertRaises(ValueError):
                    self.check(**self.options())
                replay.assert_not_called()

    def test_receipt_cannot_choose_verifier_or_trusted_context(self):
        for field in ('verifier', 'source_root', 'build_manifest', 'formatter', 'qemu_source'):
            self.row['evidence'][field] = '/archive/untrusted'
            with self.subTest(field=field), \
                    patch.object(checker, 'verify_a12_native_receipt') as replay:
                with self.assertRaises(ValueError):
                    self.check(**self.options())
                replay.assert_not_called()
            del self.row['evidence'][field]

    def test_default_catalogue_is_unpromoted_and_coverage_requires_full_context(self):
        contexts = [(self.root, self.options(), True), (None, self.options(), False),
                    (self.root, {}, False)]
        for root, options, admitted in contexts:
            with self.subTest(root=root, options=options), \
                    patch.object(checker, 'verify_a12_native_receipt') as replay:
                result = checker.validate(self.document, root, **options)
                self.assertEqual(result['states'], {'PASS': 0, 'FAIL': 0, 'NOT_RUN': 69})
                coverage = result['verifier_coverage']
                self.assertEqual('A12' in coverage['native_receipt_cases'], admitted)
                row = coverage['raw_contracts']['A12']
                self.assertEqual(row['native_receipt_admitted'], admitted)
                self.assertEqual(row['verifier'], 'tools/verify_v16_a12.py')
                self.assertTrue(row['requires_explicit_source_root'])
                self.assertFalse(result['a_acceptance_complete'])
                self.assertFalse(result['functional_acceptance_complete'])
                replay.assert_not_called()

    def inherited_a02(self):
        receipt = self.root / 'a02' / 'summary.json'
        receipt.parent.mkdir()
        receipt.write_text('{}\n')
        row = copy.deepcopy(self.document['cases'][1])
        row.update(status='PASS', evidence={'path': 'a02/summary.json',
            'sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()})
        return row

    def test_enrollment_revalidates_existing_case_and_preserves_input(self):
        document = copy.deepcopy(self.document)
        document['cases'][1] = self.inherited_a02()
        before = copy.deepcopy(document)
        a02_result = dict(test_id='A02', native_acceptance_status='PASS',
                          native_execution_verified=True, runtime_truth_attested=False)
        with patch.object(checker, 'verify_native_receipt', return_value=a02_result) as a02, \
                patch.object(checker, 'verify_a12_native_receipt',
                             return_value=self.complete) as a12:
            result, report = enrollment.enroll(document, 'A12', self.receipt,
                                                self.root, **self.options())
        a02.assert_called_once_with(self.root / 'a02', source_root=self.root,
                                    qemu_source=self.qemu)
        a12.assert_called_once_with(self.receipt.parent, source_root=self.root,
            build_manifest=self.build, formatter=self.formatter, qemu_source=self.qemu)
        self.assertEqual(document, before)
        self.assertEqual([r['id'] for r in result['cases'] if r['status'] == 'PASS'], ['A02', 'A12'])
        self.assertEqual(report['states'], {'PASS': 2, 'FAIL': 0, 'NOT_RUN': 67})
        self.assertFalse(report['functional_acceptance_complete'])

    def test_inherited_failure_aborts_without_promoting_a12(self):
        document = copy.deepcopy(self.document)
        document['cases'][1] = self.inherited_a02()
        before = copy.deepcopy(document)
        with patch.object(checker, 'verify_native_receipt', side_effect=ValueError('stale A02')), \
                patch.object(checker, 'verify_a12_native_receipt') as a12:
            with self.assertRaisesRegex(ValueError, 'stale A02'):
                enrollment.enroll(document, 'A12', self.receipt, self.root, **self.options())
            a12.assert_not_called()
        self.assertEqual(document, before)

    def test_checker_cli_forwards_explicit_context(self):
        with patch.object(checker, 'verify_a12_native_receipt',
                          return_value=self.complete) as replay, \
                contextlib.redirect_stdout(io.StringIO()):
            code = checker.main(['--manifest', str(self.manifest()), '--root', str(self.root),
                '--a12-build-manifest', str(self.build), '--a12-formatter', str(self.formatter),
                '--qemu-source', str(self.qemu)])
        self.assertEqual(code, 0)
        replay.assert_called_once_with(self.receipt.parent, source_root=self.root,
            build_manifest=self.build, formatter=self.formatter, qemu_source=self.qemu)

    def test_checker_cli_rejects_implicit_source(self):
        with patch.object(checker, 'verify_a12_native_receipt') as replay, \
                contextlib.redirect_stderr(io.StringIO()):
            code = checker.main(['--manifest', str(self.manifest()),
                '--a12-build-manifest', str(self.build), '--a12-formatter', str(self.formatter),
                '--qemu-source', str(self.qemu)])
        self.assertEqual(code, 1)
        replay.assert_not_called()

    def test_report_cli_forwards_context_and_keeps_global_gate_closed(self):
        with patch.object(checker, 'verify_a12_native_receipt',
                          return_value=self.complete) as replay, \
                contextlib.redirect_stdout(io.StringIO()):
            code = prototype.main(['report', '--manifest', str(self.manifest()), '--scope', 'A',
                '--source-root', str(self.root), '--a12-build-manifest', str(self.build),
                '--a12-formatter', str(self.formatter), '--qemu-source', str(self.qemu)])
        self.assertEqual(code, 2)
        replay.assert_called_once_with(self.receipt.parent, source_root=self.root,
            build_manifest=self.build, formatter=self.formatter, qemu_source=self.qemu)

    def test_report_cli_rejects_implicit_source(self):
        with patch.object(checker, 'verify_a12_native_receipt') as replay, \
                contextlib.redirect_stderr(io.StringIO()):
            code = prototype.main(['report', '--manifest', str(self.manifest()),
                '--a12-build-manifest', str(self.build), '--a12-formatter', str(self.formatter),
                '--qemu-source', str(self.qemu)])
        self.assertEqual(code, 1)
        replay.assert_not_called()

    def test_enroll_cli_writes_only_after_successful_replay(self):
        output = self.root / 'new-catalogue.json'
        manifest = self.manifest(admitted=False)
        args = ['--manifest', str(manifest), '--case', 'A12', '--receipt', str(self.receipt),
                '--source-root', str(self.root), '--a12-build-manifest', str(self.build),
                '--a12-formatter', str(self.formatter), '--qemu-source', str(self.qemu),
                '--output', str(output)]
        with patch.object(checker, 'verify_a12_native_receipt',
                          side_effect=ValueError('native config differs')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(enrollment.main(args), 1)
        self.assertFalse(output.exists())
        with patch.object(checker, 'verify_a12_native_receipt',
                          return_value=self.complete) as replay, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(enrollment.main(args), 0)
        replay.assert_called_once_with(self.receipt.parent, source_root=self.root,
            build_manifest=self.build, formatter=self.formatter, qemu_source=self.qemu)
        result = json.loads(output.read_text())
        self.assertEqual([r['id'] for r in result['cases'] if r['status'] == 'PASS'], ['A12'])
        self.assertTrue(all(r['status'] == 'NOT_RUN'
                            for r in json.loads(manifest.read_text())['cases']))


if __name__ == '__main__':
    unittest.main()
