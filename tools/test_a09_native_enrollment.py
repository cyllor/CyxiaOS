"""Fixed A09 adapter dispatch only; mocked verdicts are never native evidence."""
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


class A09NativeEnrollment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.document = json.loads(checker.DEFAULT.read_text())
        spec = self.document['spec']['path']
        (self.root / spec).write_bytes((checker.ROOT / spec).read_bytes())
        self.receipt = self.make_receipt('A09')
        self.row = self.pass_row('A09', self.receipt)
        self.build = self.root / 'caller-selected-memory-build'
        self.qemu = self.root / 'caller-selected-qemu'
        self.complete = dict(status='PASS', test_id='A09', native_acceptance_status='PASS',
                             native_execution_verified=True, full_a09_verified=True,
                             actual_cache_pressure_verified=True, runtime_truth_attested=False)

    def make_receipt(self, case):
        receipt = self.root / 'runs' / case / 'summary.json'
        receipt.parent.mkdir(parents=True)
        # These untrusted strings must never choose an executable or context.
        receipt.write_text(json.dumps(dict(status='PASS', build='/archive/build',
            source_root='/archive/source', qemu_source='/archive/qemu',
            verifier='/archive/checker')) + '\n')
        return receipt

    def pass_row(self, case, receipt):
        row = copy.deepcopy(next(r for r in self.document['cases'] if r['id'] == case))
        row.update(status='PASS', evidence={
            'path': receipt.relative_to(self.root).as_posix(),
            'sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()})
        return row

    def options(self):
        return dict(qemu_source=self.qemu, a09_build=self.build)

    def check(self, **options):
        return checker.check_rows([self.row], {'A09'}, 'case set', self.root,
                                  descriptions=True, **options)

    def test_missing_trusted_context_is_rejected_before_replay(self):
        # This existing-API invocation reaches the previously unregistered A09
        # path; no absent keyword or synthetic helper can create the RED.
        with patch.object(checker, 'verify_a09_native_receipt', create=True) as replay:
            with self.assertRaisesRegex(ValueError, 'A09.*explicit'):
                self.check(qemu_source=self.qemu)
            replay.assert_not_called()

    def test_each_explicit_context_is_required(self):
        for missing in self.options():
            options = self.options()
            del options[missing]
            with self.subTest(missing=missing), \
                    patch.object(checker, 'verify_a09_native_receipt', create=True) as replay:
                with self.assertRaisesRegex(ValueError, 'A09.*explicit'):
                    self.check(**options)
                replay.assert_not_called()

    def test_fixed_adapter_receives_only_caller_selected_build_source_and_qemu(self):
        with patch.object(checker, 'verify_a09_native_receipt', create=True,
                          return_value=self.complete) as replay:
            self.assertEqual(self.check(**self.options()), {'PASS': 1, 'FAIL': 0, 'NOT_RUN': 0})
            replay.assert_called_once_with(self.receipt.parent, build=self.build,
                source_root=self.root, qemu_source=self.qemu)

    def test_partial_or_forged_verdict_cannot_close_a09(self):
        changes = [('status', 'STRUCTURE_VALID'), ('test_id', 'A10'),
                   ('native_acceptance_status', 'NOT_RUN'),
                   ('native_execution_verified', False), ('full_a09_verified', False),
                   ('actual_cache_pressure_verified', False), ('runtime_truth_attested', True),
                   ('native_execution_verified', 1), ('full_a09_verified', 1),
                   ('actual_cache_pressure_verified', 1)]
        for key, value in changes:
            with self.subTest(key=key, value=value), patch.object(checker,
                    'verify_a09_native_receipt', create=True,
                    return_value=dict(self.complete, **{key: value})):
                with self.assertRaisesRegex(ValueError, 'complete A09'):
                    self.check(**self.options())
        for observed in (None, [], {}, {'status': 'PASS'}):
            with self.subTest(observed=observed), patch.object(checker,
                    'verify_a09_native_receipt', create=True, return_value=observed):
                with self.assertRaisesRegex(ValueError, 'complete A09'):
                    self.check(**self.options())

    def test_native_error_is_not_converted_to_pass(self):
        with patch.object(checker, 'verify_a09_native_receipt', create=True,
                          side_effect=ValueError('anonymous page aliases cache')):
            with self.assertRaisesRegex(ValueError, 'anonymous page aliases cache'):
                self.check(**self.options())

    def test_fail_classifier_is_unregistered(self):
        self.row['status'] = 'FAIL'
        with patch.object(checker, 'verify_a09_native_receipt', create=True) as replay:
            with self.assertRaisesRegex(ValueError, 'A09 native FAIL classification'):
                self.check(**self.options())
            replay.assert_not_called()

    def test_wrong_receipt_name_path_and_sha_never_reach_replay(self):
        other = self.receipt.with_name('producer.json')
        other.write_bytes(self.receipt.read_bytes())
        invalid = [dict(self.row['evidence'], path=other.relative_to(self.root).as_posix()),
                   dict(self.row['evidence'], path=str(self.receipt)),
                   dict(self.row['evidence'], path='../summary.json'),
                   dict(self.row['evidence'], sha256='00' * 32)]
        for evidence in invalid:
            self.row['evidence'] = evidence
            with self.subTest(evidence=evidence), patch.object(checker,
                    'verify_a09_native_receipt', create=True) as replay:
                with self.assertRaises(ValueError):
                    self.check(**self.options())
                replay.assert_not_called()

    def test_receipt_cannot_choose_adapter_context_or_executable(self):
        for field in ('verifier', 'source_root', 'a09_build', 'build', 'qemu_source', 'executable'):
            self.row['evidence'][field] = '/archive/selected'
            with self.subTest(field=field), patch.object(checker,
                    'verify_a09_native_receipt', create=True) as replay:
                with self.assertRaises(ValueError):
                    self.check(**self.options())
                replay.assert_not_called()
            del self.row['evidence'][field]

    def test_default_catalogue_stays_69_not_run_with_or_without_context(self):
        for options in ({}, self.options()):
            with self.subTest(options=options), patch.object(checker,
                    'verify_a09_native_receipt', create=True) as replay:
                result = checker.validate(self.document, self.root, **options)
                self.assertEqual(result['states'], {'PASS': 0, 'FAIL': 0, 'NOT_RUN': 69})
                self.assertFalse(result['a_acceptance_complete'])
                self.assertFalse(result['functional_acceptance_complete'])
                coverage = result['verifier_coverage']
                self.assertEqual('A09' in coverage['native_receipt_cases'], bool(options))
                self.assertEqual(coverage['raw_contracts']['A09']['native_receipt_admitted'], bool(options))
                replay.assert_not_called()

    def test_enrollment_is_new_catalogue_and_revalidates_inherited_a02(self):
        inherited = self.pass_row('A02', self.make_receipt('A02'))
        document = copy.deepcopy(self.document)
        document['cases'][1] = inherited
        before = copy.deepcopy(document)
        complete_a02 = dict(test_id='A02', native_acceptance_status='PASS',
                            native_execution_verified=True, runtime_truth_attested=False)
        with patch.object(checker, 'verify_native_receipt', return_value=complete_a02) as a02, \
                patch.object(checker, 'verify_a09_native_receipt', create=True,
                             return_value=self.complete) as a09:
            result, report = enrollment.enroll(document, 'A09', self.receipt,
                                               self.root, **self.options())
            a02.assert_called_once_with(self.root / 'runs/A02', source_root=self.root,
                                        qemu_source=self.qemu)
            a09.assert_called_once_with(self.receipt.parent, build=self.build,
                source_root=self.root, qemu_source=self.qemu)
        self.assertEqual(document, before)
        self.assertEqual(report['states'], {'PASS': 2, 'FAIL': 0, 'NOT_RUN': 67})
        self.assertEqual([r['id'] for r in result['cases'] if r['status'] == 'PASS'], ['A02', 'A09'])

    def test_inherited_failed_a02_aborts_without_mutating_input(self):
        document = copy.deepcopy(self.document)
        document['cases'][1] = self.pass_row('A02', self.make_receipt('A02'))
        before = copy.deepcopy(document)
        with patch.object(checker, 'verify_native_receipt', side_effect=ValueError('stale A02 source')), \
                patch.object(checker, 'verify_a09_native_receipt', create=True) as a09:
            with self.assertRaisesRegex(ValueError, 'stale A02 source'):
                enrollment.enroll(document, 'A09', self.receipt, self.root, **self.options())
            a09.assert_not_called()
        self.assertEqual(document, before)

    def test_a09_context_does_not_replace_inherited_a10_context(self):
        document = copy.deepcopy(self.document)
        document['cases'][9] = self.pass_row('A10', self.make_receipt('A10'))
        with patch.object(checker, 'verify_a09_native_receipt', create=True,
                          return_value=self.complete), \
                patch.object(checker, 'verify_a10_matrix_receipt', return_value={}), \
                patch.object(checker, 'verify_a10_native_matrix_receipt') as a10:
            with self.assertRaisesRegex(ValueError, 'A10.*explicit'):
                enrollment.enroll(document, 'A09', self.receipt, self.root, **self.options())
            a10.assert_not_called()
        context = dict(self.options(), a10_build_manifest=self.root / 'a10-build.json',
                       a10_formatter=self.root / 'a10-formatter')
        complete_a10 = dict(test_id='A10', native_acceptance_status='PASS',
            native_execution_verified=True, raw_matrix_verified=True,
            native_filesystem_fault_matrix_complete=True)
        with patch.object(checker, 'verify_a09_native_receipt', create=True,
                          return_value=self.complete), \
                patch.object(checker, 'verify_a10_matrix_receipt', return_value={}), \
                patch.object(checker, 'verify_a10_native_matrix_receipt', return_value=complete_a10) as a10:
            _, report = enrollment.enroll(document, 'A09', self.receipt, self.root, **context)
            a10.assert_called_once_with(self.root / 'runs/A10', source_root=self.root,
                build_manifest=context['a10_build_manifest'],
                qemu_binary=self.qemu / 'build/qemu-system-aarch64', qemu_source=self.qemu,
                formatter_binary=context['a10_formatter'])
        self.assertEqual(report['states'], {'PASS': 2, 'FAIL': 0, 'NOT_RUN': 67})

    def cli_inputs(self):
        document = copy.deepcopy(self.document)
        document['cases'][8] = self.row
        manifest = self.root / 'input-catalogue.json'
        manifest.write_text(json.dumps(document))
        return manifest

    def test_checker_cli_forwards_explicit_a09_build(self):
        manifest = self.cli_inputs()
        with patch.object(checker, 'verify_a09_native_receipt', create=True,
                          return_value=self.complete) as replay, contextlib.redirect_stdout(io.StringIO()):
            code = checker.main(['--manifest', str(manifest), '--root', str(self.root),
                '--a09-build', str(self.build), '--qemu-source', str(self.qemu)])
        self.assertEqual(code, 0)
        replay.assert_called_once_with(self.receipt.parent, build=self.build,
            source_root=self.root, qemu_source=self.qemu)

    def test_report_cli_forwards_context_and_keeps_release_gate_closed(self):
        manifest = self.cli_inputs()
        with patch.object(prototype, 'ROOT', self.root), \
                patch.object(checker, 'verify_a09_native_receipt', create=True,
                             return_value=self.complete) as replay, \
                contextlib.redirect_stdout(io.StringIO()):
            code = prototype.main(['report', '--manifest', str(manifest), '--scope', 'A',
                '--a09-build', str(self.build), '--qemu-source', str(self.qemu)])
        self.assertEqual(code, 2)
        replay.assert_called_once_with(self.receipt.parent, build=self.build,
            source_root=self.root, qemu_source=self.qemu)

    def test_enroll_cli_forwards_context_and_cannot_create_output_on_failed_replay(self):
        manifest = self.root / 'base-catalogue.json'
        manifest.write_text(json.dumps(self.document))
        output = self.root / 'run-catalogue.json'
        args = ['--manifest', str(manifest), '--case', 'A09', '--receipt', str(self.receipt),
                '--source-root', str(self.root), '--a09-build', str(self.build),
                '--qemu-source', str(self.qemu), '--output', str(output)]
        with patch.object(checker, 'verify_a09_native_receipt', create=True,
                          side_effect=ValueError('A09 stopped page changed')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(enrollment.main(args), 1)
        self.assertFalse(output.exists())
        with patch.object(checker, 'verify_a09_native_receipt', create=True,
                          return_value=self.complete) as replay, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(enrollment.main(args), 0)
        replay.assert_called_once_with(self.receipt.parent, build=self.build,
            source_root=self.root, qemu_source=self.qemu)
        result = json.loads(output.read_text())
        self.assertEqual([r['id'] for r in result['cases'] if r['status'] == 'PASS'], ['A09'])
        self.assertTrue(all(r['status'] == 'NOT_RUN' for r in json.loads(manifest.read_text())['cases']))


if __name__ == '__main__':
    unittest.main()
