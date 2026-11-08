"""Portable integrity tests; synthetic receipts never establish native A12."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_v16_a12 as a12


class CaptureIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'bank.bin').write_bytes(b'protected bank example')
        (self.root / 'summary.json').write_text('{}')
        self.summary = {'evidence_sha256': {'bank.bin': a12.sha256(self.root / 'bank.bin')}}

    def test_inventory_requires_every_file_and_original_bytes(self):
        a12._inventory(self.root, self.summary)
        (self.root / 'bank.bin').write_bytes(b'changed bank')
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            a12._inventory(self.root, self.summary)

    def test_unlisted_file_rejected(self):
        (self.root / 'unlisted.bin').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            a12._inventory(self.root, self.summary)

    def test_symlink_and_escaping_paths_rejected(self):
        (self.root / 'link').symlink_to(self.root / 'bank.bin')
        for relative in ('link', '../bank.bin', '/bank.bin', './bank.bin'):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                a12._path(self.root, relative)

    def test_duplicate_json_key_rejected(self):
        path = self.root / 'summary.json'
        path.write_text('{"status":"FAIL","status":"PASS"}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            a12._json(path)


class ReceiptReplay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name in a12.VERIFIER_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# fixed verifier test stand-in\n')
        self.directory = self.root / 'receipt'
        self.directory.mkdir()
        (self.root / 'capture').mkdir()
        # This value is deliberately synthetic. Only mocked dispatch is tested.
        self.observed = {'test_id': 'A12', 'native_acceptance_status': 'PASS'}
        self.receipt = dict(schema_version=1, test_id='A12', verifier_version=a12.VERSION,
            capture='capture', verifier_files_sha256={name: a12.sha256(self.root / name)
                for name in a12.VERIFIER_FILES}, verification=self.observed)
        self.context = dict(source_root=self.root, build_manifest=self.root / 'build.json',
                            formatter=self.root / 'formatter', qemu_source=self.root / 'qemu')

    def write(self):
        (self.directory / 'summary.json').write_text(json.dumps(self.receipt))

    def test_replays_with_caller_context(self):
        self.write()
        with patch.object(a12, 'verify_capture', return_value=self.observed) as replay:
            self.assertEqual(a12.verify_native(self.directory, **self.context), self.observed)
        replay.assert_called_once_with(self.root / 'capture', **self.context)

    def test_producer_pass_cannot_override_raw_replay_failure(self):
        self.write()
        with patch.object(a12, 'verify_capture', side_effect=ValueError('raw evidence invalid')):
            with self.assertRaisesRegex(ValueError, 'raw evidence invalid'):
                a12.verify_native(self.directory, **self.context)

    def test_stored_verdict_must_equal_recomputed_result(self):
        self.write()
        different = dict(self.observed, full_a12_verified=False)
        with patch.object(a12, 'verify_capture', return_value=different):
            with self.assertRaisesRegex(ValueError, 'independent raw replay'):
                a12.verify_native(self.directory, **self.context)

    def test_receipt_cannot_select_checker_or_outside_capture(self):
        for mutation in ({'checker': 'arbitrary.py'}, {'capture': '../outside'}):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy(self.receipt)
                self.receipt.update(mutation)
                self.write()
                with patch.object(a12, 'verify_capture') as replay, self.assertRaises(ValueError):
                    a12.verify_native(self.directory, **self.context)
                replay.assert_not_called()
                self.receipt = original

    def test_changed_verifier_before_or_during_replay_rejected(self):
        self.write()
        path = self.root / a12.VERIFIER_FILES[0]
        original = path.read_bytes()
        path.write_bytes(original + b'# changed\n')
        with patch.object(a12, 'verify_capture') as replay, self.assertRaisesRegex(ValueError, 'source differs'):
            a12.verify_native(self.directory, **self.context)
        replay.assert_not_called()
        path.write_bytes(original)

        def change_during_replay(*args, **kwargs):
            path.write_bytes(original + b'# changed again\n')
            return self.observed

        with patch.object(a12, 'verify_capture', side_effect=change_during_replay):
            with self.assertRaisesRegex(ValueError, 'changed during replay'):
                a12.verify_native(self.directory, **self.context)

    def test_issuance_rejects_tool_change_without_writing_receipt(self):
        output = self.root / 'new-receipt'

        def change_tool(*args, **kwargs):
            (self.root / a12.VERIFIER_FILES[0]).write_text('# changed during replay\n')
            return self.observed

        argv = ['--source-root', str(self.root), '--capture', str(self.root / 'capture'),
                '--output', str(output), '--build-manifest', str(self.context['build_manifest']),
                '--formatter', str(self.context['formatter']),
                '--qemu-source', str(self.context['qemu_source'])]
        with patch.object(a12, 'verify_capture', side_effect=change_tool):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = a12.main(argv)
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())


class ActorOrder(unittest.TestCase):
    def setUp(self):
        self.join = dict(actor=[4096, 4], submitted_ns=41_211_538_000,
                         completion_ns=50_173_428_000, original_deadline_ns=105_274_000_000)
        self.task = dict(probe_object=[4096, 4])

    def test_full_actor_identity_is_required(self):
        a12._actor_join(self.join, self.task, [33635])
        self.join['actor'][1] = 5
        with self.assertRaisesRegex(ValueError, 'actor/deadline'):
            a12._actor_join(self.join, self.task, [33635])

    def test_completion_cannot_exceed_original_deadline(self):
        self.join['completion_ns'] = self.join['original_deadline_ns'] + 1
        with self.assertRaisesRegex(ValueError, 'actor/deadline'):
            a12._actor_join(self.join, self.task, [33635])

    def test_pre_bound_or_same_millisecond_admission_rejected(self):
        for bound in ([], [41211], [41212]):
            with self.subTest(bound=bound), self.assertRaisesRegex(ValueError, 'after this node'):
                a12._actor_join(self.join, self.task, bound)


if __name__ == '__main__':
    unittest.main()
