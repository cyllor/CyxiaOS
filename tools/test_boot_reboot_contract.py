"""Host-only mutation tests; these do not establish native reboot acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from boot_reboot_contract import (DISK_BYTES, HANDOFF_LOG, handoff_origin, prepare_disk,
                                  verify_origin, verify_process, verify_transition)
from check_prototype_evidence import sha256


class RebootCustody(unittest.TestCase):
    def process(self):
        return dict(schema=1, started_ns=10, exited_ns=20, returncode=0, forced=False)

    def test_only_confirmed_normal_process_exit_can_transfer_disk(self):
        verify_process(self.process())
        for key, value in (('returncode', -9), ('returncode', False), ('forced', True),
                           ('exited_ns', 10), ('started_ns', 0), ('schema', True)):
            with self.subTest(key=key, value=value):
                record = self.process(); record[key] = value
                with self.assertRaises(ValueError): verify_process(record)

    def test_frozen_handoff_is_exact_and_does_not_accept_reformat(self):
        origin = dict(kind='handoff', parent_nonce='01'*16, parent_receipt_sha256='ab'*32,
                      disk_sha256='cd'*32, parent_exited_ns=20)
        before = dict(bytes=DISK_BYTES, sha256='cd'*32)
        verify_origin(origin, before, HANDOFF_LOG)
        for key, value in (('disk_sha256', 'ef'*32), ('parent_nonce', '../cold'),
                           ('parent_receipt_sha256', ''), ('parent_exited_ns', True),
                           ('path', '/arbitrary')):
            with self.subTest(key=key):
                changed = dict(origin); changed[key] = value
                with self.assertRaises(ValueError): verify_origin(changed, before, HANDOFF_LOG)
        with self.assertRaises(ValueError): verify_origin(origin, before, b'formatted anew')

    def test_same_uuid_monotonic_epoch_and_failed_boot_has_no_identity(self):
        before = dict(uuid='aa'*16, boot_epoch=7)
        for mode in (0, 3): verify_transition(before, dict(before, boot_epoch=8), mode, 8)
        for mode in (1, 2):
            for epoch in (7, 8): verify_transition(before, dict(before, boot_epoch=epoch), mode, 0)
        for mode, epoch, issued in ((0, 7, 7), (0, 9, 9), (3, 7, 7), (1, 7, 7), (2, 8, 8), (1, 6, 0)):
            with self.subTest(mode=mode, epoch=epoch, issued=issued):
                with self.assertRaises(ValueError):
                    verify_transition(before, dict(before, boot_epoch=epoch), mode, issued)
        with self.assertRaises(ValueError):
            verify_transition(before, dict(uuid='bb'*16, boot_epoch=8), 0, 8)
        verify_transition(None, dict(uuid='aa'*16, boot_epoch=1), 0, 1)
        with self.assertRaises(ValueError):
            verify_transition(None, dict(uuid='aa'*16, boot_epoch=2), 0, 2)

    def test_handoff_never_calls_formatter_and_retains_predecessor_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); previous = root/'previous'; previous.mkdir()
            output = root/'next'; output.mkdir()
            # Tiny mocked storage identity keeps this a host unit test.
            (previous/'disk.raw').write_bytes(b'previous-volume')
            (previous/'process-exit.json').write_text(json.dumps(self.process()))
            (previous/'input.json').write_text(json.dumps({'nonce': '01'*16}))
            files = {p.name: dict(bytes=p.stat().st_size, sha256=sha256(p))
                     for p in previous.iterdir()}
            (previous/'summary.json').write_text(json.dumps({'files': files}))
            def identity(path): return dict(bytes=path.stat().st_size, sha256=sha256(path))
            with patch('boot_reboot_contract.disk_identity', side_effect=identity), \
                 patch('boot_reboot_contract.subprocess.run') as formatter:
                origin = prepare_disk(output, Path('/unused'), 'unused', previous)
                self.assertEqual(origin['kind'], 'handoff')
                self.assertEqual((output/'disk.raw').read_bytes(), b'previous-volume')
                self.assertEqual((previous/'disk.raw').read_bytes(), b'previous-volume')
                self.assertEqual((output/'format.log').read_bytes(), HANDOFF_LOG)
                formatter.assert_not_called()
                (previous/'process-exit.json').write_text(json.dumps(dict(self.process(), forced=True)))
                with self.assertRaises(ValueError): handoff_origin(previous)




class RebootLinkMutations(unittest.TestCase):
    def facts(self):
        first = dict(mode=0, issued_epoch=1, disk=dict(uuid='ab'*16, boot_epoch=1),
                     image_sha256='11'*32, source_sha256='22'*32, build_sha256='33'*32,
                     run_nonce='11'*16, origin={'kind': 'fresh'}, disk_sha256='44'*32,
                     receipt_sha256='55'*32, disk_before_sha256='00'*32,
                     process=dict(schema=1, started_ns=10, exited_ns=20, returncode=0, forced=False))
        second = copy.deepcopy(first)
        second.update(issued_epoch=2, disk=dict(uuid='ab'*16, boot_epoch=2), run_nonce='22'*16,
                      disk_before_sha256=first['disk_sha256'],
                      origin=dict(kind='handoff', parent_nonce=first['run_nonce'],
                                  parent_receipt_sha256=first['receipt_sha256'],
                                  disk_sha256=first['disk_sha256'], parent_exited_ns=20),
                      process=dict(schema=1, started_ns=21, exited_ns=30, returncode=0, forced=False))
        return first, second

    def test_valid_chain_has_no_overlap_and_exact_prior_image(self):
        from verify_v13_boot_reboots import verify_link
        first, second = self.facts()
        verify_link(None, first); verify_link(first, second)
        second['process']['started_ns'] = 20
        with self.assertRaisesRegex(ValueError, 'overlapped'): verify_link(first, second)

    def test_individually_valid_fresh_boots_cannot_be_spliced_as_reboots(self):
        from verify_v13_boot_reboots import verify_link
        first, second = self.facts()
        second['origin'] = {'kind': 'fresh'}
        with self.assertRaisesRegex(ValueError, 'exact preceding'): verify_link(first, second)

    def test_edited_parent_identity_or_disk_is_refused(self):
        from verify_v13_boot_reboots import verify_link
        for key in ('parent_nonce', 'parent_receipt_sha256', 'disk_sha256', 'parent_exited_ns'):
            first, second = self.facts()
            second['origin'][key] = '00'
            with self.subTest(key=key), self.assertRaises(ValueError): verify_link(first, second)
        for key in ('image_sha256', 'source_sha256', 'build_sha256', 'disk_before_sha256'):
            first, second = self.facts(); second[key] = '00'*32
            with self.subTest(key=key), self.assertRaises(ValueError): verify_link(first, second)

    def test_same_nonce_or_reset_epoch_never_passes(self):
        from verify_v13_boot_reboots import verify_link
        first, second = self.facts(); second['run_nonce'] = first['run_nonce']
        with self.assertRaises(ValueError): verify_link(first, second)
        first, second = self.facts(); second['disk']['boot_epoch'] = second['issued_epoch'] = 1
        with self.assertRaises(ValueError): verify_link(first, second)


if __name__ == '__main__': unittest.main()
