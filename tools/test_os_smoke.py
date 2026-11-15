"""Recovery evidence invariants; synthetic receipts do not certify guest execution."""
import tempfile
import unittest
from pathlib import Path
import os_smoke
import x86_64 as pc


class RuntimeRecovery(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.disk = self.root / 'data.raw'
        self.disk.write_bytes(b'synthetic checkpoint disk')
        producer = b'synthetic frozen producer'
        (self.root / 'capture-producer.py').write_bytes(producer)
        self.current = dict(source_sha256='source', build_manifest_sha256='build',
                            producer_sha256=pc.sha_bytes(producer),
                            producer_inputs_sha256={'helper.py': 'helper'})
        self.commands = []
        self.raw = bytearray()
        for command, output in [
                ('write /run/user/0/boot-expired stale-session', b'cyxia:/> '),
                ('cat /run/user/0/boot-expired', b'\r\nstale-session\r\ncyxia:/> '),
                ('storage checkpoint', b'\r\nSTORAGE_DURABLE generation=7 slot=0 bytes=1183 flushes=2 MECHANISM\r\ncyxia:/> ')]:
            self.commands.append(dict(command=command, serial_offset=len(self.raw)))
            self.raw.extend(command.encode() + b'\r\n' + output)
        self.previous = dict(self.current, status='OS_FLOCK_PASS', disk=str(self.disk),
                             disk_after_sha256=pc.sha(self.disk),
                             runtime_checkpoint={'generation': 7, 'bytes': 1183, 'flushes': 2})
        self.save()

    def save(self):
        (self.root / 'serial.raw').write_bytes(self.raw)
        pc.write_json(self.root / 'commands.json', self.commands)
        self.previous.update(serial_sha256=pc.sha(self.root / 'serial.raw'),
                             commands_sha256=pc.sha(self.root / 'commands.json'))
        pc.write_json(self.root / 'summary.json', self.previous)

    def test_same_disk_and_durable_sentinel_are_bound_to_the_predecessor(self):
        proof = os_smoke.flock_recovery_input(self.disk, self.current)
        self.assertEqual(proof['checkpoint']['generation'], 7)
        self.assertEqual(proof['summary_sha256'], pc.sha(self.root / 'summary.json'))

    def test_success_receipt_without_actual_sentinel_output_is_rejected(self):
        self.raw = self.raw.replace(b'\r\nstale-session\r\n', b'\r\nother-session\r\n')
        self.save()
        with self.assertRaises(ValueError): os_smoke.flock_recovery_input(self.disk, self.current)

    def test_readback_without_a_subsequent_flush_is_rejected(self):
        self.raw = self.raw.replace(b'flushes=2', b'flushes=1')
        self.save()
        with self.assertRaises(ValueError): os_smoke.flock_recovery_input(self.disk, self.current)

    def test_changed_disk_source_or_capture_is_rejected(self):
        self.disk.write_bytes(b'a different disk')
        with self.assertRaises(ValueError): os_smoke.flock_recovery_input(self.disk, self.current)
        self.disk.write_bytes(b'synthetic checkpoint disk')
        for field in ('source_sha256', 'build_manifest_sha256', 'producer_sha256', 'producer_inputs_sha256'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                os_smoke.flock_recovery_input(self.disk, dict(self.current, **{field: 'changed'}))
        (self.root / 'serial.raw').write_bytes(b'changed capture')
        with self.assertRaises(ValueError): os_smoke.flock_recovery_input(self.disk, self.current)


if __name__ == '__main__': unittest.main()
