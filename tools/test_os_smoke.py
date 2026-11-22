"""Recovery evidence invariants; synthetic receipts do not certify guest execution."""
import re
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


class StorageCheckpoint(unittest.TestCase):
    class Console:
        def __init__(self, previous, outcome):
            self.raw = bytearray(previous)
            self.outcome = outcome

        def command(self, command, expected=()):
            if command != 'storage checkpoint':
                raise AssertionError(command)
            start = len(self.raw)
            self.raw.extend(self.outcome)
            for pattern in expected:
                self.until(pattern, start)
            return start

        def until(self, pattern, start=0):
            match = re.search(pattern, self.raw[start:], re.MULTILINE)
            if match is None:
                raise ValueError('checkpoint result missing')
            return match

    def test_unchanged_checkpoint_requires_latest_matching_durability_witness(self):
        durable = b'STORAGE_DURABLE generation=7 slot=0 bytes=1183 flushes=2 MECHANISM\r\n'
        reused = b'STORAGE_CHECKPOINT_UNCHANGED generation=7 flushes=2\r\n'
        self.assertEqual(os_smoke.storage_checkpoint(self.Console(durable, reused)),
                         dict(generation=7, flushes=2, reused=True))
        for previous in (b'', durable.replace(b'generation=7', b'generation=8'),
                         durable + durable.replace(b'generation=7', b'generation=8')):
            with self.subTest(previous=previous), self.assertRaises(ValueError):
                os_smoke.storage_checkpoint(self.Console(previous, reused))


class ParallelProcessReclamation(unittest.TestCase):
    def test_validates_each_killed_pid_against_the_boot_profile(self):
        class Console:
            raw = bytearray(
                b'USER_IMAGE_PROFILE name=test exec_pages=4096 heap_pages=65536 reserved_exec_bytes=1\r\n'
                b'SYSTEM_CAPACITY schema=1 cpus=4 process_grant_pages=320\r\n')
            next_pid = 16

            def command(self, command, expected=()):
                start = len(self.raw)
                if command == 'posix spawn spin':
                    self.raw.extend(f'USER pid={self.next_pid} started;\r\n'.encode())
                    self.next_pid += 1
                elif command.startswith('posix kill '):
                    self.raw.extend(f'USER pid={command.split()[-1]} killed; pages reclaimed\r\n'.encode())
                elif command == 'posix status':
                    self.raw.extend(b'UserStatus { pid: 18, free_pages: 320 }\r\n')
                elif command == 'posix list':
                    for pid in (16, 17, 18):
                        self.raw.extend((f'UserStatus {{ pid: {pid}, state: Killed, code: 137, free_pages: 320, '
                                         'heap_pages: 0, heap_free: 65536, image_pages: 0, image_free: 4096, '
                                         'thread_count: 0, heap_allocations: 0, heap_largest_free: 65536 }\r\n').encode())
                else:
                    raise AssertionError(command)
                for pattern in expected:
                    self.until(pattern, start)
                return start

            def until(self, pattern, start=0):
                match = re.search(pattern, self.raw[start:], re.MULTILINE)
                if match is None:
                    raise AssertionError(f'Unmatched console pattern {pattern!r}')
                return match

        class Qmp:
            def execute(self, command, params=None):
                if command == 'human-monitor-command':
                    return '\n'.join(f'CPU#{cpu}\nCPL=3' for cpu in (1, 2, 3))

        with tempfile.TemporaryDirectory() as output:
            result = os_smoke.parallel_checks(Console(), Qmp(), Path(output))
        self.assertEqual([(row['pid'], row['free_pages']) for row in result['reclaimed']],
                         [(16, 320), (17, 320), (18, 320)])


if __name__ == '__main__': unittest.main()
