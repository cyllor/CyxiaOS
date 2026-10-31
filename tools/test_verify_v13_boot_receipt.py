"""Host adversarial fixtures for boot provenance; never native acceptance evidence."""
import base64
import copy
import hashlib
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest import mock

from test_verify_v13_boot_recovery import fixture, verify
from verify_v13_boot_receipt import (MODES, verify_inventory, verify_launch,
                                     verify_matrix, verify_qmp)

ROOT = PurePosixPath('/captured/normal')
SYMBOLS = {name: {'pa': 0x41000000 + i * 0x10000}
           for i, name in enumerate(('boot', 'config', 'control', 'runtime', 'unified'))}
PLATFORM = {'cpus': [{'cpu-index': i} for i in range(4)],
            'memory': {'base-memory': 1024 ** 3}}


def launch():
    return ['/trusted/qemu/build/qemu-system-aarch64',
            '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
            '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
            '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
            '-drive', f'if=none,id=disk0,format=raw,file={ROOT}/disk.raw,cache=writeback',
            '-device', 'virtio-blk-device,drive=disk0',
            '-netdev', 'socket,id=net0,listen=127.0.0.1:12345',
            '-device', 'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
            '-object', 'rng-random,id=rng0,filename=/dev/urandom',
            '-device', 'virtio-rng-device,rng=rng0',
            '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
            '-qmp', 'unix:/tmp/cyx-test/q.sock,server=on,wait=off',
            '-gdb', 'unix:/tmp/cyx-test/g.sock,server=on,wait=off',
            '-kernel', str(ROOT / 'node-a.elf'), '-no-reboot']


def save(name, key, size):
    address = 0x40000000 if key == 'dtb' else SYMBOLS[key]['pa']
    return ('pmemsave', {'val': address, 'size': size, 'filename': str(ROOT / name)}, {})


def calls():
    serial = {'device': 'cyxlog', 'size': 1048576, 'format': 'base64'}
    paused = {'status': 'paused', 'running': False}
    return [
        ('qmp_capabilities', None, {}),
        ('query-cpus-fast', None, PLATFORM['cpus']),
        ('query-memory-size-summary', None, PLATFORM['memory']),
        save('dtb-header.bin', 'dtb', 40), save('platform.dtb', 'dtb', 64),
        save('config-observed.bin', 'config', 512),
        ('cont', None, {}), ('ringbuf-read', serial, base64.b64encode(b'raw serial').decode()),
        save('pending-boot.bin', 'boot', 512),
        ('stop', None, {}), ('query-status', None, paused), save('first.bin', 'boot', 512),
        ('cont', None, {}), ('ringbuf-read', serial, ''),
        ('stop', None, {}), ('query-status', None, paused), save('last.bin', 'boot', 512),
        save('control.bin', 'control', 4096), save('runtime.bin', 'runtime', 8192),
        save('unified.bin', 'unified', 4096), ('quit', None, {}),
    ]


def transcript(entries):
    rows = [{'direction': 'receive', 'message': {'QMP': {'version': {}, 'capabilities': []}}}]
    for number, (command, args, result) in enumerate(entries, 1):
        request = {'execute': command, 'id': number}
        if args is not None:
            request['arguments'] = args
        rows += [{'direction': 'send', 'message': request},
                 {'direction': 'receive', 'message': {'return': result, 'id': number}}]
    return rows


def replay(entries):
    return verify_qmp(transcript(entries), ROOT, SYMBOLS, 64, PLATFORM)


class BootSnapshotHardening(unittest.TestCase):
    def test_first_snapshot_is_not_exempt_from_terminal_assertions(self):
        for mode in range(4):
            mutations = [(14, 1)] if mode else [(7, 80), (14, 40)]
            mutations += [(19, 1), (4, 99)]
            if mode in (0, 3):
                mutations += [(20, 0), (20, 8_000_001), (21, 9), (22, 2), (23, 0)]
            else:
                mutations += [(6, 1), (7, 1), (16, 0), (18, 0), (20, 1)]
            for index, value in mutations:
                a, b, c = fixture(mode)
                a[index] = value
                with self.subTest(mode=mode, index=index), self.assertRaises(ValueError):
                    verify(a, b, c)

    def test_individually_valid_but_different_settled_facts_are_rejected(self):
        for mode, index in ((0, 7), (0, 14), (0, 15), (0, 20), (0, 23),
                            (1, 17), (1, 18), (2, 18), (3, 7), (3, 20)):
            a, b, c = fixture(mode)
            b[index] += 1
            with self.subTest(mode=mode, index=index), self.assertRaises(ValueError):
                verify(a, b, c)

    def test_terminal_kind_reserved_word_and_corrupt_model_budget_are_checked(self):
        for mode in range(4):
            for index, value in [(19, 1)] + ([(21, 9), (20, 8_000_001)] if mode in (0, 3) else []):
                a, b, c = fixture(mode)
                a[index] = b[index] = value
                with self.subTest(mode=mode, index=index), self.assertRaises(ValueError):
                    verify(a, b, c)

    def test_device_boundary_and_publication_sequence_are_bounded(self):
        for mode, index, value in ((1, 17, 131072), (2, 17, 1)):
            a, b, c = fixture(mode)
            a[index] = b[index] = value
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify(a, b, c)
        a, b, c = fixture(0)
        b[2] = 0
        with self.assertRaises(ValueError):
            verify(a, b, c)


class LaunchContract(unittest.TestCase):
    def test_exact_native_launch(self):
        self.assertEqual(verify_launch(launch()), ROOT)

    def test_other_platforms_devices_debug_actions_and_networks_are_refused(self):
        mutations = [('-smp', '1'), ('-m', '256M'), ('-accel', 'tcg'),
                     ('-monitor', 'stdio'), ('-netdev', 'user,id=net0'),
                     ('-netdev', 'socket,id=net0,listen=0.0.0.0:12345'),
                     ('-netdev', 'socket,id=net0,listen=127.0.0.1:65536'),
                     ('-kernel', '/captured/../other/node-a.elf'),
                     ('-gdb', 'tcp::1234')]
        for key, value in mutations:
            argv = launch()
            argv[argv.index(key) + 1] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                verify_launch(argv)
        for tail in (['-smp', '4'], ['-device', 'loader,file=evil'], ['-icount', '1']):
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                verify_launch(launch() + tail)


class QmpProvenance(unittest.TestCase):
    def test_two_stopped_samples_and_raw_serial(self):
        self.assertEqual(replay(calls()), b'raw serial')

    def test_retried_unsealed_sample_can_be_replaced_only_while_stopped(self):
        entries = calls()
        retry = [('stop', None, {}), ('query-status', None, {'status': 'paused', 'running': False}),
                 save('first.bin', 'boot', 512), ('cont', None, {})]
        self.assertEqual(replay(entries[:13] + retry + entries[13:]), b'raw serial')

    def test_memory_write_and_arbitrary_capture_are_forbidden(self):
        for command in ('human-monitor-command', 'memsave', 'x-write-memory', 'system_reset'):
            entries = calls()
            entries.insert(8, (command, {}, {}))
            with self.subTest(command=command), self.assertRaises(ValueError):
                replay(entries)
        for key, value in (('val', 0x40000000), ('size', 256), ('filename', '/elsewhere/first.bin')):
            entries = calls()
            args = copy.deepcopy(entries[11][1])
            args[key] = value
            entries[11] = ('pmemsave', args, {})
            with self.subTest(key=key), self.assertRaises(ValueError):
                replay(entries)

    def test_stop_status_order_and_final_authority_captures_are_required(self):
        for index in (9, 10, 11, 14, 15, 16, 17, 18, 19, 20):
            entries = calls()
            del entries[index]
            with self.subTest(index=index), self.assertRaises(ValueError):
                replay(entries)
        entries = calls()
        entries[10] = ('query-status', None, {'status': 'running', 'running': True})
        with self.assertRaises(ValueError):
            replay(entries)
        entries = calls()
        entries.insert(-1, ('cont', None, {}))
        with self.assertRaises(ValueError):
            replay(entries)

    def test_duplicate_unanswered_or_reordered_replies_are_refused(self):
        rows = transcript(calls())
        for mutation in ('duplicate', 'unanswered', 'before-request', 'wrong-id', 'error'):
            modified = copy.deepcopy(rows)
            if mutation == 'duplicate':
                modified.insert(3, copy.deepcopy(modified[2]))
            elif mutation == 'unanswered':
                modified.pop()
            elif mutation == 'before-request':
                modified[1], modified[2] = modified[2], modified[1]
            elif mutation == 'wrong-id':
                modified[2]['message']['id'] = 77
            else:
                modified[2]['message'] = {'id': 1, 'error': {'class': 'GenericError'}}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verify_qmp(modified, ROOT, SYMBOLS, 64, PLATFORM)

    def test_changed_platform_and_serial_parameters_are_refused(self):
        entries = calls()
        entries[1] = ('query-cpus-fast', None, [{'cpu-index': 0}])
        with self.assertRaises(ValueError):
            replay(entries)
        entries = calls()
        entries[7] = ('ringbuf-read', {'device': 'other', 'size': 1048576, 'format': 'base64'}, '')
        with self.assertRaises(ValueError):
            replay(entries)
        with self.assertRaises(ValueError):
            replay(calls() + [('query-status', None, {'status': 'paused', 'running': False})])


class ReceiptInventory(unittest.TestCase):
    def test_inventory_checks_bytes_and_never_promotes_producer_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'data.bin').write_bytes(b'abc')
            receipt = {'receipt_schema': 1, 'status': 'PASS', 'native_execution_verified': True,
                       'files': {'data.bin': {'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}}}
            with mock.patch('verify_v13_boot_receipt.MANDATORY', {'data.bin'}):
                self.assertIsNone(verify_inventory(root, receipt))
                (root / 'data.bin').write_bytes(b'abd')
                with self.assertRaises(ValueError):
                    verify_inventory(root, receipt)

    def test_missing_symlink_and_noncanonical_inventory_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'data.bin').write_bytes(b'abc')
            (root / 'alias').symlink_to(root / 'data.bin')
            for name in ('missing', '../data.bin', '/data.bin', 'alias'):
                receipt = {'receipt_schema': 1, 'files': {
                    name: {'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}}}
                with mock.patch('verify_v13_boot_receipt.MANDATORY', {name}):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        verify_inventory(root, receipt)

    def test_matrix_requires_every_profile_and_remains_not_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in MODES:
                (root / name).mkdir()
            def decoded(path, **kwargs):
                mode = MODES[path.name]
                return {'mode': mode, 'run_nonce': str(mode), 'image_sha256': 'same',
                        'source_sha256': 'same', 'native_acceptance_status': 'NOT_RUN'}
            with mock.patch('verify_v13_boot_receipt.verify_receipt', side_effect=decoded):
                result = verify_matrix(root, source_root=root, qemu_source=root)
                self.assertEqual(result['native_acceptance_status'], 'NOT_RUN')
                self.assertFalse(result['full_v13_acceptance'])
                (root / 'epoch-flush').rmdir()
                with self.assertRaises(ValueError):
                    verify_matrix(root, source_root=root, qemu_source=root)


if __name__ == '__main__':
    unittest.main()
