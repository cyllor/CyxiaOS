"""Publication and stale-input regressions; no compiler, VM or target execution."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import os_smithay as subject
from build_sysroot import inspect_elf


def elf(machine=62):
    data = bytearray(8192)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, b'\x7fELF\x02\x01\x01'+bytes(9),
                     2, machine, 1, 0x1001000, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x1000000, 0, 8192, 8192, 4096)
    struct.pack_into('<IIQQQQQQ', data, 120, 6, 4, 64, 0x1000040, 0, 112, 112, 8)
    return bytes(data)


def publication(root):
    prefix = root/'artifacts/sdk'; origin = root/'artifacts/build'
    prefix.mkdir(parents=True); origin.mkdir(parents=True)
    original = origin/'smithay-dynamic.elf'; original.write_bytes(elf())
    canonical = prefix/'smithay-dynamic-probe.elf'; canonical.write_bytes(original.read_bytes())
    report = dict(status='cross-built', architecture='x86_64', target_triple='x86_64-unknown-linux-musl',
                  probe=inspect_elf(original, 'x86_64'), commands=[['/never/execute/report/path']])
    source = origin/'build-report.json'; source.write_text(json.dumps(report))
    receipt = {**report, 'probe': {**report['probe'], 'file':str(canonical)},
               'publication':dict(source_build_report=str(source),
                    source_build_report_sha256=subject.digest(source), original_probe_file=str(original))}
    path = prefix/'smithay-dynamic-probe-build-report.json'; path.write_text(json.dumps(receipt))
    return prefix, origin, path


class ReceiptTests(unittest.TestCase):
    def test_canonical_and_original_are_bound_without_running_report_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); prefix, origin, _ = publication(root)
            binder = subject.Binder(root)
            report, directory = subject.publication(prefix, 'smithay-dynamic-probe', 'probe', binder)
            self.assertEqual(directory, origin)
            self.assertEqual(report['probe']['machine'], 62)
            self.assertIn(str(prefix/'smithay-dynamic-probe.elf'), binder.inputs)

    def test_report_rewrite_and_original_binary_changes_are_rejected(self):
        for change in ('report', 'binary', 'foreign', 'escape'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve(); prefix, origin, receipt = publication(root)
                data = json.loads(receipt.read_text())
                if change == 'report': data['commands'] = [['different producer']]
                if change == 'binary': (origin/'smithay-dynamic.elf').write_bytes(elf()+b'x')
                if change == 'foreign':
                    raw = bytearray((prefix/'smithay-dynamic-probe.elf').read_bytes())
                    struct.pack_into('<H', raw, 18, 183)
                    (prefix/'smithay-dynamic-probe.elf').write_bytes(raw)
                if change == 'escape': data['publication']['source_build_report'] = '/etc/passwd'
                receipt.write_text(json.dumps(data))
                with self.assertRaises((ValueError, RuntimeError)):
                    subject.publication(prefix, 'smithay-dynamic-probe', 'probe', subject.Binder(root))

    def test_model_compiler_and_static_input_maps_reject_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); binder = subject.Binder(root)
            for name in ('model.rs','compiler','libtarget.a'):
                path = root/name; path.write_bytes(b'original')
                recorded = {str(path): subject.digest(path)}
                binder.bind_map(recorded)
                path.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'changed'):
                    binder.bind_map(recorded)

    def test_missing_closure_and_escaping_artifact_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            binder = subject.Binder(Path(temp).resolve())
            with self.assertRaises(ValueError): binder.bind_map({})
            with self.assertRaises(ValueError): binder.bind_map({'../escape': '0'*64}, base=Path(temp))
            with self.assertRaises(ValueError): binder.bind_map({'/dev/zero': '0'*64})


if __name__ == '__main__': unittest.main()
