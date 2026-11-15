"""Exercise emitted image validation, without invoking a compiler or VM."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('runtime_builder', Path(__file__).with_name('build_runtime.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def elf(machine=62, base=0x10000, entry=None, flags=5, memory_size=16):
    data = bytearray(8192)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQ', data, 16, 2, machine, 1, base if entry is None else entry, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, flags, 4096, base, base, 16, memory_size, 4096)
    return bytes(data)


class RuntimeImages(unittest.TestCase):
    def test_x86_image_accepts_byte_entry_and_rejects_arm_payload(self):
        self.assertEqual(builder.validate_image(elf(entry=0x10001), 'prototype-task', 'x86_64')['machine'], 62)
        with self.assertRaises(ValueError):
            builder.validate_image(elf(machine=183), 'prototype-task', 'x86_64')

    def test_arm_image_keeps_instruction_alignment(self):
        self.assertEqual(builder.validate_image(elf(machine=183), 'prototype-task', 'aarch64')['machine'], 183)
        with self.assertRaises(ValueError):
            builder.validate_image(elf(machine=183, entry=0x10001), 'prototype-task', 'aarch64')

    def test_task_cannot_be_writable_or_exceed_one_code_page(self):
        for data in (elf(flags=7), elf(flags=6), elf(memory_size=4097)):
            with self.subTest(data=data[68:72]):
                with self.assertRaises(ValueError):
                    builder.validate_image(data, 'prototype-task', 'x86_64')

    def test_control_and_cluster_retain_distinct_permission_rules(self):
        with self.assertRaises(ValueError):
            builder.validate_image(elf(base=0x80000, flags=6), 'prototype-learning', 'x86_64')
        self.assertEqual(builder.validate_image(elf(base=0x1000000), 'prototype-cluster', 'x86_64')['entry'], 0x1000000)
        with self.assertRaises(ValueError):
            builder.validate_image(elf(base=0x1e00000), 'prototype-cluster', 'x86_64')

    def test_duplicate_segments_and_unbacked_entry_are_rejected(self):
        duplicate = bytearray(elf())
        struct.pack_into('<H', duplicate, 56, 2)
        duplicate[120:176] = duplicate[64:120]
        for data in (duplicate, elf(entry=0x10010), elf()[:4100]):
            with self.assertRaises(ValueError):
                builder.validate_image(data, 'prototype-task', 'x86_64')

    def test_unknown_architecture_and_role_are_rejected(self):
        for role, arch in [('prototype-task', 'riscv64'), ('unknown', 'x86_64')]:
            with self.assertRaises(ValueError):
                builder.validate_image(elf(), role, arch)

    def test_build_refuses_existing_output_before_touching_identity_or_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                builder.build('x86_64', directory, Path(directory) / 'missing-identity')

    def test_cluster_script_rejects_unsupported_arch_without_starting_build(self):
        script = Path(__file__).parent / 'prototype-cluster/tools/build.sh'
        result = subprocess.run(['sh', str(script), '--arch', 'riscv64'],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
