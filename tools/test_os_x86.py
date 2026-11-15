"""Real boot-format invariants for the high-half OS profile (synthetic ELF inputs)."""
import struct
import unittest
import tempfile
from pathlib import Path
from test_x86_64 import fixture_elf
import x86_64
import os_x86

HIGH = 0xffff800000000000

def runtime_elf():
    raw = bytearray(fixture_elf())
    # Add real high-half executable code; retain a physical Multiboot bootstrap.
    struct.pack_into('<H', raw, 56, 3)
    struct.pack_into('<Q', raw, 120 + 16, HIGH + 0x101000)
    raw.extend(bytes(0x1000))
    struct.pack_into('<IIQQQQQQ', raw, 176, 1, 5, 0x3000,
                     HIGH + 0x103000, 0x103000, 0x100, 0x100, 0x1000)
    struct.pack_into('<II', raw, 0x1000 + 20, 0x103100, 0x103100)
    return bytes(raw)

class RuntimeElf(unittest.TestCase):
    def test_physical_loader_preserves_high_virtual_kernel(self):
        raw = runtime_elf()
        with self.assertRaises(ValueError): x86_64.boot_image(raw)
        info = x86_64.inspect_elf(raw, runtime=True)
        self.assertEqual(info['loads'][-1]['va'], HIGH + 0x103000)
        image = x86_64.boot_image(raw, runtime=True)
        self.assertEqual(image[0x3000:0x3100], raw[0x3000:0x3100])

    def test_boot_only_and_incorrect_virtual_physical_delta_are_rejected(self):
        with self.assertRaises(ValueError):
            x86_64.boot_image(fixture_elf(), runtime=True)
        for at, value in [(176 + 16, HIGH + 0x104000), (176 + 24, 0x4000_0000)]:
            raw = bytearray(runtime_elf()); struct.pack_into('<Q', raw, at, value)
            with self.subTest(at=at), self.assertRaises(ValueError):
                x86_64.boot_image(raw, runtime=True)

    def test_writable_executable_kernel_segment_is_rejected(self):
        raw = bytearray(runtime_elf()); struct.pack_into('<I', raw, 176 + 4, 7)
        with self.assertRaises(ValueError): x86_64.boot_image(raw, runtime=True)

class UserBuildInputs(unittest.TestCase):
    def test_external_image_and_asset_changes_invalidate_the_cache_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory).resolve()
            (prefix / 'probe.elf').write_bytes(b'actual image bytes')
            (prefix / 'rootfs').mkdir()
            (prefix / 'rootfs/font').write_bytes(b'font')
            first = os_x86.catalog_inputs(prefix)
            (prefix / 'probe.elf').write_bytes(b'other image bytes')
            self.assertNotEqual(first, os_x86.catalog_inputs(prefix))
            self.assertIn('rootfs/font', first)
            (prefix / 'alias.elf').symlink_to(prefix / 'probe.elf')
            with self.assertRaises(ValueError): os_x86.catalog_inputs(prefix)

    def test_desktop_feature_requires_actual_ported_image_catalog(self):
        with self.assertRaises(ValueError):
            os_x86.select_features(graphics=True, extras=['smithay-dynamic-probe'])
        self.assertEqual(os_x86.select_features(graphics=True, ported=True,
                         extras=['smithay-dynamic-probe']),
                         ['os-runtime', 'graphics', 'ported', 'smithay-dynamic-probe'])
        with self.assertRaises(ValueError):
            os_x86.select_features(extras=['prototype-runtime'])

if __name__ == '__main__': unittest.main()
