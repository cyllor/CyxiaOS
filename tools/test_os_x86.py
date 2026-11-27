"""Real boot-format invariants for the high-half OS profile (synthetic ELF inputs)."""
import os
import struct
from unittest.mock import patch
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
    def test_larger_catalog_file_read_requires_the_explicit_runtime_bound(self):
        raw = runtime_elf() + bytes(256 * 1024**2 + 1 - len(runtime_elf()))
        with self.assertRaisesRegex(ValueError, 'file budget'):
            x86_64.inspect_elf(raw, runtime=True)
        x86_64.inspect_elf(raw, runtime=True, max_file_bytes=384 * 1024**2)
        x86_64.boot_image(raw, runtime=True, max_file_bytes=384 * 1024**2)
        for options in (dict(max_file_bytes=384 * 1024**2), dict(runtime=True, max_file_bytes=512 * 1024**2)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                x86_64.inspect_elf(runtime_elf(), **options)

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
    def test_standalone_qemu_requires_explicit_valid_firmware(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {'CYXIA_PINNED_QEMU_FIRMWARE': str(root)}):
                with self.assertRaises(ValueError):
                    os_x86.launch_argv('/qemu', '/boot')
                (root / 'bios-256k.bin').write_bytes(bytes(256 * 1024))
                command = os_x86.launch_argv('/qemu', '/boot')
                self.assertEqual(command[:3], ['/qemu', '-L', str(root)])
            with patch.dict(os.environ, {'CYXIA_PINNED_QEMU_FIRMWARE': ''}):
                self.assertNotIn('-L', os_x86.launch_argv('/qemu', '/boot'))

    def test_applet_kernel_file_bound_is_separate_from_legacy_and_ram(self):
        for name in ('cosmic-workspace-applets-v1', 'cosmic-notifications-applet-v1'):
            self.assertEqual(os_x86.kernel_file_limit([name]), 384 * 1024**2)
        for features in ([], ['full-os'], ['cosmic-core-services-v1'], ['cosmic-time-applet-v1']):
            self.assertEqual(os_x86.kernel_file_limit(features), 256 * 1024**2)
        command = os_x86.launch_argv('/qemu', '/boot')
        self.assertEqual(command[command.index('-m') + 1], '1024M')

    def test_applets_have_an_explicit_graphics_and_ported_profile(self):
        for name in ('cosmic-workspace-applets-v1', 'cosmic-notifications-applet-v1'):
            self.assertEqual(os_x86.select_features(graphics=True, ported=True, extras=[name]),
                             ['os-runtime', 'graphics', 'ported', name])
            for options in (dict(graphics=True), dict(ported=True), {}):
                with self.subTest(name=name, options=options), self.assertRaises(ValueError):
                    os_x86.select_features(extras=[name], **options)

    def test_wallpaper_profile_includes_the_desktop_catalog_bound(self):
        name = 'cosmic-bg-v1'
        features = os_x86.select_features(graphics=True, ported=True, extras=[name])
        self.assertEqual(features, ['os-runtime', 'graphics', 'ported', name])
        self.assertEqual(os_x86.kernel_file_limit(features), 384 * 1024**2)
        with self.assertRaises(ValueError):
            os_x86.select_features(ported=True, extras=[name])

    def test_application_library_uses_the_one_gib_desktop_profile(self):
        name = 'cosmic-app-library-v1'
        features = os_x86.select_features(graphics=True, ported=True, extras=[name])
        self.assertEqual(features, ['os-runtime', 'graphics', 'ported', name])
        self.assertIn(name, os_x86.NOTIFICATIONS_OBJECT_FEATURES)
        self.assertEqual(os_x86.kernel_file_limit(features), 384 * 1024**2)
        for options in (dict(graphics=True), dict(ported=True), {}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                os_x86.select_features(extras=[name], **options)

    def test_full_os_capacity_is_explicit_and_cosmic_requires_graphics(self):
        self.assertEqual(os_x86.select_features(ported=True, extras=['full-os']),
                         ['os-runtime', 'ported', 'full-os'])
        self.assertEqual(os_x86.select_features(graphics=True, ported=True,
                         extras=['full-os', 'cosmic-desktop']),
                         ['os-runtime', 'graphics', 'ported', 'cosmic-desktop', 'full-os'])
        for options in (dict(extras=['full-os']),
                        dict(ported=True, extras=['cosmic-desktop'])):
            with self.assertRaises(ValueError): os_x86.select_features(**options)
        self.assertEqual(os_x86.select_features(), ['os-runtime'])
        self.assertEqual(os_x86.select_features(graphics=True, ported=True,
                         extras=['cosmic-core-services-v1']),
                         ['os-runtime', 'graphics', 'ported', 'cosmic-core-services-v1'])
        for options in (dict(graphics=True, extras=['cosmic-core-services-v1']),
                        dict(ported=True, extras=['cosmic-core-services-v1'])):
            with self.assertRaises(ValueError): os_x86.select_features(**options)
        self.assertEqual(os_x86.select_features(graphics=True, ported=True,
                         extras=['cosmic-time-applet-v1']),
                         ['os-runtime', 'graphics', 'ported', 'cosmic-time-applet-v1'])
        for options in (dict(graphics=True, extras=['cosmic-time-applet-v1']),
                        dict(ported=True, extras=['cosmic-time-applet-v1'])):
            with self.assertRaises(ValueError): os_x86.select_features(**options)

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
