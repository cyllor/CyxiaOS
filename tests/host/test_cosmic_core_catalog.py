"""Execute the real OS catalog producer; ELF fixtures never enter a guest."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function

CORE = ('cosmic-comp', 'cosmic-session', 'cosmic-settings-daemon',
        'cosmic-notifications', 'cosmic-panel')
MIB = 1024 * 1024


def elf(path, size=8192):
    raw = bytearray(8192)
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0,
                     b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1,
                     0x1001000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 4096,
                     0x1001000, 0x1001000, 16, 16, 4096)
    path.write_bytes(raw)
    with path.open('r+b') as stream:
        stream.truncate(size)


class CosmicCoreCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        source = (ROOT / 'kernel/build/os.rs').read_text()
        code = 'use std::{env, fs, path::{Path, PathBuf}};\n'
        code += '\n'.join(function(source, signature) for signature in (
            'fn feature(', 'fn word(', 'fn x86_image(', 'fn assets(', 'fn catalog('))
        code += '\nfn main() { let args: Vec<_> = env::args().collect(); '
        code += 'catalog(Path::new(&args[1]), Path::new(&args[2])); }\n'
        rust = cls.directory / 'catalog.rs'
        rust.write_text(code)
        cls.binary = cls.directory / 'catalog'
        compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024',
                                   '-Dwarnings', str(rust), '-o', str(cls.binary)],
                                  env=env(), capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.directory)
        self.addCleanup(self.case.cleanup)
        self.root = Path(self.case.name)
        self.sdk = self.root / 'sdk'
        self.sdk.mkdir()
        self.number = 0
        elf(self.sdk / 'probe.elf')

    def run_catalog(self, core=False, full=True, clock=False):
        self.number += 1
        output = self.root / f'output-{self.number}'
        output.mkdir()
        environment = {k: v for k, v in env().items()
                       if not k.startswith(('CARGO_FEATURE_', 'CYXIA_'))}
        environment.update(CYXIA_SYSROOT=str(self.sdk), CARGO_FEATURE_PORTED='1')
        if full:
            environment['CARGO_FEATURE_FULL_OS'] = '1'
        if core or clock:
            for feature in ('COSMIC_CORE_SERVICES_V1', 'COSMIC_SESSION', 'COSMIC_DESKTOP',
                            'FULL_OS', 'LARGE_MEMORY', 'GRAPHICS'):
                environment['CARGO_FEATURE_' + feature] = '1'
        if clock:
            environment['CARGO_FEATURE_COSMIC_TIME_APPLET_V1'] = '1'
        ran = subprocess.run([str(self.binary), str(self.root), str(output)],
                             env=environment, capture_output=True, text=True, timeout=15)
        return ran, output

    def populate(self):
        for name in CORE:
            elf(self.sdk / (name + '.elf'))

    def test_missing_core_program_is_rejected_before_an_image_can_boot(self):
        self.populate()
        for name in CORE:
            path = self.sdk / (name + '.elf')
            data = path.read_bytes()
            path.unlink()
            with self.subTest(missing=name):
                ran, output = self.run_catalog(core=True)
                self.assertNotEqual(ran.returncode, 0, 'missing core program was silently omitted: ' + name)
                self.assertIn(name, ran.stderr)
                self.assertFalse((output / 'ported_catalog.rs').exists())
            path.write_bytes(data)

    def test_probe_only_legacy_profile_and_complete_core_keep_their_paths(self):
        ran, _ = self.run_catalog()
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.populate()
        ran, output = self.run_catalog(core=True)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        catalog = (output / 'ported_catalog.rs').read_text()
        for name in CORE:
            self.assertIn('/bin/' + name, catalog)

    def test_core_raw_catalog_has_an_explicit_128_mib_boundary(self):
        self.populate()
        for name, size in [('probe', 32), ('cosmic-comp', 32), ('cosmic-session', 16),
                           ('cosmic-settings-daemon', 16), ('cosmic-notifications', 16),
                           ('cosmic-panel', 16)]:
            elf(self.sdk / (name + '.elf'), size * MIB)
        ran, _ = self.run_catalog(core=True)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        (self.sdk / 'rootfs').mkdir()
        (self.sdk / 'rootfs/one-extra-byte').write_bytes(b'x')
        ran, _ = self.run_catalog(core=True)
        self.assertNotEqual(ran.returncode, 0)
        self.assertIn('catalog', ran.stderr)

    def test_original_96_and_48_mib_limits_remain_enforced(self):
        for full, bound in [(True, 96), (False, 48)]:
            elf(self.sdk / 'probe.elf', 32 * MIB)
            elf(self.sdk / 'dbus-daemon.elf', (bound - 32) * MIB)
            ran, _ = self.run_catalog(full=full)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            with (self.sdk / 'dbus-daemon.elf').open('ab') as stream:
                stream.write(b'x')
            ran, _ = self.run_catalog(full=full)
            self.assertNotEqual(ran.returncode, 0)

    def test_core_cannot_admit_an_interpreted_or_wrong_architecture_image(self):
        self.populate()
        path = self.sdk / 'cosmic-notifications.elf'
        pristine = path.read_bytes()
        for offset, value, width in [(18, 183, '<H'), (64, 3, '<I')]:
            data = bytearray(pristine)
            struct.pack_into(width, data, offset, value)
            path.write_bytes(data)
            ran, _ = self.run_catalog(core=True)
            self.assertNotEqual(ran.returncode, 0)

    def test_clock_profile_requires_the_real_executable_and_desktop_entry(self):
        self.populate()
        ran, _ = self.run_catalog(clock=True)
        self.assertNotEqual(ran.returncode, 0)
        self.assertIn('cosmic-applet-time', ran.stderr)
        elf(self.sdk / 'cosmic-applet-time.elf')
        ran, _ = self.run_catalog(clock=True)
        self.assertNotEqual(ran.returncode, 0)
        entry = self.sdk / 'rootfs/usr/share/applications/com.system76.CosmicAppletTime.desktop'
        entry.parent.mkdir(parents=True)
        entry.write_text('[Desktop Entry]\nExec=cosmic-applet-time\nX-CosmicApplet=true\n')
        ran, output = self.run_catalog(clock=True)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertIn('/bin/cosmic-applet-time', (output / 'ported_catalog.rs').read_text())
        for contents in ('[Desktop Entry]\nExec=another-program\nX-CosmicApplet=true\n',
                         '[Desktop Entry]\nExec=cosmic-applet-time\n'):
            entry.write_text(contents)
            ran, _ = self.run_catalog(clock=True)
            self.assertNotEqual(ran.returncode, 0)

    def test_clock_can_be_isolated_without_requiring_the_complete_core_profile(self):
        elf(self.sdk / 'cosmic-applet-time.elf')
        ran, output = self.run_catalog()
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertIn('/bin/cosmic-applet-time', (output / 'ported_catalog.rs').read_text())

    def test_clock_rom_budget_is_explicit_and_does_not_expand_the_core_profile(self):
        self.populate()
        for name in ('probe', 'cosmic-comp', 'cosmic-session', 'cosmic-settings-daemon',
                     'cosmic-notifications', 'cosmic-panel'):
            elf(self.sdk / (name + '.elf'), 24 * MIB)
        elf(self.sdk / 'cosmic-applet-time.elf', 32 * MIB)
        entry = self.sdk / 'rootfs/usr/share/applications/com.system76.CosmicAppletTime.desktop'
        entry.parent.mkdir(parents=True)
        entry.write_text('[Desktop Entry]\nExec=cosmic-applet-time\nX-CosmicApplet=true\n')
        padding = self.sdk / 'rootfs/padding'
        with padding.open('wb') as stream:
            stream.truncate(16 * MIB - entry.stat().st_size)
        ran, _ = self.run_catalog(clock=True)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        with padding.open('ab') as stream:
            stream.write(b'x')
        ran, _ = self.run_catalog(clock=True)
        self.assertNotEqual(ran.returncode, 0)
        self.assertIn('catalog', ran.stderr)
        ran, _ = self.run_catalog(core=True)
        self.assertNotEqual(ran.returncode, 0)


if __name__ == '__main__':
    unittest.main()
