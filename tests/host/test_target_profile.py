"""Actual ELF/archive bytes must match the selected user-space target."""
from pathlib import Path
import struct
import json
import sys
import tempfile
import unittest

from tools.target_profile import profile_for
from tools import target_profile
from tools import build_sysroot
from tests.host.test_build_sysroot import executable

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import build_smithay_wayland_client as clients
import build_mesa
import cosmic_ports
import build_cosmic


from tests.host.sdk_fixtures import object_archive


class TargetProfiles(unittest.TestCase):
    def test_only_musl_compatibility_archives_can_be_empty_and_bind_actual_libc(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            lib = prefix / 'sysroot/usr/lib'
            lib.mkdir(parents=True)
            libc = lib / 'libc.a'
            libc.write_bytes(object_archive([62]))
            (prefix / 'build-report.json').write_text(json.dumps({
                'target': 'x86_64-linux-musl', 'libc_sha256': clients.digest(libc)}))
            math = lib / 'libm.a'
            math.write_bytes(b'!<arch>\n')
            result = target_profile.inspect_link_archive(math, prefix, 'x86_64')
            self.assertEqual(result['kind'], 'musl-compatibility-archive')
            self.assertEqual(result['object_count'], 0)
            self.assertIsNone(result['machine'])
            with self.assertRaises(ValueError):
                profile_for('x86_64').inspect_archive(math)
            other = lib / 'libexample.a'
            other.write_bytes(math.read_bytes())
            with self.assertRaises(ValueError):
                target_profile.inspect_link_archive(other, prefix, 'x86_64')
            math.write_bytes(object_archive([183]))
            with self.assertRaises(ValueError):
                target_profile.inspect_link_archive(math, prefix, 'x86_64')
            math.write_bytes(b'!<arch>\n')
            libc.write_bytes(object_archive([183]))
            with self.assertRaises(ValueError):
                target_profile.inspect_link_archive(math, prefix, 'x86_64')

    def test_x86_compiler_driver_selects_real_musl_isa_without_arm_options(self):
        target = profile_for('x86_64')
        self.assertEqual(target.c_target, 'x86_64-linux-musl')
        self.assertEqual(target.rust_target, 'x86_64-unknown-linux-musl')
        self.assertEqual(target.clang_args, ('--target=x86_64-linux-musl', '-mno-red-zone'))
        self.assertEqual(target.linker_emulation, 'elf_x86_64')
        self.assertEqual(target.builtins_archive, 'libclang_rt.builtins-x86_64.a')

    def test_unknown_architecture_cannot_silently_select_arm(self):
        with self.assertRaises(ValueError):
            profile_for('amd64')

    def test_foreign_or_mixed_object_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'libexample.a'
            path.write_bytes(object_archive([62, 62]))
            self.assertEqual(profile_for('x86_64').inspect_archive(path)['object_count'], 2)
            with self.assertRaises(ValueError):
                profile_for('aarch64').inspect_archive(path)
            path.write_bytes(object_archive([62, 183]))
            with self.assertRaises(ValueError):
                profile_for('x86_64').inspect_archive(path)

    def test_x86_elf_accepts_byte_entry_but_rejects_arm_and_writable_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'probe.elf'
            data = executable()
            struct.pack_into('<H', data, 18, 62)
            struct.pack_into('<Q', data, 24, build_sysroot.BASE + 4097)
            path.write_bytes(data)
            self.assertEqual(build_sysroot.inspect_elf(path, target='x86_64')['machine'], 62)
            with self.assertRaises(build_sysroot.BuildError):
                build_sysroot.inspect_elf(path)
            struct.pack_into('<I', data, 64 + 112 + 4, 7)
            path.write_bytes(data)
            with self.assertRaises(build_sysroot.BuildError):
                build_sysroot.inspect_elf(path, target='x86_64')

    def test_sdk_input_target_mismatch_is_rejected_before_compilation(self):
        target = profile_for('x86_64')
        target.require_report({'target': 'x86_64-linux-musl'})
        target.require_report({'target_triple': 'x86_64-unknown-linux-musl'})
        for report in ({}, {'target': 'aarch64-linux-musl'}, {'target': 'x86_64-linux-musl', 'architecture': 'aarch64'}):
            with self.assertRaises(ValueError):
                target.require_report(report)

    def test_compiler_runtime_uses_real_x86_float_environment_and_x87_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lib/builtins').mkdir(parents=True)
            (root / 'lib/builtins/CMakeLists.txt').write_text(
                'set(GENERIC_SOURCES fp_mode.c adddf3.c)\n'
                'set(GENERIC_TF_SOURCES addtf3.c)\n'
                'set(x86_80_BIT_SOURCES divxc3.c mulxc3.c)\n')
            names = build_sysroot.compiler_runtime_sources(root, target='x86_64')
            self.assertIn('i386/fp_mode.c', names)
            self.assertIn('divxc3.c', names)
            self.assertIn('x86_64/floatundixf.S', names)
            self.assertNotIn('aarch64/fp_mode.c', names)

    def test_wayland_link_inputs_bind_actual_object_isa_and_report_target(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            library = prefix / 'sysroot/usr/lib'
            library.mkdir(parents=True)
            hashes = {}
            for name in ('libwayland-client.a', 'libffi.a', 'libxkbcommon.a', 'libc.a'):
                path = library / name
                path.write_bytes(object_archive([62]))
                hashes[name] = clients.digest(path)
            wayland = dict(status='cross-built', target_triple='x86_64-unknown-linux-musl',
                           manifest_sha256=clients.digest(clients.ROOT / 'ports/cosmic/wayland-source.json'),
                           target={'archives': {'libwayland-client.a': {'sha256': hashes['libwayland-client.a']}}},
                           target_libffi_sha256=hashes['libffi.a'], target_libc_sha256=hashes['libc.a'])
            xkb = dict(status='cross-built', target_triple='x86_64-unknown-linux-musl',
                       manifest_sha256=clients.digest(clients.ROOT / 'ports/cosmic/xkbcommon-source.json'),
                       target={'archive': {'sha256': hashes['libxkbcommon.a']}}, target_libc_sha256=hashes['libc.a'])
            (prefix / 'wayland-build-report.json').write_text(json.dumps(wayland))
            path = prefix / 'xkbcommon-build-report.json'
            path.write_text(json.dumps(xkb))
            self.assertIn(library / 'libffi.a', clients.prerequisite_inputs(prefix, target='x86_64'))
            xkb['target_triple'] = 'aarch64-unknown-linux-musl'
            path.write_text(json.dumps(xkb))
            with self.assertRaises(ValueError):
                clients.prerequisite_inputs(prefix, target='x86_64')

    def test_mesa_uses_x86_type_layouts_from_the_original_pinned_commit(self):
        package = json.loads((build_mesa.ROOT / 'ports/cosmic/mesa-source.json').read_text())
        selected = build_mesa.target_uapi_spec(package, 'x86_64')
        self.assertEqual(selected['source_commit'], 'adc218676eef25575469234709c2d87185ca223a')
        self.assertEqual(selected['architecture'], 'x86_64')
        self.assertEqual(selected['files']['asm/posix_types.h']['source_path'], 'arch/x86/include/uapi/asm/posix_types.h')
        self.assertEqual(selected['files']['asm/posix_types_64.h']['source_path'], 'arch/x86/include/uapi/asm/posix_types_64.h')
        self.assertEqual(build_mesa.target_uapi_spec(package, 'aarch64'), package['target_uapi'])

    def test_cosmic_inventory_checks_selected_isa_instead_of_accepting_arm_std(self):
        data = object_archive([62])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'libexample.a'
            path.write_bytes(data)
            self.assertEqual(cosmic_ports.architecture(path, target='x86_64')['machine'], 62)
            with self.assertRaises(ValueError):
                cosmic_ports.architecture(path)
            path.write_bytes(object_archive([183]))
            with self.assertRaises(ValueError):
                cosmic_ports.architecture(path, target='x86_64')

    def test_cosmic_resource_profile_cannot_cross_the_requested_target(self):
        document = {'schema_version': 1, 'target': 'x86_64-unknown-linux-musl',
                    'build_profiles': {'static': {'jobs_max': 1, 'min_free_bytes': 1,
                        'max_build_bytes': 100, 'timeout_seconds': 10, 'max_elf_bytes': 100,
                        'image_bytes': 100, 'stack_bytes': 10}}}
        self.assertEqual(build_cosmic.select_profile(document, 'static', 1, target='x86_64')['jobs_max'], 1)
        with self.assertRaises(ValueError):
            build_cosmic.select_profile(document, 'static', 1, target='aarch64')


if __name__ == '__main__':
    unittest.main()
