"""Tool selection/environment fixtures; no compiler, Cargo, Git or guest is run."""
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import cosmic_notifications_toolchain as subject


def write(path, data, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    if executable:
        path.chmod(0o755)
    return path


def object_bytes(machine=62):
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 1, machine)
    return bytes(data)


def archive(machine=62):
    data = object_bytes(machine)
    header = ('object.o/'.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
              + '644'.ljust(8) + str(len(data)).ljust(10) + '`\n').encode()
    return b'!<arch>\n' + header + data


class NotificationToolchain(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.rust = self.root / 'rust-1.95.0'
        self.host_cc = self.root / 'private-clang/bin/clang'
        self.sysroot = self.root / 'sdk'
        self.cache = self.root / 'cargo-cache'; self.cache.mkdir()
        self.host = 'x86_64-unknown-linux-gnu'
        self.version = 'rustc 1.95.0 (probe fixture)\nhost: ' + self.host + '\nrelease: 1.95.0\n'
        self.clang_version = 'clang version 19.1.7 (probe fixture, never executed)\n'
        self.tools = {}
        for name in ('rustc', 'cargo', 'rustdoc'):
            write(self.rust / 'bin' / name, 'unexecuted tool fixture: ' + name, executable=True)
        write(self.host_cc, 'unexecuted clang fixture', executable=True)
        write(self.host_cc.with_name('clang++'), 'unexecuted clang++ fixture', executable=True)
        for name in ('cc', 'ar', 'ranlib'):
            write(self.sysroot / 'bin' / ('x86_64-linux-musl-' + name), 'unexecuted SDK tool ' + name, executable=True)
        write(self.rust / 'lib/rustlib' / self.host / 'bin/llvm-strip', 'unexecuted strip fixture', executable=True)
        self.pkg_config = write(self.root / 'host/pkg-config', 'unexecuted pkg-config fixture', executable=True)
        self.git = write(self.root / 'host/git', 'unexecuted Git fixture', executable=True)
        self.libdir = self.rust / 'lib/rustlib/x86_64-unknown-linux-musl/lib'
        self.std = write(self.libdir / 'libstd-fixture.rlib', archive())
        write(self.libdir / 'self-contained/libunwind.a', archive())
        native = []
        for name in ('libc.a', 'libclang_rt.builtins-x86_64.a', 'crt1.o', 'crti.o', 'crtn.o'):
            path = write(self.sysroot / 'sysroot/usr/lib' / name,
                         archive() if name.endswith('.a') else object_bytes())
            native.append({'path': str(path.relative_to(self.sysroot)), 'sha256': subject.base.digest(path)})
        self.recipe = {'target': 'x86_64-unknown-linux-musl', 'native_inputs': native, 'static_link_inputs': []}
        self.probes = []

    def probe(self, command, **kwargs):
        # Only the version/sysroot observations are synthetic. Selection,
        # permissions, hashes and archive/ELF architecture use actual files.
        self.probes.append(command)
        self.assertEqual(kwargs.get('timeout'), 30)
        self.assertTrue(kwargs.get('text'))
        self.assertEqual(kwargs['env']['PATH'], subject.HOST_PATH)
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC_WRAPPER',
                     'CARGO_BUILD_TARGET', 'CARGO_HTTP_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY'):
            self.assertNotIn(name, kwargs['env'])
        if command == [str(self.rust / 'bin/rustc'), '--print', 'sysroot']:
            return str(self.rust) + '\n'
        if command == [str(Path.home() / '.cargo/bin/rustc'), '--print', 'sysroot']:
            return str(self.rust) + '\n'
        if command == [str(self.rust / 'bin/rustc'), '-vV']:
            return self.version
        if command == [str(self.host_cc), '--version']:
            return self.clang_version
        raise AssertionError('Unexpected tool probe: ' + repr(command))

    def which(self, name, *, path):
        self.assertEqual(path, subject.HOST_PATH)
        return str({'pkg-config': self.pkg_config, 'git': self.git}[name])

    def select(self, recipe=None):
        with mock.patch.object(subject.subprocess, 'check_output', side_effect=self.probe), \
             mock.patch.object(subject.shutil, 'which', side_effect=self.which):
            return subject.tools_and_sysroot(self.sysroot, recipe or self.recipe,
                                            rust_root=self.rust, host_cc=self.host_cc)

    def test_explicit_rust_and_host_compiler_record_exact_paths_bytes_and_target(self):
        tools, identities = self.select()
        self.assertEqual(identities['selection'], {'schema_version': 1,
                         'rust_root': str(self.rust), 'host_cc': str(self.host_cc)})
        self.assertEqual(identities['host_cc_version'], self.clang_version)
        self.assertEqual(identities['rustc_version'], self.version)
        self.assertEqual(identities['target'], self.recipe['target'])
        self.assertEqual(identities['tools']['host_cc']['sha256'], subject.base.digest(self.host_cc))
        self.assertEqual(tools['cargo'], self.rust / 'bin/cargo')
        self.assertEqual(len(identities['tools']), 9)
        self.assertEqual(identities['tools']['target_cxx']['available'], False)
        self.assertIsNone(identities['tools']['target_cxx']['sha256'])

    def test_no_explicit_selection_delegates_to_unchanged_generic_builder(self):
        sentinel = (object(), object())
        with mock.patch.object(subject.base, 'tools_and_sysroot', return_value=sentinel) as old, \
             mock.patch.object(subject, 'rust_toolchain', side_effect=AssertionError('new selection path invoked')):
            self.assertIs(subject.tools_and_sysroot(self.sysroot, self.recipe), sentinel)
            old.assert_called_once_with(self.sysroot, self.recipe)

    def test_default_host_compiler_alias_records_the_real_system_tool(self):
        alias = self.root / 'system/clang'
        alias.parent.mkdir()
        alias.symlink_to(self.host_cc)
        with mock.patch.object(subject, 'DEFAULT_HOST_CC', alias), \
             mock.patch.object(subject.subprocess, 'check_output', side_effect=self.probe), \
             mock.patch.object(subject.shutil, 'which', side_effect=self.which):
            tools, identities = subject.tools_and_sysroot(self.sysroot, self.recipe, rust_root=self.rust)
        self.assertEqual(tools['host_cc'], self.host_cc)
        self.assertEqual(identities['selection']['host_cc'], str(self.host_cc))
        self.assertEqual(identities['tools']['host_cc']['sha256'], subject.base.digest(self.host_cc))
        # The exception is only for the conventional default; an explicit alias
        # remains subject to the caller-selected path restriction.
        with mock.patch.object(subject.subprocess, 'check_output', side_effect=self.probe), \
             self.assertRaisesRegex(ValueError, 'symlink'):
            subject.tools_and_sysroot(self.sysroot, self.recipe, rust_root=self.rust, host_cc=alias)

    def test_wrong_rust_sysroot_alias_missing_tool_and_permissions_fail(self):
        with mock.patch.object(subject.subprocess, 'check_output', return_value=str(self.root / 'other')):
            with self.assertRaisesRegex(ValueError, 'different sysroot'):
                subject.rust_toolchain(self.rust)
        alias = self.root / 'rust-alias'; alias.symlink_to(self.rust, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            subject.rust_toolchain(alias)
        rustdoc = self.rust / 'bin/rustdoc'
        rustdoc.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'required Rust tool missing: rustdoc'):
            subject.rust_toolchain(self.rust)
        rustdoc.unlink()
        with self.assertRaisesRegex(ValueError, 'required Rust tool missing: rustdoc'):
            subject.rust_toolchain(self.rust)

    def test_std_target_native_hash_duplicates_and_missing_required_inputs_fail(self):
        self.std.write_bytes(archive(183))
        with self.assertRaisesRegex(ValueError, 'not a x86_64 ELF'):
            self.select()
        self.std.write_bytes(archive())
        duplicate = write(self.libdir / 'libstd-duplicate.rlib', archive())
        with self.assertRaisesRegex(ValueError, 'exactly one official target libstd'):
            self.select()
        duplicate.unlink()
        changed = copy.deepcopy(self.recipe); changed['native_inputs'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'native input identity mismatch'):
            self.select(changed)
        changed = copy.deepcopy(self.recipe); changed['native_inputs'].append(changed['native_inputs'][0])
        with self.assertRaisesRegex(ValueError, 'duplicate native input'):
            self.select(changed)
        changed = copy.deepcopy(self.recipe); changed['native_inputs'].pop()
        with self.assertRaisesRegex(ValueError, 'lacks pinned target'):
            self.select(changed)

    def test_missing_host_compiler_and_escaped_sdk_library_fail(self):
        self.host_cc.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'required tool missing: host_cc'):
            self.select()
        self.host_cc.chmod(0o755)
        native = self.sysroot / 'sysroot/usr/lib/libc.a'
        outside = write(self.root / 'external.a', native.read_bytes())
        native.unlink(); native.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'native input identity mismatch'):
            self.select()

    def test_proxy_transport_is_acquisition_only_and_never_copied_into_receipts(self):
        proxy_names = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                       'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
        secret = 'fixture-credential-do-not-record'
        poison = 'unreviewed-setting-do-not-propagate'
        environment = {name: 'http://fixture:' + secret + '@proxy.invalid:8080' for name in proxy_names}
        environment.update(HOME=str(self.root / 'home'), PATH='/untrusted/bin', RUSTFLAGS=poison,
            RUSTDOCFLAGS=poison, CARGO_ENCODED_RUSTFLAGS=poison, CARGO_ENCODED_RUSTDOCFLAGS=poison,
            RUSTC_WRAPPER=poison, CARGO_BUILD_TARGET=poison, CARGO_HTTP_PROXY=poison,
            CARGO_HOME=poison, CARGO_NET_OFFLINE='false', CARGO_PROFILE_RELEASE_LTO=poison,
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=poison)
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(subject.subprocess, 'check_output', side_effect=self.probe), \
             mock.patch.object(subject.shutil, 'which', side_effect=self.which):
            cargo, acquisition, receipt = subject.acquisition_environment(self.cache, self.rust)
            self.assertEqual(cargo, self.rust / 'bin/cargo')
            self.assertEqual(acquisition['CARGO_NET_OFFLINE'], 'false')
            self.assertEqual(acquisition['CARGO_NET_GIT_FETCH_WITH_CLI'], 'true')
            self.assertEqual(acquisition['CARGO_HOME'], str(self.cache))
            self.assertEqual(acquisition['CARGO_HTTP_PROXY'], environment['https_proxy'])
            self.assertEqual(receipt['proxy_environment_names'], sorted(proxy_names))
            self.assertTrue(receipt['git_fetch_with_cli'])
            self.assertEqual(receipt['git'], {'path': str(self.git), 'sha256': subject.base.digest(self.git)})
            for name in proxy_names:
                self.assertEqual(acquisition[name], environment[name])
            self.assertNotIn(secret, json.dumps(receipt))
            self.assertNotIn(poison, json.dumps(acquisition))
            tools, identities = subject.tools_and_sysroot(self.sysroot, self.recipe,
                                                          rust_root=self.rust, host_cc=self.host_cc)
            output = self.root / 'build'; output.mkdir()
            control = self.root / 'control'; control.mkdir()
            build_env = subject.base.cargo_environment(tools, identities, self.sysroot, output, self.cache, control)
            self.assertEqual(build_env['CARGO_NET_OFFLINE'], 'true')
            self.assertNotIn('CARGO_NET_GIT_FETCH_WITH_CLI', build_env)
            self.assertNotIn('CARGO_HTTP_PROXY', build_env)
            self.assertTrue(all(name not in build_env for name in proxy_names))
            self.assertNotIn(secret, json.dumps(identities))
            self.assertNotIn(poison, json.dumps(build_env))
            self.assertEqual(build_env['CC'], str(self.host_cc))
            self.assertEqual(build_env['CXX'], str(self.host_cc.with_name('clang++')))


if __name__ == '__main__':
    unittest.main()
