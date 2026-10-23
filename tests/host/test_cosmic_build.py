import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import build_cosmic as build


class CosmicBuildTests(unittest.TestCase):
    def local_source(self, root):
        source = root / 'fixture'
        subprocess.run(['git', 'init', '-q', str(source)], check=True)
        (source / 'src').mkdir()
        (source / 'src/main.rs').write_text('fn main() { println!("controlled Cargo fixture"); }\n')
        (source / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="0.1.0"\nedition="2024"\n')
        (source / 'Cargo.lock').write_text('version = 4\n[[package]]\nname = "fixture"\nversion = "0.1.0"\n')
        subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(source), '-c', 'user.name=test', '-c',
                        'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        url = 'https://github.com/pop-os/cyxia-test-fixture'
        subprocess.run(['git', '-C', str(source), 'remote', 'add', 'origin', url], check=True)
        return {'name': 'fixture', 'directory': 'fixture', 'repository': url,
                'commit': build.git(source, 'rev-parse', 'HEAD')}

    def test_paths_fail_closed_and_preserve_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'keep').mkdir()
            marker = root / 'keep/user.txt'
            marker.write_text('preserve')
            with self.assertRaises(build.CosmicBuildError):
                build.new_output(root / 'keep')
            (root / 'link').symlink_to(root / 'keep', target_is_directory=True)
            with self.assertRaises(build.CosmicBuildError):
                build.new_output(root / 'link/new')
            self.assertEqual(marker.read_text(), 'preserve')

    def test_environment_does_not_inherit_target_or_rust_injection(self):
        polluted = {'PATH': '/bad', 'HOME': '/real', 'RUSTFLAGS': '-L/bad',
                    'CARGO_BUILD_RUSTFLAGS': '-L/bad', 'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER': '/bad',
                    'RUSTC_WRAPPER': '/bad', 'PKG_CONFIG_PATH': '/bad', 'CPATH': '/bad',
                    'LD_PRELOAD': '/bad', 'DYLD_LIBRARY_PATH': '/bad', 'CARGO_HOME': '/bad'}
        with patch.dict(os.environ, polluted, clear=True):
            env = build.clean_environment('/safe/bin')
        self.assertEqual(env['HOME'], '/real')
        self.assertEqual(env['PATH'], '/safe/bin')
        self.assertNotIn('RUSTFLAGS', env)
        self.assertNotIn('CARGO_HOME', env)
        self.assertNotIn('LD_PRELOAD', env)
        self.assertNotIn('CPATH', env)

    def test_real_process_failure_timeout_and_resource_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'log'
            env = dict(os.environ)
            with self.assertRaisesRegex(build.CosmicBuildError, 'exit 7'):
                build.run_bounded([sys.executable, '-c', 'raise SystemExit(7)'],
                                  root, env, log, 10, 0, 10**8)
            with self.assertRaisesRegex(build.CosmicBuildError, 'deadline'):
                build.run_bounded([sys.executable, '-c', 'import time; time.sleep(20)'],
                                  root, env, log, .1, 0, 10**8)
            marker = root / 'must-not-run'
            with self.assertRaisesRegex(build.CosmicBuildError, 'free space'):
                build.run_bounded([sys.executable, '-c', f'open({str(marker)!r},"w").close()'],
                                  root, env, log, 10, 10**30, 10**8)
            self.assertFalse(marker.exists())

    def test_archive_export_rejects_external_links_and_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            subprocess.run(['git', 'init', '-q', str(source)], check=True)
            (source / 'outside').symlink_to('/etc/passwd')
            subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(source), '-c', 'user.name=test', '-c',
                            'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            with self.assertRaisesRegex(build.CosmicBuildError, 'symlink'):
                build.export_source(source, root / 'out')

    def test_unknown_profile_and_oversized_jobs_are_rejected(self):
        profile = {'schema_version': 1, 'target': build.TARGET,
                   'build_profiles': {'static': {'jobs_max': 1, 'min_free_bytes': 1,
                       'max_build_bytes': 100, 'timeout_seconds': 10,
                       'max_elf_bytes': 100, 'image_bytes': 100, 'stack_bytes': 10}}}
        with self.assertRaises(build.CosmicBuildError):
            build.select_profile(profile, 'missing', 1)
        with self.assertRaises(build.CosmicBuildError):
            build.select_profile(profile, 'static', 2)

    def test_explicit_cache_rejects_global_config_and_external_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache = root / 'cache'
            cache.mkdir()
            self.assertEqual(build.validate_cache(cache), cache)
            (cache / 'config.toml').write_text('[build]\nrustflags=["-L/bad"]\n')
            with self.assertRaisesRegex(build.CosmicBuildError, 'config'):
                build.validate_cache(cache)
            (cache / 'config.toml').unlink()
            (cache / 'registry').symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(build.CosmicBuildError, 'aliases'):
                build.validate_cache(cache)
            with self.assertRaises(build.CosmicBuildError):
                build.validate_cache(Path.home() / '.cargo')

    def test_source_cargo_config_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.local_source(root)
            (root / 'fixture/.cargo').mkdir()
            (root / 'fixture/.cargo/config.toml').write_text('[build]\nrustc-wrapper="/unwanted"\n')
            subprocess.run(['git', '-C', str(root / 'fixture'), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(root / 'fixture'), '-c', 'user.name=test', '-c',
                            'user.email=test@example.invalid', 'commit', '-qm', 'config'], check=True)
            with self.assertRaisesRegex(build.CosmicBuildError, 'Cargo config'):
                build.export_source(root / 'fixture', root / 'stage')
            self.assertFalse((root / 'stage/.cargo/config.toml').exists())

    def test_patch_path_escape_and_wrong_hash_do_not_modify_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.local_source(root)
            original = build.digest(root / 'fixture/src/main.rs')
            recipe = {'patches': [{'path': '../outside.patch', 'sha256': '0' * 64}]}
            with self.assertRaises(ValueError):
                build.apply_patches(recipe, root / 'fixture', root)
            patch_path = root / 'fix.patch'
            patch_path.write_text('unused')
            recipe['patches'][0]['path'] = 'fix.patch'
            with self.assertRaisesRegex(build.CosmicBuildError, 'identity'):
                build.apply_patches(recipe, root / 'fixture', root)
            self.assertEqual(build.digest(root / 'fixture/src/main.rs'), original)

    def test_compile_budget_counts_scratch_and_cache_growth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            out, scratch = root / 'out', root / 'scratch'
            out.mkdir(); scratch.mkdir()
            (scratch / 'large').write_bytes(b'x' * 256)
            with self.assertRaisesRegex(build.CosmicBuildError, 'budget'):
                build.run_bounded([sys.executable, '-c', 'pass'], out, dict(os.environ), out / 'log',
                                  10, 0, 128, scratch_roots=(scratch,))

    def test_real_git_identity_dirty_ignored_and_environment_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = self.local_source(root)
            with patch.dict(os.environ, {'GIT_DIR': '/no-such-git-dir', 'GIT_WORK_TREE': '/no-such-tree'}):
                self.assertTrue(build.inspect_source(root, source)['verified'])
            with self.assertRaisesRegex(build.CosmicBuildError, 'commit'):
                build.inspect_source(root, dict(source, commit='0' * 40))
            (root / 'fixture/.git/info/exclude').write_text('local-input\n')
            (root / 'fixture/local-input').write_text('not in pinned tree')
            with self.assertRaisesRegex(build.CosmicBuildError, 'ignored'):
                build.inspect_source(root, source)
            self.assertEqual((root / 'fixture/local-input').read_text(), 'not in pinned tree')

    def test_target_pkg_config_actually_rejects_host_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pkg = root / 'pkg-config'
            pkg.write_text('#!' + sys.executable + '\nprint("-I/usr/include -L/opt/homebrew/lib -lx")\n')
            pkg.chmod(0o755)
            wrapper = build.target_pkg_wrapper(root / 'wrapper', pkg, {}, root / 'target')
            result = subprocess.run([str(wrapper), '--libs', 'x'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('host/relative', result.stderr)
            self.assertEqual(result.stdout, '')
            pkg.write_text('#!' + sys.executable + '\nprint(' + repr('-I' + str(root / 'target/include') + ' -lx') + ')\n')
            result = subprocess.run([str(wrapper), '--libs', 'x'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('-lx', result.stdout)

    def test_metadata_rejects_path_dependency_outside_staging_and_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'source').mkdir()
            (root / 'outside').mkdir()
            (root / 'outside/Cargo.toml').write_text('outside')
            metadata = {'packages': [
                {'name': 'fixture', 'manifest_path': str(root / 'source/Cargo.toml'),
                 'version': '0.1.0', 'source': None,
                 'targets': [{'name': 'fixture', 'kind': ['bin']}]},
                {'name': 'outside', 'manifest_path': str(root / 'outside/Cargo.toml'),
                 'version': '0.1.0', 'source': None, 'targets': []}]}
            with self.assertRaisesRegex(build.CosmicBuildError, 'escapes'):
                build.verify_metadata(metadata, root / 'source', root / 'cache',
                                      {'package': 'fixture', 'binary': 'fixture'})

    @unittest.skipUnless((build.DEFAULT_SYSROOT / 'sysroot/usr/lib/libc.a').is_file(),
                         'real pinned target sysroot is not installed')
    def test_real_single_binary_cargo_cross_build_uses_isolated_target(self):
        # A tiny local fixture validates the tool, not any COSMIC component.
        # No registry/git dependencies, downloads, kernel build or guest run.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = self.local_source(root)
            record = build.inspect_source(root, source)
            cache = root / 'cache'
            cache.mkdir()
            recipe = {'schema_version': 1, 'component': 'fixture', 'commit': source['commit'],
                      'target': build.TARGET, 'purpose': 'bounded-build-experiment', 'package': 'fixture',
                      'binary': 'fixture', 'resource_profile': 'static', 'default_features': False,
                      'features': [], 'patches': [], 'source_lock_sha256': build.digest(root / 'fixture/Cargo.lock'),
                      'effective_lock_sha256': build.digest(root / 'fixture/Cargo.lock'), 'native_inputs': []}
            for name in ('libc.a', 'libclang_rt.builtins-aarch64.a', 'crt1.o', 'crti.o', 'crtn.o'):
                relative = 'sysroot/usr/lib/' + name
                recipe['native_inputs'].append({'path': relative, 'sha256': build.digest(build.DEFAULT_SYSROOT / relative)})
            recipe_path = root / 'recipe.json'
            recipe_path.write_text(json.dumps(recipe))
            profile = {'jobs_max': 1, 'min_free_bytes': 128 * 1024**2, 'max_build_bytes': 128 * 1024**2,
                       'timeout_seconds': 60, 'max_elf_bytes': 16 * 1024**2,
                       'image_bytes': 16 * 1024**2, 'stack_bytes': 256 * 1024}
            with patch.dict(os.environ, {'RUSTFLAGS': '--invalid-flag', 'RUSTC_WRAPPER': '/bad-wrapper',
                                        'CC': '/bad-cc', 'PKG_CONFIG_PATH': '/bad-pkg-config'}):
                report = build.perform_build(source, record, recipe, recipe_path, root / 'out',
                                             build.DEFAULT_SYSROOT, cache, profile, 1)
            self.assertEqual(report['status'], 'cross-built')
            self.assertTrue(report['source_preserved'])
            self.assertTrue(report['cargo_offline'])
            self.assertEqual(report['guest_execution'], 'not performed')
            self.assertEqual(report['cargo_dependencies'][0]['name'], 'fixture')
            self.assertGreater(report['executable']['bytes'], 1000)
            self.assertTrue((root / 'out/fixture.elf').is_file())
            self.assertFalse((root / 'fixture/target').exists())


if __name__ == '__main__':
    unittest.main()
