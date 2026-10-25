"""Apply the maintained patch and test the actual backend selector and feature graph."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = ROOT / 'artifacts/cosmic-sources/cosmic-comp-epoch'
PATCH = ROOT / 'ports/cosmic/patches/cosmic-comp-41497b42-cyxia-nested.patch'
SMITHAY = ROOT / 'artifacts/smithay-research/smithay-e3d461a057ba244d213a8498ec372b0799cca103/Cargo.toml'


class NestedPatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='cosmic-nested-test-')
        cls.stage = Path(cls.tmp.name) / 'source'
        shutil.copytree(ORIGINAL, cls.stage, ignore=shutil.ignore_patterns('.git', 'target'))
        applied = subprocess.run(['patch', '--batch', '-p1', '-i', str(PATCH)],
                                 cwd=cls.stage, text=True, capture_output=True)
        if applied.returncode:
            raise AssertionError(applied.stdout + applied.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_nested_feature_does_not_activate_native_device_dependencies(self):
        comp = tomllib.loads((self.stage / 'Cargo.toml').read_text())
        smithay = tomllib.loads(SMITHAY.read_text())
        config = tomllib.loads((self.stage / 'cosmic-comp-config/Cargo.toml').read_text())
        self.assertFalse(comp['dependencies']['cosmic-comp-config']['default-features'])
        self.assertTrue(config['dependencies']['input']['optional'])
        active = set(comp['dependencies']['smithay']['features'])
        todo = list(comp['features']['backend-winit'])
        seen = set()
        while todo:
            item = todo.pop()
            if item in seen:
                continue
            seen.add(item)
            if item.startswith('smithay/'):
                active.add(item.split('/', 1)[1])
            elif item in comp['features']:
                todo.extend(comp['features'][item])
        todo = list(active)
        while todo:
            item = todo.pop()
            for child in smithay['features'].get(item, []):
                if child not in active:
                    active.add(child)
                    todo.append(child)
        self.assertFalse(active & {'backend_gbm', 'backend_libinput', 'backend_udev',
                                  'backend_session_libseat', 'backend_vulkan',
                                  'gbm', 'input', 'udev', 'libseat', 'ash', 'renderer_multi'})
        self.assertIn('backend_winit', active)
        self.assertIn('renderer_glow', active)
        self.assertIn('backend_drm', active)  # data types remain, by design
        self.assertEqual(comp['features']['default'],
                         ['systemd', 'backend-kms', 'backend-winit', 'backend-x11'])

    def test_actual_selector_in_winit_only_build(self):
        self.compile_selector(['backend-winit'], '''
        assert_eq!(candidates(None, true).unwrap(), &[Backend::Winit]);
        assert_eq!(candidates(Some("winit"), false).unwrap(), &[Backend::Winit]);
        assert!(candidates(Some("kms"), true).is_err());
        assert!(candidates(Some("x11"), true).is_err());
        assert!(candidates(Some("bogus"), true).is_err());
        assert!(candidates(None, false).is_err());
        ''')

    def test_actual_selector_preserves_upstream_default_order(self):
        self.compile_selector(['backend-winit', 'backend-x11', 'backend-kms'], '''
        assert_eq!(candidates(None, true).unwrap(), &[Backend::X11, Backend::Winit]);
        assert_eq!(candidates(None, false).unwrap(), &[Backend::Kms]);
        assert_eq!(candidates(Some("kms"), true).unwrap(), &[Backend::Kms]);
        ''')

    def test_no_available_nested_backend_is_error(self):
        self.compile_selector(['backend-kms'], '''
        assert!(candidates(None, true).is_err());
        assert_eq!(candidates(None, false).unwrap(), &[Backend::Kms]);
        ''')

    def test_build_identity_never_inherits_ancestor_repository(self):
        binary = Path(self.tmp.name) / 'build-script'
        compiled = subprocess.run([str(Path.home()/'.cargo/bin/rustc'), '--edition=2024',
                                   str(self.stage/'build.rs'), '-o', str(binary)],
                                  text=True, capture_output=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        repository = Path(self.tmp.name) / 'parent-git'
        repository.mkdir()
        subprocess.run(['git', 'init', '-q', str(repository)], check=True)
        subprocess.run(['git', '-C', str(repository), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid', 'commit', '-q',
                        '--allow-empty', '-m', 'fixture'], check=True)
        exported = repository/'exported-compositor'
        exported.mkdir()
        env = dict(__import__('os').environ, CARGO_MANIFEST_DIR=str(exported))
        env.pop('CYXIA_COSMIC_UPSTREAM_COMMIT', None)
        result = subprocess.run([str(binary)], cwd=exported, env=env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('cargo:rustc-env=GIT_HASH=unknown', result.stdout)
        pin = '41497b42d9744d9963c4c6d17e8add49489b45ee'
        env['CYXIA_COSMIC_UPSTREAM_COMMIT'] = pin
        result = subprocess.run([str(binary)], cwd=exported, env=env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('cargo:rustc-env=GIT_HASH='+pin, result.stdout)
        env['CYXIA_COSMIC_UPSTREAM_COMMIT'] = pin+'\ncargo:injected=yes'
        result = subprocess.run([str(binary)], cwd=exported, env=env,
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('cargo:rustc-env=GIT_HASH=', result.stdout)

    def compile_selector(self, features, assertions):
        source = self.stage / 'src/backend/selection.rs'
        wrapper = Path(self.tmp.name) / 'selector-tests.rs'
        binary = Path(self.tmp.name) / 'selector-tests'
        wrapper.write_text(f'#[path = {json.dumps(str(source))}] mod selection;\n'
                           'use selection::{candidates, Backend};\n'
                           '#[test] fn actual_selection() {\n' + assertions + '\n}\n')
        cmd = [str(Path.home()/'.cargo/bin/rustc'), '--edition=2024', '--test',
               str(wrapper), '-o', str(binary)]
        for feature in features:
            cmd.extend(['--cfg', f'feature="{feature}"'])
        compiled = subprocess.run(cmd, text=True, capture_output=True)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        run = subprocess.run([str(binary)], text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
