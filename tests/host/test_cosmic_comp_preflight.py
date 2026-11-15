"""Real read-only source/cache fixtures; no Cargo, compiler or network required."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from tools import cosmic_comp_preflight as preflight


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


class CosmicCompPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cosmic-preflight-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        self.cache = self.root / 'archives'
        self.cache.mkdir()
        self.url = 'https://github.com/example/compositor'
        self.cargo = b'[package]\nname="cosmic-comp"\nversion="1.0.0"\n[features]\ndefault=[]\nbackend-winit=[]\n'
        self.lock = b'version = 4\n[[package]]\nname="cosmic-comp"\nversion="1.0.0"\n'

    def commit_source(self):
        (self.source / 'Cargo.toml').write_bytes(self.cargo)
        (self.source / 'Cargo.lock').write_bytes(self.lock)
        git(self.source, 'init', '-q')
        git(self.source, 'add', '.')
        git(self.source, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-qm', 'fixture')
        git(self.source, 'remote', 'add', 'origin', self.url)
        self.commit = git(self.source, 'rev-parse', 'HEAD')
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'schema_version': 1,
            'components': [{'name': 'cosmic-comp', 'commit': self.commit,
                            'repository': self.url}],
            'compositor': {'cargo_lock_sha256': sha(self.lock)},
            'target_libraries': [],
        }))

    def crate(self, name='fixture', version='1.0.0'):
        path = self.cache / f'{name}-{version}.crate'
        content = f'[package]\nname="{name}"\nversion="{version}"\n'.encode()
        with tarfile.open(path, 'w:gz') as archive:
            entry = tarfile.TarInfo(f'{name}-{version}/Cargo.toml')
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
        self.lock += (f'[[package]]\nname="{name}"\nversion="{version}"\n'
                      'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                      f'checksum="{sha(path.read_bytes())}"\n').encode()
        return path

    def inspect(self, **options):
        return preflight.inspect(source=self.source, manifest=self.manifest,
                                 patch_manifest=options.pop('patch_manifest', None),
                                 archive_caches=[self.cache], cargo_caches=options.pop('cargo_caches', []),
                                 git_sources=options.pop('git_sources', []),
                                 sysroot=self.root / 'sdk', **options)

    def test_verified_archive_proves_bytes_but_never_cargo_resolution_or_build(self):
        archive = self.crate()
        self.commit_source()
        before = {p.relative_to(self.source): p.read_bytes()
                  for p in self.source.rglob('*') if p.is_file()}
        report = self.inspect()
        self.assertTrue(report['source']['verified'])
        self.assertTrue(report['closure']['all_locked_sources_available'])
        self.assertEqual(report['closure']['registry_available'], 1)
        self.assertEqual(report['closure']['packages'][1]['evidence'][0]['sha256'],
                         sha(archive.read_bytes()))
        self.assertFalse(report['cargo_offline_ready'])
        self.assertFalse(report['target_resolution_proven'])
        self.assertFalse(report['compositor_built'])
        self.assertEqual(report['status'], 'blocked')
        after = {p.relative_to(self.source): p.read_bytes()
                 for p in self.source.rglob('*') if p.is_file()}
        self.assertEqual(before, after, 'even Git index bytes must remain unchanged')

    def test_wrong_archive_checksum_and_missing_archive_are_distinct(self):
        archive = self.crate()
        self.commit_source()
        archive.write_bytes(b'tampered archive')
        bad = self.inspect()['closure']
        self.assertFalse(bad['all_locked_sources_available'])
        self.assertEqual(bad['packages'][1]['status'], 'invalid')
        archive.unlink()
        missing = self.inspect()['closure']
        self.assertEqual(missing['packages'][1]['status'], 'missing')

    def test_unpacked_vendor_receipt_without_original_archive_is_not_trusted(self):
        archive = self.crate()
        checksum = sha(archive.read_bytes())
        archive.unlink()
        vendor = self.cache / 'fixture-1.0.0'
        vendor.mkdir()
        (vendor / '.cargo-checksum.json').write_text(json.dumps({'package': checksum, 'files': {}}))
        self.commit_source()
        self.assertFalse(self.inspect()['closure']['all_locked_sources_available'])

    def test_git_checkout_requires_exact_commit_origin_cleanliness_and_package(self):
        dep = self.root / 'dependency'
        dep.mkdir()
        (dep / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="1.0.0"\n')
        git(dep, 'init', '-q')
        git(dep, 'add', '.')
        git(dep, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-qm', 'fixture')
        git(dep, 'remote', 'add', 'origin', 'https://github.com/example/dependency')
        revision = git(dep, 'rev-parse', 'HEAD')
        self.lock += (f'[[package]]\nname="fixture"\nversion="1.0.0"\n'
                      f'source="git+https://github.com/example/dependency#{revision}"\n').encode()
        self.commit_source()
        self.assertFalse(self.inspect()['closure']['all_locked_sources_available'])
        good = self.inspect(git_sources=[dep])
        self.assertTrue(good['closure']['all_locked_sources_available'])
        self.assertFalse(good['cargo_offline_ready'])
        (dep / 'injected.rs').write_text('untracked input')
        bad = self.inspect(git_sources=[dep])
        self.assertFalse(bad['closure']['all_locked_sources_available'])
        self.assertEqual(bad['closure']['packages'][1]['status'], 'invalid')

    def test_source_changed_lock_blocks_even_when_lock_is_parseable(self):
        self.commit_source()
        (self.source / 'Cargo.lock').write_bytes(self.lock + b'# changed\n')
        report = self.inspect()
        self.assertFalse(report['source']['verified'])
        self.assertFalse(report['closure']['all_locked_sources_available'])

    def test_git_index_assume_unchanged_cannot_hide_changed_source_bytes(self):
        self.commit_source()
        git(self.source, 'update-index', '--assume-unchanged', 'Cargo.toml')
        (self.source / 'Cargo.toml').write_bytes(self.cargo + b'# hidden change\n')
        self.assertEqual(git(self.source, 'status', '--porcelain'), '')
        report = self.inspect()
        self.assertFalse(report['source']['verified'])
        self.assertFalse(report['closure']['all_locked_sources_available'])

    def test_cargo_checkout_without_upstream_remote_uses_pinned_commit_and_safe_marker(self):
        cargo = self.root / 'cargo'
        dep = cargo / 'git/checkouts/fixture-hash/revision'
        dep.mkdir(parents=True)
        (dep / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="1.0.0"\n')
        git(dep, 'init', '-q')
        git(dep, 'add', '.')
        git(dep, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-qm', 'fixture')
        revision = git(dep, 'rev-parse', 'HEAD')
        (dep / '.cargo-ok').write_text('{"v":1}')
        self.lock += (f'[[package]]\nname="fixture"\nversion="1.0.0"\n'
                      f'source="git+https://github.com/example/dependency#{revision}"\n').encode()
        self.commit_source()
        report = self.inspect(cargo_caches=[cargo])
        self.assertTrue(report['closure']['all_locked_sources_available'])
        (dep / '.cargo-ok').write_text('unreviewed bytes')
        self.assertFalse(self.inspect(cargo_caches=[cargo])['closure']['all_locked_sources_available'])

    def test_patch_digest_before_after_and_features_are_verified_in_memory(self):
        self.commit_source()
        changed = self.cargo.replace(b'backend-winit=[]', b'backend-winit=["dep:window"]')
        import difflib
        patch = ''.join(difflib.unified_diff(self.cargo.decode().splitlines(True),
                                            changed.decode().splitlines(True),
                                            'a/Cargo.toml', 'b/Cargo.toml')).encode()
        patch_path = self.root / 'nested.patch'
        patch_path.write_bytes(patch)
        document = {'schema_version': 1, 'repository': self.url, 'commit': self.commit,
                    'patch_sha256': sha(patch), 'before': {'Cargo.toml': sha(self.cargo)},
                    'after': {'Cargo.toml': sha(changed)},
                    'features': ['--no-default-features', '--features', 'backend-winit']}
        path = self.root / 'nested.json'
        path.write_text(json.dumps(document))
        good = self.inspect(patch_manifest=path)
        self.assertTrue(good['patch']['verified'])
        self.assertEqual(good['feature_analysis']['selected'], ['backend-winit'])
        self.assertIn('dep:window', good['feature_analysis']['expanded_root_features'])
        self.assertEqual((self.source / 'Cargo.toml').read_bytes(), self.cargo)
        patch_path.write_bytes(patch + b'garbage\n')
        self.assertFalse(self.inspect(patch_manifest=path)['patch']['verified'])
        patch_path.write_bytes(patch)
        document['after']['Cargo.toml'] = '0' * 64
        path.write_text(json.dumps(document))
        self.assertFalse(self.inspect(patch_manifest=path)['patch']['verified'])

    def test_cargo_gitlinks_verify_nested_commit_and_marker_then_find_package(self):
        cargo = self.root / 'cargo'
        dep = cargo / 'git/checkouts/fixture-hash/revision'
        sub = dep / 'submodule'
        sub.mkdir(parents=True)
        (dep / 'Cargo.toml').write_text('[workspace]\nmembers=["submodule"]\n')
        (sub / 'Cargo.toml').write_text('[package]\nname="nested"\nversion.workspace=true\n'
                                      '[workspace.package]\nversion="1.0.0"\n')
        (sub / 'frappé.txt').write_text('valid upstream Unicode asset')
        for repo in (sub, dep):
            git(repo, 'init', '-q')
            git(repo, 'add', 'Cargo.toml')
            if repo == sub:
                git(repo, 'add', 'frappé.txt')
            else:
                git(repo, 'update-index', '--add', '--cacheinfo',
                    '160000,' + git(sub, 'rev-parse', 'HEAD') + ',submodule')
            git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '-qm', 'fixture')
        (sub / '.cargo-ok').write_text('{"v":1}')
        revision = git(dep, 'rev-parse', 'HEAD')
        self.lock += (f'[[package]]\nname="nested"\nversion="1.0.0"\n'
                      f'source="git+https://github.com/example/dependency#{revision}"\n').encode()
        self.commit_source()
        self.assertTrue(self.inspect(cargo_caches=[cargo])['closure']['all_locked_sources_available'])
        (sub / 'Cargo.toml').write_text('[package]\nname="tampered"\nversion="1.0.0"\n')
        self.assertFalse(self.inspect(cargo_caches=[cargo])['closure']['all_locked_sources_available'])

    def test_cli_emits_json_and_nonzero_for_missing_sources(self):
        archive = self.crate()
        archive.unlink()
        self.commit_source()
        result = subprocess.run(['python3', str(Path(preflight.__file__)),
                                 '--source', str(self.source), '--manifest', str(self.manifest),
                                 '--no-patch', '--archive-cache', str(self.cache),
                                 '--cargo-cache', str(self.root / 'absent'),
                                 '--sysroot', str(self.root / 'sdk')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['closure']['registry_missing'], 1)
        self.assertFalse(report['cargo_offline_ready'])


if __name__ == '__main__':
    unittest.main()
