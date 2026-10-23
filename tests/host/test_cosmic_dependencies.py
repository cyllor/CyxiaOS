import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from tools import cosmic_dependencies as dep


class CosmicDependencyTests(unittest.TestCase):
    def test_tree_rejects_escape_duplicate_and_truncation(self):
        good = {'tree': [{'path': 'Cargo.toml', 'type': 'blob', 'mode': '100644',
                          'sha': 'a' * 40, 'size': 10}], 'truncated': False}
        self.assertEqual(len(dep.validate_tree(good)), 1)
        for tree in (dict(good, truncated=True),
                     dict(good, tree=good['tree'] * 2),
                     dict(good, tree=[dict(good['tree'][0], path='../escape')])):
            with self.subTest(tree=tree), self.assertRaises(dep.DependencyError):
                dep.validate_tree(tree)

    def test_lock_records_checksums_but_never_claims_vendoring(self):
        data = b'''version = 4
[[package]]
name = "crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[[package]]
name = "other"
version = "0.1.0"
source = "git+https://github.com/pop-os/test#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
'''
        result = dep.lock_summary(data)
        self.assertEqual(result['package_count'], 2)
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['unfixed_sources'], [])
        self.assertFalse(result['vendored'])
        bad = data.replace(b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', b'main')
        self.assertEqual(len(dep.lock_summary(bad)['unfixed_sources']), 1)

    def test_cached_blob_is_bound_to_git_blob_and_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b'[package]\nname="fixture"\nversion="0.1.0"\n'
            sha = dep.git_blob_sha(content)
            source = {'name': 'fixture', 'directory': 'fixture', 'commit': 'a' * 40,
                      'repository': 'https://github.com/pop-os/fixture'}
            path = root / 'Cargo.toml'
            path.write_bytes(content)
            record = {'path': 'Cargo.toml', 'sha256': hashlib.sha256(content).hexdigest(),
                      'git_blob': sha, 'bytes': len(content)}
            (root / 'evidence.json').write_text(json.dumps({'source': source, 'files': [record]}))
            self.assertEqual(dep.read_evidence(root, source)['files'][0]['git_blob'], sha)
            path.write_bytes(content + b'# changed\n')
            with self.assertRaisesRegex(dep.DependencyError, 'identity'):
                dep.read_evidence(root, source)

    def test_manifest_dependencies_include_target_and_workspace(self):
        result = dep.cargo_summary(b'''[workspace.dependencies]
zbus = { version="5", features=["tokio"] }
[target.'cfg(unix)'.dependencies]
notify = "8"
[features]
default = ["systemd"]
systemd = []
''')
        self.assertEqual({p['name'] for p in result['dependencies']}, {'zbus', 'notify'})
        self.assertEqual(result['default_features'], ['systemd'])

    def test_selected_metadata_is_bounded_and_does_not_fetch_asset_payloads(self):
        items = [dict(path='Cargo.toml', type='blob', mode='100644', size=100, sha='a'*40),
                 dict(path='large.png', type='blob', mode='100644', size=10**9, sha='b'*40)]
        self.assertEqual([p['path'] for p in dep.selected_paths(items)], ['Cargo.toml'])
        items[0]['size'] = dep.MAX_FILE + 1
        with self.assertRaisesRegex(dep.DependencyError, 'limit'):
            dep.selected_paths(items)

    def test_real_pinned_git_metadata_fetch_uses_no_network_or_asset_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source_path = root / 'sources/fixture'
            subprocess.run(['git', 'init', '-q', str(source_path)], check=True)
            (source_path / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
            (source_path / 'large.png').write_bytes(b'not-fetched' * 1000)
            subprocess.run(['git', '-C', str(source_path), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(source_path), '-c', 'user.name=test', '-c',
                            'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            url = 'https://github.com/pop-os/fixture'
            subprocess.run(['git', '-C', str(source_path), 'remote', 'add', 'origin', url], check=True)
            source = {'name': 'fixture', 'directory': 'fixture', 'repository': url,
                      'commit': dep.ports.git(source_path, 'rev-parse', 'HEAD')}
            with patch.object(dep, 'download', side_effect=AssertionError('network forbidden')):
                result = dep.fetch(source, root / 'metadata', root / 'sources')
                cached = dep.fetch(source, root / 'metadata', root / 'sources')
            self.assertEqual(result, cached)
            self.assertEqual(result['mode'], 'verified-local-git')
            self.assertEqual(len(result['files']), 1)
            self.assertFalse((root / 'metadata/fixture' / source['commit'] / 'large.png').exists())
            summary = dep.inventory_component(source, root / 'metadata')
            self.assertEqual(summary['assets']['count'], 1)
            self.assertIsNone(summary['cargo_lock'])
            self.assertFalse(summary['dependency_closure_complete'])

    def test_real_inventory_keeps_all_thirty_components_and_unknown_closure(self):
        inventory = dep.inventory(dep.ports.load_manifest())
        self.assertEqual(inventory['component_count'], 30)
        self.assertFalse(inventory['full_dependency_closure_locked'])
        self.assertFalse(inventory['all_target_builds_ready'])
        self.assertTrue(all(not p['target_built'] for p in inventory['components']))


if __name__ == '__main__':
    unittest.main()
