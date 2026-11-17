"""Pinned dependency fixtures, including real Git; never Cargo or guest execution."""
import copy
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import cosmic_notifications_dependencies as subject


class NotificationDependencies(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'source'; self.source.mkdir()
        self.cache = self.root / 'cache'
        self.checkout = self.cache / 'git/checkouts/winit-fixture/9567503'
        (self.checkout / 'dpi').mkdir(parents=True)
        (self.checkout / '.git').mkdir()
        (self.checkout / '.cargo-ok').write_text('')
        (self.checkout / 'LICENSE').write_text('fixture license\n')
        (self.checkout / 'README.md').write_text('fixture readme\n')
        (self.checkout / 'dpi/Cargo.toml').write_text('[package]\nname="dpi"\nversion="0.1.0"\n')
        (self.checkout / 'dpi/LICENSE').symlink_to('../LICENSE')
        self.declared = self.inventory()
        (self.source / 'Cargo.toml').write_text('[package]\nname="cosmic-notifications"\nversion="1.10.0"\n')
        self.write_lock(subject.WINIT_SOURCE)
        self.recipe = {'package': 'cosmic-notifications', 'binary': 'cosmic-notifications'}
        self.metadata = {'version': 1, 'packages': [
            {'name': 'cosmic-notifications', 'version': '1.10.0', 'id': 'local-id', 'source': None,
             'manifest_path': str(self.source / 'Cargo.toml'),
             'targets': [{'name': 'cosmic-notifications', 'kind': ['bin']}]},
            {'name': 'dpi', 'version': '0.1.0', 'id': 'dpi-id', 'source': subject.WINIT_SOURCE,
             'manifest_path': str(self.checkout / 'dpi/Cargo.toml'), 'targets': []}],
            'resolve': {'nodes': [{'id': 'local-id', 'dependencies': ['dpi-id']},
                                  {'id': 'dpi-id', 'dependencies': []}]}}

    def inventory(self):
        result = {}
        for path in self.checkout.rglob('*'):
            if path.name == '.cargo-ok' or path.is_dir():
                continue
            raw = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
            result[str(path.relative_to(self.checkout))] = {
                'mode': '120000' if path.is_symlink() else '100644', 'blob': subject.git_blob(raw)}
        return result

    def write_lock(self, spec):
        (self.source / 'Cargo.lock').write_text(
            'version=4\n[[package]]\nname="cosmic-notifications"\nversion="1.10.0"\n'
            '[[package]]\nname="dpi"\nversion="0.1.0"\nsource="' + spec + '"\n')

    def git(self, root, *arguments):
        self.assertEqual(root, self.checkout)
        self.assertEqual(arguments[0], '--no-replace-objects')
        arguments = arguments[1:]
        values = {('rev-parse', '--show-toplevel'): str(self.checkout),
                  ('rev-parse', 'HEAD'): subject.WINIT_COMMIT,
                  ('rev-parse', 'HEAD^{tree}'): subject.WINIT_TREE,
                  ('ls-tree', '-rz', 'HEAD'): ''.join(
                      f"{v['mode']} blob {v['blob']}\t{k}\0" for k, v in self.declared.items())}
        return values[arguments]

    def verify(self, metadata=None):
        with mock.patch.object(subject.build, 'git', side_effect=self.git), mock.patch.object(
                subject.build.subprocess, 'run', side_effect=AssertionError('native subprocess forbidden')):
            return subject.verify_metadata(metadata or self.metadata, self.source, self.cache, self.recipe)

    def test_exact_checkout_binds_shared_target_and_complete_parent_tree(self):
        records = self.verify()
        origin = records[1]['git_checkout']
        self.assertEqual(origin['commit'], subject.WINIT_COMMIT)
        self.assertEqual(set(origin['files']), set(self.declared))
        link = origin['files']['dpi/LICENSE']
        self.assertEqual((link['symlink'], link['resolved_path']), ('../LICENSE', 'LICENSE'))
        self.assertEqual(link['resolved_identity']['sha256'], origin['files']['LICENSE']['sha256'])

    def test_modified_shared_target_retargeted_link_and_untracked_parent_file_fail(self):
        license_path = self.checkout / 'LICENSE'
        original = license_path.read_bytes()
        license_path.write_text('tampered license')
        with self.assertRaises(ValueError): self.verify()
        license_path.write_bytes(original)
        link = self.checkout / 'dpi/LICENSE'
        link.unlink(); link.symlink_to('../README.md')
        with self.assertRaises(ValueError): self.verify()
        link.unlink(); link.symlink_to('../LICENSE')
        (self.checkout / 'unexpected.rs').write_text('untracked input')
        with self.assertRaises(ValueError): self.verify()

    def test_even_declared_symlinks_cannot_escape_checkout_or_be_absolute(self):
        outside = self.root / 'other-checkout'; outside.mkdir()
        (outside / 'LICENSE').write_text('outside')
        link = self.checkout / 'dpi/LICENSE'
        for target in (str(outside / 'LICENSE'), os.path.relpath(outside / 'LICENSE', link.parent),
                       str(self.checkout / 'LICENSE')):
            link.unlink(); link.symlink_to(target)
            declared = self.inventory()
            with self.subTest(target=target), self.assertRaises(ValueError):
                subject.validate_checkout_tree(self.checkout, declared)

    def test_broken_cycle_and_file_replaced_by_link_fail(self):
        link = self.checkout / 'dpi/LICENSE'
        for target in ('../missing', 'LICENSE'):
            link.unlink(); link.symlink_to(target)
            with self.subTest(target=target), self.assertRaises(ValueError):
                subject.validate_checkout_tree(self.checkout, self.inventory())
        link.unlink(); link.symlink_to('../LICENSE')
        real = self.checkout / 'README.md'
        real.unlink(); real.symlink_to('LICENSE')
        with self.assertRaises(ValueError): self.verify()

    def test_wrong_commit_tree_checkout_and_source_do_not_gain_link_exception(self):
        original_git = self.git
        for command in (('rev-parse', 'HEAD'), ('rev-parse', 'HEAD^{tree}'),
                        ('rev-parse', '--show-toplevel')):
            def wrong(root, *args):
                return 'wrong' if args == ('--no-replace-objects', *command) else original_git(root, *args)
            with self.subTest(command=command), mock.patch.object(subject.build, 'git', side_effect=wrong), self.assertRaises(ValueError):
                subject.checkout_identity(self.checkout / 'dpi/Cargo.toml', self.cache, subject.WINIT_SOURCE)
        spec = subject.WINIT_SOURCE.replace('pop-os/winit', 'elsewhere/winit')
        self.write_lock(spec)
        changed = copy.deepcopy(self.metadata); changed['packages'][1]['source'] = spec
        with self.assertRaises(ValueError): self.verify(changed)

    def test_metadata_lock_graph_source_root_and_package_aliases_fail(self):
        cases = []
        changed = copy.deepcopy(self.metadata); changed['packages'][1]['version'] = '9.9.9'; cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['packages'][1]['id'] = 'local-id'; cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['resolve']['nodes'][0]['dependencies'] = ['missing']; cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['packages'][1]['manifest_path'] = str(self.source / 'Cargo.toml'); cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['packages'][0]['targets'] = []; cases.append(changed)
        for metadata in cases:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError): self.verify(metadata)
        alias = self.checkout / 'dpi/alias.toml'; alias.symlink_to('Cargo.toml')
        changed = copy.deepcopy(self.metadata); changed['packages'][1]['manifest_path'] = str(alias)
        with self.assertRaises(ValueError): self.verify(changed)

    def test_transitive_wrapper_maps_include_actual_validation_helpers(self):
        tools = Path(__file__).resolve().parent
        with mock.patch.object(sys, 'path', [str(tools), *sys.path]):
            import os_x86
            build = os_x86.producer_sources(tools / 'build_cosmic_notifications.py')
            prepare = os_x86.producer_sources(tools / 'prepare_cosmic_notifications.py')
        self.assertTrue({'tools/cosmic_notifications_dependencies.py', 'tools/build_sysroot.py',
                         'tools/target_profile.py', 'tools/cosmic_ports.py', 'tools/os_x86.py'} <= set(build))
        self.assertTrue({'tools/cosmic_notifications_source.py', 'tools/cosmic_port_source.py',
                         'tools/build_sysroot.py', 'tools/target_profile.py'} <= set(prepare))


@unittest.skipUnless(Path('/usr/bin/git').is_file(), 'real Git is required')
class NotificationReplacementObjects(unittest.TestCase):
    def test_real_tree_replacement_cannot_relabel_changed_dependency_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary).resolve() / 'cache'
            checkout = cache / 'git/checkouts/winit-fixture/pinned'
            (checkout / 'dpi/src').mkdir(parents=True)
            manifest = checkout / 'dpi/Cargo.toml'
            manifest.write_text('[package]\nname="dpi"\nversion="0.1.0"\n')
            code = checkout / 'dpi/src/lib.rs'
            code.write_text('pub fn selected_source() -> u8 { 1 }\n')
            (checkout / 'LICENSE').write_text('fixture license\n')
            (checkout / 'dpi/LICENSE').symlink_to('../LICENSE')

            def git(*arguments):
                return subprocess.check_output(['/usr/bin/git', '-c', 'user.name=Dependency Test',
                    '-c', 'user.email=dependency@example.invalid', '-C', str(checkout), *arguments],
                    env=subject.build.clean_environment('/usr/bin:/bin'), text=True).strip()

            git('init', '-q'); git('add', '.'); git('commit', '-qm', 'Pinned fixture')
            commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
            spec = 'git+https://github.com/pop-os/winit.git?rev=fixture#' + commit
            (checkout / '.cargo-ok').write_text('')
            with mock.patch.object(subject, 'WINIT_SOURCE', spec), \
                 mock.patch.object(subject, 'WINIT_COMMIT', commit), \
                 mock.patch.object(subject, 'WINIT_TREE', tree):
                before = subject.checkout_identity(manifest, cache, spec)
                code.write_text('pub fn selected_source() -> u8 { 9 }\n')
                git('add', 'dpi/src/lib.rs')
                git('replace', tree, git('write-tree'))
                # The public commit/tree IDs remain pinned: this is the bypass
                # that a plain ls-tree previously accepted as the original tree.
                self.assertEqual(git('rev-parse', 'HEAD'), commit)
                self.assertEqual(git('rev-parse', 'HEAD^{tree}'), tree)
                self.assertNotEqual(git('ls-tree', '-r', 'HEAD'),
                                    git('--no-replace-objects', 'ls-tree', '-r', 'HEAD'))
                with self.assertRaisesRegex(ValueError, 'Pinned Git blob bytes changed'):
                    subject.checkout_identity(manifest, cache, spec)
                # Canonical bytes are still valid even while the cache retains
                # the replacement; identity comes from objects, not local refs.
                code.write_text('pub fn selected_source() -> u8 { 1 }\n')
                self.assertEqual(subject.checkout_identity(manifest, cache, spec), before)


if __name__ == '__main__':
    unittest.main()
