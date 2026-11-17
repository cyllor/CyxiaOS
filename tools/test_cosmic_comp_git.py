"""Real local Git fixtures for recursive compositor source validation.

No network, Cargo, compiler or guest is used. Child repositories deliberately
have real .git directories, matching the observed Cargo submodule checkouts.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import cosmic_comp_git as b


class RecursiveGitContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve() / 'parent'
        self.parent.mkdir()
        self.git(self.parent, 'init', '--quiet')
        (self.parent / 'Cargo.toml').write_text('[package]\nname="parent"\nversion="1.0.0"\n')
        (self.parent / 'ROOT_LICENSE').write_text('immutable parent license\n')
        self.child = self.add_child(self.parent, 'child')
        self.commit = self.commit_all(self.parent)

    def git(self, root, *args):
        env = b.build.clean_environment('/usr/bin:/bin')
        result = subprocess.run(['/usr/bin/git', '-c', 'user.name=Fixture',
                                 '-c', 'user.email=fixture@example.invalid', '-C', str(root), *args],
                                env=env, check=True, text=True, capture_output=True)
        return result.stdout.strip()

    def commit_all(self, root):
        self.git(root, 'add', '--all')
        self.git(root, 'commit', '--quiet', '-m', 'immutable fixture')
        return self.git(root, 'rev-parse', 'HEAD')

    def add_child(self, parent, name):
        child = parent / name
        child.mkdir()
        self.git(child, 'init', '--quiet')
        (child / 'Cargo.toml').write_text('[package]\nname="child"\nversion="1.0.0"\n')
        (child / 'data').write_text('immutable child content\n')
        self.commit_all(child)
        with (parent / '.gitmodules').open('a') as handle:
            handle.write('[submodule "' + name + '"]\n\tpath = ' + name
                         + '\n\turl = https://example.invalid/' + name + '.git\n')
        return child

    def identity(self):
        return b.git_identity(self.parent, self.commit)

    def test_actual_initialized_submodule_is_verified_and_flattened(self):
        identity = self.identity()
        self.assertEqual(identity['submodules']['child']['commit'], self.git(self.child, 'rev-parse', 'HEAD'))
        self.assertIn('child/Cargo.toml', identity['files'])
        self.assertIn('.gitmodules', identity['files'])
        self.assertEqual(identity['files']['child/data']['git_blob'],
                         self.git(self.child, 'rev-parse', 'HEAD:data'))
        self.assertGreater(identity['total_bytes'], len((self.child / 'data').read_bytes()))

    def test_nested_initialized_submodules_are_recursively_bound(self):
        grandchild = self.add_child(self.child, 'grandchild')
        self.commit_all(self.child)
        self.commit = self.commit_all(self.parent)
        identity = self.identity()
        self.assertEqual(set(identity['submodules']), {'child', 'child/grandchild'})
        self.assertEqual(identity['submodules']['child/grandchild']['commit'],
                         self.git(grandchild, 'rev-parse', 'HEAD'))
        self.assertIn('child/grandchild/Cargo.toml', identity['files'])

    def test_parent_head_must_match_requested_commit(self):
        (self.parent / 'ROOT_LICENSE').write_text('new parent commit\n')
        self.commit_all(self.parent)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'HEAD differs'):
            self.identity()

    def test_child_head_must_match_parent_gitlink(self):
        (self.child / 'data').write_text('new child commit\n')
        self.commit_all(self.child)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'HEAD differs'):
            self.identity()

    def test_changed_child_blob_cannot_hide_behind_matching_head(self):
        (self.child / 'data').write_text('dirty bytes without a commit\n')
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'blob bytes changed'):
            self.identity()

    def test_changed_parent_blob_cannot_hide_behind_matching_head(self):
        (self.parent / 'ROOT_LICENSE').write_text('dirty parent\n')
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'blob bytes changed'):
            self.identity()

    def test_changed_executable_mode_is_rejected(self):
        (self.child / 'data').chmod(0o755)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'executable mode changed'):
            self.identity()

    def test_untracked_and_gitignored_child_files_are_rejected(self):
        (self.child / '.git/info/exclude').write_text('.ignored\n')
        for relative in ('extra', '.ignored', 'nested/.cargo-ok'):
            path = self.child / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text('not pinned')
            with self.subTest(relative=relative), self.assertRaisesRegex(b.build.CosmicBuildError, 'inventory changed'):
                self.identity()
            path.unlink()

    def test_inaccessible_inventory_directory_cannot_hide_files(self):
        original = os.scandir

        def guarded(directory):
            if Path(directory) == self.child:
                raise PermissionError('fixture directory cannot be enumerated')
            return original(directory)

        with patch.object(b.os, 'scandir', side_effect=guarded), \
             self.assertRaisesRegex(b.build.CosmicBuildError, 'Cannot enumerate complete'):
            self.identity()

    def test_only_each_verified_repo_regular_cargo_marker_is_ignored(self):
        original = self.identity()
        for node in (self.parent, self.child):
            (node / '.cargo-ok').write_text('{"cache_marker":true}\n')
        self.assertEqual(self.identity(), original)
        (self.child / '.cargo-ok').unlink()
        (self.child / '.cargo-ok').symlink_to('data')
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'Cargo cache marker'):
            self.identity()
        (self.child / '.cargo-ok').unlink()
        (self.child / '.cargo-ok').mkdir()
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'Cargo cache marker'):
            self.identity()

    def test_unknown_nested_git_directory_is_not_ignored(self):
        (self.parent / 'not-a-submodule/.git').mkdir(parents=True)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'Unverified'):
            self.identity()

    def test_uninitialized_gitlink_cannot_fall_back_to_parent_repository(self):
        shutil.rmtree(self.child)
        self.child.mkdir()
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'initialized independent'):
            self.identity()

    def test_gitlink_directory_cannot_be_a_symlink(self):
        outside = self.parent.parent / 'outside-child'
        self.child.rename(outside)
        self.child.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'aliased gitlink'):
            self.identity()

    def test_git_metadata_pointer_files_and_aliases_remain_unsupported(self):
        outside = self.parent.parent / 'child-metadata'
        (self.child / '.git').rename(outside)
        (self.child / '.git').write_text('gitdir: ' + str(outside) + '\n')
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'initialized independent'):
            self.identity()
        (self.child / '.git').unlink()
        (self.child / '.git').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'initialized independent'):
            self.identity()

    def test_git_replacement_cannot_hide_changed_submodule_content(self):
        old = self.git(self.child, 'rev-parse', 'HEAD')
        (self.child / 'data').write_text('replacement commit content\n')
        replacement = self.commit_all(self.child)
        self.git(self.child, 'replace', old, replacement)
        self.git(self.child, 'checkout', '--quiet', '--detach', old)
        self.assertEqual(self.git(self.child, 'rev-parse', 'HEAD'), old)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'blob bytes changed'):
            self.identity()

    def test_pinned_cross_submodule_file_and_directory_links_are_allowed(self):
        (self.parent / 'child-data').symlink_to('child/data')
        (self.child / 'parent-license').symlink_to('../ROOT_LICENSE')
        (self.child / 'assets').mkdir()
        (self.child / 'assets/icon').write_text('pinned asset\n')
        (self.parent / 'child-assets').symlink_to('child/assets', target_is_directory=True)
        self.commit_all(self.child)
        self.commit = self.commit_all(self.parent)
        identity = self.identity()
        self.assertEqual(identity['files']['child/parent-license']['resolved_path'], 'ROOT_LICENSE')
        self.assertEqual(identity['files']['child-data']['resolved_path'], 'child/data')
        self.assertIn('git_entries_sha256', identity['files']['child-assets']['resolved_identity'])

    def test_tracked_symlink_cannot_escape_parent_checkout(self):
        outside = self.parent.parent / 'outside'
        outside.write_text('outside bytes\n')
        (self.child / 'escape').symlink_to('../../outside')
        self.commit_all(self.child)
        self.commit = self.commit_all(self.parent)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'escapes parent'):
            self.identity()

    def test_symlink_target_must_be_pinned_not_git_control_metadata(self):
        (self.child / 'head-alias').symlink_to('.git/HEAD')
        self.commit_all(self.child)
        self.commit = self.commit_all(self.parent)
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'not a pinned regular'):
            self.identity()

    def test_missing_tracked_child_file_is_rejected(self):
        (self.child / 'data').unlink()
        with self.assertRaisesRegex(b.build.CosmicBuildError, 'inventory changed'):
            self.identity()

    def test_aggregate_limit_counts_parent_and_all_children_together(self):
        identity = self.identity()
        own = sum(item.get('bytes', 0) for name, item in identity['files'].items() if not name.startswith('child/'))
        child = sum(item.get('bytes', 0) for name, item in identity['files'].items() if name.startswith('child/'))
        with patch.object(b, 'MAX_TREE_BYTES', max(own, child)), \
             self.assertRaisesRegex(b.build.CosmicBuildError, 'Entire pinned checkout'):
            self.identity()
        with patch.object(b, 'MAX_FILE_BYTES', 8), \
             self.assertRaisesRegex(b.build.CosmicBuildError, 'blob exceeds'):
            self.identity()

    def test_recursion_depth_and_repository_count_are_bounded(self):
        with patch.object(b, 'MAX_DEPTH', 0), \
             self.assertRaisesRegex(b.build.CosmicBuildError, 'recursion exceeds'):
            self.identity()
        with patch.object(b, 'MAX_REPOSITORIES', 1), \
             self.assertRaisesRegex(b.build.CosmicBuildError, 'recursion exceeds'):
            self.identity()

    def test_gitlink_entry_kind_mode_and_duplicates_are_strict(self):
        oid = '1' * 40
        for text in ('160000 blob ' + oid + '\tchild\0',
                     '100644 commit ' + oid + '\tchild\0',
                     '160000 commit ' + oid + '\t../child\0',
                     ('160000 commit ' + oid + '\tchild\0') * 2):
            with self.subTest(text=text), self.assertRaises(ValueError):
                b.parse_tree(text)


if __name__ == '__main__':
    unittest.main()
