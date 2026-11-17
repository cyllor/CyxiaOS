"""Font identity/publication fixtures only; fixture bytes are never rendered."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import install_cosmic_fonts_v1 as subject


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o644)
    return path


def save(path, value):
    return write(path, json.dumps(value, indent=2) + '\n')


class FontPolicyContract(unittest.TestCase):
    def test_reviewed_policy_has_exact_nine_real_assets_and_original_lock_pin(self):
        policy = subject.load_policy()
        self.assertEqual(len(policy['files']), 9)
        self.assertEqual(sum(row['bytes'] for row in policy['files'].values()), 2150905)
        self.assertEqual(policy['notification_lock']['sha256'],
                         '448b38cb6bff1447d0b4fcd3b2f5bafa0b0c72d5200174f2932887eea831953b')
        self.assertEqual(policy['notification_lock']['package']['source'],
                         'git+https://github.com/pop-os/libcosmic#' + subject.COMMIT)


@unittest.skipUnless(Path('/usr/bin/git').is_file(), 'real Git is required')
class FontInstallationContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.output = self.root / 'checkout', self.root / 'installed'
        self.lock, self.policy_path = self.root / 'notification/Cargo.lock', self.root / 'port/source-policy.json'
        self.source.mkdir()
        files = {}
        for relative in subject.SOURCES:
            raw = ('Identity contract fixture only, never a rendered font: ' + relative + '\n').encode()
            write(self.source / relative, raw)
            files[subject.destination(relative)] = {'source_relative': relative, 'mode': '100644',
                **subject.identity(raw), 'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        write(self.source / 'unrelated.rs', '// unrelated source fixture\n')
        self.git('init', '-q'); self.git('add', '.')
        self.git('-c', 'user.name=Font Test', '-c', 'user.email=fonts@example.invalid', 'commit', '-qm', 'Asset identity fixture')
        commit, tree = self.git('rev-parse', 'HEAD'), self.git('rev-parse', 'HEAD^{tree}')
        self.git('remote', 'add', 'origin', (self.root / 'cargo-git-db/libcosmic').as_uri())
        # Cargo cache markers and unrelated worktree changes are outside this asset closure.
        write(self.source / '.cargo-ok', '')
        write(self.source / 'unrelated.rs', '// changed unrelated cache source\n')
        lock_pin = {'name': 'libcosmic', 'version': '1.0.0', 'source': 'git+' + subject.REPOSITORY + '#' + commit}
        write(self.lock, 'version=4\n[[package]]\n' + ''.join(k + '=' + json.dumps(v) + '\n' for k, v in lock_pin.items()))
        self.policy = {'schema_version': 1, 'kind': 'cosmic-font-assets-v1',
                       'source': {'repository': subject.REPOSITORY, 'commit': commit, 'git_tree': tree},
                       'notification_lock': {'sha256': subject.identity(self.lock.read_bytes())['sha256'], 'package': lock_pin},
                       'files': dict(sorted(files.items()))}
        save(self.policy_path, self.policy)
        # Replace only fixture pins. All production filesystem/Git validators run.
        for name, value in (('COMMIT', commit), ('GIT_TREE', tree),
                            ('POLICY_SHA256', subject.identity(self.policy_path.read_bytes())['sha256'])):
            patcher = mock.patch.object(subject, name, value)
            patcher.start(); self.addCleanup(patcher.stop)

    def git(self, *args):
        result = subprocess.run(['/usr/bin/git', '-C', str(self.source), *args],
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
                                     'GIT_CONFIG_GLOBAL': os.devnull},
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()

    def install(self, output=None):
        return subject.install(output or self.output, checkout=self.source,
                               notification_lock=self.lock, policy_path=self.policy_path)

    def test_atomic_install_accepts_cargo_file_origin_and_retains_all_nine_files(self):
        self.assertTrue(self.git('remote', 'get-url', 'origin').startswith('file://'))
        original_run, original_rename = subprocess.run, Path.rename
        publications = []
        def only_git(command, *args, **kwargs):
            self.assertEqual(command[0], '/usr/bin/git')
            self.assertIn('--no-replace-objects', command)
            self.assertNotIn('GIT_DIR', kwargs['env'])
            return original_run(command, *args, **kwargs)
        def publish(source, target):
            self.assertEqual(target, self.output)
            self.assertFalse(target.exists())
            self.assertEqual(len(subject.validate_inputs(source)['files']), 9)
            publications.append(source)
            return original_rename(source, target)
        with mock.patch.object(subprocess, 'run', side_effect=only_git), \
             mock.patch.dict(os.environ, {'GIT_DIR': '/malicious/ignored', 'GIT_CONFIG_COUNT': '999'}), \
             mock.patch.object(Path, 'rename', publish):
            report = self.install()
        self.assertEqual(len(publications), 1)
        self.assertEqual(report['status'], 'ASSETS_INSTALLED_NOT_RUN')
        self.assertIs(report['guest_font_loading_observed'], False)
        self.assertEqual(subject.validate_inputs(self.output), report)
        for guest, row in report['files'].items():
            self.assertEqual((self.output / 'rootfs' / guest.lstrip('/')).read_bytes(), Path(row['source']).read_bytes())

    def test_source_content_mode_head_and_git_replacement_are_rejected(self):
        path = self.source / subject.SOURCES[0]; raw = path.read_bytes()
        path.write_bytes(raw + b'changed')
        with self.assertRaisesRegex(ValueError, 'content differs'): self.install()
        path.write_bytes(raw); path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'mode changed'): self.install()
        path.chmod(0o644); path.write_bytes(raw + b'changed')
        original_commit, original_tree = subject.COMMIT, subject.GIT_TREE
        self.git('add', '.')
        self.git('-c', 'user.name=Font Test', '-c', 'user.email=fonts@example.invalid', 'commit', '-qm', 'Changed fixture')
        replacement = self.git('rev-parse', 'HEAD^{tree}')
        with self.assertRaisesRegex(ValueError, 'HEAD or canonical tree'): self.install()
        self.git('reset', '--mixed', original_commit)
        self.git('replace', original_tree, replacement)
        self.assertEqual(self.git('rev-parse', 'HEAD'), original_commit)
        self.assertNotEqual(self.git('ls-tree', 'HEAD', '--', subject.SOURCES[0]),
                            subject.git_bytes(self.source, 'ls-tree', 'HEAD', '--', subject.SOURCES[0]).decode().strip())
        with self.assertRaisesRegex(ValueError, 'content differs'): self.install()
        self.assertFalse(self.output.exists())

    def test_original_lock_policy_and_full_pin_cannot_be_replaced(self):
        data = self.lock.read_bytes(); self.lock.write_bytes(data.replace(b'github.com', b'example.invalid'))
        with self.assertRaisesRegex(ValueError, 'Cargo.lock changed'): self.install()
        self.lock.write_bytes(data)
        original = self.policy_path.read_bytes()
        changed = copy.deepcopy(self.policy); changed['files'].pop(next(iter(changed['files'])))
        save(self.policy_path, changed)
        with self.assertRaisesRegex(ValueError, 'Unreviewed'): self.install()
        self.policy_path.write_bytes(original)
        # Even a deliberately re-pinned test policy cannot omit the full repository+commit source pin.
        changed = copy.deepcopy(self.policy)
        changed['notification_lock']['package']['source'] = subject.COMMIT
        save(self.policy_path, changed)
        with mock.patch.object(subject, 'POLICY_SHA256', subject.identity(self.policy_path.read_bytes())['sha256']):
            with self.assertRaisesRegex(ValueError, 'complete notification lock pin'): self.install()

    def test_alias_overlap_and_existing_output_are_rejected_without_overwriting(self):
        path = self.source / subject.SOURCES[0]; data = path.read_bytes()
        other = write(self.root / 'aliased-input', data); path.unlink(); path.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'aliases'): self.install()
        path.unlink(); write(path, data)
        with self.assertRaisesRegex(ValueError, 'overlaps'): self.install(self.source / 'output')
        self.output.mkdir(); marker = write(self.output / 'keep', 'original')
        with self.assertRaisesRegex(ValueError, 'Preserving existing'): self.install()
        self.assertEqual(marker.read_text(), 'original')

    def test_source_changed_after_copy_prevents_atomic_publication(self):
        last = self.source / list(self.policy['files'].values())[-1]['source_relative']
        first = self.source / list(self.policy['files'].values())[0]['source_relative']
        original_read = subject.read_regular
        reads = []
        def mutate_after_copy(path, *args, **kwargs):
            data = original_read(path, *args, **kwargs)
            if Path(path) == last:
                reads.append(True)
                if len(reads) == 2: write(first, b'changed after staging began')
            return data
        with mock.patch.object(subject, 'read_regular', side_effect=mutate_after_copy):
            with self.assertRaisesRegex(ValueError, 'content differs'): self.install()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.installed-*')))

    def test_installed_license_bytes_modes_and_receipt_are_rechecked(self):
        report = self.install()
        receipt = self.output / subject.RECEIPT
        wrong = copy.deepcopy(report); wrong['guest_font_loading_observed'] = True; save(receipt, wrong)
        with self.assertRaisesRegex(ValueError, 'receipt'): subject.validate_inputs(self.output)
        save(receipt, report)
        license_path = self.output / 'rootfs/usr/share/licenses/cosmic-fonts/OpenSans-LICENSE'
        data = license_path.read_bytes(); license_path.write_bytes(data + b'changed')
        with self.assertRaisesRegex(ValueError, 'Installed font/license'): subject.validate_inputs(self.output)
        license_path.write_bytes(data); license_path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'Installed font/license'): subject.validate_inputs(self.output)
        license_path.chmod(0o644)
        wrong = copy.deepcopy(report); wrong['producers'] = {}; save(receipt, wrong)
        with self.assertRaisesRegex(ValueError, 'installer identity'): subject.validate_inputs(self.output)


if __name__ == '__main__':
    unittest.main()
