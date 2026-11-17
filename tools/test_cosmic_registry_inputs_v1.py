"""Pure archive/source contract tests; no registry/network/Cargo execution."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

from tools import cosmic_registry_inputs_v1 as subject


class RegistryInputs(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cache, self.stage = self.root / 'cache', self.root / 'source'
        self.stage.mkdir()
        self.source = self.cache / 'registry/src/fixture/test-crate-1.0.0'
        self.source.mkdir(parents=True)
        self.files = {'Cargo.toml': b'[package]\nname="test-crate"\nversion="1.0.0"\n',
                      'src/lib.rs': b'// complete canonical registry fixture\n', 'LICENSE': b'Fixture license\n'}
        for name, raw in self.files.items():
            selected = self.source / name
            selected.parent.mkdir(parents=True, exist_ok=True)
            selected.write_bytes(raw)
        self.archive = self.cache / 'registry/cache/fixture/test-crate-1.0.0.crate'
        self.archive.parent.mkdir(parents=True)
        self.locked = {'name': 'test-crate', 'version': '1.0.0', 'source': 'registry+https://example.invalid/index'}
        self.pack()

    def pack(self, extra=None):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as stream:
            root = tarfile.TarInfo(self.source.name + '/')
            root.type = tarfile.DIRTYPE
            root.mode = 0o755
            stream.addfile(root)
            for name, raw in self.files.items():
                entry = tarfile.TarInfo(self.source.name + '/' + name)
                entry.mode, entry.size = 0o644, len(raw)
                stream.addfile(entry, io.BytesIO(raw))
            if extra:
                extra(stream)
        self.archive.write_bytes(data.getvalue())
        self.locked['checksum'] = hashlib.sha256(data.getvalue()).hexdigest()

    def inspect(self):
        return subject.registry_identity(self.source / 'Cargo.toml', self.cache, self.locked)

    def reject(self, message='.'):
        with self.assertRaisesRegex(subject.BuildError, message):
            self.inspect()

    def test_exact_archive_complete_extraction_and_optional_metadata_are_stable(self):
        first = self.inspect()
        self.assertEqual(first, self.inspect())
        self.assertEqual(first['name'], 'test-crate')
        self.assertEqual(first['file_count'], 3)
        self.assertEqual(first['source_bytes'], sum(map(len, self.files.values())))
        sidecar = {'package': self.locked['checksum'], 'files': {name: hashlib.sha256(raw).hexdigest()
                                                               for name, raw in self.files.items()}}
        (self.source / '.cargo-checksum.json').write_text(json.dumps(sidecar))
        (self.source / '.cargo-ok').write_text('{"v":1}')
        actual = self.inspect()
        self.assertEqual(actual['files_sha256'], first['files_sha256'])
        self.assertEqual(set(actual['cargo_metadata_sha256']), {'.cargo-ok', '.cargo-checksum.json'})

    def test_metadata_packages_are_bound_to_exact_lock_checksum(self):
        lock = 'version=4\n[[package]]\n' + ''.join(key + '=' + json.dumps(value) + '\n'
                                                  for key, value in self.locked.items())
        (self.stage / 'Cargo.lock').write_text(lock)
        package = {**{key: self.locked[key] for key in ('name', 'version', 'source')},
                   'id': 'registry-test', 'manifest_path': str(self.source / 'Cargo.toml')}
        self.assertEqual(subject.registry_identities({'packages': [package]}, self.stage, self.cache),
                         {'registry-test': self.inspect()})
        (self.stage / 'Cargo.lock').write_text(lock + '\n[[package]]\n' + lock.split('[[package]]\n')[1])
        with self.assertRaisesRegex(subject.BuildError, 'Duplicate registry'):
            subject.registry_identities({'packages': [package]}, self.stage, self.cache)

    def test_archive_checksum_is_required_even_with_a_forged_source_sidecar(self):
        (self.source / '.cargo-checksum.json').write_text(json.dumps({'package': '0'*64, 'files': {}}))
        self.archive.write_bytes(self.archive.read_bytes() + b'changed archive')
        self.reject('Cargo.lock checksum')

    def test_missing_or_modified_file_cannot_pass(self):
        selected = self.source / 'src/lib.rs'
        selected.write_bytes(b'changed source')
        self.reject('differs from pinned archive')
        selected.unlink()
        self.reject()

    def test_extra_source_file_or_symlink_is_rejected(self):
        extra = self.source / 'extra.rs'
        extra.write_text('not in the archive')
        self.reject('unbound files')
        extra.unlink()
        extra.symlink_to(self.source / 'Cargo.toml')
        self.reject('Non-regular')

    def test_source_file_and_directory_symlinks_are_rejected(self):
        selected = self.source / 'src/lib.rs'
        selected.unlink()
        selected.symlink_to(self.source / 'LICENSE')
        self.reject()
        selected.unlink()
        (self.source / 'src').rmdir()
        (self.source / 'src').symlink_to(self.root)
        self.reject()

    def test_source_executable_mode_is_bound(self):
        (self.source / 'src/lib.rs').chmod(0o755)
        self.reject('executable mode')

    def test_unarchived_empty_directory_cannot_change_build_script_inputs(self):
        (self.source / 'unreviewed-build-switch').mkdir()
        self.reject('unbound files/directories')

    def test_checksum_sidecar_cannot_ignore_files_or_change_package(self):
        (self.source / '.cargo-checksum.json').write_text(json.dumps({'package': self.locked['checksum'], 'files': {}}))
        self.reject('sidecar differs')

    def test_archive_duplicate_path_is_rejected(self):
        def duplicate(stream):
            entry = tarfile.TarInfo(self.source.name + '/LICENSE')
            entry.size, entry.mode = len(self.files['LICENSE']), 0o644
            stream.addfile(entry, io.BytesIO(self.files['LICENSE']))
        self.pack(duplicate)
        self.reject('Duplicate')

    def test_archive_symlink_hardlink_and_escape_are_rejected(self):
        for kind, name in [(tarfile.SYMTYPE, 'link'), (tarfile.LNKTYPE, 'hard'), (tarfile.REGTYPE, '../escape')]:
            def extra(stream, kind=kind, name=name):
                entry = tarfile.TarInfo(self.source.name + '/' + name)
                entry.type, entry.linkname = kind, 'LICENSE'
                stream.addfile(entry)
            self.pack(extra)
            with self.subTest(kind=kind):
                self.reject()

    def test_archive_and_manifest_must_share_the_exact_registry_namespace(self):
        wrong = self.cache / 'registry/src/other' / self.source.name
        shutil.copytree(self.source, wrong)
        with self.assertRaises(subject.BuildError):
            subject.registry_identity(wrong / 'Cargo.toml', self.cache, self.locked)
        wrong_lock = copy.deepcopy(self.locked)
        wrong_lock['version'] = '2.0.0'
        with self.assertRaisesRegex(subject.BuildError, 'exact locked package'):
            subject.registry_identity(self.source / 'Cargo.toml', self.cache, wrong_lock)

    def test_bounded_compressed_and_expanded_inputs(self):
        from unittest.mock import patch
        with patch.object(subject, 'MAX_ARCHIVE', 8):
            self.reject()
        with patch.object(subject, 'MAX_TREE', 8):
            self.reject('expanded byte budget')


if __name__ == '__main__':
    unittest.main()
