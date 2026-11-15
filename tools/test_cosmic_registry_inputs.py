"""Locked archive/extraction validation; fixture bytes are not build evidence."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import cosmic_session_inputs as inputs


class RegistryOrigins(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.patch = patch.object(inputs, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.original = self.root / 'original'
        self.original.mkdir()
        registry = self.root / 'artifacts/cosmic-cargo-cache/registry'
        self.archive = registry / 'cache/index/example-1.0.0.crate'
        self.source = registry / 'src/index/example-1.0.0'
        self.archive.parent.mkdir(parents=True)
        self.source.mkdir(parents=True)
        self.contents = {'Cargo.toml': b'[package]\nname="example"\nversion="1.0.0"\n',
                         'src/lib.rs': b'pub const ANSWER: u8 = 42;\n'}
        for name, data in self.contents.items():
            p = self.source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        self.pack()

    def pack(self, extra=None):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in {**self.contents, **(extra or {})}.items():
                info = tarfile.TarInfo('example-1.0.0/' + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        files = {name: hashlib.sha256(data).hexdigest() for name, data in self.contents.items()}
        self.record = dict(package='example', version='1.0.0', checksum=digest, archive_sha256=digest,
                           path=str(self.source.relative_to(self.root)),
                           archive=str(self.archive.relative_to(self.root)),
                           source='registry+https://github.com/rust-lang/crates.io-index', files=files,
                           tree_sha256=hashlib.sha256(json.dumps(files, sort_keys=True,
                                                     separators=(',', ':')).encode()).hexdigest())
        (self.original / 'Cargo.lock').write_text(
            'version=4\n[[package]]\nname="example"\nversion="1.0.0"\n'
            f'source="{self.record["source"]}"\nchecksum="{digest}"\n')

    def validate(self):
        hashes = {}
        inputs.validate_registry_inputs({'registry_inputs': {'example': self.record}}, self.original, hashes)
        return hashes

    def test_locked_archive_and_extraction_are_both_bound(self):
        self.assertEqual(set(self.validate()), {str(self.archive), *(str(self.source / n) for n in self.contents)})
        (self.source / 'src/lib.rs').write_bytes(b'modified source')
        with self.assertRaises(ValueError): self.validate()

    def test_changed_archive_or_additional_extracted_code_is_rejected(self):
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        with self.assertRaises(ValueError): self.validate()
        self.pack()
        (self.source / 'unrecorded.rs').write_text('pub fn unrecorded() {}')
        with self.assertRaises(ValueError): self.validate()

    def test_rebound_path_escape_and_symlink_are_rejected(self):
        self.pack({'../outside.rs': b'outside'})
        with self.assertRaises(ValueError): self.validate()
        self.pack()
        target = self.source / 'src/lib.rs'
        target.unlink()
        target.symlink_to(self.source / 'Cargo.toml')
        with self.assertRaises(ValueError): self.validate()


if __name__ == '__main__':
    unittest.main()
