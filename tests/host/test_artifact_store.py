"""Immutable build bytes may share storage; writable disk evidence may not."""
import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))

class ArtifactStore(unittest.TestCase):
    def materialize(self,*args):
        try:module=importlib.import_module('artifact_store')
        except ModuleNotFoundError:self.fail('verified immutable artifact store missing')
        return module.materialize(*args)

    def test_reuses_verified_bytes_without_linking_original_mutable_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.write_bytes(b'ELF bytes')
            digest=hashlib.sha256(source.read_bytes()).hexdigest();cache=root/'cache'
            first,second=root/'first',root/'second'
            self.materialize(source,first,digest,cache)
            self.materialize(source,second,digest,cache)
            self.assertEqual(first.read_bytes(),b'ELF bytes')
            self.assertEqual(first.stat().st_ino,second.stat().st_ino)
            self.assertNotEqual(source.stat().st_ino,first.stat().st_ino)
            source.write_bytes(b'changed source')
            self.assertEqual(first.read_bytes(),b'ELF bytes')
            self.assertEqual(cache.stat().st_mode & 0o777,0o700)
            self.assertEqual(first.stat().st_mode & 0o222,0)

    def test_changed_source_cache_symlink_or_existing_destination_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.write_bytes(b'ELF bytes')
            digest=hashlib.sha256(source.read_bytes()).hexdigest();cache=root/'cache'
            self.materialize(source,root/'first',digest,cache)
            with self.assertRaises(ValueError):self.materialize(source,root/'first',digest,cache)
            with self.assertRaises(ValueError):self.materialize(source,root/'bad','00'*32,cache)
            blob=cache/digest;blob.chmod(0o600);blob.write_bytes(b'corrupted cached bytes')
            with self.assertRaises(ValueError):self.materialize(source,root/'second',digest,cache)
            blob.unlink();blob.symlink_to(source)
            with self.assertRaises(ValueError):self.materialize(source,root/'third',digest,cache)

    def test_default_copy_has_same_hash_without_shared_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.write_bytes(b'ELF bytes')
            digest=hashlib.sha256(source.read_bytes()).hexdigest()
            self.materialize(source,root/'copy',digest)
            self.assertEqual((root/'copy').read_bytes(),source.read_bytes())
            self.assertNotEqual((root/'copy').stat().st_ino,source.stat().st_ino)
