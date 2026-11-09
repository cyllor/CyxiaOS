#!/usr/bin/env python3
"""Host build-policy fixtures; this test never builds kernels or uses identities."""
import unittest
from unittest.mock import patch
import build_v16_learning_collection as b

class ProfileBuildPolicy(unittest.TestCase):
    def test_environment_is_explicit_and_nonsecret(self):
        got = b.profile_environment('coreset-one-pair', {'PATH':'/toolchain', 'HOME':'/home/fixture',
            'CYXIA_LEARNING_COLLECTION':'full', 'CYXIA_STORAGE_FAULT_PROBE':'1',
            'AWS_SECRET_ACCESS_KEY':'never', 'PRIVATE_KEY':'never', 'RUSTFLAGS':'-Dchanged',
            'CYXIA_CLUSTER_IDENTITY':'/wrong'})
        self.assertEqual(got, {'PATH':'/toolchain', 'HOME':'/home/fixture',
            'CYXIA_LEARNING_COLLECTION':'coreset-one-pair'})
        self.assertEqual(b.profile_environment('full',{})['CYXIA_LEARNING_COLLECTION'],'full')
        with self.assertRaises(Exception): b.profile_environment('arbitrary',{})
    def test_stale_elf_profile_refused(self):
        import struct
        from pathlib import Path
        with patch.object(Path,'read_bytes',return_value=b'fixture'), \
            patch.object(b,'symbol',return_value={'size':40,'va':100}), \
            patch.object(b,'loaded_bytes',return_value=struct.pack('<5Q',b.LAYOUT[0],1,0,1024,96)):
            with self.assertRaises(Exception): b.elf_profile('/host-fixture','coreset-one-pair')
            self.assertEqual(b.elf_profile('/host-fixture','full')['words'][2],0)
    def test_additive_bounded_profile_version(self):
        import struct
        from pathlib import Path
        self.assertEqual(b.PROFILES, {'full':0,'coreset-one-pair':1,'coreset-data-one-pair':2})
        with patch.object(Path,'read_bytes',return_value=b'fixture'), patch.object(b,'symbol',return_value={'size':40,'va':100}), patch.object(b,'loaded_bytes',return_value=struct.pack('<5Q',b.LAYOUT[0],2,2,1024,96)):
            self.assertEqual(b.elf_profile('/host-fixture','coreset-data-one-pair')['words'][1:3],[2,2])
            with self.assertRaises(Exception): b.elf_profile('/host-fixture','coreset-one-pair')
    def test_bad_width_and_version_refused(self):
        import struct
        from pathlib import Path
        with patch.object(Path,'read_bytes',return_value=b'fixture'), \
            patch.object(b,'symbol',return_value={'size':32,'va':100}):
            with self.assertRaises(Exception): b.elf_profile('/host-fixture','full')
        with patch.object(Path,'read_bytes',return_value=b'fixture'), \
            patch.object(b,'symbol',return_value={'size':40,'va':100}), \
            patch.object(b,'loaded_bytes',return_value=struct.pack('<5Q',b.LAYOUT[0],2,0,1024,96)):
            with self.assertRaises(Exception): b.elf_profile('/host-fixture','full')
if __name__ == '__main__': unittest.main()
