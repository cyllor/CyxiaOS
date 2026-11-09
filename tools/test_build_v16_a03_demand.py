"""Build-profile isolation tests; no compiler, private identity or VM starts."""
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
import build_v16_a03_demand as b


class DemandBuildPolicy(unittest.TestCase):
    def test_profile_drops_inherited_faults_secrets_and_collection(self):
        got = b.profile_environment({'PATH':'/toolchain', 'HOME':'/fixture',
            'CYXIA_A03_DEMAND':'off', 'CYXIA_LEARNING_COLLECTION':'coreset-data-one-pair',
            'CYXIA_STORAGE_FAULT_PROBE':'1', 'RUSTFLAGS':'-Dchanged', 'PRIVATE_KEY':'secret'})
        self.assertEqual(got, {'PATH':'/toolchain','HOME':'/fixture',
            'CYXIA_A03_DEMAND':'ordinary-rise-fall','CYXIA_LEARNING_COLLECTION':'full'})

    def test_stale_layout_and_missing_bank_refused(self):
        with patch.object(Path, 'read_bytes', return_value=b'ELF'), \
             patch.object(b, 'symbol', side_effect=lambda data, name: {'size':48 if name.endswith('LAYOUT') else 5120 if 'QUIET_MODEL' in name else 1024,'va':100}), \
             patch.object(b, 'loaded_bytes', return_value=struct.pack('<6Q',*b.LAYOUT)):
            self.assertEqual(b.elf_profile('/fixture')['words'], list(b.LAYOUT))
        for words in [(b.LAYOUT[0],1,0,*b.LAYOUT[3:]), (b.LAYOUT[0],2,*b.LAYOUT[2:])]:
            with patch.object(Path,'read_bytes',return_value=b'ELF'), \
                 patch.object(b,'symbol',return_value={'size':48,'va':100}), \
                 patch.object(b,'loaded_bytes',return_value=struct.pack('<6Q',*words)):
                with self.assertRaises(ValueError): b.elf_profile('/fixture')
        with patch.object(Path,'read_bytes',return_value=b'ELF'), \
             patch.object(b,'symbol',side_effect=lambda data,name: {'size':48 if name.endswith('LAYOUT') else 512,'va':100}), \
             patch.object(b,'loaded_bytes',return_value=struct.pack('<6Q',*b.LAYOUT)):
            with self.assertRaises(ValueError): b.elf_profile('/fixture')

    def test_reviewed_builder_closure_includes_new_entry_and_old_builder(self):
        closure = b.builder_closure()
        self.assertIn('tools/build_v16_a03_demand.py', closure)
        self.assertIn('tools/build_unified.py', closure)


if __name__ == '__main__': unittest.main()
