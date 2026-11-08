"""Negative A09 raw-memory contract; fixtures never prove native execution."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from doctor import ROOT
from verify_v15_memory import MAGIC,WORDS,PAGES,PRIVATE_VAS,pattern,verify_raw


def fixture():
    config=[0]*64;config[4:18]=range(1,15)
    captures={};banks=[]
    pte=lambda pa,write,execute:pa|3|(1<<6)|(1<<10)|(1<<11)|(3<<8)|(1<<53)|(0 if write else 1<<7)|(0 if execute else 1<<54)
    for stage in (1,2,3):
        w=[0]*WORDS;w[:8]=[MAGIC,1,2,7,stage,2,0,0];w[8:22]=config[4:18]
        w[22:30]=[0x42000000,4096,stage*20,stage*10000,stage*PAGES*4096,62500000,stage*1000000000,0]
        for role in (1,2):
            b=64+(role-1)*192;root=0x41000000+(role-1)*0x100000;mid=root+4096;leaf=root+8192
            captures[f'{stage}-{role}-table-addresses']=[root,mid,leaf]
            w[b:b+8]=[role+10,1,role,root,1,4,0,0]
            table=[0]*512;table[0]=mid|3;captures[f'{stage}-{role}-root.bin']=struct.pack('<512Q',*table)
            table[0]=leaf|3;captures[f'{stage}-{role}-mid.bin']=struct.pack('<512Q',*table)
            table=[0]*512
            for page in range(4):table[16+page]=pte(0x40600000+page*4096,False,True)
            for page,va in enumerate(PRIVATE_VAS):
                pa=root+0x10000+page*4096;table[va//4096]=pte(pa,va!=0x72000,False)
                if page<4:data=bytes(4096) if stage==1 else struct.pack('<512Q',*(pattern(config[4:6],role,page,k) for k in range(512)))
                elif page==6:
                    progress=[0]*512;progress[:7]=[0x435958413039434c,role,stage,0,2560,0 if stage==1 else 1,PAGES if stage==3 and role==1 else 0]
                    data=struct.pack('<512Q',*progress)
                else:data=bytes(4096)
                captures[f'{stage}-{role}-page{page}.bin']=data
            captures[f'{stage}-{role}-leaf.bin']=struct.pack('<512Q',*table)
            for s in range(1,stage+1):
                at=b+32+(s-1)*48
                w[at:at+16]=[2,s*1000000000,s,0,2560,0 if s==1 else 1,PAGES if s==3 and role==1 else 0,
                    s*20,s*20,40,500,0,0,0,18,32]
                w[at+16:at+23]=[table[va//4096] for va in PRIVATE_VAS]
                w[at+24:at+28]=table[16:20]
                w[at+28:at+35]=[table[va//4096]&0x0000fffffffff000 for va in PRIVATE_VAS]
        banks.append(struct.pack('<%dQ'%WORDS,*w))
    return banks,captures,struct.pack('<64Q',*config)


class MemoryContract(unittest.TestCase):
    def test_raw_structure_still_not_native(self):
        banks,captures,config=fixture();r=verify_raw(banks,captures,config)
        self.assertEqual(r['native_acceptance_status'],'NOT_RUN')
        self.assertFalse(r['full_a09_verified'])
        self.assertFalse(r['actual_cache_pressure_verified'])

    def test_alias_mutation_or_content_loss_is_rejected(self):
        banks,captures,config=fixture()
        for name in ('1-1-page0.bin','3-2-page3.bin'):
            changed=copy.copy(captures);changed[name]=b'X'+changed[name][1:]
            with self.subTest(name=name),self.assertRaises(ValueError):verify_raw(banks,changed,config)

    def test_permissions_and_cross_owner_root_are_verified_from_actual_tables(self):
        banks,captures,config=fixture()
        changed=copy.copy(captures);p=bytearray(changed['2-1-leaf.bin']);v=struct.unpack_from('<Q',p,0x60*8)[0];struct.pack_into('<Q',p,0x60*8,v&~(1<<54));changed['2-1-leaf.bin']=bytes(p)
        with self.assertRaises(ValueError):verify_raw(banks,changed,config)
        changed=copy.copy(captures);changed['3-2-root.bin']=changed['3-1-root.bin']
        with self.assertRaises(ValueError):verify_raw(banks,changed,config)

    def test_no_actual_eviction_or_missing_stage_is_not_pressure(self):
        banks,captures,config=fixture();w=list(struct.unpack('<%dQ'%WORDS,banks[2]));w[24]=40
        changed=banks[:2]+[struct.pack('<%dQ'%WORDS,*w)]
        with self.assertRaises(ValueError):verify_raw(changed,captures,config)
        with self.assertRaises(ValueError):verify_raw(banks[1:],captures,config)

    def test_wrong_owner_metadata_identity_or_readonly_bytes_is_rejected(self):
        banks,captures,config=fixture()
        for index in (8,64+32+28,64+192+1):
            changed=banks.copy();words=list(struct.unpack('<%dQ'%WORDS,changed[2]));words[index]^=1;changed[2]=struct.pack('<%dQ'%WORDS,*words)
            with self.subTest(index=index),self.assertRaises(ValueError):verify_raw(changed,captures,config)
        changed=copy.copy(captures);changed['3-1-page4.bin']=b'X'+bytes(4095)
        with self.assertRaises(ValueError):verify_raw(banks,changed,config)

    def test_other_private_mapping_cannot_alias_immutable_client_code(self):
        banks,captures,config=fixture();changed=copy.copy(captures)
        for stage in (1,2,3):
            name=f'{stage}-1-leaf.bin';leaf=list(struct.unpack('<512Q',changed[name]))
            code_pa=leaf[16]&0x0000fffffffff000
            from verify_v15_memory import leaf_value
            leaf[0x40]=leaf_value(code_pa,True,False)
            changed[name]=struct.pack('<512Q',*leaf)
        with self.assertRaises(ValueError):verify_raw(banks,changed,config)

    def test_actual_private_page_tables_cannot_use_file_cache_backing(self):
        banks,captures,config=fixture();changed=copy.copy(captures);mutated=[]
        for stage,bank in enumerate(banks,1):
            words=list(struct.unpack('<%dQ'%WORDS,bank));root=words[22];mid=root+4096;leaf=root+8192
            words[64+3]=root;mutated.append(struct.pack('<%dQ'%WORDS,*words))
            changed[f'{stage}-1-table-addresses']=[root,mid,leaf]
            for name,address in [('root',mid),('mid',leaf)]:
                table=[0]*512;table[0]=address|3
                changed[f'{stage}-1-{name}.bin']=struct.pack('<512Q',*table)
        with self.assertRaises(ValueError):verify_raw(mutated,changed,config)

    def test_physical_client_progress_must_confirm_all_4097_pages(self):
        banks,captures,config=fixture();changed=copy.copy(captures)
        data=bytearray(changed['3-1-page6.bin']);struct.pack_into('<Q',data,6*8,4096)
        changed['3-1-page6.bin']=bytes(data)
        with self.assertRaises(ValueError):verify_raw(banks,changed,config)

    def test_producer_pass_scope_cannot_replace_complete_native_custody(self):
        from memory_v15_custody import verify_native
        from check_prototype_evidence import sha256
        with tempfile.TemporaryDirectory(prefix='cyx-a09-incomplete-') as temp:
            root=Path(temp);summary=root/'summary.json'
            summary.write_text(json.dumps(dict(status='PASS',test_id='A09',full_a09_verified=True,
                native_execution_verified=True,actual_cache_pressure_verified=True,scope='A09')))
            (root/'inventory.json').write_text(json.dumps(dict(schema=1,files={'summary.json':dict(bytes=summary.stat().st_size,sha256=sha256(summary))})))
            # Isolate the downstream custody gate; this mock does not create a
            # successful native receipt or bypass any gate in the real runner.
            with patch('memory_v15_custody.verify_build',return_value=({}, {}, bytes(16384))):
                with self.assertRaisesRegex(ValueError,'incomplete A09 inventory'):
                    verify_native(root,build=root,source_root=ROOT,qemu_source=root)


if __name__=='__main__':unittest.main()
