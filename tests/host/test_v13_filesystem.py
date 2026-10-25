import hashlib
import importlib
import struct
import unittest
from tests.host import test_v13_disk


class OrdinaryVolume(unittest.TestCase):
    def setUp(self):
        self.fixture=test_v13_disk.BootVolume()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.path=self.fixture.path
        self.inode(0,2,512,2,0,4118)
        self.inode(4,2,128,1,0,8216)
        self.inode(5,1,4096,2,4,8217)
        root=bytearray(self.read(4118))
        root[128:256]=root[256:384]=self.entry(0xffffffff,'',generation=0)
        root[384:512]=self.entry(4,'a10');self.fixture.write(4118,root)
        self.fixture.write(8216,self.entry(5,'value')+bytes(3968))
        self.fixture.write(8217,bytes([2])*4096)
        bitmap=bytearray(self.read(4098));bitmap[1027]|=3;self.fixture.write(4098,bitmap)

    def read(self,block):
        with self.path.open('rb') as stream:
            stream.seek(block*4096);return stream.read(4096)

    def inode(self,identity,kind,size,sequence,parent,start):
        slot=bytearray(256)
        struct.pack_into('<IH',slot,0,0x4359494e,kind)
        struct.pack_into('<QQQH',slot,8,1,size,sequence,int(size>0))
        struct.pack_into('<IQ',slot,36,parent,1)
        if size:
            struct.pack_into('<III',slot,48,0,start,(size+4095)//4096)
        self.fixture.crc(slot,252)
        block=4102+identity//16;table=bytearray(self.read(block));at=(identity%16)*256
        table[at:at+256]=slot;self.fixture.write(block,table)

    def entry(self,identity,name,generation=1):
        slot=bytearray(128);name=name.encode()
        struct.pack_into('<IH',slot,0,identity,len(name));struct.pack_into('<Q',slot,8,generation)
        slot[16:16+len(name)]=name;self.fixture.crc(slot,124)
        return slot

    def inspect(self):
        try:
            module=importlib.import_module('check_v13_filesystem')
        except ModuleNotFoundError as error:
            if error.name!='check_v13_filesystem':raise
            self.fail('ordinary filesystem independent decoder is missing')
        return module.inspect(self.path)

    def test_valid_ordinary_file_preserves_identity_durable_sequence_and_bytes(self):
        result=self.inspect()
        value=result['files']['/a10/value']
        self.assertEqual((value['inode'],value['generation'],value['size'],value['durable_write_seq']),(5,1,4096,2))
        self.assertEqual(value['sha256'],hashlib.sha256(bytes([2])*4096).hexdigest())
        self.assertEqual(result['last_commit_lsn'],6)

    def test_missing_allocation_duplicate_ownership_and_orphan_inode_fail(self):
        self.fixture.corrupt(4098,1027)
        with self.assertRaisesRegex(ValueError,'allocation'):self.inspect()
        self.fixture.corrupt(4098,1027)
        self.inode(5,1,4096,2,4,8216)
        with self.assertRaisesRegex(ValueError,'ownership'):self.inspect()
        self.inode(5,1,4096,2,4,8217)
        self.inode(6,1,0,0,0,0)
        with self.assertRaisesRegex(ValueError,'reference'):self.inspect()

    def test_stale_directory_reference_and_duplicate_names_fail(self):
        self.fixture.write(8216,self.entry(5,'value',generation=2)+bytes(3968))
        with self.assertRaisesRegex(ValueError,'directory reference'):self.inspect()
        self.fixture.write(8216,self.entry(5,'value')+bytes(3968))
        root=bytearray(self.read(4118));root[384:512]=self.entry(4,'.cyxia-boot');self.fixture.write(4118,root)
        with self.assertRaisesRegex(ValueError,'duplicate directory name'):self.inspect()

    def append_version(self,block,txid,begin,version,commit=True):
        image=bytes([version])*4096
        table=bytearray(self.read(4102));slot=bytearray(table[5*256:6*256])
        struct.pack_into('<Q',slot,24,version);slot[252:]=bytes(4);self.fixture.crc(slot,252)
        table[5*256:6*256]=slot
        self.fixture.write(block,self.fixture.record(1,begin,struct.pack('<IIQ',2,0,8192),txid=txid))
        digest=hashlib.sha256()
        for index,(home,data) in enumerate(((8217,image),(4102,table))):
            self.fixture.write(block+1+2*index,self.fixture.record(2,begin+1+index,data,home,index,2,txid=txid))
            digest.update(struct.pack('<Q',home)+data)
        if commit:
            body=struct.pack('<QQQII',txid,begin,begin+2,2,0)+digest.digest()
            self.fixture.write(block+5,self.fixture.record(3,begin+3,body,txid=txid))

    def test_same_home_uses_highest_committed_lsn_and_ignores_incomplete_suffix(self):
        self.append_version(2,1,7,3)
        self.append_version(8,2,11,4)
        self.append_version(14,3,15,5,commit=False)
        result=self.inspect()
        value=result['files']['/a10/value']
        self.assertEqual((result['last_commit_lsn'],result['committed_transactions'],result['replayed_blocks']),(14,2,2))
        self.assertEqual(value['durable_write_seq'],4)
        self.assertEqual(value['sha256'],hashlib.sha256(bytes([4])*4096).hexdigest())
        self.assertTrue(result['discarded_tail'])


if __name__=='__main__':unittest.main()
