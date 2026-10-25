from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import test_v13_disk as boot_fixture
from check_v13_disk import inspect,crc32c


class ClusterVolume(unittest.TestCase):
    def setUp(self):
        self.fixture=boot_fixture.BootVolume()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.path=self.fixture.path
    def read(self,block,count=1):
        with self.path.open('rb') as f:
            f.seek(block*4096)
            return bytearray(f.read(count*4096))
    def crc(self,data,at):
        data[at:at+4]=bytes(4)
        struct.pack_into('<I',data,at,crc32c(data))
    def provision(self,two=True):
        records=[b'CXID1'+bytes([7])*16+bytes([8])*32+bytes([9])*32,b'CXE1'+(1).to_bytes(8,'little')+b'\x01'+bytes(48)]
        table=self.read(4102,16)
        root_size=384 if two else 256
        struct.pack_into('<QQ',table,16,root_size,root_size//128)
        root=bytearray(table[:256]);self.crc(root,252);table[:256]=root
        directory=self.read(4118)
        bitmap=self.read(4098,4)
        for file in range(2 if two else 1):
            bodies=records if file==0 else [b'a'*5000]
            stream=bytearray()
            for body in bodies:
                header=bytearray(b'CXV1'+struct.pack('<II',len(body),crc32c(body))+bytes(4))
                struct.pack_into('<I',header,12,crc32c(header[:12]));stream+=header+body
            inode=bytearray(256);struct.pack_into('<IH',inode,0,0x4359494e,1);struct.pack_into('<Q',inode,8,1)
            blocks=(len(stream)+4095)//4096
            struct.pack_into('<QQH',inode,16,len(stream),len(bodies),1)
            struct.pack_into('<QIII',inode,40,1,0,4120+file*2048,blocks);self.crc(inode,252)
            table[(file+2)*256:(file+3)*256]=inode
            entry=bytearray(128);name=f'.cyxia-cluster-{chr(97+file)}'.encode()
            struct.pack_into('<IH',entry,0,file+2,len(name));struct.pack_into('<Q',entry,8,1);entry[16:16+len(name)]=name;self.crc(entry,124)
            directory[(file+1)*128:(file+2)*128]=entry
            for block in range(4120+file*2048,4120+file*2048+blocks):bitmap[block//8]|=1<<(block%8)
            self.fixture.write(4120+file*2048,stream+bytes(blocks*4096-len(stream)))
        self.fixture.write(4102,table);self.fixture.write(4118,directory);self.fixture.write(4098,bitmap)
        return records+([b'a'*5000] if two else [])
    def test_one_and_two_reserved_files_decode_exact_records(self):
        expected=self.provision(False)
        self.assertEqual(inspect(self.path)['cluster_records'],[b.hex() for b in expected])
        # Add second file via fresh fixture to preserve the first stream.
        expected=self.provision(True)
        self.assertEqual(inspect(self.path)['cluster_records'],[b.hex() for b in expected])
    def test_body_and_header_crc_tamper_rejected(self):
        self.provision()
        for offset in (8,16,140):
            self.fixture.corrupt(4120,offset)
            with self.subTest(offset=offset),self.assertRaises(ValueError):inspect(self.path)
            self.fixture.corrupt(4120,offset)
    def test_allocated_prefix_and_entire_unused_suffix_must_be_zero(self):
        self.provision()
        self.fixture.corrupt(4098,900)
        with self.assertRaises(ValueError):inspect(self.path)
        self.fixture.corrupt(4098,900)
        self.fixture.corrupt(4123,1)
        with self.assertRaisesRegex(ValueError,'suffix'):inspect(self.path)
    def test_no_other_live_inode_even_with_valid_crc(self):
        self.provision()
        block=self.read(4102);slot=bytearray(block[4*256:5*256]);struct.pack_into('<H',slot,4,1);self.crc(slot,252);block[4*256:5*256]=slot;self.fixture.write(4102,block)
        with self.assertRaises(ValueError):inspect(self.path)


if __name__=='__main__':unittest.main()
