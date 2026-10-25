from pathlib import Path
import hashlib
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from check_v13_disk import inspect,crc32c

class BootVolume(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'disk.raw'
        with self.path.open('wb') as f:f.truncate(512*1024*1024)
        sb=bytearray(4096)
        struct.pack_into('<IHHII',sb,0,0x43594653,1,80,4096,131072)
        sb[16:32]=bytes([7])*16;struct.pack_into('<3Q5I',sb,32,2,6,2,4098,4102,4118,256,0)
        self.crc(sb,76);self.write(0,sb);self.write(1,sb)
        bitmap=bytes([255])*515+bytes(16384-515)
        for i in range(4):self.write(4098+i,bitmap[i*4096:(i+1)*4096])
        table=bytearray(65536)
        for inode in range(256):
            slot=bytearray(256);struct.pack_into('<IH',slot,0,0x4359494e,2 if inode==0 else 1 if inode==1 else 0)
            struct.pack_into('<Q',slot,8,1)
            if inode<2:
                struct.pack_into('<QQH',slot,16,128 if inode==0 else 64,1,1)
                struct.pack_into('<QIII',slot,40,1,0,4118+inode,1)
            self.crc(slot,252);table[inode*256:(inode+1)*256]=slot
        for i in range(16):self.write(4102+i,table[i*4096:(i+1)*4096])
        slot=bytearray(128);struct.pack_into('<IH',slot,0,1,11);struct.pack_into('<Q',slot,8,1);slot[16:27]=b'.cyxia-boot';self.crc(slot,124)
        self.write(4118,slot+bytes(4096-128))
        body=bytearray(4096);body[:8]=b'CYXBOOT1';body[8:24]=bytes([7])*16;struct.pack_into('<Q',body,24,1)
        struct.pack_into('<I',body,32,crc32c(body[:32]));self.write(4119,body)
    def crc(self,data,at):struct.pack_into('<I',data,at,crc32c(data))
    def write(self,block,data):
        with self.path.open('r+b') as f:f.seek(block*4096);f.write(data)
    def corrupt(self,block,at):
        with self.path.open('r+b') as f:
            f.seek(block*4096+at);b=f.read(1);f.seek(-1,1);f.write(bytes([b[0]^1]))
    def test_independent_crc_golden_and_checkpointed_boot(self):
        self.assertEqual(crc32c(b'123456789'),0xe3069283)
        result=inspect(self.path);self.assertEqual(result['boot_epoch'],1);self.assertEqual(result['last_commit_lsn'],6)
    def test_one_bad_superblock_falls_back_both_bad_reject(self):
        self.corrupt(0,32);self.assertEqual(inspect(self.path)['boot_epoch'],1)
        self.corrupt(1,32)
        with self.assertRaises(ValueError):inspect(self.path)
    def test_bitmap_inode_directory_body_corruption_rejected(self):
        for block,offset in ((4098,900),(4102,256+24),(4118,16),(4119,24)):
            self.corrupt(block,offset)
            with self.subTest(block=block),self.assertRaises(ValueError):inspect(self.path)
            self.corrupt(block,offset)
    def test_newer_superblock_requires_strict_epoch_advance(self):
        with self.path.open('rb') as f: data=bytearray(f.read(4096))
        struct.pack_into('<Q',data,32,3);data[76:80]=bytes(4);self.crc(data,76);self.write(1,data)
        with self.assertRaises(ValueError):inspect(self.path)
    def test_complete_redo_chain_checks_sha_even_with_valid_record_crcs(self):
        # The checkpoint fixture uses epoch2/checkpoint6. A one-image commit
        # may rewrite identical bytes; it still requires a complete SHA-bound log.
        with self.path.open('rb') as disk:
            disk.seek(4119*4096); image=disk.read(4096)
        def record(kind,lsn,payload,home=0,index=0,count=0):
            length=64+len(payload)
            data=bytearray((length+4095)//4096*4096)
            struct.pack_into('<IHHIIQQQQII',data,0,0x43594c47,1,kind,length,
                crc32c(payload),1,lsn,2,home,index,count)
            struct.pack_into('<I',data,56,crc32c(data[:64]))
            data[64:64+len(payload)]=payload
            return data
        self.write(2,record(1,7,struct.pack('<IIQ',1,0,4096)))
        self.write(3,record(2,8,image,4119,0,1))
        digest=hashlib.sha256(struct.pack('<Q',4119)+image).digest()
        commit=struct.pack('<QQQII',1,7,8,1,0)+digest
        self.write(5,record(3,9,commit))
        recovered=inspect(self.path)
        self.assertEqual(recovered['committed_transactions'],1)
        self.assertEqual(recovered['last_commit_lsn'],9)
        self.assertEqual(recovered['boot_epoch'],1)
        # Regenerate BOTH CRCs after changing the digest, so a CRC-only checker
        # would incorrectly accept this mutation.
        corrupted=bytearray(commit); corrupted[-1]^=1
        self.write(5,record(3,9,bytes(corrupted)))
        with self.assertRaisesRegex(ValueError,'COMMIT digest mismatch'):
            inspect(self.path)
    def test_current_epoch_record_after_gap_rejected(self):
        data=bytearray(4096);struct.pack_into('<I',data,0,0x43594c47);struct.pack_into('<Q',data,32,2);self.write(44,data)
        with self.assertRaises(ValueError):inspect(self.path)

if __name__=='__main__':unittest.main()
