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
    def record(self,kind,lsn,payload,home=0,index=0,count=0,txid=1,epoch=2):
        length=64+len(payload)
        data=bytearray((length+4095)//4096*4096)
        struct.pack_into('<IHHIIQQQQII',data,0,0x43594c47,1,kind,length,
            crc32c(payload),txid,lsn,epoch,home,index,count)
        struct.pack_into('<I',data,56,crc32c(data[:64]))
        data[64:64+len(payload)]=payload
        return data
    def append_boot_update(self,at=2,txid=1,lsn=7,epoch=2):
        with self.path.open('rb') as disk:
            disk.seek(4119*4096);image=disk.read(4096)
        self.write(at,self.record(1,lsn,struct.pack('<IIQ',1,0,4096),txid=txid,epoch=epoch))
        self.write(at+1,self.record(2,lsn+1,image,4119,0,1,txid=txid,epoch=epoch))
        digest=hashlib.sha256(struct.pack('<Q',4119)+image).digest()
        body=struct.pack('<QQQII',txid,lsn,lsn+1,1,0)+digest
        self.write(at+3,self.record(3,lsn+2,body,txid=txid,epoch=epoch))
        return body
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
        commit=self.append_boot_update()
        recovered=inspect(self.path)
        self.assertEqual(recovered['committed_transactions'],1)
        self.assertEqual(recovered['last_commit_lsn'],9)
        self.assertEqual(recovered['boot_epoch'],1)
        # Regenerate BOTH CRCs after changing the digest, so a CRC-only checker
        # would incorrectly accept this mutation.
        corrupted=bytearray(commit); corrupted[-1]^=1
        self.write(5,self.record(3,9,bytes(corrupted)))
        with self.assertRaisesRegex(ValueError,'COMMIT digest mismatch'):
            inspect(self.path)
    def test_incomplete_final_transaction_retains_the_committed_prefix(self):
        self.append_boot_update()
        self.append_boot_update(at=6,txid=2,lsn=10)
        self.write(9,bytes(4096))
        result=inspect(self.path)
        self.assertEqual((result['boot_epoch'],result['last_commit_lsn'],result['committed_transactions']),(1,9,1))
        self.assertTrue(result['discarded_tail'])
    def test_torn_final_redo_without_commit_is_discarded(self):
        self.append_boot_update()
        self.corrupt(3,100)
        self.write(5,bytes(4096))
        result=inspect(self.path)
        self.assertEqual((result['boot_epoch'],result['last_commit_lsn']),(1,6))
        self.assertTrue(result['discarded_tail'])
    def test_damaged_committed_chains_and_valid_commit_after_gap_are_rejected(self):
        for block,offset in ((2,56),(3,100),(4,0)):
            self.append_boot_update()
            self.corrupt(block,offset)
            with self.subTest(block=block),self.assertRaises(ValueError):inspect(self.path)
        self.write(2,bytes(4096))
        with self.assertRaises(ValueError):inspect(self.path)
    def test_corrupt_middle_commit_cannot_hide_a_later_commit(self):
        self.append_boot_update()
        self.append_boot_update(at=6,txid=2,lsn=10)
        self.corrupt(5,100)
        with self.assertRaises(ValueError):inspect(self.path)
    def test_old_epoch_residue_and_uncommitted_records_after_gap_are_not_replayed(self):
        self.append_boot_update(at=44,epoch=1)
        self.write(48,self.record(1,7,struct.pack('<IIQ',1,0,4096)))
        result=inspect(self.path)
        self.assertEqual((result['boot_epoch'],result['last_commit_lsn'],result['committed_transactions']),(1,6,0))
    def test_malformed_commit_counter_does_not_establish_commitment(self):
        body=self.append_boot_update()
        malformed=bytearray(body);struct.pack_into('<Q',malformed,16,99)
        self.write(5,self.record(3,9,malformed))
        result=inspect(self.path)
        self.assertEqual(result['last_commit_lsn'],6)
        self.assertTrue(result['discarded_tail'])

if __name__=='__main__':unittest.main()
