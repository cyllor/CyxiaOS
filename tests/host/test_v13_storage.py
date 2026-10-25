import importlib.util
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_v13_storage as storage

class StorageEvidence(unittest.TestCase):
    def fixture(self, epoch=1):
        identity=bytes(range(16)); h=[0]*512
        h[:15]=[storage.MAGIC,1,epoch,*struct.unpack('<2Q',identity),0 if epoch==1 else 1,
                0 if epoch==1 else 4,0,6 if epoch==1 else 10,epoch+1,epoch+1,4200,11,4,200]
        serial=b'SMP_BOOT_OK a=4 b=15 c=0\nSTORAGE_V13_BOOT_DURABLE\nSTORAGE_V13_READY\n'
        serial+=b''.join(f'SMP_CPU_ON a={cpu} b={cpu} c=0\n'.encode() for cpu in (1,2,3))
        return serial,struct.pack('<512Q',*h),identity
    def test_both_boots(self):
        for epoch in (1,2):
            serial,page,identity=self.fixture(epoch)
            self.assertEqual(storage.validate(serial,page,4,epoch,identity)['epoch'],epoch)
    def test_no_flush_no_recovery_wrong_epoch_and_reserved_are_rejected(self):
        serial,page,identity=self.fixture(2)
        for index in (0,2,3,5,6,8,9,10,13,15):
            changed=bytearray(page); struct.pack_into('<Q',changed,index*8,99)
            with self.subTest(index=index),self.assertRaises(ValueError):
                storage.validate(serial,changed,4,2,identity)
    def test_boot_marker_cannot_replace_native_evidence(self):
        serial,page,identity=self.fixture()
        for altered in (serial.replace(b'SMP_CPU_ON a=2 b=2 c=0\n',b''),serial+b'STORAGE_V13_READY\n',serial+b'PANIC\n'):
            with self.assertRaises(ValueError): storage.validate(altered,page,4,1,identity)
        with self.assertRaises(ValueError): storage.validate(serial,page[:-1],4,1,identity)
        with self.assertRaises(ValueError): storage.validate(serial,page,1,1,identity)

if __name__=='__main__': unittest.main()
