import struct
import unittest
from tools.check_elf import inspect_elf

def fixture(flags=5,pa=0x40200000,mem=4096):
 b=bytearray(512)
 struct.pack_into('<16sHHIQQQIHHHHHH',b,0,b'\x7fELF\x02\x01\x01'+b'\0'*9,2,183,1,0x40200000,64,0,0,64,56,1,64,0,0)
 struct.pack_into('<IIQQQQQQ',b,64,1,flags,256,pa,pa,16,mem,1)
 return bytes(b)
class ElfTests(unittest.TestCase):
 def test_valid(self):self.assertEqual(inspect_elf(fixture())['entry'],0x40200000)
 def test_truncated(self):
  with self.assertRaises(ValueError):inspect_elf(fixture()[:80])
 def test_wx(self):
  with self.assertRaises(ValueError):inspect_elf(fixture(flags=7))
 def test_dtb_cover(self):
  with self.assertRaises(ValueError):inspect_elf(fixture(pa=0x40000000))
 def test_segment_overflow(self):
  with self.assertRaises(ValueError):inspect_elf(fixture(mem=2**64-1))
 def test_nonempty_file_with_zero_memory_is_rejected(self):
  b=bytearray(fixture());struct.pack_into('<H',b,56,2)
  struct.pack_into('<IIQQQQQQ',b,120,1,7,256,0x40000000,0x40000000,16,0,1)
  with self.assertRaises(ValueError):inspect_elf(b)
