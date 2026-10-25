import struct
import unittest
from tools.check_elf import inspect_elf, boot_profile, symbol

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

class BootProfileTests(unittest.TestCase):
 def image(self, version=1, ram=512, heap=4096, size=24, backed=True):
  b=bytearray(fixture())+bytearray(512)
  struct.pack_into('<Q', b, 40, 512)
  struct.pack_into('<H', b, 60, 3)
  struct.pack_into('<Q', b, 64+32, 32 if backed else 16)
  struct.pack_into('<QQQ', b, 264, version, ram, heap)
  struct.pack_into('<IIQQQQIIQQ', b, 576, 0, 2, 0, 0, 800, 24, 2, 0, 8, 24)
  name=b'\0CYXIA_BOOT_PROFILE\0'
  struct.pack_into('<IIQQQQIIQQ', b, 640, 0, 3, 0, 0, 900, len(name), 0, 0, 1, 0)
  struct.pack_into('<IBBHQQ', b, 800, 1, 0x11, 0, 1, 0x40200008, size)
  b[900:900+len(name)]=name
  return b
 def test_legacy_and_explicit_profiles(self):
  self.assertEqual(boot_profile(fixture()), dict(version=0, ram_mib=256, heap_pages=2048))
  self.assertEqual(boot_profile(self.image()), dict(version=1, ram_mib=512, heap_pages=4096))
  self.assertEqual(boot_profile(self.image(ram=256,heap=2048))['ram_mib'],256)
 def test_native_prototype_profile(self):
  self.assertEqual(boot_profile(self.image(ram=1024,heap=2048)),
                   dict(version=1,ram_mib=1024,heap_pages=2048))
 def test_unsupported_or_unbacked_profile_rejected(self):
  for options in ({'version':2}, {'ram':256}, {'heap':2048}, {'size':16}, {'backed':False}):
   with self.subTest(options=options), self.assertRaises(ValueError):
    boot_profile(self.image(**options))
 def test_malformed_symbol_tables_fail_with_value_error(self):
  changes=[(576+40,'<I',3), (576+56,'<Q',16), (576+32,'<Q',25),
           (576+24,'<Q',1020), (800,'<I',1000), (640+4,'<I',1)]
  for offset,encoding,value in changes:
   b=self.image();struct.pack_into(encoding,b,offset,value)
   with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):
    symbol(b,'CYXIA_BOOT_PROFILE')
  for length in range(64):
   with self.assertRaises(ValueError):symbol(bytes(length),'CYXIA_BOOT_PROFILE')
