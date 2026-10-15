import struct
import unittest
import zlib
from tools.transport import FrameDecoder

def frame(seq,payload=b'BOOT_ENTRY',session=1):
 b=struct.pack('<4sBBHQQ',b'CYX1',1,0,len(payload),session,seq)+payload
 return b+struct.pack('<I',zlib.crc32(b))
class TransportTests(unittest.TestCase):
 def test_fragmented(self):
  d=FrameDecoder();b=frame(1);self.assertEqual(d.feed(b[:13]),[]);self.assertEqual(d.feed(b[13:]),[b'BOOT_ENTRY']);self.assertEqual(d.loss,0)
 def test_corruption_resync_and_gap(self):
  d=FrameDecoder();d.feed(frame(1));b=bytearray(frame(2));b[-1]^=1
  self.assertEqual(d.feed(b+frame(4,b'NEXT')),[b'NEXT']);self.assertEqual(d.loss,2);self.assertGreater(d.corrupt,0)
 def test_oversized_replay_and_session(self):
  d=FrameDecoder();d.feed(frame(1));self.assertEqual(d.feed(frame(1)+frame(2,session=2)),[]);self.assertGreater(d.corrupt,0)
 def test_fake_plain_text_not_accepted(self):self.assertEqual(FrameDecoder().feed(b'BOOT_ENTRY PLATFORM_OK'),[])
