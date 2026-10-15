"""Validate frames before interpreting guest success markers."""
import struct
import zlib
class FrameDecoder:
 def __init__(self):self.buffer=b'';self.last=0;self.session=None;self.loss=0;self.corrupt=0;self.frames=0
 def feed(self,data):
  self.buffer+=data;out=[]
  if len(self.buffer)>2*1024*1024:raise ValueError('transport buffer limit')
  while len(self.buffer)>=4:
   pos=self.buffer.find(b'CYX1')
   if pos<0:self.corrupt+=len(self.buffer)-3;self.buffer=self.buffer[-3:];break
   if pos:self.corrupt+=pos;self.buffer=self.buffer[pos:]
   if len(self.buffer)<24:break
   _,version,cpu,length,session,seq=struct.unpack_from('<4sBBHQQ',self.buffer)
   if version!=1 or cpu!=0 or length>96 or session==0 or seq==0:
    self.corrupt+=1;self.buffer=self.buffer[1:];continue
   size=28+length
   if len(self.buffer)<size:break
   b=self.buffer[:size]
   if zlib.crc32(b[:-4])!=struct.unpack_from('<I',b,size-4)[0]:
    self.corrupt+=1;self.buffer=self.buffer[1:];continue
   self.buffer=self.buffer[size:]
   if self.session is not None and (session!=self.session or seq<=self.last):self.corrupt+=1;continue
   self.session=session;self.loss+=seq-self.last-1;self.last=seq;self.frames+=1;out.append(b[24:-4])
  return out
