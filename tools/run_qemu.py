"""Bounded QMP runner; cleanup only the subprocess this invocation owns."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import struct
import tempfile
import time
try:from .doctor import ROOT,env
except ImportError:from doctor import ROOT,env
try:from .transport import FrameDecoder
except ImportError:from transport import FrameDecoder
CASES={'boot-entry':['BOOT_ENTRY','PLATFORM_OK'],'pages':['PAGE_SELFTEST_OK'],'mmu':['HIGH_VA_OK','IDENTITY_UNMAPPED','WX_SELFTEST_OK'],'timer':['MMU_TIMER_OK','IRQ_SELFTEST_OK'],'all':['BOOT_ENTRY','PLATFORM_OK','PAGE_SELFTEST_OK','HIGH_VA_OK','IDENTITY_UNMAPPED','WX_SELFTEST_OK','MMU_TIMER_OK','IRQ_SELFTEST_OK']}
CASES['pressure']=CASES['all']

def validate_progress(before,after):
 if before[0]!=0x43595850524f4731 or after[0]!=before[0] or before[5]!=1 or after[5]!=1:raise ValueError('invalid progress page')
 if after[1]<=before[1] or after[2]<=before[2]:raise ValueError('guest did not advance')
 if after[3]-before[3]<=2*1048576:raise ValueError('backend not filled twice')
 return True

def pressure(qmp,elf,output,deadline):
 try:from .check_elf import symbol
 except ImportError:from check_elf import symbol
 location=symbol(elf.read_bytes(),'TEST_PROGRESS');pa=location['pa']
 if pa%4096 or location['size']!=4096:raise ValueError('invalid progress symbol')
 def snapshot(name):
  qmp.execute('stop')
  try:qmp.execute('pmemsave',{'val':pa,'size':4096,'filename':str((output/name).resolve())})
  finally:qmp.execute('cont')
  return struct.unpack_from('<6Q',(output/name).read_bytes())
 before=snapshot('progress-before.bin')
 while time.monotonic()<deadline:
  time.sleep(.1);after=snapshot('progress-after.bin')
  if after[3]-before[3]>2*1048576:
   validate_progress(before,after);return {'before':before,'after':after,'physical_address':pa}
 raise TimeoutError('pressure scenario made insufficient progress')

class JsonLines:
 def __init__(self):self.buffer=b''
 def feed(self,data):
  self.buffer+=data
  if len(self.buffer)>4*1024*1024:raise ValueError('QMP frame too large')
  out=[]
  while b'\n' in self.buffer:
   line,self.buffer=self.buffer.split(b'\n',1)
   if line.strip():
    value=json.loads(line)
    if not isinstance(value,dict):raise ValueError('QMP object required')
    out.append(value)
  return out
class Qmp:
 def __init__(self,sock):self.sock=sock;self.lines=JsonLines();self.pending=[];self.seq=0;self.transcript=[]
 def receive(self,deadline):
  while not self.pending:
   left=deadline-time.monotonic()
   if left<=0:raise TimeoutError('QMP response timeout')
   self.sock.settimeout(min(1,left))
   try:data=self.sock.recv(65536)
   except socket.timeout:continue
   if not data:raise RuntimeError('QMP disconnected')
   messages=self.lines.feed(data)
   self.transcript.extend({'direction':'receive','message':m} for m in messages)
   self.pending+=messages
  return self.pending.pop(0)
 def execute(self,command,args=None):
  self.seq+=1;ident=self.seq;msg={'execute':command,'id':ident}
  if args is not None:msg['arguments']=args
  self.transcript.append({'direction':'send','message':msg})
  self.sock.sendall(json.dumps(msg).encode()+b'\n');deadline=time.monotonic()+5
  while True:
   response=self.receive(deadline)
   if response.get('id')!=ident:continue
   if 'error' in response:raise RuntimeError(response['error'])
   return response['return']
def required_markers(data,case):
 return b'FAIL' not in data and all(any(line.startswith(x.encode()+b' ') or line==x.encode() for line in data.splitlines()) for x in CASES[case])
def run(elf,case='all',output=None,timeout=30):
 elf=Path(elf).resolve();output=Path(output or ROOT/'artifacts'/('run-'+str(time.time_ns())));output.mkdir(parents=True,exist_ok=True)
 result={'case':case,'status':'FAIL','timeout_seconds':timeout,'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest()};data=bytearray();decoded=bytearray();decoder=FrameDecoder();proc=None;sock=None;qmp=None
 # macOS Unix socket names have a short fixed length. Keep sockets out of long project paths.
 with tempfile.TemporaryDirectory(prefix='cyx-') as td, (output/'qemu-stderr.log').open('wb') as err:
  path=str(Path(td)/'q.sock')
  args=[shutil.which('qemu-system-aarch64',path=env()['PATH']),'-machine','virt-10.2,gic-version=2,secure=off,virtualization=off','-cpu','cortex-a53','-smp','1','-m','256M','-accel','tcg','-display','none','-monitor','none','-nic','none','-chardev','ringbuf,id=cyxlog,size=1048576','-serial','chardev:cyxlog','-qmp',f'unix:{path},server=on,wait=off','-kernel',str(elf),'-no-reboot']
  result['argv']=args
  try:
   proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=err,env=env());deadline=time.monotonic()+timeout
   sock=socket.socket(socket.AF_UNIX)
   while True:
    try:sock.connect(path);break
    except (FileNotFoundError,ConnectionRefusedError):
     if proc.poll() is not None:raise RuntimeError('QEMU exited before QMP')
     if time.monotonic()>deadline:raise TimeoutError('QMP startup')
     time.sleep(.01)
   qmp=Qmp(sock)
   if 'QMP' not in qmp.receive(deadline):raise RuntimeError('missing QMP greeting')
   qmp.execute('qmp_capabilities')
   while time.monotonic()<deadline:
    chunk=qmp.execute('ringbuf-read',{'device':'cyxlog','size':65536,'format':'base64'});raw=base64.b64decode(chunk,validate=True);data.extend(raw)
    for payload in decoder.feed(raw):decoded.extend(payload+b'\n')
    if len(data)>8*1024*1024:raise ValueError('serial capture limit')
    if b'FAIL' in decoded:raise RuntimeError('guest selftest failed')
    if required_markers(decoded,case):
     if case=='pressure':
      result['progress']=pressure(qmp,elf,output,deadline)
      chunk=qmp.execute('ringbuf-read',{'device':'cyxlog','size':1048576,'format':'base64'});raw=base64.b64decode(chunk,validate=True);data.extend(raw)
      for payload in decoder.feed(raw):decoded.extend(payload+b'\n')
      if b'FAIL' in decoded:raise RuntimeError('guest selftest failed in final pressure capture')
      if decoder.loss==0:raise ValueError('expected transport loss after overwrite')
     result['status']='PASS';break
    if proc.poll() is not None:raise RuntimeError('guest exited')
    time.sleep(.01)
   else:raise TimeoutError('required guest markers missing')
  except Exception as e:result['error']=str(e)
  finally:
   if proc is not None:
    if proc.poll() is None:
     try:
      if qmp:qmp.execute('quit')
     except Exception:pass
     try:proc.wait(timeout=2)
     except subprocess.TimeoutExpired:proc.terminate()
     try:proc.wait(timeout=2)
     except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
    result['qemu_exit']=proc.returncode
   if sock:sock.close()
   if qmp:(output/'qmp.jsonl').write_text(''.join(json.dumps(m)+'\n' for m in qmp.transcript))
 (output/'serial.txt').write_bytes(decoded);result['transport']={'frames':decoder.frames,'lost_records':decoder.loss,'corrupt_bytes_or_frames':decoder.corrupt,'complete':decoder.loss==0 and decoder.corrupt==0};(output/'serial.bin').write_bytes(data);result['serial_sha256']=hashlib.sha256(data).hexdigest();(output/'summary.json').write_text(json.dumps(result,indent=2));return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--elf',required=True);p.add_argument('--case',choices=CASES,default='all');p.add_argument('--output');p.add_argument('--timeout',type=float,default=30);a=p.parse_args();r=run(a.elf,a.case,a.output,a.timeout);print(json.dumps(r,indent=2));raise SystemExit(0 if r['status']=='PASS' else 1)
