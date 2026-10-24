import unittest
from tools.run_qemu import validate_progress
class RunnerTests(unittest.TestCase):
 def test_process_alive_is_not_progress(self):
  with self.assertRaises(ValueError):validate_progress((1,10,20,0,0,1),(1,10,20,3000000,0,1))
 def test_insufficient_output_is_not_pressure(self):
  with self.assertRaises(ValueError):validate_progress((1,10,20,0,0,1),(1,11,21,10,0,1))
 def test_forward_progress_with_full_backend(self):
  self.assertTrue(validate_progress((0x43595850524f4731,100,99,1024,1,1),(0x43595850524f4731,200,199,3001024,1,1)))

class CleanupTests(unittest.TestCase):
 def test_timeout_reaps_only_owned_qemu(self):
  # Test the actual subprocess lifecycle, not availability of an emulator or
  # support for a particular QEMU machine version. This helper never boots a guest.
  import os,shlex,subprocess,sys,tempfile
  from pathlib import Path
  from unittest.mock import patch
  from test_elf import fixture
  from tools.run_qemu import run
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);elf=p/'silent.elf';elf.write_bytes(fixture())
   pidfile=p/'owned.pid'
   helper=p/'no-qmp-helper'
   program='import os,time; from pathlib import Path; Path('+repr(str(pidfile))+').write_text(str(os.getpid())); time.sleep(30)'
   helper.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' -c '+shlex.quote(program)+'\n')
   helper.chmod(0o700)
   other=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
   try:
    with patch('tools.run_qemu.shutil.which',return_value=str(helper)):
     r=run(elf,'boot-entry',p/'out',timeout=1)
    self.assertEqual(r['status'],'FAIL')
    self.assertIn('QMP startup',r.get('error',''))
    self.assertIsNotNone(r['qemu_exit'])
    self.assertLess(r['qemu_exit'],0)
    owned=int(pidfile.read_text())
    self.assertNotEqual(owned,other.pid)
    with self.assertRaises(ProcessLookupError):os.kill(owned,0)
    self.assertIsNone(other.poll())
   finally:other.terminate();other.wait(timeout=2)

class FinalCaptureTests(unittest.TestCase):
 def test_panic_in_final_pressure_capture_cannot_pass(self):
  import base64,tempfile
  from pathlib import Path
  from unittest.mock import Mock,patch
  from tools.run_qemu import run,CASES
  from test_transport import frame
  from test_elf import fixture
  initial=b''.join(frame(i+1,(marker+' BOOTSTRAP').encode()) for i,marker in enumerate(CASES['all']))
  captures=iter([base64.b64encode(initial).decode(),base64.b64encode(frame(100,b'FAIL panic')).decode()])
  qmp=Mock();qmp.transcript=[];qmp.receive.return_value={'QMP':{}}
  qmp.execute.side_effect=lambda cmd,args=None:next(captures) if cmd=='ringbuf-read' else {}
  proc=Mock();proc.poll.return_value=None;proc.returncode=0;proc.wait.return_value=0
  with tempfile.TemporaryDirectory() as td:
   elf=Path(td)/'test.elf';elf.write_bytes(fixture())
   with patch('tools.run_qemu.Qmp',return_value=qmp),patch('tools.run_qemu.socket.socket'),patch('tools.run_qemu.subprocess.Popen',return_value=proc),patch('tools.run_qemu.pressure',return_value={'validated':True}):
    r=run(elf,'pressure',Path(td)/'out',timeout=1)
   self.assertEqual(r['status'],'FAIL')
   self.assertIn('guest selftest failed',r.get('error',''))
