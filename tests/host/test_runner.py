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
  import subprocess,sys,tempfile
  from pathlib import Path
  from test_elf import fixture
  from tools.run_qemu import run
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);elf=p/'silent.elf';elf.write_bytes(fixture())
   other=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'])
   try:
    r=run(elf,'boot-entry',p/'out',timeout=.2)
    self.assertEqual(r['status'],'FAIL');self.assertIsNotNone(r['qemu_exit']);self.assertIsNone(other.poll())
   finally:other.terminate();other.wait(timeout=2)
