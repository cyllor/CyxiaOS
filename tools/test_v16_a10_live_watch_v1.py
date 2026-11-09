"""Real owned subprocess, SIGINT/finally and sibling logs; no VM/native verdict."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from v16_a10_live_watch_v1 import (MAGIC,RepeatedStall,OperatorDiagnosticStop,
                                  run_monitored_clean,process_identity)

FIXTURE=r'''
import hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
capture,mode,foreign,binary=sys.argv[1:]
p=Path(capture);p.mkdir();(p/'nbd').mkdir();events=p/'nbd/events.jsonl';events.write_text('fixture event\n')
leaf=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(30)'])
(p/'native-context.json').write_text(json.dumps(dict(capture_root=capture,binary=binary,pid=int(foreign) or leaf.pid)))
def bank(revision,mask=1):
 w=[0]*32;w[:4]=[0x43595441534b0001,1000000000+revision,mask,1]
 (p/'pending-domain-task.bin').write_bytes(struct.pack('<32Q',*w))
def done(status='PASS'):
 raw=(json.dumps(dict(status=status,error='original fixture error' if status=='FAIL' else None,untouched='original summary'),sort_keys=True)+'\n').encode()
 (p/'summary.original.sha256').write_text(hashlib.sha256(raw).hexdigest())
 (p/'summary.tmp').write_bytes(raw);(p/'summary.tmp').replace(p/'summary.json')
if mode=='fallback':
 signal.signal(signal.SIGINT,lambda *x:(p/'signal-seen').write_text('SIGINT'))
try:
 bank(1,0 if mode in ('healthy','fail') else 1)
 time.sleep(.25)
 if mode=='single':done()
 elif mode in ('healthy','fail','progress'):
  if mode=='progress':
   with events.open('a') as f:f.write('fixture new event\n');f.flush()
  bank(2,0 if mode in ('healthy','fail') else 1)
  time.sleep(.25);bank(3,0);time.sleep(.1);done('FAIL' if mode=='fail' else 'PASS')
 else:
  bank(2)
  while True:
   if mode=='fallback' and leaf.poll() is not None:raise RuntimeError('original producer observed QEMU stop')
   time.sleep(.01)
except BaseException as error:
 (p/'original-error.txt').write_text(type(error).__name__+': original fixture failure')
 raise
finally:
 if leaf.poll() is None:leaf.kill()
 leaf.wait();(p/'original-finally.json').write_text(json.dumps(dict(pid=os.getpid(),qemu_pid=leaf.pid,qemu_returncode=leaf.returncode)))
if mode=='fail':sys.exit(1)
'''


class LiveWatch(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='a10-watch-');self.root=Path(self.tmp.name).resolve()
        self.capture=self.root/'child';self.logs=self.root/'outside-diagnostics'
    def tearDown(self):self.tmp.cleanup()
    def run_child(self,mode,foreign=0):
        # macOS Python's launcher execs the actual app binary without changing
        # PID. The QEMU proxy identity is the eventual real interpreter binary.
        binary=Path(process_identity(os.getpid())['binary'])
        return run_monitored_clean([sys.executable,'-B','-c',FIXTURE,str(self.capture),mode,str(foreign),str(binary)],
            cwd=self.root,environment=dict(os.environ),capture=self.capture,diagnostics=self.logs,
            qemu_binary=binary,poll_seconds=.01,cleanup_grace=.1 if mode=='fallback' else 2)
    def assert_finally(self):
        cleanup=json.loads((self.capture/'original-finally.json').read_text())
        self.assertIsNone(process_identity(cleanup['qemu_pid']))
        self.assertIsNone(process_identity(cleanup['pid']))
        return cleanup
    def test_two_real_revisions_stop_only_owned_producer_and_keep_original_error(self):
        with self.assertRaises(OperatorDiagnosticStop):self.run_child('stall')
        self.assertIn('KeyboardInterrupt: original fixture failure',(self.capture/'original-error.txt').read_text())
        self.assertFalse((self.capture/'summary.json').exists(),'observer must not mint a child verdict')
        self.assert_finally()
        observation=json.loads((self.logs/'observation.json').read_text())
        self.assertTrue(observation['live_hint_only']);self.assertTrue(observation['operator_stopped'])
        self.assertEqual(len(observation['repeated_hints']),2)
        self.assertEqual(observation['cleanup']['signals'],[dict(pid=observation['cleanup']['child_pid'],signal=signal.SIGINT)])
        self.assertEqual(observation['native_acceptance_status'],'NOT_RUN')
        self.assertFalse(observation['cache_eviction_verified'])
        self.assertNotIn('status',observation)
        self.assertTrue(self.logs.is_relative_to(self.root) and not self.logs.is_relative_to(self.capture))
    def test_one_revision_does_not_trigger_and_original_summary_bytes_survive(self):
        result=self.run_child('single')
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['untouched'],'original summary')
        self.assertEqual(hashlib.sha256((self.capture/'summary.json').read_bytes()).hexdigest(),(self.capture/'summary.original.sha256').read_text())
        observation=json.loads((self.logs/'observation.json').read_text())
        self.assertFalse(observation['operator_stopped']);self.assertIsNone(observation['cleanup'])
        self.assert_finally()
    def test_advancing_backend_is_not_stall(self):
        self.assertEqual(self.run_child('progress')['status'],'PASS');self.assert_finally()
    def test_nonquarantined_revisions_are_not_stall(self):
        self.assertEqual(self.run_child('healthy')['status'],'PASS');self.assert_finally()
    def test_original_failure_return_and_error_are_not_rewritten(self):
        result=self.run_child('fail')
        self.assertEqual(result['status'],'FAIL');self.assertEqual(result['error'],'original fixture error')
        self.assertEqual(hashlib.sha256((self.capture/'summary.json').read_bytes()).hexdigest(),(self.capture/'summary.original.sha256').read_text())
        self.assert_finally()
    def test_foreign_pid_from_context_never_receives_a_signal(self):
        foreign=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(20)'])
        try:
            with self.assertRaises(OperatorDiagnosticStop):self.run_child('stall',foreign.pid)
            self.assertIsNone(foreign.poll())
            observation=json.loads((self.logs/'observation.json').read_text())
            self.assertIsNone(observation['cleanup']['qemu_before'])
            self.assertTrue(all(s['pid'] != foreign.pid for s in observation['cleanup']['signals']))
            self.assert_finally()
        finally:
            if foreign.poll() is None:foreign.kill()
            foreign.wait()
    def test_fallback_kills_only_observed_owned_qemu_then_original_finally_runs(self):
        with self.assertRaises(OperatorDiagnosticStop):self.run_child('fallback')
        observation=json.loads((self.logs/'observation.json').read_text())
        signals=observation['cleanup']['signals'];qemu=observation['cleanup']['qemu_before']
        self.assertEqual(signals,[dict(pid=observation['cleanup']['child_pid'],signal=signal.SIGINT),dict(pid=qemu['pid'],signal=signal.SIGKILL)])
        self.assertIn('RuntimeError: original fixture failure',(self.capture/'original-error.txt').read_text())
        self.assert_finally()
    def test_missing_process_visibility_fails_before_any_child_is_started(self):
        with patch('v16_a10_live_watch_v1.process_identity',side_effect=PermissionError('host policy')), \
             patch('v16_a10_live_watch_v1.subprocess.Popen') as launch:
            with self.assertRaises(PermissionError):
                run_monitored_clean([sys.executable],cwd=self.root,environment=dict(os.environ),
                    capture=self.capture,diagnostics=self.logs,qemu_binary=Path(sys.executable))
            launch.assert_not_called()

    def test_existing_child_is_never_reused_or_overwritten(self):
        self.capture.mkdir();original=self.capture/'summary.json';original.write_text('original bytes')
        with patch('v16_a10_live_watch_v1.subprocess.Popen') as launch:
            with self.assertRaisesRegex(ValueError,'refuses existing'):
                run_monitored_clean([sys.executable],cwd=self.root,environment=dict(os.environ),
                    capture=self.capture,diagnostics=self.logs,qemu_binary=Path(sys.executable))
            launch.assert_not_called();self.assertEqual(original.read_text(),'original bytes')

    def test_detector_requires_two_different_writes_and_reset_on_progress(self):
        def hint(revision,nbd=1,mask=1,overruns=1):
            return dict(revision=[revision],nbd_revision=[nbd],quarantine_mask=mask,overruns=overruns,guest_publication_ns=revision)
        detector=RepeatedStall();self.assertIsNone(detector.observe(hint(1)))
        self.assertIsNone(detector.observe(hint(1)))
        self.assertIsNone(detector.observe(hint(2,nbd=2)))
        self.assertIsNone(detector.observe(hint(3,mask=0)))
        self.assertIsNone(detector.observe(hint(4,nbd=2)))
        self.assertIsNotNone(detector.observe(hint(5,nbd=2)))

if __name__=='__main__':unittest.main()
