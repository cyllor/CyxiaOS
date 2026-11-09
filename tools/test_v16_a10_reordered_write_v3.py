"""Host-owned transport fixtures: never native VM acceptance evidence."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v16_a10_reordered_write_v3 as v3
from v16_a10_reordered_write_v3 import validate_selector
from v16_a10_write_v2 import Qmp, Server, Witness, close_capture
from v13_fault_disk import Backend
from check_v13_fault_disk import inspect as inspect_nbd
from test_v16_a10_write_v2 import CHILD as ORIGINAL_CHILD

# The child owns actual Unix sockets. Three pipelined requests let the real
# backend ACK 2 then 1 and cut 3 before executing its body.
CHILD = ORIGINAL_CHILD.replace(
 "n.sendall(struct.pack('>IHHQQI',0x25609513,0,1,1,512,512)+b'x'*512)\n  assert n.recv(16)==b'';n.close()",
 "n.sendall(b''.join(struct.pack('>IHHQQI',0x25609513,0,1,i,i*512,512)+bytes([119+i])*512 for i in (1,2,3)))\n  replies=exact(n,32)\n  assert struct.unpack('>IIQ',replies[:16])[2]==2\n  assert struct.unpack('>IIQ',replies[16:])[2]==1\n  assert n.recv(16)==b'';n.close()")

class ReorderedWriteV3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='a10-v3-');cls.root=Path(cls.tmp.name)
        for name in ('initial.raw','disk.raw'):(cls.root/name).write_bytes(bytes(16384))
        cls.witness=Witness(cls.root/'native-provenance.jsonl')
        cls.backend=Backend(cls.root/'disk.raw',cls.root/'nbd',cut=3,phase='before',
            unflushed='reverse-half',reverse_replies=True,compress=True,witness=cls.witness.record,
            event_clock='host-monotonic-ns-v1',arm_input_sha256='1'*64)
        cls.server=Server(cls.backend,cls.root/'n.sock')
        cls.proc=subprocess.Popen([sys.executable,'-B','-c',CHILD,str(cls.server.path),str(cls.root/'q.sock')],
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        cls.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            until=time.monotonic()+5
            while True:
                try:cls.sock.connect(str(cls.root/'q.sock'));break
                except (FileNotFoundError,ConnectionRefusedError):
                    if time.monotonic()>=until:raise
                    time.sleep(.001)
            cls.qmp=Qmp(cls.sock,cls.witness,journal_path=cls.root/'qmp.jsonl',byte_limit=65536,command_limit=32)
            assert 'QMP' in cls.qmp.receive(until)
            while not cls.backend.ready and time.monotonic()<until:time.sleep(.001)
            assert cls.backend.ready;cls.backend.arm();cls.qmp.execute('cont')
            assert cls.server.completed.wait(3)
            cls.qmp.execute('ringbuf-read',{'device':'cyxlog','size':1048576,'format':'base64'})
            cls.qmp.execute('stop');cls.qmp.execute('query-status')
            report={'cut_observed':True}
            close_capture(cls.proc,cls.sock,cls.server,cls.qmp,cls.backend,cls.witness,report)
            assert 'error' not in report,report
        except BaseException:
            if cls.proc.poll() is None:cls.proc.kill();cls.proc.wait()
            cls.server.close();cls.sock.close();cls.tmp.cleanup();raise
        finally:cls.proc.stderr.close()
        cls.rows=[json.loads(x) for x in (cls.root/'qmp.jsonl').read_bytes().splitlines()]
        cls.wrows=[json.loads(x) for x in (cls.root/'native-provenance.jsonl').read_bytes().splitlines()]
        cls.lifecycle=v3.Lifecycle(iter(cls.wrows));events=[];cls.errors=[]
        for command,_ in v3.transactions(cls.rows,32,events,fault_events=cls.errors):
            assert cls.lifecycle.take('qmp-request')['id']==command['id']
            assert cls.lifecycle.take('qmp-response')['id']==command['id']
        cls.lifecycle.take(None)
        cls.context=dict(pid=cls.proc.pid,backend_run_id=cls.backend.meta['run_id'],
            endpoints={'qmp':str(cls.root/'q.sock'),'nbd':str(cls.server.path)})
        cls.transport=v3.validate_observations(cls.root,cls.context,cls.rows,cls.lifecycle)
        cls.trace=inspect_nbd(cls.root/'initial.raw',cls.root/'disk.raw',cls.root/'nbd')
        cls.expected=dict(cut=3,offset=1536,length=512,data_sha256=hashlib.sha256(b'z'*512).hexdigest())
        cls.protocol=dict(lifecycle=cls.lifecycle.events,transport=cls.transport,fault_io_events=cls.errors)
        cls.scope=dict(post_resume_points=[1,2,3],resume_monotonic_ns=next(r['monotonic_ns'] for r in cls.wrows if r['event']=='qmp-request'))

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def check(self,mode=3,**changes):
        inputs=dict(mode=mode,cut=3,phase='before',unflushed='reverse-half',reverse_replies=True)
        inputs.update(changes)
        return v3.verify_write_cut_causality(self.root,self.context,inputs,self.protocol,
            {'nbd_trace':self.trace},self.scope,self.expected)

    def test_real_backend_inversion_and_unexecuted_body(self):
        self.assertTrue(self.trace['reordered_replies'])
        for mode in (2,3):self.check(mode)
        self.assertEqual(self.proc.returncode,0)
        self.assertEqual(len(self.transport['errors']),3)
        self.assertEqual((self.root/'disk.raw').read_bytes()[1536:2048],bytes(512))

    def test_profile_refusals(self):
        for key,value in [('mode',True),('mode',1),('mode',4),('phase','after-ack'),
                          ('reverse_replies',False),('unflushed','drop'),('cut',True)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.check(**{key:value})

    def test_exact_caller_body_and_range(self):
        for key,value in [('cut',2),('offset',512),('length',1024),('data_sha256','0'*64)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                v3.verify_write_cut_causality(self.root,self.context,dict(mode=3,cut=3,phase='before',
                    unflushed='reverse-half',reverse_replies=True),self.protocol,{'nbd_trace':self.trace},self.scope,
                    dict(self.expected,**{key:value}))

    def test_missing_inversion_not_configuration_credit(self):
        old=self.trace;self.trace=dict(old,reordered_replies=False)
        try:
            with self.assertRaises(ValueError):self.check()
        finally:self.trace=old

    def test_selector_closed_schema_and_integer_types(self):
        validate_selector(self.expected)
        for bad in (None,{},dict(self.expected,checker='evil'),dict(self.expected,cut=True),
                    dict(self.expected,length=0),dict(self.expected,offset=1),dict(self.expected,data_sha256='A'*64)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_selector(bad)

    def test_transport_negative_custody_and_all_errors(self):
        for event,key,value in [('qmp-eof','buffer_bytes',1),('qmp-eof','peer_pid',1),
            ('nbd-close-complete','fd_after',0),('nbd-close-complete','shutdown_errno',5),
            ('nbd-backend-return','disk_closed',False),('wait-observed','begin_ns',1)]:
            bad=SimpleNamespace(auxiliary=copy.deepcopy(self.lifecycle.auxiliary))
            bad.auxiliary[event][0][key]=value
            with self.subTest(event=event,key=key),self.assertRaises(ValueError):
                v3.validate_observations(self.root,self.context,self.rows,bad)
        rows=copy.deepcopy(self.rows)
        next(r['message'] for r in reversed(rows) if r['message'].get('event')=='BLOCK_IO_ERROR')['data']['operation']='flush'
        with self.assertRaises(ValueError):list(v3.transactions(rows,32,[],fault_events=[]))



    def test_legacy_v2_profile_still_refuses_reordered_receipts(self):
        import verify_v16_a10_write_v2 as old
        with self.assertRaises(ValueError):
            old.verify_write_cut_causality(self.root,self.context,dict(mode=3,cut=3,
                phase='before',unflushed='reverse-half',reverse_replies=True),self.protocol,
                {'nbd_trace':self.trace},self.scope,self.expected)

    def test_before_write_cannot_accept_selected_completion_or_orphan_ack(self):
        import gzip
        import shutil
        with tempfile.TemporaryDirectory(prefix='a10-v3-damage-') as temp:
            root=Path(temp);shutil.copytree(self.root/'nbd',root/'nbd')
            path=root/'nbd/events.jsonl.gz'
            original=[json.loads(line) for line in gzip.decompress(path.read_bytes()).splitlines()]
            for event in ('complete','ack'):
                rows=copy.deepcopy(original)
                selected=next(row for row in rows if row['event']=='request' and row['id']==3)
                rows.insert(-1,dict(event=event,id=selected['id']))
                path.write_bytes(gzip.compress(b''.join((json.dumps(row)+'\n').encode() for row in rows)))
                with self.subTest(event=event),self.assertRaises(ValueError):
                    v3.verify_write_cut_causality(root,self.context,dict(mode=3,cut=3,phase='before',
                        unflushed='reverse-half',reverse_replies=True),self.protocol,{'nbd_trace':self.trace},self.scope,self.expected)
                # Independent raw every-byte checker also refuses this stream.
                with self.assertRaises((ValueError,KeyError)):
                    inspect_nbd(self.root/'initial.raw',self.root/'disk.raw',root/'nbd')

    def test_causal_errors_match_complete_transport_not_detached_count(self):
        for change in (lambda p:p['fault_io_events'].pop(),
                       lambda p:p['fault_io_events'][0].update(sha256='0'*64),
                       lambda p:p['lifecycle']['backend-cut'].update(run_id='b'*32),
                       lambda p:p['transport']['backend_return'].update(acks=0)):
            protocol=copy.deepcopy(self.protocol);change(protocol)
            with self.assertRaises(ValueError):
                v3.verify_write_cut_causality(self.root,self.context,dict(mode=3,cut=3,phase='before',
                    unflushed='reverse-half',reverse_replies=True),protocol,{'nbd_trace':self.trace},self.scope,self.expected)

    def test_native_version_guard_and_explicit_mode_are_not_relaxed(self):
        from v16_a10_reordered_write_v3 import validate_profile
        inputs=dict(mode=2,cut=3,phase='before',unflushed='reverse-half',reverse_replies=True,
            sample_ms=30000,capture_timeout_seconds=1920)
        for mode in (None,True,1,3):
            with self.subTest(mode=mode),self.assertRaises(ValueError):validate_profile(inputs,mode,capture=True)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);build=root/'build.json';build.write_text('{}')
            for version in ('a10-native-v1','a10-write-native-v2','a10-recut-diagnostic-v2'):
                (root/'native-context.json').write_text(json.dumps({'version':version}))
                with self.assertRaisesRegex(ValueError,'context version'):
                    v3.verify_native_reordered_write_child(root,source_root=Path(__file__).resolve().parents[1],
                        build_manifest=build,qemu_binary=Path('/caller/qemu'),qemu_source=Path('/caller/qemu-source'),
                        initial_disk=root/'missing.raw',expected_write=self.expected,expected_mode=2)

    def test_v3_native_admission_keeps_fixed_common_guards_and_replay_order(self):
        import inspect
        import ast
        import verify_v16_a10_write_v2 as old
        source=inspect.getsource(v3.verify_native_reordered_write_child)
        self.assertLess(source.index('replayed = replay_child('),source.index('verify_write_cut_causality('))
        # All common source/build/image/config/model/launch/input/NBD/oracle
        # guards from v2 remain verbatim AST statements except the declared v3
        # profile and closure roots. This detects accidental omissions in copy.
        old_tree=ast.parse(inspect.getsource(old.verify_native_write_child)).body[0]
        new_tree=ast.parse(source).body[0]
        def common(tree):
            found=[]
            for node in tree.body:
                if not isinstance(node,ast.Expr) or not isinstance(node.value,ast.Call):continue
                call=node.value
                if not isinstance(call.func,ast.Name) or call.func.id!='require':continue
                message=call.args[-1]
                if isinstance(message,ast.Constant) and isinstance(message.value,str) and not message.value.startswith(('v2 ','v3 ')):
                    found.append(ast.dump(node,include_attributes=False))
            return found
        self.assertEqual(common(old_tree),common(new_tree))
        self.assertEqual(v3.sha256(Path(v3.v1.__file__)),v3.V1_INPUT_GUARD_SHA256)
        closure=v3.tool_closure()
        for name in ('run_v16_a10_reordered_write_v3.py','verify_v16_a10_reordered_write_v3.py',
                     'v16_a10_reordered_write_v3.py','v16_a10_write_v2.py'):
            self.assertIn(name,closure)

class ProducerFinalizationV3(unittest.TestCase):
    """Direct final-report filesystem tests, no producer/VM launch."""
    def test_inventory_failure_preserves_primary_and_writes_failed_summary(self):
        from unittest.mock import patch
        import os
        import run_v16_a10_reordered_write_v3 as producer
        from v16_a10_reordered_write_v3 import bounded_inventory
        for kind,message in (('empty','extra inventory directory'),('fifo','special file'),('cap','entry bound')):
            with tempfile.TemporaryDirectory() as temp,self.subTest(kind=kind):
                root=Path(temp);(root/'raw.bin').write_bytes(b'preserved')
                if kind=='empty':(root/'extra-empty').mkdir()
                elif kind=='fifo':os.mkfifo(root/'fifo')
                else:(root/'extra.bin').write_bytes(b'x')
                report=dict(status='FAIL',native_mode_verified=False,error='RuntimeError: primary capture failure')
                def limited(root,**kwargs):
                    return bounded_inventory(root,**kwargs,**({'max_entries':1} if kind=='cap' else {}))
                with patch.object(producer,'bounded_inventory',side_effect=limited):
                    result=producer.finalize_report(root,report)
                saved=json.loads((root/'summary.json').read_text())
                self.assertEqual(result,saved)
                self.assertEqual(saved['error'],'RuntimeError: primary capture failure')
                self.assertEqual(saved['status'],'FAIL')
                self.assertFalse(saved['native_mode_verified'])
                self.assertFalse(saved['artifact_inventory_complete'])
                self.assertIsNone(saved['artifacts'])
                self.assertIn(message,saved['artifact_inventory_error'])
                self.assertEqual((root/'raw.bin').read_bytes(),b'preserved')
    def test_invalid_inventory_demotes_optimistic_report(self):
        import run_v16_a10_reordered_write_v3 as producer
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'extra-empty').mkdir()
            result=producer.finalize_report(root,dict(status='PASS',native_mode_verified=True))
            self.assertEqual(result['status'],'FAIL')
            self.assertFalse(result['native_mode_verified'])
            self.assertIn('extra inventory directory',result['error'])
            self.assertIsNone(result['artifacts'])
    def test_valid_inventory_keeps_exact_artifacts_and_status(self):
        import run_v16_a10_reordered_write_v3 as producer
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'nbd').mkdir();(root/'nbd/raw.bin').write_bytes(b'host fixture')
            result=producer.finalize_report(root,dict(status='NOT_RUN',native_mode_verified=False))
            self.assertEqual(result['status'],'NOT_RUN')
            self.assertTrue(result['artifact_inventory_complete'])
            self.assertEqual(result['artifacts'],{'nbd/raw.bin':hashlib.sha256(b'host fixture').hexdigest()})
            self.assertNotIn('artifact_inventory_error',result)

if __name__=='__main__':unittest.main()
