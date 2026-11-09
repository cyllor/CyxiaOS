"""Portable host transport proofs, not native acceptance fixtures."""
import ast
import copy
import builtins
import dis
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
import types

sys.path.insert(0,str(Path(__file__).resolve().parent))
import verify_v13_a10_native_receipt as v1
import verify_v16_a10_write_v2 as v2
from check_v13_fault_disk import inspect as inspect_nbd
from v13_fault_disk import Backend
from v16_a10_write_v2 import Qmp, Server, Witness, CloseOwner, close_capture, canonical


CHILD=r'''
import json,socket,struct,sys,time
nbdpath,qmppath=sys.argv[1:3]
listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(qmppath);listener.listen(1)
n=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);n.connect(nbdpath)
def exact(sock,count):
 b=b''
 while len(b)<count:
  x=sock.recv(count-len(b))
  if not x:raise RuntimeError('short fixture NBD')
  b+=x
 return b
exact(n,18);n.sendall(struct.pack('>I',3)+struct.pack('>QII',0x49484156454f5054,1,0));exact(n,10)
q,_=listener.accept();f=q.makefile('rwb',buffering=0)
def send(value):f.write(json.dumps(value).encode()+b'\n')
def event(name,data=None,ordinal=1):
 x={'event':name,'timestamp':{'seconds':1,'microseconds':ordinal}}
 if data is not None:x['data']=data
 send(x)
def error(ordinal):
 event('BLOCK_IO_ERROR',{'device':'disk0','node-name':'cyxia-a10-disk','qom-path':'/machine/peripheral-anon/device[0]',
  'reason':'Input/output error','operation':'write','action':'report','nospace':False},ordinal)
send({'QMP':{'version':{'qemu':{'major':10,'minor':2,'micro':2},'package':'v10.2.2-dirty'},'capabilities':[]}})
for line in f:
 r=json.loads(line);op=r['execute']
 if op=='cont':
  event('RESUME');send({'return':{},'id':r['id']})
  n.sendall(struct.pack('>IHHQQI',0x25609513,0,1,1,512,512)+b'x'*512)
  assert n.recv(16)==b'';n.close()
 elif op=='ringbuf-read':error(1);error(2);send({'return':'','id':r['id']})
 elif op=='stop':event('STOP');send({'return':{},'id':r['id']})
 elif op=='query-status':send({'return':{'running':False,'status':'paused'},'id':r['id']})
 elif op=='quit':
  event('SHUTDOWN',{'guest':False,'reason':'host-qmp-quit'})
  send({'return':{},'id':r['id']})
  time.sleep(.2)  # Load-bearing: longer than the old quiet window.
  error(3);break
 else:raise RuntimeError('unexpected fixture command')
f.close();q.shutdown(socket.SHUT_RDWR);q.close();listener.close()
'''


class WriteV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='a10-v2-')
        cls.root=Path(cls.tmp.name)
        (cls.root/'initial.raw').write_bytes(bytes(16384))
        (cls.root/'disk.raw').write_bytes(bytes(16384))
        cls.witness=Witness(cls.root/'native-provenance.jsonl')
        cls.backend=Backend(cls.root/'disk.raw',cls.root/'nbd',cut=1,phase='before',
            unflushed='reverse-half',reverse_replies=False,compress=True,witness=cls.witness.record,
            event_clock='host-monotonic-ns-v1',arm_input_sha256='1'*64)
        cls.server=Server(cls.backend,cls.root/'n.sock')
        cls.stderr=(cls.root/'child.stderr').open('wb')
        cls.proc=subprocess.Popen([sys.executable,'-B','-c',CHILD,str(cls.server.path),str(cls.root/'q.sock')],
            stdout=subprocess.DEVNULL,stderr=cls.stderr)
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
            assert cls.backend.ready
            cls.backend.arm()
            cls.qmp.execute('cont');assert cls.server.completed.wait(3)
            cls.qmp.execute('ringbuf-read',{'device':'cyxlog','size':1048576,'format':'base64'})
            cls.qmp.execute('stop');cls.qmp.execute('query-status')
            cls.report={'cut_observed':True}
            close_capture(cls.proc,cls.sock,cls.server,cls.qmp,cls.backend,cls.witness,cls.report)
            assert 'error' not in cls.report,cls.report
        except BaseException:
            if cls.proc.poll() is None:cls.proc.kill();cls.proc.wait()
            cls.server.close();cls.sock.close();cls.stderr.close();cls.tmp.cleanup();raise
        cls.stderr.close()
        cls.rows=[json.loads(x) for x in (cls.root/'qmp.jsonl').read_bytes().splitlines()]
        cls.wrows=[json.loads(x) for x in (cls.root/'native-provenance.jsonl').read_bytes().splitlines()]
        cls.lifecycle=v2.Lifecycle(iter(cls.wrows))
        cls.events=[];cls.errors=[]
        commands=list(v2.transactions(cls.rows,32,cls.events,fault_events=cls.errors))
        for command,_ in commands:
            assert cls.lifecycle.take('qmp-request')['id']==command['id']
            assert cls.lifecycle.take('qmp-response')['id']==command['id']
        cls.lifecycle.take(None)
        cls.context=dict(pid=cls.proc.pid,backend_run_id=cls.backend.meta['run_id'],
            endpoints={'qmp':str(cls.root/'q.sock'),'nbd':str(cls.server.path)})
        cls.transport=v2.validate_observations(cls.root,cls.context,cls.rows,cls.lifecycle)
        cls.nbd=inspect_nbd(cls.root/'initial.raw',cls.root/'disk.raw',cls.root/'nbd')

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def altered(self,event,change):
        lifecycle=self.snapshot()
        change(lifecycle.auxiliary[event][0])
        return lifecycle

    def snapshot(self):
        return SimpleNamespace(auxiliary=copy.deepcopy(self.lifecycle.auxiliary))

    def test_actual_owned_shutdown_quit_eof_wait_and_late_event(self):
        self.assertEqual(self.proc.returncode,0)
        with self.assertRaises(ProcessLookupError):os.kill(self.proc.pid,0)
        self.assertTrue(self.transport['complete_received_wire_verified'])
        self.assertEqual(self.events,['RESUME','STOP','SHUTDOWN'])
        self.assertEqual(len(self.transport['errors']),3)
        # Third actual receive happens after quit and after the old100ms cap.
        self.assertGreater(self.transport['errors'][-1]['recv_return_ns']-
                           self.transport['quit']['append_entry_ns'],100_000_000)
        self.assertEqual(self.server.owner.result['peer_pid'],self.proc.pid)
        self.assertEqual(self.server.owner.result['shutdown_errno'],None)

    def test_actual_small_nbd_prefix_has_unique_unacked_before_write(self):
        self.assertEqual(self.nbd['cut']['id'],1)
        self.assertEqual(self.nbd['requests'],1)
        self.assertFalse(self.nbd['reordered_replies'])
        self.assertEqual((self.root/'initial.raw').read_bytes(),(self.root/'disk.raw').read_bytes())
        protocol=dict(lifecycle=self.lifecycle.events,transport=self.transport,fault_io_events=self.errors)
        inputs=dict(mode=3,cut=1,phase='before',reverse_replies=False)
        selected=dict(cut=1,offset=512,length=512,data_sha256=hashlib.sha256(b'x'*512).hexdigest())
        # Pure host causal gate only. Native ELF/config/inventory acceptance is
        # independently required by the full entry and is not claimed here.
        resumed=next(r['monotonic_ns'] for r in self.wrows if r['event']=='qmp-request')
        scope=dict(post_resume_points=[1],resume_monotonic_ns=resumed)
        v2.verify_write_cut_causality(self.root,self.context,inputs,protocol,{'nbd_trace':self.nbd},scope,selected)
        for key,value in [('offset',1024),('length',1024),('data_sha256','0'*64),('cut',2)]:
            wrong=dict(selected,**{key:value})
            with self.subTest(key=key),self.assertRaises(ValueError):
                v2.verify_write_cut_causality(self.root,self.context,inputs,protocol,{'nbd_trace':self.nbd},scope,wrong)
        for key,value in [('mode',4),('phase','after-ack'),('reverse_replies',True),('cut',0)]:
            wrong=dict(inputs,**{key:value})
            with self.subTest(profile=key),self.assertRaises(ValueError):
                v2.verify_write_cut_causality(self.root,self.context,wrong,protocol,{'nbd_trace':self.nbd},scope,selected)

    def test_missing_eof_cannot_be_replaced_by_idle_window(self):
        bad=self.snapshot();bad.auxiliary['qmp-eof']=[]
        with self.assertRaisesRegex(ValueError,'qmp-eof'):
            v2.validate_observations(self.root,self.context,self.rows,bad)

    def test_close_identity_fd_or_errno_mismatches_rejected(self):
        for key,value in [('peer_pid',self.proc.pid+1),('run_id','b'*32),('endpoint','/wrong'),
                          ('fd_after',1),('shutdown_errno',5),('close_errno',5)]:
            bad=self.altered('nbd-close-complete',lambda r:r.update({key:value}))
            with self.subTest(key=key),self.assertRaises(ValueError):
                v2.validate_observations(self.root,self.context,self.rows,bad)

    def test_actual_preclose_receive_not_relabelled_by_later_log(self):
        bad=self.snapshot()
        e=next(x for x in bad.auxiliary['qmp-observed'] if x['qmp_row']==self.errors[0]['qmp_row'])
        e['recv_return_ns']=self.transport['closed']['shutdown_begin_ns']-1
        with self.assertRaises(ValueError):v2.validate_observations(self.root,self.context,self.rows,bad)

    def test_duplicate_close_or_eof_rejected(self):
        for kind in ('qmp-connected','qmp-eof','nbd-close-complete','nbd-close-intent','wait-observed','nbd-backend-return'):
            bad=self.snapshot();bad.auxiliary[kind].append(copy.deepcopy(bad.auxiliary[kind][0]))
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                v2.validate_observations(self.root,self.context,self.rows,bad)

    def test_missing_message_observation_or_raw_event_rejected(self):
        bad=self.snapshot();bad.auxiliary['qmp-observed'].pop()
        with self.assertRaises(ValueError):v2.validate_observations(self.root,self.context,self.rows,bad)
        without=[r for i,r in enumerate(self.rows,1) if i!=self.errors[-1]['qmp_row']]
        with self.assertRaises(ValueError):v2.validate_observations(self.root,self.context,without,self.lifecycle)

    def test_unknown_wrong_device_operation_nospace_and_reason_rejected(self):
        original=next(r['message'] for r in self.rows if r['message'].get('event')=='BLOCK_IO_ERROR')
        for key,value in [('device','disk1'),('node-name','#block131'),('operation','read'),
                          ('action','stop'),('nospace',True),('reason','No space left on device')]:
            rows=copy.deepcopy(self.rows);message=next(r['message'] for r in rows if r['message'].get('event')=='BLOCK_IO_ERROR')
            message['data'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                list(v2.transactions(rows,32,[],fault_events=[]))

    def test_stream_response_without_quit_or_early_eof_not_accepted(self):
        for kind,key,value in [('qmp-eof','buffer_bytes',1),('qmp-eof','wire_bytes',0),
                              ('qmp-eof','peer_pid',1),('qmp-eof','fd',10000),
                              ('qmp-eof','seq',1),('qmp-connected','seq',100000),
                              ('wait-observed','begin_ns',1)]:
            bad=self.altered(kind,lambda r:r.update({key:value}))
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                v2.validate_observations(self.root,self.context,self.rows,bad)

    def test_no_quit_permission_while_backend_file_or_trace_stream_remains_open(self):
        for key in ('disk_closed','events_closed','wire_closed'):
            bad=self.altered('nbd-backend-return',lambda r:r.update({key:False}))
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'backend files'):
                v2.validate_observations(self.root,self.context,self.rows,bad)

    def test_old_v1_and_diagnostic_schemas_cannot_be_resigned(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);build=root/'caller-build.json';build.write_text('{}\n')
            for version in ('a10-native-v1','a10-recut-diagnostic-v2'):
                (root/'native-context.json').write_text(json.dumps({'version':version}))
                with self.subTest(version=version),self.assertRaisesRegex(ValueError,'missing native context version'):
                    v2.verify_native_write_child(root,source_root=Path(__file__).resolve().parents[1],
                        build_manifest=build,qemu_binary=Path('/caller/qemu'),qemu_source=Path('/caller/source'),
                        initial_disk=root/'absent.raw',expected_write={})

    def test_v1_double_event_still_rejected(self):
        with self.assertRaisesRegex(ValueError,'outside bounded fault observation'):
            list(v1.transactions(self.rows,32,[],fault_events=[]))

    def test_final_gate_stays_after_every_byte_replay(self):
        source=inspect.getsource(v2.verify_native_write_child)
        self.assertLess(source.index('replayed = replay_child('),source.index('verify_write_cut_causality('))
        self.assertIn('strict_nbd_events(root)',source)
        self.assertIn("native_filesystem_fault_matrix_complete=False",source)

    def test_common_v1_native_input_guards_cannot_silently_drift(self):
        self.assertEqual(v2.sha256(Path(v1.__file__)),v2.V1_INPUT_GUARD_SHA256)
        old=ast.parse(inspect.getsource(v1.verify_native_child)).body[0]
        new=ast.parse(inspect.getsource(v2.verify_native_write_child)).body[0]
        new.name=old.name
        new.args.kwonlyargs=new.args.kwonlyargs[:-2]
        new.args.kw_defaults=new.args.kw_defaults[:-2]
        class OnlyDeclaredV2Differences(ast.NodeTransformer):
            def visit_Expr(self,node):
                call=node.value
                if isinstance(call,ast.Call):
                    if isinstance(call.func,ast.Name) and call.func.id=='require' and call.args:
                        message=call.args[-1]
                        if isinstance(message,ast.Constant) and type(message.value) is str and message.value.startswith('v2 '):
                            return None
                    if (isinstance(call.func,ast.Attribute) and call.func.attr=='update'
                        and isinstance(call.func.value,ast.Name) and call.func.value.id=='derived'):
                        self.assertKeys(call)
                        return None
                return self.generic_visit(node)
            @staticmethod
            def assertKeys(call):
                assert {k.arg for k in call.keywords}=={'native_write_cut_custody_verified',
                    'native_execution_verified','native_filesystem_fault_matrix_complete','native_acceptance_status'}
            def visit_ImportFrom(self,node):
                if node.module=='run_v16_a10_write_v2':node.module='run_v13_a10'
                return node
            def visit_Set(self,node):
                node.elts=[x for x in node.elts if not (isinstance(x,ast.Constant) and x.value=='qmp-wire.bin')]
                return self.generic_visit(node)
            def visit_Call(self,node):
                if isinstance(node.func,ast.Name) and node.func.id=='verify_write_cut_causality':
                    node.func.id='verify_fault_io_events';node.args=node.args[:-1]
                if (isinstance(node.func,ast.Name) and node.func.id=='one' and len(node.args)==1
                        and isinstance(node.args[0],ast.Constant) and node.args[0].value=='wait'):
                    node.args[0].value='kill'
                return self.generic_visit(node)
        new=OnlyDeclaredV2Differences().visit(new)
        self.assertEqual(ast.dump(old),ast.dump(new))


class CleanupFailures(unittest.TestCase):
    def test_static_producer_all_global_names_are_real_bindings(self):
        import run_v16_a10_write_v2 as producer
        missing=set()
        def visit(code,namespace):
            for instruction in dis.get_instructions(code):
                if instruction.opname=='LOAD_GLOBAL':
                    name=instruction.argval
                    if name not in namespace and not hasattr(builtins,name):missing.add(name)
            for value in code.co_consts:
                if isinstance(value,types.CodeType):visit(value,namespace)
        for function in (producer.run,producer.main,v2.verify_native_write_child,v2.validate_protocol,
                         v2.validate_observations,v2.verify_write_cut_causality,v2.main):
            visit(function.__code__,function.__globals__)
        self.assertFalse(missing,sorted(missing))

    def test_real_owned_child_still_killed_when_kill_witness_hits_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            witness=Witness(Path(temp)/'bound.jsonl',row_limit=0)
            proc=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(60)'])
            report={};error=None;ended_before_harness=False
            try:
                try:close_capture(proc,None,None,None,None,witness,report)
                except BaseException as failure:error=failure
                ended_before_harness=proc.poll() is not None
            finally:
                if proc.poll() is None:proc.kill();proc.wait(timeout=5)
            self.assertTrue(ended_before_harness,repr(error))
            self.assertIsNone(error)
            self.assertIn('error',report)

    def test_actual_accepted_socket_closed_even_when_intent_record_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            witness=Witness(Path(temp)/'bound.jsonl',row_limit=0)
            left,right=socket.socketpair();right.settimeout(1)
            owner=CloseOwner(left,witness,run_id='a'*32,endpoint='/fixture/nbd')
            try:
                with self.assertRaises(ValueError):owner.close()
                self.assertEqual(left.fileno(),-1)
                self.assertEqual(right.recv(1),b'')
            finally:left.close();right.close()


if __name__=='__main__':unittest.main(verbosity=2)
