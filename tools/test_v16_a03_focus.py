"""Synthetic serializer fixtures only: no AcceptedSample or native authority."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import v16_a03_focus as focus


def put(raw, at, *values):
    struct.pack_into('<'+'Q'*len(values), raw, at, *values)


def bank():
    raw = bytearray(512)
    put(raw, 0, 2, focus.COLLECTION_MAGIC, 1, 1, 25, 1, 1, 2, 0, 2, 2, 1, 0, 1, 1, 1, 90, 1, 2048)
    raw[152:184] = b'X'*32
    for at, trial in ((184, 1), (280, 2)):
        put(raw, at, 1, trial, trial, 80, 1, (trial-1)*500, 500)
        raw[at+56:at+88] = bytes([trial])*32
    put(raw, 376, 100, 4, 1)
    return raw


class CollectionContract(unittest.TestCase):
    def test_only_fully_released_typed_collection_is_candidate(self):
        self.assertEqual(focus.collection_boundary(bank())['family'], [1, 2])
        for word in (0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18, 47, 48, 49, 63):
            changed=bank(); put(changed, word*8, 0 if word not in (8,12,63) else 1)
            with self.subTest(word=word):
                self.assertIsNone(focus.collection_boundary(changed))
        changed=bank(); put(changed,0,3)
        self.assertIsNone(focus.collection_boundary(changed))

    def test_rejects_wrong_action_and_index_and_padding(self):
        raw=bytearray(24); struct.pack_into('<4HHQ',raw,0,1,2,10,0,1,6)
        self.assertEqual(focus.core_action(raw,1),6)
        for at in (0,2,4,6,8,10,23):
            changed=bytearray(raw); changed[at]^=1
            with self.subTest(at=at), self.assertRaises(ValueError): focus.core_action(changed,1)

    def test_archive_reference_exact_width_nonzero_and_overflow(self):
        raw=bank()[184:280]
        self.assertEqual(focus.archive_ref(raw)['trial_id'],1)
        for value in (raw[:-1], raw+bytes(1), bytes(96)):
            with self.assertRaises(ValueError): focus.archive_ref(value)
        changed=bytearray(raw); put(changed,40,2**64-1)
        with self.assertRaises(ValueError): focus.archive_ref(changed)
        changed=bytearray(raw); changed[95]=1
        with self.assertRaises(ValueError): focus.archive_ref(changed)

    def test_bounded_inventory_rejects_links_depth_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'x').write_bytes(b'x')
            self.assertEqual(set(focus.bounded_inventory(root)),{'x'})
            (root/'y').symlink_to(root/'x')
            with self.assertRaises(ValueError): focus.bounded_inventory(root)

    def test_witness_reserved_bytes_rejected_before_numeric_comparison(self):
        with self.assertRaises(ValueError): focus.sample_witness(bytes(1024))
        raw=bytearray(1024); raw[:16]=b'CYXIA_SAMPLE_16\0'; raw[816]=1
        with self.assertRaises(ValueError): focus.sample_witness(raw)




def core_fixture(candidate):
    """Independent byte writer for test-only one-shot CoreSet, zero-model fixture."""
    model=bytes(2772); model_hash=hashlib.sha256(model).digest(); first=2_000_000_000+(int(candidate)*20_000_000_000)
    trial=1+int(candidate); target=0x434f5245; schema=bytes.fromhex(focus.SCHEMAS[0]); node=b'N'*32
    row=bytearray(6144); put(row,0,31 if candidate else 40,7)
    put(row,152,7,first,2,3,target,1)
    struct.pack_into('<4H',row,200,int(candidate),2 if candidate else 0,2 if candidate else 1,0)
    masks=(2,6) if candidate else (6,)
    for i,mask in enumerate(masks): struct.pack_into('<5HQ',row,512+24*i,1,2,10,0,i,mask)
    put(row,344,1,first,first+1,first+1000,0,first+200_000_001,1,first+2,0,first+3,1,0)
    # baseline request id shares offset440 with candidate concurrent count.
    put(row,440,1)
    encoded=[]
    if candidate:
        put(row,80,1); row[88:120]=model_hash; row[120:152]=schema
        inp=bytearray(4096)
        put(inp,0,0x4359585254494e31,3,7,9,first,1_000_000_000,3,2,1,2,target,1,1,1,1,2)
        inp[128:160]=model_hash; put(inp,320,15)
        canonical=bytearray(b'CYXIA_CANDIDATES_V1.3\0')+struct.pack('<8Q',7,first,2,3,target,1,1,2)+model_hash+schema
        for i,mask in enumerate(masks):
            payload=struct.pack('<HQ',i,mask).ljust(16,b'\0'); at=(64+10*i)*8
            put(inp,at,10); inp[at+8:at+24]=payload; put(inp,at+64,1,mask.bit_count()*1000)
            canonical+=struct.pack('<4HQ',1,2,10,i,mask)+bytes(96)+b'\x0f'+bytes(36)+b'\x01'+struct.pack('<Q',mask.bit_count()*1000)
            e=[0]*64; e[0]=256; e[32:36]=[256]*4; e[40]=2; e[41]=64*mask.bit_count(); e[42]=64*mask.bit_count(); e[48:51]=[256]*3
            encoded.append(e)
        set_hash=hashlib.sha256(canonical).digest(); row[16:48]=set_hash; inp[160:192]=set_hash
        put(inp,404*8,10); inp[405*8:407*8]=struct.pack('<HQ',0,6).ljust(16,b'\0')
        row[2048:]=inp; row[48:80]=hashlib.sha256(inp).digest()
        put(row,272,1,9,10,0,target,1); row[1280:1328]=row[272:320]
        put(row,320,1,first,0); put(row,488,first,1); row[448:480]=bytes.fromhex(focus.EMPTY_SHARED.hex())
    h=bytearray(2048); h[:17]=b'CYXIA_REPLAY_1.3\0'
    put(h,32,1,trial,trial,1,2,target,1,1,first,first-1_000_000_000,first,first+10_000_000_100,1,1,100,int(candidate))
    put(h,176,5,0,0,0,0,10,0)
    h[256:288]=bytes.fromhex(focus.coreset_workload_hash()); h[288:320]=b'I'*32; h[320:352]=b'F'*32; h[384:416]=b'E'*32
    for i,s in enumerate(focus.SCHEMAS): h[448+i*32:480+i*32]=bytes.fromhex(s)
    put(h,576,13,13,13,13,0,4,0,2048); h[640:672]=node
    put(h,672,first,first,first+10_000_000_000,first+10_000_000_100,3,3,1,100,4,0,1,1000)
    sources=((target,1,0,7),(target,1,1,15),(0x5245504c4159,1,2,1),(0x5245504c434f,1,2,6))
    for i,s in enumerate(sources): put(h,768+32*i,*s)
    scope=bytearray(b'CYXIA_NATIVE_WORKLOAD_SCOPE_1.3\0')+struct.pack('<9Q',1,trial,1,2,target,1,1,first,first)+h[256:352]
    for s in sources: scope+=struct.pack('<4Q',*s)
    requests=bytearray()
    for i in range(100):
        relative=i//10*1_000_000_000+i%10*1000; arrival=first+relative
        requests+=struct.pack('<12Q',i+1,arrival,1,arrival+1,1,arrival+1,0x5245504c4159,1,arrival,1,first,1)+bytes(32)
        scope+=struct.pack('<4Q',i+1,0x5245504c4159,1,relative)
    h[352:384]=hashlib.sha256(scope).digest()
    close=memoryview(h)[1792:]; close[:8]=b'CYCLOSE1'; put(close,8,1,2,10); struct.pack_into('<HQ',close,32,0,6)
    put(close,48,1,9,99,0,target,1,1,first,0,7,first,2,3,1,1,first,first+1,1,first+2,first+3,first+200_000_001,0)
    cpu=node+struct.pack('<4Q',1,first+30,first+35,2)
    warm=struct.pack('<6Q',0x5245504c434f,1,1,1,first-1_000_000_000,first-999_999_995)+bytes(16)
    canonical=bytearray(b'CYXIA_FULL_CPU_TRIAL_1.3\0')+bytes([candidate])
    canonical+=struct.pack('<11Q',trial,1,2,1,first,first+10_000_000_000,first-1_000_000_000,first+10_000_000_100,5,0,1000)
    canonical+=h[256:352]
    for i in range(4): canonical+=struct.pack('<Q',13)+h[448+i*32:480+i*32]
    canonical+=node+struct.pack('<Q',1)+node+struct.pack('<6Q',int(candidate),int(not candidate),100,1,1,0)
    if candidate:
        for e in encoded: canonical+=struct.pack('<64hh',*e,0)
        canonical+=struct.pack('<22Q',7,1,9,10,0,target,1,1,1,first,first+1,first+1000,0,1,first+2,first+3,0,first+200_000_001,0,2,1,0)
        canonical+=row[1280:1328]+row[16:48]+model_hash+schema+struct.pack('<Q',1)
    else:
        canonical+=struct.pack('<16Q',1,7,target,1,1,7,first,3,2,first,first+1,1,first+2,first+3,0,first+200_000_001)
    canonical+=struct.pack('<3HQ',1,2,0,2 if candidate else 6)
    for i in range(100):
        arrival=first+i//10*1_000_000_000+i%10*1000
        canonical+=struct.pack('<4Q',i+1,arrival,0,arrival+1)
    canonical+=node+struct.pack('<6Q',first,first,first+10_000_000_000,first+10_000_000_100,3,3)+cpu
    h[416:448]=hashlib.sha256(canonical).digest()
    return bytes(h+row+cpu+requests+warm),model


class NumericCoreContract(unittest.TestCase):
    def test_explicit_one_shot_pair_numeric_and_canonical(self):
        c,model=core_fixture(True); b,_=core_fixture(False)
        result=focus.numeric_core_pair(c,b,model)
        self.assertEqual(result['family'],[1,2]); self.assertTrue(result['trial_canonical_matches_native'])
        self.assertFalse(result['source_event_hash_recomputed'])
        self.assertFalse(result['accepted_training_sample_verified'])
        self.assertEqual(result['candidate']['performance']['completed'],100)
        self.assertEqual(result['candidate']['cpu']['union_ns'],5)

    def test_mutated_cpu_model_arrival_receipt_or_padding_rejected(self):
        c,model=core_fixture(True); b,_=core_fixture(False)
        for at in (2048+208,2048+384,2048+512+10,2048+6144+48,2048+6144+64+8,len(c)-1):
            raw=bytearray(c); raw[at]^=1
            with self.subTest(at=at),self.assertRaises(ValueError): focus.numeric_core_pair(raw,b,model)
        with self.assertRaises(ValueError): focus.numeric_core_pair(c,b,b'X'+model[1:])

    def test_legacy_weight_parser_still_refuses_coreset(self):
        from v16_learning_reward import numeric_pair
        c,model=core_fixture(True);b,_=core_fixture(False)
        with self.assertRaises(ValueError): numeric_pair(c,b,model)


class CoreImageAndWitness(unittest.TestCase):
    def test_preserves_actual_original_mask_six(self):
        model=bytes(2772);target=[0x434f5245,1]
        queue=hashlib.sha256(b'CYXIA_EMPTY_REAL_CACP_QUEUE_1.3\0'+struct.pack('<3Q',*target,1)
            +hashlib.sha256(model).digest()+bytes.fromhex(focus.SCHEMAS[0])+struct.pack('<Q',1)
            +b'100-owned-relative-arrivals;no-running-context;no-outstanding-output\0').digest()
        image=hashlib.sha256(b'CYXIA_ORIGINAL_CORESET_IMAGE_1.3\0'+struct.pack('<6Q',*target,6,9,15,0)).digest()
        side=dict(target=target,seed=1,initial_image_sha256=hashlib.sha256(b'CYXIA_REPLAY_RESTORED_WORKING_SET_1.3\0'+queue+image).hexdigest())
        self.assertEqual(focus.core_image(side,model)['control'],6)
        side['initial_image_sha256']='01'*32
        with self.assertRaises(ValueError):focus.core_image(side,model)

    def test_actual_protected_input_reward_and_evidence_must_match_pair(self):
        import copy
        c,model=core_fixture(True); b,_=core_fixture(False); numeric=focus.numeric_core_pair(c,b,model)
        context=dict(boot_epoch=1,model_generation=1,model_sha256=hashlib.sha256(model).hexdigest(),schema_hash=focus.SCHEMAS[0],schema_hashes=focus.SCHEMAS,node_id=(b'N'*32).hex())
        baseline,candidate=(focus._side(raw,context) for raw in (b,c))
        raw=bytearray(1024);raw[:16]=b'CYXIA_SAMPLE_16\0';put(raw,32,1,2)
        raw[48:80]=b[416:448];raw[80:112]=c[416:448];put(raw,112,1,2,1);put(raw,368,8)
        raw[136:168]=b[256:288];raw[168:200]=b[288:320]
        for i,s in enumerate(focus.SCHEMAS):put(raw,200+40*i,13);raw[208+40*i:240+40*i]=bytes.fromhex(s)
        struct.pack_into('<64h',raw,376,*numeric['candidate']['input64'])
        for kind,at,cost_at in (('candidate',504,632),('baseline',568,688)):
            p=numeric[kind]['performance'];cpu=numeric[kind]['cpu']
            put(raw,at,*(p[k] for k in ('emitted','completed','rejected','timed_out','pending','penalty_p99_ns')),1,p['actual_completed_p99_ns'])
            put(raw,cost_at,*(cpu[k] for k in ('union_ns','policy_ns','executor_ns','optional_ns')),*cpu['raw_tagged_ns'])
        put(raw,744,*(int(numeric['reward'][k]['bits'],16) for k in ('raw_cost','clipped_cost','delta_throughput','delta_latency','value')))
        raw[784:816]=bytes.fromhex(numeric['prospective_paired_label_sha256'])
        witness=focus.sample_witness(raw)
        self.assertTrue(focus.match_sample_witness(witness,numeric,baseline,candidate))
        for field in ('input64','candidate_performance','baseline_cpu','reward_bits'):
            changed=copy.deepcopy(witness); changed[field][0]^=1
            with self.subTest(field=field),self.assertRaises(ValueError):focus.match_sample_witness(changed,numeric,baseline,candidate)
        changed=copy.deepcopy(witness);changed['evidence_hash']='00'*32
        with self.assertRaises(ValueError):focus.match_sample_witness(changed,numeric,baseline,candidate)




class CoreSetLifecycle(unittest.TestCase):
    # The child is a host-only QMP protocol fixture, never QEMU or guest code.
    SCRIPT = r'''
import json,socket,sys,struct,pathlib
path, root, mode = sys.argv[1:]
listener=socket.socket(socket.AF_UNIX);listener.bind(path);listener.listen(1)
sock,_=listener.accept();reader=sock.makefile('rb');sock.sendall(b'{"QMP": {}}\n')
paused=False;stops=0
for line in reader:
 m=json.loads(line);c=m['execute'];a=m.get('arguments',{});value={}
 if c=='stop':paused=True;stops+=1
 if c=='cont':paused=False
 if c=='query-status':value={'status':'paused' if paused else 'running'}
 if c=='ringbuf-read':value='UEFOSUM=' if mode=='fault' else ''
 if c=='pmemsave':
  name=pathlib.Path(a['filename']).name
  if name.startswith(('probe-','boot.','replay.','control.','runtime.','unified.','failure-')) and not paused:
   sock.sendall((json.dumps({'id':m['id'],'error':'saved final before paused'})+'\n').encode());continue
  data=bytes(a['size'])
  if a['val']==1024:
   w=[0]*64;w[0]=2;w[1]=0x435952504c593133;w[2]=25;w[3]=1;w[4]=2;w[10]=w[17]=2;w[19]=1
   if paused and stops==1 and mode in ('torn','moved'):w[0]=3 if mode=='torn' else 2;w[20]=int(mode=='moved')
   if mode=='excluded':w[11]=1
   data=struct.pack('<64Q',*w)
  if a['val']==8192:
   w=[0]*1024;w[:3]=[0x43595852554e3133,3,2];w[32]=1;data=struct.pack('<1024Q',*w)
  if a['val']==3072:
   w=[0]*64;w[:19]=[2,0x43594c434f4c3136,1,1,25,1,1,2,0,2,2,1,0,1,1,1,90,1,2048]
   w[19:23]=[1]*4;w[47:50]=[100,4,1]
   for at,trial in [(23,1),(35,2)]:w[at:at+11]=[1,trial,trial,80,1,(trial-1)*500,500,1,1,1,1]
   data=struct.pack('<64Q',*w)
  if a['val']==2048 and mode=='optimization':
   w=[0]*(a['size']//8);w[160]=0x43594f5053540001;w[161]=1;w[162]=1;w[191]=2;data=struct.pack('<'+'Q'*len(w),*w)
  pathlib.Path(a['filename']).write_bytes(data)
 sock.sendall((json.dumps({'id':m['id'],'return':value})+'\n').encode())
 if c=='quit':break
sock.close();listener.close()
'''

    def exercise(self, mode='good', attempts=64, close_error=False):
        import json, socket, subprocess, sys, tempfile, time
        from pathlib import Path
        self.assertIsNotNone(importlib.util.find_spec('run_v16_a03_focus'),
                             'missing stopped-capture process lifecycle')
        import run_v16_a03_focus as runner
        from run_qemu import Qmp
        from transport import FrameDecoder
        with tempfile.TemporaryDirectory(prefix='lp-test-') as temp:
            root=Path(temp).resolve(); endpoint=root/'q.sock'
            proc=subprocess.Popen([sys.executable, '-c', self.SCRIPT, str(endpoint), str(root), mode])
            sock=socket.socket(socket.AF_UNIX)
            qmp=None;raw=bytearray();text=bytearray()
            try:
                end=time.monotonic()+5
                while True:
                    try:sock.connect(str(endpoint));break
                    except (FileNotFoundError,ConnectionRefusedError):
                        if time.monotonic()>end:raise
                        time.sleep(.01)
                owner=sock
                if close_error:
                    owner=runner.WireSocket(sock,root)
                qmp=Qmp(owner);qmp.receive(end)
                symbols={key:{'pa': {'replay':1024,'control':2048,'collection':3072,'runtime':8192}.get(key,4096), 'size':size}
                         for key,(_,size) in focus.BANKS.items()}
                def save(name,address,size):
                    target=root/name
                    qmp.execute('pmemsave',dict(val=address,size=size,filename=str(target)))
                    return target.read_bytes()
                failure=None
                try:
                    runner.observe_pair(qmp,save,symbols,proc,time.monotonic()+3,
                                        FrameDecoder(),raw,text,max_stops=attempts)
                except (ValueError,TimeoutError) as error:failure=str(error)
                if close_error:
                    class BadClose:
                        def __init__(self,stream):self.stream=stream
                        def __getattr__(self,name):return getattr(self.stream,name)
                        def close(self):
                            self.stream.close()
                            raise OSError('injected evidence flush failure')
                    received,sent=owner.received,owner.sent
                    owner.received=BadClose(received);owner.sent=BadClose(sent)
                try:
                    cleanup=runner.close_owned(proc,owner,qmp,started_ns=time.monotonic_ns()-1)
                except OSError as error:
                    self.fail('evidence cleanup escaped: '+str(error))
                if close_error:
                    self.assertTrue(received.closed and sent.closed, 'every evidence handle must close')
                    self.assertEqual(sock.fileno(),-1, 'owned raw socket leaked')
                return failure,cleanup,list(qmp.transcript),{p.name:p.read_bytes() for p in root.glob('*.bin')}
            finally:
                sock.close()
                if proc.poll() is None:proc.kill();proc.wait()

    def test_evidence_close_errors_do_not_escape_or_skip_other_owned_resources(self):
        failure,record,_,_=self.exercise('excluded',close_error=True)
        self.assertIn('native replay error',failure)
        self.assertEqual(record['returncode'],0)
        self.assertTrue(record['quit_ok'])
        self.assertEqual(len(record['errors']),2)
        self.assertTrue(all('injected evidence flush failure' in error for error in record['errors']))

    def test_partial_wire_socket_constructor_closes_raw_socket_and_first_evidence_file(self):
        import socket,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import run_v16_a03_focus as runner
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);connection,peer=socket.socketpair();opened=[]
            original=Path.open
            def opening(path,*args,**kwargs):
                if path.name=='qmp-sent.bin':raise OSError('injected second evidence open')
                stream=original(path,*args,**kwargs);opened.append(stream);return stream
            try:
                with patch.object(Path,'open',opening),self.assertRaisesRegex(OSError,'second evidence'):
                    runner.WireSocket(connection,root)
                self.assertTrue(opened[0].closed, 'partially opened evidence file leaked')
                self.assertEqual(connection.fileno(),-1, 'partial constructor leaked raw socket')
            finally:
                for stream in opened:stream.close()
                connection.close();peer.close()

    def test_final_banks_saved_only_after_stop_and_confirmed_pause(self):
        failure,exit_record,rows,files=self.exercise()
        self.assertIsNone(failure)
        self.assertEqual(exit_record['returncode'],0)
        self.assertEqual(exit_record.get('peer_pid'),exit_record['pid'])
        self.assertFalse(exit_record['forced'])
        self.assertIsNotNone(focus.released_pair_candidate(files['replay.bin']))
        names=[r['message']['execute'] for r in rows if r['direction']=='send']
        self.assertEqual(names[-1],'quit')
        self.assertLess(names.index('stop'),names.index('query-status'))

    def test_torn_or_moved_stopped_hint_resumes_instead_of_publishing_it(self):
        for mode in ('torn','moved'):
            failure,_,rows,files=self.exercise(mode)
            self.assertIsNone(failure)
            self.assertIsNotNone(focus.released_pair_candidate(files['replay.bin']))
            commands=[r['message']['execute'] for r in rows if r['direction']=='send']
            self.assertEqual(commands.count('stop'),2)
            self.assertEqual(commands.count('cont'),2)

    def test_stopped_probe_bound_retains_failure_and_quits_owned_process(self):
        failure,exit_record,_,files=self.exercise('torn',attempts=1)
        self.assertIn('probe limit',failure)
        self.assertEqual(exit_record['returncode'],0)
        self.assertNotIn('replay.bin',files)

    def test_native_error_or_optimization_stop_is_fatal_without_green_retry(self):
        for mode in ('excluded','optimization'):
            failure,exit_record,rows,files=self.exercise(mode)
            self.assertIsNotNone(failure)
            self.assertEqual(exit_record['returncode'],0)
            self.assertNotIn('replay.bin',files)
            self.assertEqual(sum(r['direction']=='send' and r['message']['execute']=='cont' for r in rows),1)

class CoreSetFailureFinalization(unittest.TestCase):
    def test_finalization_io_failure_preserves_original_error_and_attempts_other_outputs(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import run_v16_a03_focus as runner
        for broken in ('process-exit.json','serial.bin','disk-after.json'):
            with self.subTest(broken=broken),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();build=root/'build';build.mkdir();output=root/'capture'
                (build/'node-a.elf').write_bytes(b'image');(build/'build-manifest.json').write_text('{}');(build/'base-build-manifest.json').write_text('{}')
                context=dict(paths=dict(source_root=str(root),build_manifest=str(build/'build-manifest.json'),
                    formatter=str(root/'formatter'),qemu_binary=str(root/'qemu'),qemu_source=str(root)),
                    symbols={},artifacts={'node-a.elf':runner.sha(build/'node-a.elf')},tools={},source_map={})
                original_json=runner.write_json;original_bytes=Path.write_bytes
                def write_json(path,value):
                    if path.name==broken:raise OSError('injected finalization I/O failure')
                    return original_json(path,value)
                def write_bytes(path,value):
                    if path.name==broken:raise OSError('injected finalization I/O failure')
                    return original_bytes(path,value)
                def prepare(*args):
                    (output/'disk.raw').write_bytes(b'raw stopped disk')
                    raise ValueError('original capture failure')
                with patch.object(runner,'trusted_context',return_value=context), \
                     patch.object(runner,'symbol',return_value={'va':1,'size':1}), \
                     patch.object(runner,'loaded_bytes',return_value=b'model'), \
                     patch.object(runner,'prepare_disk',side_effect=prepare), \
                     patch.object(runner,'write_json',side_effect=write_json),patch.object(Path,'write_bytes',write_bytes):
                    try:result=runner.run(build/'build-manifest.json',output,source_root=root,
                        formatter=root/'formatter',qemu=root/'qemu',qemu_source=root)
                    except OSError as error:self.fail('finalization escaped: '+str(error))
                self.assertEqual(result['status'],'FAIL')
                self.assertIn('original capture failure',result['error'])
                self.assertTrue(result['cleanup_errors'])
                self.assertEqual(json.loads((output/'summary.json').read_text())['status'],'FAIL')
                self.assertTrue((output/'serial.txt').is_file())
                if broken!='disk-after.json':self.assertTrue((output/'disk-after.json').is_file())






class FullRuntimeWitness(unittest.TestCase):
    def runtime_fixture(self):
        c,model=core_fixture(True)
        context=dict(boot_epoch=1,model_generation=1,model_sha256=hashlib.sha256(model).hexdigest(),schema_hash=focus.SCHEMAS[0],schema_hashes=focus.SCHEMAS,node_id=(b'N'*32).hex())
        side=focus._side(c,context);row=c[2048:8192];first=struct.unpack_from('<Q',row,160)[0]
        bank=bytearray((512+64*640)*8)
        put(bank,0,0x435958444f4d3031,1,1);put(bank,12*8,64,640,1)
        bank[16*8:20*8]=hashlib.sha256(model).digest();bank[20*8:24*8]=bytes.fromhex(focus.SCHEMAS[0])
        record=memoryview(bank)[512*8:(512+640)*8]
        put(record,0,7,7,1,2,0x434f5245,1,9,1,first,first+100,100,100,100,1,2,0,2,0,0,1)
        put(record,28*8,first+200,100,1)
        record[32*8:544*8]=row[2048:];record[608*8:612*8]=row[48:80];put(record,639*8,2)
        runtime=bytearray(8192);put(runtime,0,0x43595852554e3133,3,2,10000,100000000)
        put(runtime,14*8,10);put(runtime,19*8,1,1);put(runtime,28*8,4);put(runtime,32*8,1)
        return bank,runtime,side,context

    def test_full_raw_native_candidate_link_and_unchanged_cost_caps(self):
        bank,runtime,side,context=self.runtime_fixture()
        proof=focus.actual_candidate_runtime(bank,runtime,side,context)
        self.assertEqual(proof['candidate']['sequence'],7)
        for word,value in ((12,500001),(10,2000001),(639,3),(17,1),(13,2),(30,0),(608,0)):
            changed=bytearray(bank);put(changed,(512+word)*8,value)
            with self.subTest(word=word),self.assertRaises(ValueError):focus.actual_candidate_runtime(changed,runtime,side,context)
        for word,value in ((2,3),(9,1),(38,1),(56,1),(29,1),(35,701),(14,0)):
            changed=bytearray(runtime);put(changed,word*8,value)
            with self.subTest(word=word),self.assertRaises(ValueError):focus.actual_candidate_runtime(bank,changed,side,context)

    def test_live_done_hint_with_torn_stopped_runtime_cannot_release(self):
        replay=bytearray(512);put(replay,0,2,0x435952504c593133,25,1,2,0)
        put(replay,80,2);put(replay,136,2);put(replay,152,1)
        _,runtime,_,_=self.runtime_fixture()
        probe=dict(collection=bank(),replay=replay,boot=bytes(512),runtime=runtime)
        self.assertTrue(focus.stopped_collection_ready(probe))
        put(runtime,16,3)
        self.assertFalse(focus.stopped_collection_ready(probe))


class TreeLimits(unittest.TestCase):
    def test_hardlink_and_depth_are_bounded(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'first').write_bytes(b'fixture')
            os.link(root/'first',root/'second')
            with self.assertRaises(ValueError):focus.bounded_inventory(root)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);child=root
            for _ in range(25):child=child/'d';child.mkdir()
            with self.assertRaises(ValueError):focus.bounded_inventory(root)



class BuilderClosureContracts(unittest.TestCase):
    def test_actual_wrapper_closure_is_exact_transitive_thirteen(self):
        from build_v16_learning_collection import builder_closure
        actual=focus.builder_source_closure(Path(__file__).resolve().parents[1])
        self.assertEqual(actual,builder_closure())
        self.assertEqual(set(actual),{
            'tools/build_sources.py','tools/build_unified.py','tools/build_v16_learning_collection.py',
            'tools/check_elf.py','tools/check_prototype_evidence.py','tools/check_v13_preparation_stack.py',
            'tools/doctor.py','tools/elf64.py','tools/memory_v15_client.py','tools/run_qemu.py',
            'tools/transport.py','tools/verify_smp.py','tools/verify_v13_model.py'})
        self.assertEqual(len(actual),13)

    def test_shared_builder_dependencies_are_individually_hash_bound(self):
        source=Path(__file__).resolve().parents[1]
        expected=focus.builder_source_closure(source)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'tools').mkdir()
            for name in expected:(root/name).write_bytes((source/name).read_bytes())
            self.assertEqual(focus.builder_source_closure(root),expected)
            for name in ('tools/build_sources.py','tools/elf64.py'):
                path=root/name;original=path.read_bytes()
                path.write_bytes(original+b'\nraise RuntimeError("must never execute shared captured code")\n')
                changed=focus.builder_source_closure(root)
                with self.subTest(name=name):
                    self.assertEqual(set(changed),set(expected))
                    self.assertEqual(changed[name],hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertNotEqual(changed[name],expected[name])
                    self.assertEqual({key for key in expected if changed[key]!=expected[key]},{name})
                path.write_bytes(original)

    def test_closure_reads_ast_only_and_binds_nested_function_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'tools').mkdir()
            (root/'tools/build_v16_learning_collection.py').write_text('raise RuntimeError("must never execute")\ndef nested():\n import leaf\n')
            (root/'tools/leaf.py').write_text('value=1\n')
            self.assertEqual(set(focus.builder_source_closure(root)),{'tools/build_v16_learning_collection.py','tools/leaf.py'})

    def test_actual_coreset_first_training_slot_is_eight(self):
        raw=bytearray(1024);raw[:16]=b'CYXIA_SAMPLE_16\0';put(raw,32,1,2);put(raw,112,1,2,1);put(raw,368,8)
        self.assertEqual(focus.sample_witness(raw)['slot'],8)
        put(raw,368,0)
        with self.assertRaises(ValueError):focus.sample_witness(raw)



class PaidBankPublication(unittest.TestCase):
    def test_absent_task_publication_never_hides_fault_payload(self):
        for fault in (False,True):
            tasks=bytearray(256)
            if fault:put(tasks,16,1,1)
            with self.subTest(fault=fault),self.assertRaises(ValueError):focus.paid_bank_facts(tasks,bytes(512),bytes(512))
        tasks=bytearray(256);put(tasks,0,0x43595441534b0001)
        self.assertEqual(focus.paid_bank_facts(tasks,bytes(512),bytes(512))['quarantine_mask'],0)



class CaptureRootAdmission(unittest.TestCase):
    def test_capture_symlink_is_rejected_before_caller_context_or_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'actual').mkdir();(root/'linked').symlink_to(root/'actual')
            context={name:root for name in ('source_root','build_manifest','formatter','qemu_binary','qemu_source')}
            with self.assertRaisesRegex(ValueError,'linked capture'):
                focus.verify_focus_capture(root/'linked',**context)




def warm_failure_fixture():
    raw=bytearray(256)
    put(raw,0,2,0x4359505746413136,1,2,6,1,1,9,10,2100000000,2100001000,2000000000,0,2,0,256,0,0,1,1,0,2,2100000000,0,1000000000,1,8,0,0,0)
    return raw


class FocusFirstCauseDiagnostics(unittest.TestCase):
    def test_exact_native_symbols_are_mandatory_bounded_and_distinct(self):
        from unittest.mock import patch
        expected={'replay_owner_first':('REPLAY_OWNER_EVIDENCE',256),'prewarm_first_failure':('LEARNING_PREWARM_FIRST_FAILURE',256),'prewarm_progress':('CORESET_PREWARM_PROGRESS',1024)}
        self.assertEqual(focus.FOCUS_DIAGNOSTICS,expected)
        def lookup(image,name):
            index=list(value[0] for value in expected.values()).index(name)
            return dict(va=0xffffffc040200000+2048*index,pa=0x40200000+2048*index,size=list(expected.values())[index][1])
        with patch.object(focus,'symbol',side_effect=lookup):self.assertEqual(set(focus.focus_diagnostic_symbols(b'ELF')),set(expected))
        for location in (dict(va=1,pa=0x40200000,size=255),dict(va=1,pa=0x40200001,size=256),dict(va=1,pa=0x80000000,size=256)):
            with self.subTest(location=location),patch.object(focus,'symbol',return_value=location),self.assertRaises(ValueError):focus.focus_diagnostic_symbols(b'ELF')

    def test_actual_firstcause_abi_retains_original_auth_and_absent_clock(self):
        parsed=focus.decode_focus_diagnostic('prewarm_first_failure',warm_failure_fixture())
        self.assertEqual(parsed['site'],'finish_auth');self.assertEqual(parsed['original_error_code'],6)
        self.assertEqual(parsed['observed_clock_ns'],0);self.assertEqual(parsed['attempt_session'],9)
        self.assertFalse(parsed['clock_observed']);self.assertTrue(parsed['current_session_observed'])
        self.assertFalse(parsed['authorizes_replay'])
        for at,value in ((0,4),(8,1),(16,2),(24,9),(152,2),(200,2),(208,16),(240,1)):
            raw=warm_failure_fixture();put(raw,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):focus.decode_focus_diagnostic('prewarm_first_failure',raw)
        with self.assertRaises(ValueError):focus.decode_focus_diagnostic('prewarm_first_failure',bytes(255))
        empty=focus.decode_focus_diagnostic('prewarm_first_failure',bytes(256));self.assertFalse(empty['observed'])
        partial=warm_failure_fixture();put(partial,0,1)
        self.assertEqual(focus.decode_focus_diagnostic('prewarm_first_failure',partial)['state'],'partial')

    def test_both_failure_banks_are_saved_even_if_one_read_fails(self):
        import run_v16_a03_focus as runner
        locations={key:dict(pa=0x40200000+512*i,va=1,size=width) for i,(key,(_,width)) in enumerate(focus.FOCUS_DIAGNOSTICS.items())}
        calls=[]
        def save(name,address,size):
            calls.append((name,address,size))
            if name=='diagnostic-replay_owner_first.bin':raise OSError('first bank read failed')
            return bytes(size)
        result=runner.capture_diagnostics(save,locations)
        self.assertEqual([name for name,_,_ in calls],['diagnostic-'+key+'.bin' for key in focus.FOCUS_DIAGNOSTICS])
        self.assertIn('replay_owner_first',result['errors']);self.assertFalse(result['facts']['prewarm_first_failure']['observed'])
        self.assertFalse(result['authorizes_replay'])



class FocusDiagnosticFailureAccounting(unittest.TestCase):
    def test_owner_first_phase_and_causal_error_are_observation_only(self):
        raw=bytearray(256);put(raw,0,2,0x4359524f574e3133,1,3,2,6,6,0,0,200,0,0,0,0,1,2)
        put(raw,31*8,100)
        fact=focus.decode_focus_diagnostic('replay_owner_first',raw)
        self.assertEqual(fact['original_error_code'],6);self.assertEqual(fact['failed_ns'],200)
        self.assertEqual(fact['service_entry_ns'],100);self.assertFalse(fact['authorizes_replay'])
        for at,value in ((0,0),(8,1),(16,2),(32,99),(40,0),(72,99),(31*8,0)):
            changed=bytearray(raw);put(changed,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):focus.decode_focus_diagnostic('replay_owner_first',changed)

    def test_bad_width_short_read_and_parse_failure_still_attempt_every_bank(self):
        import run_v16_a03_focus as runner
        for fault in ('width','short','parse'):
            locations={key:dict(pa=0x40200000+512*i,va=1,size=width) for i,(key,(_,width)) in enumerate(focus.FOCUS_DIAGNOSTICS.items())}
            calls=[]
            if fault=='width':locations['replay_owner_first']['size']=512*1024+1
            def save(name,address,size):
                calls.append(name)
                if name=='diagnostic-replay_owner_first.bin':
                    return bytes(size-1) if fault=='short' else b'X'*size
                return bytes(size)
            result=runner.capture_diagnostics(save,locations)
            self.assertIn('replay_owner_first',result['errors'])
            self.assertIn('diagnostic-prewarm_first_failure.bin',calls)
            self.assertFalse(result['facts']['prewarm_first_failure']['observed'])



class RequiredFocusDiagnosticFiles(unittest.TestCase):
    def test_successful_diagnostic_profile_requires_both_exact_raw_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with self.assertRaises(ValueError):focus.focus_diagnostic_files(root)
            for key,(_,width) in focus.FOCUS_DIAGNOSTICS.items():(root/('diagnostic-'+key+'.bin')).write_bytes(bytes(width))
            facts=focus.focus_diagnostic_files(root)
            self.assertEqual(set(facts),set(focus.FOCUS_DIAGNOSTICS))
            self.assertTrue(all(not value['authorizes_replay'] for value in facts.values()))
            (root/'diagnostic-prewarm_first_failure.bin').write_bytes(bytes(255))
            with self.assertRaises(ValueError):focus.focus_diagnostic_files(root)



class DiagnosticReadCustody(unittest.TestCase):
    def fixture(self,root):
        locations={key:dict(pa=0x40200000+2048*i,size=width) for i,(key,(_,width)) in enumerate(focus.FOCUS_DIAGNOSTICS.items())}
        rows=[dict(direction='receive',message={'QMP':{}})];number=0
        def command(name,args=None,result=None):
            nonlocal number
            number+=1;message=dict(execute=name,id=number)
            if args is not None:message['arguments']=args
            rows.append(dict(direction='send',message=message));rows.append(dict(direction='receive',message={'id':number,'return':{} if result is None else result}))
        command('cont');command('stop');command('query-status',result={'status':'paused'})
        for key,location in locations.items():
            path=root/('diagnostic-'+key+'.bin');path.write_bytes(bytes(location['size']))
            command('pmemsave',dict(val=location['pa'],size=location['size'],filename=str(path)))
        command('quit')
        return rows,dict(diagnostic_symbols=locations)

    def test_required_files_need_both_successful_final_paused_reads(self):
        import copy
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();rows,context=self.fixture(root)
            self.assertEqual(set(focus.verify_focus_diagnostic_reads(rows,root,context)),set(focus.FOCUS_DIAGNOSTICS))
            for mutation in ('missing','pa','width','file','before-pause','after-quit','failed-response','resume-after-read'):
                changed=copy.deepcopy(rows)
                read=next(r for r in changed if r['direction']=='send' and r['message'].get('execute')=='pmemsave')
                index=changed.index(read)
                if mutation=='missing':del changed[index:index+2]
                elif mutation=='pa':read['message']['arguments']['val']+=64
                elif mutation=='width':read['message']['arguments']['size']=255
                elif mutation=='file':read['message']['arguments']['filename']=str(root/'orphan.bin')
                elif mutation=='before-pause':changed[6]['message']['return']={'status':'running'}
                elif mutation=='after-quit':changed[index:index+2],changed[-2:]=changed[-2:],changed[index:index+2]
                elif mutation=='failed-response':changed[index+1]['message']={'id':read['message']['id'],'error':{'class':'GenericError'}}
                else:
                    changed[index+2:index+2]=[dict(direction='send',message={'execute':'cont','id':99}),dict(direction='receive',message={'id':99,'return':{}})]
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):focus.verify_focus_diagnostic_reads(changed,root,context)



class FailedDiagnosticProjection(unittest.TestCase):
    def test_expected_failure_retains_error_and_never_promotes_pair_or_sample_flags(self):
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for key,(_,width) in focus.FOCUS_DIAGNOSTICS.items():(root/('diagnostic-'+key+'.bin')).write_bytes(bytes(width))
            artifacts=focus.bounded_inventory(root)
            summary=dict(version=focus.VERSION,status='FAIL',capture_complete=False,released_pair_observed=False,error='original native replay error/exclusion',artifacts=artifacts)
            (root/'summary.json').write_text(json.dumps(summary))
            inventory=focus.bounded_inventory(root)
            checked=dict(raw_inventory=inventory,trusted_context={'fixed':'caller context'},diagnostic_reads={'fixture':'synthetic already-checked custody seam'},boot_epoch=1)
            with patch.object(focus,'_verify_capture_custody',return_value=checked) as base,patch.object(focus,'trusted_context',return_value=checked['trusted_context']):
                result=focus.verify_diagnostic_capture(root,source_root=root,build_manifest=root,formatter=root,qemu_binary=root,qemu_source=root)
            self.assertEqual(base.call_args.kwargs['terminal_contract'],'pre-collection-diagnostic-failure')
            self.assertEqual(result['status'],'FAIL');self.assertIn('original native replay',result['original_failure'])
            self.assertTrue(result['diagnostic_custody_verified'])
            for key in ('capture_complete','released_pair_observed','reward_numeric_verified','protected_sample_export_verified','native_acceptance_inferred_from_trusted_producer','accepted_training_sample_verified','model_trained','authorizes_replay'):
                self.assertIs(result[key],False,key)
            self.assertEqual(result['native_acceptance_status'],'NOT_RUN')
            summary['artifacts'].pop(next(iter(artifacts)))
            (root/'summary.json').write_text(json.dumps(summary));checked['raw_inventory']=focus.bounded_inventory(root)
            with patch.object(focus,'_verify_capture_custody',return_value=checked),self.assertRaisesRegex(ValueError,'inventory'):
                focus.verify_diagnostic_capture(root,source_root=root,build_manifest=root,formatter=root,qemu_binary=root,qemu_source=root)

    def test_failure_contract_requires_final_raw_standard_banks_too(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();rows,context=DiagnosticReadCustody().fixture(root)
            with self.assertRaisesRegex(ValueError,'both exact paused'):
                focus.verify_failure_diagnostic_reads(rows,root,context)




def positive_prewarm_fixture():
    raw=bytearray(1024);put(raw,0,8,0x4359505750523136,1,20000000000,25,1,2,0,1)
    put(raw,47*8,100,100,1150000000,1000000000,0)
    for i in range(16):put(raw,(52+i)*8,1000000000+i*10000000)
    put(raw,76*8,0,0,2000000000,16,1000000000,0,1)
    return raw


class PositivePrewarmStatus(unittest.TestCase):
    def test_positive_symbol_is_exact_and_custodied_with_both_first_banks(self):
        self.assertEqual(focus.FOCUS_DIAGNOSTICS['prewarm_progress'],('CORESET_PREWARM_PROGRESS',1024))
        self.assertEqual(focus.FOCUS_DIAGNOSTICS['replay_owner_first'],('REPLAY_OWNER_EVIDENCE',256))
        self.assertEqual(focus.FOCUS_DIAGNOSTICS['prewarm_first_failure'],('LEARNING_PREWARM_FIRST_FAILURE',256))
        from unittest.mock import patch
        names={name:dict(va=1,pa=0x40200000+2048*i,size=width) for i,(name,width) in enumerate(focus.FOCUS_DIAGNOSTICS.values())}
        with patch.object(focus,'symbol',side_effect=lambda image,name:names[name]):
            self.assertEqual(set(focus.focus_diagnostic_symbols(b'ELF')),set(focus.FOCUS_DIAGNOSTICS))
        names['CORESET_PREWARM_PROGRESS']['size']=512
        with patch.object(focus,'symbol',side_effect=lambda image,name:names[name]),self.assertRaises(ValueError):focus.focus_diagnostic_symbols(b'ELF')

    def test_final_complete_reset_session_and_stale_actual_times_are_observations(self):
        raw=positive_prewarm_fixture();result=focus.decode_focus_diagnostic('prewarm_progress',raw)
        self.assertEqual(result['state'],'published');self.assertEqual(result['producer_phase'],25)
        self.assertEqual(result['prewarm']['session'],0)
        self.assertEqual(result['prewarm']['completion_times_ns'],[1000000000+i*10000000 for i in range(16)])
        self.assertEqual(result['completion_window_as_of_sample']['sampled_ns'],20000000000)
        self.assertEqual(result['completion_window_as_of_sample']['within_one_second_count'],0)
        self.assertFalse(result['readiness_asserted']);self.assertFalse(result['authorizes_replay'])
        self.assertEqual(result['prewarm']['completed_before'],100)

    def test_current_queue_result_reason_and_sample_identity_are_retained(self):
        raw=positive_prewarm_fixture();put(raw,3*8,2000000000);put(raw,9*8,4,1,2,1000000000,6,1,0x434f5245,1,1)
        put(raw,18*8,9,1,1,0x434f5245,1,0,0,0,0,1,2,20,1800000000,1900000000,1,0,1,1900000000,1900000010,3,1,0,1,1900000000,1900000100)
        put(raw,43*8,7,1,0,0);put(raw,76*8,2,1)
        result=focus.decode_focus_diagnostic('prewarm_progress',raw)
        self.assertEqual(result['preparation']['id'],4);self.assertEqual(result['queue']['has_scope'],False)
        self.assertEqual(result['warm']['phase'],2);self.assertEqual(result['warm']['result_tag'],1)
        self.assertEqual(result['primary']['phase'],3);self.assertEqual(result['hint_reason'],'retired_ready')
        self.assertEqual(result['completion_window_as_of_sample']['within_one_second_count'],16)
        self.assertFalse(result['readiness_asserted'])

    def test_empty_partial_and_published_zero_state_never_grant_authority(self):
        self.assertEqual(focus.decode_focus_diagnostic('prewarm_progress',bytes(1024))['state'],'empty')
        partial=positive_prewarm_fixture();put(partial,0,9)
        self.assertEqual(focus.decode_focus_diagnostic('prewarm_progress',partial)['state'],'partial')
        raw=bytearray(1024);put(raw,0,2,0x4359505750523136,1,100)
        result=focus.decode_focus_diagnostic('prewarm_progress',raw)
        self.assertEqual(result['prewarm']['completion_times_ns'],[0]*16);self.assertFalse(result['authorizes_replay'])

    def test_status_abi_negative_fields_are_bounded(self):
        for at,value in ((0,0),(8,1),(16,2),(8*8,3),(23*8,2),(28*8,4),(32*8,3),(38*8,3),(44*8,2),(76*8,4),(82*8,2),(86*8,2),(91*8,1),(127*8,1)):
            raw=positive_prewarm_fixture();put(raw,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):focus.decode_focus_diagnostic('prewarm_progress',raw)
        with self.assertRaises(ValueError):focus.decode_focus_diagnostic('prewarm_progress',bytes(1023))



class PositivePrewarmReadCustody(unittest.TestCase):
    def test_status1024_read_is_required_with_exact_metadata_not_an_orphan(self):
        import copy
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();rows,context=DiagnosticReadCustody().fixture(root)
            payload=positive_prewarm_fixture();(root/'diagnostic-prewarm_progress.bin').write_bytes(payload)
            receipts=focus.verify_focus_diagnostic_reads(rows,root,context)
            self.assertEqual(receipts['prewarm_progress']['bytes'],1024)
            self.assertEqual(receipts['prewarm_progress']['sha256'],hashlib.sha256(payload).hexdigest())
            for mutation in ('missing-status-read','wrong-width','wrong-pa','wrong-file'):
                changed=copy.deepcopy(rows)
                read=next(r for r in changed if r['direction']=='send' and r['message'].get('arguments',{}).get('filename')==str(root/'diagnostic-prewarm_progress.bin'))
                index=changed.index(read)
                if mutation=='missing-status-read':del changed[index:index+2]
                elif mutation=='wrong-width':read['message']['arguments']['size']=512
                elif mutation=='wrong-pa':read['message']['arguments']['val']+=64
                else:read['message']['arguments']['filename']=str(root/'different-positive-bank.bin')
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):focus.verify_focus_diagnostic_reads(changed,root,context)

    def test_timestamp_observations_after_sample_are_retained_without_readiness_claim(self):
        raw=positive_prewarm_fixture();put(raw,52*8,21000000000)
        result=focus.decode_focus_diagnostic('prewarm_progress',raw)
        self.assertEqual(result['prewarm']['completion_times_ns'][0],21000000000)
        self.assertEqual(result['completion_window_as_of_sample']['timestamps_after_sample_count'],1)
        self.assertFalse(result['readiness_asserted']);self.assertFalse(result['authorizes_replay'])



class PositivePreparationClaimObservation(unittest.TestCase):
    def test_claim_original_snapshot_and_deadline_are_reported_without_refresh(self):
        raw=positive_prewarm_fixture();put(raw,86*8,1,42,2000000000,2050000000,3)
        result=focus.decode_focus_diagnostic('prewarm_progress',raw)
        self.assertEqual(result['primary_preparation_claim'],dict(present=True,sequence=42,snapshot_taken_ns=2000000000,original_deadline_ns=2050000000,last_retire_reason_code=3))
        self.assertEqual(result['sampled_ns'],20000000000)
        self.assertFalse(result['authorizes_replay']);self.assertFalse(result['readiness_asserted'])

if __name__=='__main__': unittest.main()
