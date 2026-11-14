"""Released ownership and explicit-caller custody regressions (no native VM)."""
import importlib.util
import struct
import unittest


def api():
    spec = importlib.util.find_spec('v16_learning_pair')
    assert spec is not None, 'missing standalone released-pair capture behavior'
    import v16_learning_pair
    return v16_learning_pair


def bank(**changes):
    words = [0] * 64
    for index, value in {0: 2, 1: 0x435952504c593133, 2: 0, 3: 1, 4: 1,
                         10: 2, 17: 2, 19: 1, **{int(k): v for k, v in changes.items()}}.items():
        words[index] = value
    return struct.pack('<64Q', *words)


class ReleasedBoundary(unittest.TestCase):
    def test_released_prepare_accepts_zero_current_boot_without_inventing_archive_identity(self):
        result = api().released_pair_candidate(bank())
        self.assertEqual(result['paired'], 1)
        self.assertNotIn('group', result)
        self.assertNotIn('boot_epoch', result)

    def test_paired_counter_before_archive_retirement_is_not_released(self):
        for index, value in ((10, 1), (17, 1), (19, 0)):
            with self.subTest(index=index):
                self.assertIsNone(api().released_pair_candidate(bank(**{str(index): value})))

    def test_archive_readback_and_live_scopes_are_not_released(self):
        for index in (9, 13, 14, 15, 16, 20, 63):
            with self.subTest(index=index):
                self.assertIsNone(api().released_pair_candidate(bank(**{str(index): 1})))

    def test_wrong_phase_unpublished_torn_short_or_wrong_magic_cannot_authorize_stop(self):
        for changes in ({'0': 0}, {'0': 3}, {'1': 1}, {'2': 16}):
            self.assertIsNone(api().released_pair_candidate(bank(**changes)))
        self.assertIsNone(api().released_pair_candidate(bytes(511)))
        self.assertIsNotNone(api().released_pair_candidate(bank(**{'2': 17})))

    def test_errors_and_exclusions_never_become_success(self):
        for index in (11, 12, 21):
            self.assertIsNone(api().released_pair_candidate(bank(**{str(index): 1})))


class Lifecycle(unittest.TestCase):
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
   w=[0]*64;w[0]=2;w[1]=0x435952504c593133;w[10]=w[17]=2;w[19]=1
   if paused and stops==1 and mode in ('torn','moved'):w[0]=3 if mode=='torn' else 2;w[20]=int(mode=='moved')
   if mode=='excluded':w[11]=1
   data=struct.pack('<64Q',*w)
  if a['val']==2048 and mode=='optimization':
   w=[0]*512;w[160]=0x43594f5053540001;w[161]=1;w[162]=1;w[191]=2;data=struct.pack('<512Q',*w)
  pathlib.Path(a['filename']).write_bytes(data)
 sock.sendall((json.dumps({'id':m['id'],'return':value})+'\n').encode())
 if c=='quit':break
sock.close();listener.close()
'''

    def exercise(self, mode='good', attempts=64, close_error=False):
        import json, socket, subprocess, sys, tempfile, time
        from pathlib import Path
        self.assertIsNotNone(importlib.util.find_spec('run_v16_learning_pair'),
                             'missing stopped-capture process lifecycle')
        import run_v16_learning_pair as runner
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
                symbols={key:{'pa': {'replay':1024,'control':2048}.get(key,4096), 'size':size}
                         for key,(_,size) in api().BANKS.items()}
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
        import run_v16_learning_pair as runner
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
        self.assertEqual(files['replay.bin'],bank(**{'3':0,'4':0}))
        names=[r['message']['execute'] for r in rows if r['direction']=='send']
        self.assertEqual(names[-1],'quit')
        self.assertLess(names.index('stop'),names.index('query-status'))

    def test_torn_or_moved_stopped_hint_resumes_instead_of_publishing_it(self):
        for mode in ('torn','moved'):
            failure,_,rows,files=self.exercise(mode)
            self.assertIsNone(failure)
            self.assertIsNotNone(api().released_pair_candidate(files['replay.bin']))
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

class FailureFinalization(unittest.TestCase):
    def test_finalization_io_failure_preserves_original_error_and_attempts_other_outputs(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import run_v16_learning_pair as runner
        for broken in ('process-exit.json','serial.bin','disk-after.json'):
            with self.subTest(broken=broken),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();build=root/'build';build.mkdir();output=root/'capture'
                (build/'node-a.elf').write_bytes(b'image');(build/'build-manifest.json').write_text('{}')
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


class Provenance(unittest.TestCase):
    def test_caller_source_and_normal_profile_mismatch_rejected_before_native_start(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import v16_learning_pair as module
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();(root/'tools').mkdir();(root/'tools/build_unified.py').write_text('builder')
            exe=root/'exe';exe.write_text('#!/bin/sh\nexit 0\n');exe.chmod(0o700)
            build=root/'build-manifest.json'
            manifest={'schema_version':1,'status':'BUILT_NOT_RUN','profiles':{'selftest':True,'fault':'normal'},
                      'code_source_map':{'kernel':'wrong'},'builder_sha256':module.sha(root/'tools/build_unified.py')}
            build.write_text(json.dumps(manifest))
            kwargs=dict(source_root=root,build_manifest=build,formatter=exe,qemu_binary=exe,qemu_source=root)
            with patch.object(module,'code_source_map',return_value={'kernel':'actual'}), \
                 patch.object(module,'attest_qemu',side_effect=AssertionError('executable must not run')):
                with self.assertRaisesRegex(ValueError,'source/build'):
                    module.trusted_context(**kwargs)
                manifest['code_source_map']={'kernel':'actual'}
                for key,value in (('fault','hang-once'),('selftest',False),('storage_fault',True),('leave',True),('runtime_fault','active')):
                    changed=json.loads(json.dumps(manifest));changed['profiles'][key]=value
                    build.write_text(json.dumps(changed))
                    with self.subTest(key=key),self.assertRaisesRegex(ValueError,'profile'):
                        module.trusted_context(**kwargs)

    def fixture(self,root):
        import hashlib,json,time
        from pathlib import Path
        from test_verify_v13_boot_recovery import fixture,packed
        from run_v13_a02 import config_write_packet
        import v16_learning_pair as module
        context={'version':module.VERSION,'paths':{'source_root':'/caller/source','build_manifest':'/caller/build',
                 'formatter':'/caller/formatter','qemu_binary':'/caller/qemu','qemu_source':'/caller/qemu-source'},
                 'artifacts':{},'source_map':{},'tools':{},'node_id':'ab'*32,'model_sha256':hashlib.sha256(b'model').hexdigest(),
                 'model_generation':1,'schema_hash':'cd'*32,
                 'diagnostic_symbols':{},'symbols':{key:{'pa':(i+1)*8192,'size':size} for i,(key,(_,size)) in enumerate(module.BANKS.items())}}
        inputs=dict(version=module.VERSION,mode=0,nonce='11'*16,disk_uuid='22'*16,timeout_seconds=600,
                    poll_seconds=.1,serial_seconds=1,max_stopped_attempts=64,disk_origin={'kind':'fresh'},
                    scope='released local pair observation; no native acceptance')
        module.write_json(root/'input.json',inputs);module.write_json(root/'source-manifest.json',{})
        (root/'build-manifest.json').write_bytes(b'build');context['build_sha256']=module.sha(root/'build-manifest.json')
        (root/'model.bin').write_bytes(b'model')
        config=struct.pack('<4Q',0x4359584130314346,1,0,0)+bytes.fromhex(inputs['nonce'])+bytes.fromhex('33'*32)+bytes.fromhex(module.sha(root/'input.json'))+bytes.fromhex(module.sha(root/'source-manifest.json'))+bytes(368)
        context['artifacts']['node-a.elf']='33'*32
        (root/'node-a.elf').write_bytes(b'image')
        # The expected actual image hash replaces the hand-selected config digest.
        context['artifacts']['node-a.elf']=module.sha(root/'node-a.elf')
        config=config[:48]+bytes.fromhex(context['artifacts']['node-a.elf'])+config[80:]
        (root/'config.bin').write_bytes(config);(root/'config-observed.bin').write_bytes(config)
        first,_,_=fixture(0);first[32:46]=struct.unpack('<64Q',config)[4:18]
        for key,(_,size) in module.BANKS.items():
            if key!='config':(root/(key+'.bin')).write_bytes(packed(first) if key=='boot' else bank() if key=='replay' else bytes(size))
        (root/'serial.bin').write_bytes(b'');(root/'serial.txt').write_bytes(b'')
        module.write_json(root/'native-context.json',context)
        module.write_json(root/'process-exit.json',dict(schema=1,pid=123,peer_pid=123,started_ns=1,exited_ns=2,
                          returncode=0,forced=False,quit_ok=True,eof=True,errors=[]))
        module.write_json(root/'platform.json',dict(cpus=[{'cpu-index':i} for i in range(4)],memory={'base-memory':1024**3}))
        dtb=struct.pack('>2I',0xd00dfeed,40)+bytes(32)
        (root/'dtb-header.bin').write_bytes(dtb);(root/'platform.dtb').write_bytes(dtb)
        module.write_json(root/'formatter-command.json',dict(argv=['/caller/formatter',str(root/'disk.raw'),inputs['disk_uuid']]))
        (root/'format.log').write_bytes(b'formatted fixture')
        with (root/'disk.raw').open('wb') as stream:stream.truncate(512*1024**2)
        module.write_json(root/'disk-before.json',dict(bytes=512*1024**2,sha256='44'*32))
        module.write_json(root/'disk-after.json',dict(bytes=512*1024**2,sha256=module.sha(root/'disk.raw')))
        packet=config_write_packet(config,context['symbols']['config']['pa'])
        module.write_json(root/'config-injection.json',dict(request_hex=packet.hex(),received_hex='2b244f4b233961',ack_hex='2b'))
        launch=dict(argv=module.launch_argv('/caller/qemu',root,'/tmp/q.sock','/tmp/g.sock',1234),
                    qmp='/tmp/q.sock',gdb='/tmp/g.sock',port=1234,symbols=context['symbols'])
        module.write_json(root/'launch.json',launch)
        rows=[]
        def command(name,args=None,result=None):
            m={'execute':name,'id':len(rows)//2+1}
            if args is not None:m['arguments']=args
            rows.extend([{'direction':'send','message':m},{'direction':'receive','message':{'id':m['id'],'return':{} if result is None else result}}])
        rows.append({'direction':'receive','message':{'QMP':{}}})
        command('qmp_capabilities');command('query-cpus-fast',result=[{'cpu-index':i} for i in range(4)])
        command('query-memory-size-summary',result={'base-memory':1024**3})
        command('pmemsave',dict(val=0x40000000,size=40,filename=str(root/'dtb-header.bin')))
        command('pmemsave',dict(val=0x40000000,size=40,filename=str(root/'platform.dtb')))
        command('pmemsave',dict(val=context['symbols']['config']['pa'],size=512,filename=str(root/'config-observed.bin')))
        command('cont');command('stop');command('query-status',result={'status':'paused'})
        for key,(_,size) in module.BANKS.items():
            if key!='config':
                target=root/f'probe-01-{key}.bin'
                target.write_bytes((root/(key+'.bin')).read_bytes())
                command('pmemsave',dict(val=context['symbols'][key]['pa'],size=size,filename=str(target)))
        for key,(_,size) in module.BANKS.items():
            if key!='config':command('pmemsave',dict(val=context['symbols'][key]['pa'],size=size,filename=str(root/(key+'.bin'))))
        command('quit')
        self.save_rows(root,rows)
        return context,rows

    def save_rows(self,root,rows):
        import json
        api().write_json(root/'qmp-transcript.json',rows)
        for direction,name in (('send','qmp-sent.bin'),('receive','qmp-received.bin')):
            (root/name).write_bytes(b''.join((json.dumps(r['message'])+'\n').encode() for r in rows if r['direction']==direction))

    def test_independent_replay_derives_boundary_without_summary_booleans(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=api()
        self.assertTrue(hasattr(module,'verify_capture'),'missing independent caller-trusted replay')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();context,_=self.fixture(root)
            module.write_json(root/'summary.json',{'status':'FAIL','capture_complete':True})
            with patch.object(module,'trusted_context',return_value=context):
                checked=module.verify_capture(root,**context['paths'])
            self.assertTrue(checked['released_pair_observed'])
            self.assertFalse(checked['capture_complete'])
            self.assertFalse(checked['reward_replay_verified'])
            self.assertEqual(checked['boot_epoch'],1)

    def test_replay_requires_complete_retained_probe_artifacts_and_final_equality(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=api()
        for change in ('missing','short','modified','incomplete','no-probes'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();context,rows=self.fixture(root)
                probe=root/'probe-01-replay.bin'
                if change=='missing':probe.unlink()
                elif change=='short':probe.write_bytes(bytes(511))
                elif change=='modified':probe.write_bytes(bank(**{'19':2}))
                else:
                    names={'probe-01-unified.bin'} if change=='incomplete' else {f'probe-01-{key}.bin' for key in module.BANKS if key!='config'}
                    kept=[];skip_id=None
                    for row in rows:
                        if row['direction']=='send' and Path(row['message'].get('arguments',{}).get('filename','')).name in names:
                            skip_id=row['message']['id'];continue
                        if skip_id is not None and row['direction']=='receive' and row['message'].get('id')==skip_id:continue
                        kept.append(row)
                    ident=0
                    for row in kept:
                        if row['direction']=='send':ident+=1;row['message']['id']=ident
                        elif 'id' in row['message']:row['message']['id']=ident
                    self.save_rows(root,kept)
                with patch.object(module,'trusted_context',return_value=context),self.assertRaises(ValueError):
                    module.verify_capture(root,**context['paths'])

    def test_replay_checks_every_resumed_attempt_before_selecting_second_probe(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=api()
        for damaged in (None,'missing-prior','valid-prior','excluded-prior'):
            with self.subTest(damaged=damaged),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();context,rows=self.fixture(root)
                for row in rows:
                    message=row['message'];args=message.get('arguments',{})
                    filename=args.get('filename','')
                    if 'probe-01-' in filename:
                        destination=Path(filename.replace('probe-01-','probe-02-'))
                        destination.write_bytes(Path(filename).read_bytes());args['filename']=str(destination)
                prior=[]
                def command(name,args=None,result=None):
                    message={'execute':name,'id':0}
                    if args is not None:message['arguments']=args
                    prior.extend([{'direction':'send','message':message},
                                  {'direction':'receive','message':{'id':0,'return':{} if result is None else result}}])
                command('stop');command('query-status',result={'status':'paused'})
                for key,(_,size) in module.BANKS.items():
                    if key=='config':continue
                    target=root/f'probe-01-{key}.bin'
                    if key=='replay':target.write_bytes(bank(**({'0':3} if damaged!='valid-prior' else {})))
                    if key=='replay' and damaged=='excluded-prior':target.write_bytes(bank(**{'11':1}))
                    command('pmemsave',dict(val=context['symbols'][key]['pa'],size=size,filename=str(target)))
                command('cont')
                position=next(i for i,row in enumerate(rows) if row['direction']=='send' and row['message'].get('execute')=='stop')
                rows[position:position]=prior
                ident=0
                for row in rows:
                    if row['direction']=='send':ident+=1;row['message']['id']=ident
                    elif 'id' in row['message']:row['message']['id']=ident
                self.save_rows(root,rows)
                if damaged=='missing-prior':(root/'probe-01-runtime.bin').unlink()
                with patch.object(module,'trusted_context',return_value=context):
                    if damaged is None:self.assertTrue(module.verify_capture(root,**context['paths'])['released_pair_observed'])
                    else:
                        with self.assertRaises(ValueError):module.verify_capture(root,**context['paths'])

    def test_replay_rejects_changed_caller_identity_files_commands_or_forced_exit(self):
        import copy,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=api()
        self.assertTrue(hasattr(module,'verify_capture'),'missing independent caller-trusted replay')
        for change in ('caller','source','tool','config','command','pause','process','serial','disk','address','ringbuf','query-args','event','id'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();context,rows=self.fixture(root);trusted=copy.deepcopy(context)
                if change=='caller':trusted['paths']['qemu_binary']='/another/executable'
                elif change=='source':trusted['source_map']={'kernel/x':'00'*32}
                elif change=='tool':trusted['tools']={'tools/other.py':'00'*32}
                elif change=='config':(root/'config.bin').write_bytes(bytes(512))
                elif change=='command':rows[9]['message']['execute']='human-monitor-command';self.save_rows(root,rows)
                elif change=='address':
                    for row in rows:
                        if row['direction']=='send' and row['message']['execute']=='pmemsave':
                            row['message']['arguments']['val']=0;break
                    self.save_rows(root,rows)
                elif change=='ringbuf':
                    rows.insert(-2,{'direction':'send','message':{'execute':'ringbuf-read','id':99,'arguments':{'device':'other'}}})
                    rows.insert(-2,{'direction':'receive','message':{'id':99,'return':''}});self.save_rows(root,rows)
                elif change=='query-args':rows[3]['message']['arguments']={'cpu':9};self.save_rows(root,rows)
                elif change=='event':
                    rows.insert(1,{'direction':'receive','message':{'event':'GUEST_PANICKED'}});self.save_rows(root,rows)
                elif change=='id':
                    rows[3]['message']['id']=rows[4]['message']['id']=1;self.save_rows(root,rows)
                elif change=='pause':
                    for row in rows:
                        if row['direction']=='receive' and row['message'].get('return')=={'status':'paused'}:row['message']['return']={'status':'running'}
                    self.save_rows(root,rows)
                elif change=='process':
                    record=__import__('json').loads((root/'process-exit.json').read_text());record['forced']=True
                    module.write_json(root/'process-exit.json',record)
                elif change=='serial':(root/'serial.bin').write_bytes(b'PANIC')
                elif change=='disk':(root/'disk.raw').write_bytes(b'changed')
                with patch.object(module,'trusted_context',return_value=trusted),self.assertRaises(ValueError):
                    module.verify_capture(root,**context['paths'])


class FrozenProducerProvenance(unittest.TestCase):
    def test_caller_frozen_root_is_ast_hashed_never_executed_and_keeps_five_paths(self):
        import hashlib, json, shutil, tempfile
        from pathlib import Path
        from unittest.mock import patch
        module = api()
        self.assertIn('producer_tools_root', __import__('inspect').signature(module.trusted_context).parameters,
                      'missing explicit frozen producer root')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.mkdir()
            (source / 'tools').mkdir(); (source / 'tools' / 'build_unified.py').write_bytes(b'builder')
            (source / 'crates/prototype/src').mkdir(parents=True)
            (source / 'crates/prototype/src/features.rs').write_bytes(b'features')
            frozen = root / 'frozen'; shutil.copytree(Path(module.__file__).resolve().parent, frozen / 'tools')
            producer = frozen / 'tools/v16_learning_pair.py'
            producer.write_text(producer.read_text() + "\nraise RuntimeError('MUST NOT EXECUTE FROZEN CODE')\n")
            executable = root / 'exe'; executable.write_text('#!/bin/sh\nexit 0\n'); executable.chmod(0o700)
            build = root / 'build'; build.mkdir()
            artifacts = {}
            for name in ('node-a.elf', 'service-a.elf', 'task.elf', 'node-a.pub'):
                (build / name).write_bytes(name.encode())
                artifacts[name] = dict(bytes=len(name), sha256=hashlib.sha256(name.encode()).hexdigest())
            manifest = dict(schema_version=1, status='BUILT_NOT_RUN', profiles={'selftest': True, 'fault': 'normal'},
                            code_source_map={'kernel': 'digest'}, builder_sha256=hashlib.sha256(b'builder').hexdigest(),
                            artifacts=artifacts, nodes={'a': {'node_id': artifacts['node-a.pub']['sha256']}})
            build_manifest = build / 'build-manifest.json'; build_manifest.write_text(json.dumps(manifest))
            args = dict(source_root=source, build_manifest=build_manifest, formatter=executable,
                        qemu_binary=executable, qemu_source=root)
            def symbol(_image, name):
                size = next((n for symbol, n in module.BANKS.values() if symbol == name), 16)
                return {'size': 2772 if name == 'A02_BOOT_MODEL' else size, 'va': 1, 'pa': 1}
            with patch.object(module, 'code_source_map', return_value={'kernel': 'digest'}), \
                 patch.object(module, 'inspect_elf'), patch.object(module, 'symbol', side_effect=symbol), \
                 patch.object(module, 'boot_profile', return_value=dict(version=1, ram_mib=1024, heap_pages=2048)), \
                 patch.object(module, 'loaded_bytes', return_value=b'M' * 2772), \
                 patch.object(module, 'attest_qemu', return_value={'qemu_pmu_patch_attested': True}):
                current = module.trusted_context(**args)
                retained = module.trusted_context(**args, producer_tools_root=frozen)
                self.assertEqual(set(retained['paths']), set(args))
                self.assertEqual(retained['paths'], current['paths'])
                self.assertEqual(len(retained['tools']), 44)
                self.assertEqual(retained['tools']['tools/v16_learning_pair.py'], hashlib.sha256(producer.read_bytes()).hexdigest())
                self.assertNotEqual(retained['tools'], current['tools'])
                for name in ('tools/build_sources.py','tools/elf64.py'):
                    shared=frozen/name;original=shared.read_bytes()
                    with self.subTest(shared_dependency=name):
                        self.assertIn(name,retained['tools'])
                        self.assertEqual(retained['tools'][name],hashlib.sha256(original).hexdigest())
                        shared.write_bytes(original+b'\nraise RuntimeError("MUST NOT EXECUTE SHARED FROZEN CODE")\n')
                        changed=module.trusted_context(**args,producer_tools_root=frozen)
                        self.assertEqual(set(changed['tools']),set(retained['tools']))
                        self.assertEqual(changed['tools'][name],hashlib.sha256(shared.read_bytes()).hexdigest())
                        self.assertEqual({key for key in retained['tools']
                            if changed['tools'][key]!=retained['tools'][key]},{name})
                        self.assertEqual(changed['paths'],retained['paths'])
                    shared.write_bytes(original)
                with self.assertRaises(FileNotFoundError):
                    module.trusted_context(**args, producer_tools_root=root / 'absent')
                producer.unlink()
                with self.assertRaises(ValueError):
                    module.trusted_context(**args, producer_tools_root=frozen)

    def test_frozen_replay_checks_all_hashes_and_receipt_cannot_select_root(self):
        import copy, hashlib, json, shutil, tempfile
        from pathlib import Path
        from unittest.mock import patch
        module = api()
        self.assertIn('producer_tools_root', __import__('inspect').signature(module.verify_capture).parameters,
                      'missing explicit frozen producer root replay')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); root = base / 'capture'; root.mkdir()
            context, _ = Provenance().fixture(root)
            frozen = base / 'frozen'; shutil.copytree(Path(module.__file__).resolve().parent, frozen / 'tools')
            path = frozen / 'tools/v16_learning_pair.py'
            path.write_text(path.read_text() + "\nraise RuntimeError('MUST NOT EXECUTE FROZEN CODE')\n")
            context['tools'] = module.tool_closure(frozen)
            for name in context['tools']:
                target = root / 'producer-tools' / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((frozen / name).read_bytes())
            module.write_json(root / 'native-context.json', context)
            def caller_context(*, producer_tools_root=None, **_args):
                result = copy.deepcopy(context)
                result['tools'] = module.tool_closure(module.TOOL_ROOT if producer_tools_root is None else producer_tools_root)
                return result
            module.write_json(root / 'summary.json', {'producer_tools_root': str(frozen), 'checker': str(path)})
            with patch.object(module, 'trusted_context', side_effect=caller_context):
                with self.assertRaisesRegex(ValueError, 'caller/source/build/tool context'):
                    module.verify_capture(root, **context['paths'])
                retained = module.verify_capture(root, producer_tools_root=frozen, **context['paths'])
                self.assertTrue(retained['released_pair_observed'])
                self.assertFalse(retained['capture_complete'])
                self.assertEqual(retained['producer_tools_root'], str(frozen.resolve()))
                self.assertEqual(retained['checker_identity']['tools']['tools/v16_learning_pair.py'],
                                 hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
                self.assertNotEqual(retained['checker_identity']['tools'], context['tools'])
                self.assertIn('version', retained['checker_identity'])
                for name in context['tools']:
                    target = root / 'producer-tools' / name
                    original = target.read_bytes(); target.write_bytes(original + b'\n# tampered\n')
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        module.verify_capture(root, producer_tools_root=frozen, **context['paths'])
                    target.write_bytes(original)
                path.write_text(path.read_text() + '\n# wrong caller producer hash\n')
                with self.assertRaisesRegex(ValueError, 'caller/source/build/tool context'):
                    module.verify_capture(root, producer_tools_root=frozen, **context['paths'])
                with self.assertRaises(FileNotFoundError):
                    module.verify_capture(root, producer_tools_root=base / 'absent', **context['paths'])
                # A native-context selector is extra data, not authority to select any root.
                changed = dict(context, producer_tools_root=str(frozen))
                module.write_json(root / 'native-context.json', changed)
                with self.assertRaises(ValueError):
                    module.verify_capture(root, **context['paths'])


if __name__ == '__main__':
    unittest.main()
