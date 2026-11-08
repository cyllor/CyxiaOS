"""Actual run_case with modeled QMP/DMA publication; never native acceptance."""
import base64
from contextlib import ExitStack
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import run_v13_boot_recovery as runner
import build_unified
from test_verify_v13_boot_recovery import fixture, packed
from test_verify_v15_a01 import fixture as formal_fixture
from test_verify_v13_boot_receipt import PLATFORM, ROOT, SYMBOLS, transcript
from verify_v13_boot_receipt import verify_qmp


class Clock:
    def __init__(self): self.value = 1.
    def monotonic(self): self.value += .01; return self.value
    def monotonic_ns(self): return int(self.value * 1e9)
    def sleep(self, seconds): self.value += seconds


class Socket:
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def bind(self, address): pass
    def getsockname(self): return ('127.0.0.1', 12345)
    def connect(self, path): pass
    def close(self): pass


class RunCaseStoppedPublication(unittest.TestCase):
    def capture(self, *, odd_stop=1, odd_formal_stop=None, ownership=False, bad_owner_stop=None,
                expected_error=None):
        # All control/verification functions below are real; only platform,
        # image construction and QMP I/O are modeled. The actual run_case
        # takes the live-even -> stopped-odd publication interleaving.
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(mock.patch.object(runner,'ROOT',Path(build_unified.__file__).resolve().parents[1]))
            root = Path(directory).resolve(); build = root/'build'; build.mkdir()
            image = build/'node-a.elf'; image.write_bytes(b'host-only-elf-fixture')
            source = {}; config = [None]; processes = []
            manifest = dict(profiles=dict(selftest=True, fault='normal'), code_source_map=source,
                builder_sha256=runner.sha(runner.ROOT/'tools/build_unified.py'),
                artifacts={'node-a.elf': {'sha256': runner.sha(image)}})
            (build/'build-manifest.json').write_text(json.dumps(manifest))
            names = ('boot','config','control','runtime','unified','formal','ownership')
            symbols = {name: {'pa': 0x41000000+i*0x10000,
                'size': 512 if name in ('boot','config') else 2048 if name=='formal' else 4096}
                for i,name in enumerate(names)}
            qmp_instances = []

            class Process:
                returncode = None
                def __init__(self, *args, **kwargs): processes.append(self)
                def poll(self): return self.returncode
                def wait(self, timeout): self.returncode = 0; return 0
                def kill(self): raise AssertionError('unexpected forced cleanup')

            class Qmp:
                def __init__(self, socket):
                    self.transcript = [{'direction':'receive','message':{'QMP':{}}}]
                    self.seq=0; self.stops=0; self.running=False
                    qmp_instances.append(self)
                def receive(self, deadline): return {'QMP':{}}
                def boot(self, odd=False):
                    sample, _, _ = fixture(1)
                    sample[2] = 2 + self.stops*2 + int(odd)
                    for i in (8,10,11,12,13): sample[i] += self.stops*10
                    sample[32:46] = struct.unpack('<64Q', config[0])[4:18]
                    return packed(sample)
                def execute(self, command, args=None):
                    self.seq+=1
                    request={'execute':command,'id':self.seq}
                    if args is not None: request['arguments']=args
                    self.transcript.append({'direction':'send','message':request})
                    response={}
                    if command=='query-cpus-fast': response=PLATFORM['cpus']
                    elif command=='query-memory-size-summary': response=PLATFORM['memory']
                    elif command=='query-status': response={'status':'paused','running':False}
                    elif command=='cont': self.running=True
                    elif command=='stop': self.stops+=1; self.running=False
                    elif command=='quit': processes[0].returncode=0
                    elif command=='ringbuf-read': response=base64.b64encode(b'').decode()
                    elif command=='human-monitor-command': response='host-only registers'
                    elif command=='pmemsave':
                        path=Path(args['filename']); name=path.name; size=args['size']
                        if name=='dtb-header.bin': data=struct.pack('>2I',0xd00dfeed,64)+bytes(32)
                        elif name=='config-observed.bin': data=config[0]
                        elif args['val']==symbols['boot']['pa']:
                            odd=(not self.running and (odd_stop=='all' or self.stops==odd_stop)
                                 and not name.startswith('failure-'))
                            data=self.boot(odd)
                        elif args['val']==symbols['formal']['pa']:
                            _, formal=formal_fixture(1)
                            formal[16:30]=struct.unpack('<64Q',config[0])[4:18]
                            if not self.running and self.stops==odd_formal_stop: formal[32]=1
                            data=struct.pack('<256Q',*formal)
                        elif args['val']==symbols['ownership']['pa']:
                            from test_verify_v15_ownership import fixture as owner_fixture
                            owner=owner_fixture()
                            owner[16:30]=struct.unpack('<64Q',config[0])[4:18]
                            if not self.running and self.stops==bad_owner_stop: owner[128]=3
                            data=struct.pack('<'+str(len(owner))+'Q',*owner)
                        else:data=bytes(size)
                        assert len(data)==size,(name,len(data),size)
                        path.write_bytes(data)
                    self.transcript.append({'direction':'receive','message':{'return':response,'id':self.seq}})
                    return response

            def prepare(output, formatter, uuid, previous):
                (output/'disk.raw').write_bytes(b'host-only-disk')
                (output/'format.log').write_bytes(b'host-only-formatter')
                return {'kind':'fresh'}
            def inject(path, value, address): config[0]=value; return {}
            def symbol(data, name):
                all_names=dict(runner.DEBUG_SYMBOLS)
                all_names.update(boot='A01_BOOT_EVIDENCE',config='A01_BOOT_CONFIG',
                    control='DOMAIN_CONTROL_EVIDENCE',runtime='RUNTIME_V13_EVIDENCE',
                    unified='UNIFIED_EVIDENCE',formal='A01_FORMAL_EVIDENCE',ownership='OWNERSHIP_V15_EVIDENCE')
                key=next((key for key,value in all_names.items() if value==name and key in symbols),None)
                if key is None: raise KeyError(name)
                if key=='ownership':
                    from verify_v15_ownership import WORDS
                    return dict(symbols[key],size=WORDS*8)
                return symbols[key]
            for name,value in dict(time=Clock(),Qmp=Qmp,code_source_map=lambda root:source,
                    prepare_disk=prepare,inspect_elf=lambda data:None,symbol=symbol,
                    inject_config=inject,attest_qemu=lambda *args:{}).items():
                stack.enter_context(mock.patch.object(runner,name,value))
            stack.enter_context(mock.patch.object(runner.socket,'socket',lambda *args:Socket()))
            stack.enter_context(mock.patch.object(runner.subprocess,'Popen',Process))
            result=runner.run_case(build,root/'capture',Path('/unused'),Path('/unused'),
                Path('/unused'),1,60,formal=True,ownership=ownership)
            if expected_error:
                self.assertEqual(result['status'],'FAIL')
                self.assertIn(expected_error,result['error'])
                self.assertEqual(processes[0].returncode,0)
                return qmp_instances[0]
            self.assertEqual(result['status'],'PASS',result.get('error'))
            launch=json.loads((root/'capture/launch.json').read_text())
            serial=verify_qmp(qmp_instances[0].transcript,(root/'capture').resolve(),
                launch['symbols'],64,PLATFORM,formal=True,ownership=ownership)
            self.assertEqual(serial,b'')
            self.assertEqual(processes[0].returncode,0)
            return qmp_instances[0]

    def test_live_even_then_first_stopped_odd_retries_before_authority(self):
        self.capture(odd_stop=1)

    def test_last_stopped_odd_retries_before_last_authority(self):
        self.capture(odd_stop=2)

    def test_stopped_formal_partial_retries_before_any_authority(self):
        self.capture(odd_stop=None,odd_formal_stop=1)

    def test_stopped_owner_partial_retries_before_any_authority(self):
        self.capture(odd_stop=None,ownership=True,bad_owner_stop=1)

    def test_repeated_odd_publication_is_bounded_and_never_publishes_authority(self):
        qmp=self.capture(odd_stop='all',expected_error='stopped candidate probe limit exceeded')
        names=[Path(row['message']['arguments']['filename']).name for row in qmp.transcript
            if row['direction']=='send' and row['message']['execute']=='pmemsave']
        from verify_v13_boot_receipt import MAX_STOPPED_PROBE_STOPS
        self.assertEqual(names.count('stopped-boot-probe.bin'),MAX_STOPPED_PROBE_STOPS)
        self.assertNotIn('first.bin',names)
        self.assertNotIn('last.bin',names)


class StoppedProbeCustody(unittest.TestCase):
    def entries(self):
        from test_verify_v15_a01 import FormalA01CaptureContract
        return FormalA01CaptureContract().calls()

    def check(self, entries):
        symbols=dict(SYMBOLS,formal={'pa':0x41600000})
        return verify_qmp(transcript(entries),ROOT,symbols,64,PLATFORM,formal=True)

    def probe(self, key='boot'):
        return ('pmemsave',{'val':SYMBOLS['boot']['pa'] if key=='boot' else 0x41600000,
            'size':512 if key=='boot' else 2048,'filename':str(ROOT/('stopped-'+key+'-probe.bin'))},{})

    def retry(self, probes=None):
        return [('stop',None,{}),('query-status',None,{'status':'paused','running':False})]+\
            ([self.probe()] if probes is None else probes)+[('cont',None,{})]

    def with_retry(self, retry):
        entries=self.entries(); at=next(i for i,e in enumerate(entries) if e[0]=='stop')
        return entries[:at]+retry+entries[at:]

    def test_probe_only_retry_before_any_authority_and_full_groups_are_valid(self):
        self.assertEqual(self.check(self.with_retry(self.retry())),b'raw serial')
        self.assertEqual(self.check(self.with_retry(self.retry([self.probe(),self.probe('formal')]))),b'raw serial')
        entries=[]
        for row in self.entries():
            entries.append(row)
            if row[0]=='query-status':entries.extend([self.probe(),self.probe('formal')])
        self.assertEqual(self.check(entries),b'raw serial')

    def test_probe_requires_verified_pause_and_exact_address_size_path(self):
        for mutation in ('running','unchecked','address','size','path'):
            retry=self.retry()
            if mutation=='running':retry=retry[2:]
            elif mutation=='unchecked':del retry[1]
            else:
                args=dict(retry[2][1]); key,value={'address':('val',0x40000000),
                    'size':('size',256),'path':('filename','/elsewhere/stopped-boot-probe.bin')}[mutation]
                args[key]=value;retry[2]=('pmemsave',args,{})
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                self.check(self.with_retry(retry))

    def test_duplicate_or_reordered_probes_and_incomplete_pair_before_authority_are_rejected(self):
        for probes in ([self.probe(),self.probe()],[self.probe('formal')],
                       [self.probe(),self.probe('formal'),self.probe('formal')]):
            with self.subTest(probes=probes),self.assertRaises(ValueError):
                self.check(self.with_retry(self.retry(probes)))
        entries=self.entries(); at=next(i for i,e in enumerate(entries) if e[0]=='query-status')
        entries.insert(at+1,self.probe())
        with self.assertRaisesRegex(ValueError,'authority before complete stopped candidate probes'):
            self.check(entries)

    def test_any_partial_authority_before_resume_or_subsequent_probe_is_rejected(self):
        for name,key,size in (('first.bin','boot',512),('last.bin','boot',512),
                              ('formal-first.bin','formal',2048)):
            address=SYMBOLS['boot']['pa'] if key=='boot' else 0x41600000
            authority=('pmemsave',{'val':address,'size':size,'filename':str(ROOT/name)},{})
            retry=self.retry([self.probe(),self.probe('formal'),authority])
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'resume after authority capture'):
                self.check(self.with_retry(retry))
            retry.insert(-1,self.probe())
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'stopped probe outside verified stop or after authority'):
                self.check(self.with_retry(retry))

    def test_only_probes_or_missing_final_authority_cannot_confer_pass(self):
        for filename in ('formal-first.bin','formal-last.bin','last.bin','control.bin'):
            entries=[e for e in self.entries() if not (e[0]=='pmemsave' and e[1]['filename'].endswith('/'+filename))]
            with self.subTest(filename=filename),self.assertRaises(ValueError):self.check(entries)
        entries=self.with_retry(self.retry())
        entries=[e for e in entries if not (e[0]=='pmemsave' and Path(e[1]['filename']).name in
            ('first.bin','last.bin','formal-first.bin','formal-last.bin','control.bin','runtime.bin','unified.bin'))]
        with self.assertRaises(ValueError):self.check(entries)

    def test_stopped_probe_rows_are_bounded(self):
        from verify_v13_boot_receipt import MAX_STOPPED_PROBE_STOPS
        entries=self.entries(); at=next(i for i,e in enumerate(entries) if e[0]=='stop')
        entries=entries[:at]+self.retry()*MAX_STOPPED_PROBE_STOPS+entries[at:]
        with self.assertRaisesRegex(ValueError,'too many stopped candidate probes'):self.check(entries)


if __name__=='__main__': unittest.main()
