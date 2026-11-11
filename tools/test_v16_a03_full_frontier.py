"""Host protocol fixtures only; never a native dataset or AcceptedSample."""
import importlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def banks(pairs=2, **changes):
    w = [0] * 64
    for k, v in {0: 2, 1: 0x435952504c593133, 2: 0, 3: 1, 4: 1,
                 5: pairs, 6: 2, 7: 2*pairs+1, 10: 2*pairs, 17: 2*pairs,
                 18: 1, 19: pairs, 24: pairs, **changes}.items():
        w[int(k)] = v
    c = [0] * 64
    for k, v in {0: 2, 1: 0x43594c434f4c3136, 2: 1, 3: 0, 4: 0,
                 6: 1, 7: 1, 8: pairs, 9: 2*pairs, 10: 2*pairs,
                 11: pairs, 14: 1, 47: 100}.items():
        c[k] = v
    return struct.pack('<64Q', *w), struct.pack('<64Q', *c)


class Frontier(unittest.TestCase):
    def setUp(self):
        self.f = importlib.import_module('v16_a03_full_frontier')

    def test_one_pair_is_not_the_two_group_frontier(self):
        self.assertIsNone(self.f.frontier_boundary(*banks(1)))
        x = self.f.frontier_boundary(*banks())
        self.assertEqual(x['training_per_family'], [2]+[0]*17)
        self.assertFalse(x['full_dataset_verified'])
        self.assertFalse(x['final_credit_release_verified'])

    def test_final_custody_rechecks_raw_inventory_context_and_checker(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);raw=root/'control.bin';raw.write_bytes(b'original')
            context={'identity':'first'};checker={'checker':'first'}
            inventory=self.f.bounded_inventory(root)
            with patch.object(self.f,'trusted_context',return_value=context),patch.object(self.f,'closure',return_value=checker):
                self.f.finish_custody(root,inventory,context,checker,{})
                raw.write_bytes(b'replaced-after-verification')
                with self.assertRaisesRegex(ValueError,'inventory'):
                    self.f.finish_custody(root,inventory,context,checker,{})
                raw.write_bytes(b'original')
            with patch.object(self.f,'trusted_context',return_value={'identity':'changed'}),patch.object(self.f,'closure',return_value=checker):
                with self.assertRaisesRegex(ValueError,'context'):
                    self.f.finish_custody(root,inventory,context,checker,{})
            with patch.object(self.f,'trusted_context',return_value=context),patch.object(self.f,'closure',return_value={'checker':'changed'}):
                with self.assertRaisesRegex(ValueError,'checker'):
                    self.f.finish_custody(root,inventory,context,checker,{})

    def test_store_before_archive_retirement_does_not_qualify(self):
        for changes in ({'17': 3}, {'10': 3}, {'13': 1}, {'20': 1},
                        {'24': 1}, {'42': 1}, {'0': 3}, {'11': 1}, {'21': 1}):
            self.assertIsNone(self.f.frontier_boundary(*banks(**changes)))

    def test_other_profile_and_torn_collection_are_not_full(self):
        r, c = banks()
        for at, value in ((0, 3), (3, 1), (3, 2), (8, 1), (12, 1), (14, 0)):
            w = list(struct.unpack('<64Q', c)); w[at] = value
            self.assertIsNone(self.f.frontier_boundary(r, struct.pack('<64Q', *w)))

    def test_stopped_frontier_accepts_the_actual_clean_boot_seqlock(self):
        """A01_BOOT_EVIDENCE word2 advances only inside the non-returning
        SAFE_EXEC loop, so a clean boot that reached the frontier reads 0."""
        replay, collection = banks()
        def probe(boot_seq=0, runtime_seq=2):
            boot = bytearray(self.f.BANKS['boot'][1])
            runtime = bytearray(self.f.BANKS['runtime'][1])
            struct.pack_into('<Q', boot, 16, boot_seq)
            struct.pack_into('<Q', runtime, 16, runtime_seq)
            return dict(replay=replay, collection=collection, boot=bytes(boot),
                runtime=bytes(runtime), control=bytes(self.f.BANKS['control'][1]))
        with patch.object(self.f, 'fatal_evidence'):
            self.assertEqual(self.f.stopped_frontier(probe())['paired'], 2)
            for boot_seq, runtime_seq in ((1, 2), (3, 2), (0, 0), (0, 3), (2, 0)):
                self.assertIsNone(self.f.stopped_frontier(probe(boot_seq, runtime_seq)),
                    'torn/unpublished stop accepted: boot=%d runtime=%d' % (boot_seq, runtime_seq))

    def test_transcript_reader_outlives_the_generic_json_bound(self):
        """A complete capture's QMP transcript exceeds read_json's generic 4 MiB
        bound, so the tool reads it under its own bound instead."""
        with tempfile.TemporaryDirectory() as temp:
            pad = 'x'*(5*1024*1024)
            path = Path(temp)/'qmp-transcript.json'
            path.write_text(json.dumps([{'direction':'send','message':{'pad':pad}}]))
            self.assertGreater(path.stat().st_size, 4*1024*1024)
            with self.assertRaisesRegex(ValueError,'bounded size'):
                self.f.read_json(path)
            self.assertEqual(self.f.read_transcript(path)[0]['message']['pad'], pad)
            over = Path(temp)/'over.json'
            over.write_text(json.dumps([{'pad':pad}]*4))
            self.assertGreater(over.stat().st_size, self.f.QMP_TRANSCRIPT_BYTES)
            with self.assertRaisesRegex(ValueError,'transcript exceeds bounded size'):
                self.f.read_transcript(over)

    def test_full_manifest_refuses_ordinary_and_focused(self):
        good = dict(schema_version=1, contract='v16-learning-collection-build-v1',
                    collection_profile='full', profile_id=0, status='BUILT_NOT_RUN',
                    profile_environment={'CYXIA_LEARNING_COLLECTION':'full'})
        self.f.require_full_profile(good)
        for changes in ({'profile_id':1}, {'collection_profile':'coreset-one-pair'},
                        {'contract':'v16-a03-ordinary-demand-build-v1'},
                        {'profile_environment':{'CYXIA_A03_DEMAND':'ordinary-rise-fall'}}):
            with self.assertRaises(ValueError):
                self.f.require_full_profile(dict(good, **changes))

    def test_raw_qmp_duplicate_key_and_truncation_are_rejected(self):
        self.assertEqual(self.f.raw_qmp_messages(b'{"id":1,"return":{}}\n'),
                         [{'id':1,'return':{}}])
        for raw in (b'{"id":1,"id":2}\n', b'{"id":1'):
            with self.assertRaises(ValueError): self.f.raw_qmp_messages(raw)

    def test_protected_payload_workload_matches_existing_seed1_golden(self):
        self.assertEqual(self.f.workload_digest(1),
            '324fe297c7f2eeb0d2c4b2530a41adb4a657b109a211d5da291696b48071fc1a')
        self.assertNotEqual(self.f.workload_digest(1),self.f.workload_digest(2))
        with self.assertRaises(ValueError): self.f.workload_digest(3)

    def test_real_old_seed1_trial_replays_and_seed_change_requires_new_workload(self):
        root=Path(__file__).resolve().parents[1]
        capture=root/'artifacts/v016-progress-20261109-r7/learning-pair-01'
        exports=capture.parent/'learning-offline-extraction-01'
        if not (exports/'manifest.json').is_file():
            self.skipTest('immutable R7 optional regression fixture absent')
        raws=[p.read_bytes() for p in sorted(exports.glob('side-*.bin'))]
        baseline=next(v for v in raws if self.f.word(v,152)==0)
        candidate=next(v for v in raws if self.f.word(v,152)==1)
        result=self.f.numeric_frontier_pair(candidate,baseline,(capture/'model.bin').read_bytes())
        self.assertEqual(result['candidate']['trial_canonical_sha256'],
            '484ff15ea6041b3fb222440d3abc41dc258b2b1141abc9e678e260bdd8d0dfcc')
        self.assertEqual(result['reward']['value']['bits'],'bf2e8876709c8da7')
        changed=bytearray(candidate);struct.pack_into('<Q',changed,88,2)
        with self.assertRaisesRegex(ValueError,'group/hash'):
            self.f.numeric_frontier_side(changed,(capture/'model.bin').read_bytes())

    def test_qmp_custody_replays_exact_paused_double_reads(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); seq=[]; identity=0
            symbols={key:{'pa':n+100} for n,key in enumerate(self.f.BANKS)}
            def command(name,arguments=None,result=None):
                nonlocal identity
                identity+=1; message={'execute':name,'id':identity}
                if arguments is not None:message['arguments']=arguments
                seq.extend([{'direction':'send','message':message},
                    {'direction':'receive','message':{'id':identity,'return':{} if result is None else result}}])
            seq.append({'direction':'receive','message':{'QMP':{}}})
            platform={'cpus':[],'memory':{}}
            command('qmp_capabilities');command('query-cpus-fast',result=[])
            command('query-memory-size-summary')
            def save(name,key,value=None):
                size=self.f.BANKS[key][1] if key in self.f.BANKS else 40
                data=bytes(size) if value is None else value
                (root/name).write_bytes(data)
                command('pmemsave',{'val':symbols[key]['pa'] if key in symbols else 0x40000000,
                    'size':len(data),'filename':str(root/name)})
            save('dtb-header.bin','dtb');save('platform.dtb','dtb');save('config-observed.bin','config')
            command('cont');save('pending-replay.bin','replay',banks()[0])
            command('stop');command('query-status',result={'status':'paused'})
            for key,(_,size) in self.f.BANKS.items():
                if key=='config':continue
                value=banks()[0] if key=='replay' else banks()[1] if key=='collection' else bytes(size)
                if key=='runtime':
                    value=bytearray(value);struct.pack_into('<Q',value,16,2);value=bytes(value)
                save('probe-01-'+key+'.bin',key,value)
            for key in self.f.BANKS:
                if key!='config':save(key+'.bin',key,(root/('probe-01-'+key+'.bin')).read_bytes())
            command('quit')
            self.assertEqual(self.f.verify_qmp(root,{'symbols':symbols},seq,platform,bytes(40)),b'')
            for name in ('replay.bin','collection.bin'):
                original=(root/name).read_bytes();(root/name).write_bytes(bytes(len(original)))
                with self.assertRaises(ValueError):self.f.verify_qmp(root,{'symbols':symbols},seq,platform,bytes(40))
                (root/name).write_bytes(original)


class Observer(unittest.TestCase):
    def test_final_inventory_or_summary_failure_clears_success_and_preserves_first_error(self):
        import io
        producer=importlib.import_module('run_v16_a03_full_frontier')
        for label in ('inventory','summary'):
            result={'status':'FULL_TWO_GROUP_FRONTIER_VERIFIED','frontier_verified':True,
                    'capture_complete':True,'error':'original failure'}
            def fail():raise OSError('disk failed')
            with patch.object(producer.sys,'stderr',new_callable=io.StringIO) as errors:
                producer.finalize_capture(result,label,fail)
                self.assertEqual(result['status'],'FAIL')
                self.assertFalse(result['frontier_verified'])
                self.assertFalse(result['capture_complete'])
                self.assertEqual(result['error'],'original failure')
                if label=='summary':self.assertIn('summary',errors.getvalue())
            with patch.object(producer,'run',return_value=result),patch.object(producer.sys,'stdout',new_callable=io.StringIO):
                argv=[]
                for name in ('source-root','build-manifest','output','formatter','qemu-binary','qemu-source'):
                    argv += ['--'+name,'/unused-host-fixture']
                self.assertEqual(producer.main(argv),1)

    def test_real_observer_stops_waiting_when_clean_frontier_has_been_passed(self):
        f=importlib.import_module('v16_a03_full_frontier')
        producer=importlib.import_module('run_v16_a03_full_frontier')
        class Proc:
            def poll(self):return None
        class Qmp:
            def execute(self,name,args=None):return '' if name=='ringbuf-read' else {}
        symbols={k:{'pa':n} for n,k in enumerate(f.BANKS)}
        calls=[]
        def save(name,address,size):
            calls.append(name)
            if name=='pending-replay.bin':return banks(3)[0]
            if name=='pending-collection.bin':return banks(3)[1]
            return bytes(size)
        with self.assertRaisesRegex(ValueError,'frontier passed'):
            producer.observe(Qmp(),save,symbols,Proc(),producer.time.monotonic()+5,
                             producer.FrameDecoder(),bytearray(),bytearray())
        self.assertEqual(calls,['pending-replay.bin','pending-collection.bin','pending-control.bin'])

    def test_real_observer_continues_first_group_and_double_reads_paused_banks(self):
        f = importlib.import_module('v16_a03_full_frontier')
        producer = importlib.import_module('run_v16_a03_full_frontier')
        class Proc:
            def poll(self): return None
        class Qmp:
            def __init__(self): self.calls=[]; self.paused=False
            def execute(self, name, args=None):
                self.calls.append(name)
                if name=='stop': self.paused=True
                if name=='cont': self.paused=False
                return {'status':'paused'} if name=='query-status' else '' if name=='ringbuf-read' else {}
        q=Qmp(); live=[1,2]; saved=[]
        symbols={k:{'pa':n} for n,k in enumerate(f.BANKS)}
        def save(name, address, size):
            key=next(k for k,v in symbols.items() if v['pa']==address)
            if name=='pending-replay.bin': return banks(live.pop(0))[0]
            if name=='pending-collection.bin': return banks(2 if not live else 1)[1]
            if name=='pending-control.bin': return bytes(size)
            self.assertTrue(q.paused)
            saved.append(name)
            if key=='replay': return banks()[0]
            if key=='collection': return banks()[1]
            w=bytearray(size)
            if key=='runtime': struct.pack_into('<Q',w,16,2)
            return bytes(w)
        with patch.object(producer.time,'sleep'), patch.object(f,'fatal_evidence'):
            result=producer.observe(q,save,symbols,Proc(),producer.time.monotonic()+5,
                                    producer.FrameDecoder(),bytearray(),bytearray())
        self.assertEqual(result['frontier']['paired'],2)
        self.assertEqual(q.calls.count('stop'),1)
        self.assertEqual(len(saved),2*(len(f.BANKS)-1))


if __name__=='__main__': unittest.main()
