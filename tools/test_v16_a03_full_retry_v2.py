"""Host protocol fixtures only; never a native dataset or AcceptedSample."""
import importlib
import copy
import os
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
        self.f = importlib.import_module('v16_a03_full_retry_v2')

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
                if key in ('boot','runtime'):
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
        producer=importlib.import_module('run_v16_a03_full_retry_v2')
        for label in ('inventory','summary'):
            result={'status':'FULL_RETRY_TWO_GROUP_FRONTIER_VERIFIED','frontier_verified':True,
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
        f=importlib.import_module('v16_a03_full_retry_v2')
        producer=importlib.import_module('run_v16_a03_full_retry_v2')
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
        self.assertEqual(calls,['pending-replay.bin','pending-collection.bin','pending-control.bin','pending-tasks.bin'])

    def test_real_observer_continues_first_group_and_double_reads_paused_banks(self):
        f = importlib.import_module('v16_a03_full_retry_v2')
        producer = importlib.import_module('run_v16_a03_full_retry_v2')
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
            if name in ('pending-control.bin','pending-tasks.bin'): return bytes(size)
            self.assertTrue(q.paused)
            saved.append(name)
            if key=='replay': return banks()[0]
            if key=='collection': return banks()[1]
            w=bytearray(size)
            if key in ('boot','runtime'): struct.pack_into('<Q',w,16,2)
            return bytes(w)
        with patch.object(producer.time,'sleep'), patch.object(f,'fatal_evidence'):
            result=producer.observe(q,save,symbols,Proc(),producer.time.monotonic()+5,
                                    producer.FrameDecoder(),bytearray(),bytearray())
        self.assertEqual(result['frontier']['paired'],2)
        self.assertEqual(q.calls.count('stop'),1)
        self.assertEqual(len(saved),2*(len(f.BANKS)-1))


def retry_banks(exclusions=1, verified=5):
    replay,collection=banks()
    w=list(struct.unpack('<64Q',replay));c=list(struct.unpack('<64Q',collection))
    archived=verified+exclusions
    w[7]=archived+1;w[10]=verified;w[11]=exclusions;w[17]=archived
    c[9]=verified;c[10]=archived
    return struct.pack('<64Q',*w),struct.pack('<64Q',*c)


class Retry(unittest.TestCase):
    def setUp(self):
        self.f=importlib.import_module('v16_a03_full_retry_v2')

    def test_actual_observer_retains_regular_failure_then_reaches_retry_frontier(self):
        # Baseline mode runs the unchanged old production observer, whose
        # rejection of the first real retry state is the RED observation.
        name='run_v16_a03_full_frontier' if os.getenv('CYXIA_RETRY_OBSERVER_BASELINE')=='1' else 'run_v16_a03_full_retry_v2'
        p=importlib.import_module(name);f=self.f
        w=list(struct.unpack('<64Q',banks(0)[0]))
        w[2]=10;w[6]=1;w[7]=2;w[10]=1;w[12]=7;w[17]=1;w[20]=1
        first=struct.pack('<64Q',*w)
        w[2]=16;w[7]=3;w[11]=1;w[12]=0;w[17]=2;w[20]=0
        restart=struct.pack('<64Q',*w)
        final,collection=retry_banks()
        live=[first,restart,final];index=[0]
        class Proc:
            def poll(self):return None
        class Qmp:
            def __init__(self):self.paused=False;self.stops=0
            def execute(self,name,args=None):
                if name=='cont':self.paused=False
                if name=='stop':self.paused=True;self.stops+=1
                return {'status':'paused'} if name=='query-status' else '' if name=='ringbuf-read' else {}
        q=Qmp();symbols={k:{'pa':n} for n,k in enumerate(f.BANKS)};retained=[]
        def save(name,address,size):
            key=next(k for k,v in symbols.items() if v['pa']==address)
            if name.startswith('pending-'):
                value=live[index[0]] if key=='replay' else collection if key=='collection' else bytes(size)
                if key=='tasks':index[0]=min(index[0]+1,2)
                return value
            self.assertTrue(q.paused);retained.append(name)
            if key=='replay':return final
            if key=='collection':return collection
            value=bytearray(size)
            if key in ('boot','runtime'):struct.pack_into('<Q',value,16,2)
            return bytes(value)
        with patch.object(p.time,'sleep'):
            result=p.observe(q,save,symbols,Proc(),p.time.monotonic()+5,p.FrameDecoder(),bytearray(),bytearray())
        self.assertEqual(result['frontier']['exclusions'],1)
        self.assertEqual(result['frontier']['archived'],6)
        self.assertEqual(result['frontier']['verified'],5)
        self.assertEqual(result['frontier']['next_trial_id'],7)
        self.assertEqual(q.stops,1)
        self.assertEqual(len(retained),2*(len(f.BANKS)-1))

    def test_retry_counts_split_and_unsupported_phases_fail_closed(self):
        self.assertEqual(self.f.frontier_boundary(*retry_banks())['exclusions'],1)
        for exclusions,verified in ((9,5),(1,3),(1,6)):
            self.assertIsNone(self.f.frontier_boundary(*retry_banks(exclusions,verified)))
        for phase in (18,19,20,21,22,23,24,25,26,27):
            raw=banks(**{'2':phase})[0]
            self.assertIn('unsupported',self.f.frontier_deviation(raw))
        raw=banks(**{'12':7,'2':10})[0]
        self.f.fatal_evidence(raw,bytes(self.f.BANKS['control'][1]))
        for field,value in (('12',20),('21',7),('11',9)):
            with self.assertRaises(ValueError):self.f.fatal_evidence(banks(**{field:value})[0],bytes(4096))
        tasks=bytearray(256);struct.pack_into('<Q',tasks,16,1)
        with self.assertRaisesRegex(ValueError,'quarantine'):
            self.f.fatal_evidence(raw,bytes(4096),tasks)

    def test_actual_full01_failed_rows_preserve_stale_and_expired_without_scores_mask(self):
        root=Path(__file__).resolve().parents[1]
        p10=root/'artifacts/v016-focus-a03-a10-20261109-r10'
        path=p10/'a03-full-native01-checkpoint-history.bin'
        if not path.is_file():self.skipTest('immutable actual Full01 raw fixture absent')
        raw=path.read_bytes();h=raw[:2048];model=(p10/'a03-full-frontier-01/model.bin').read_bytes()
        context={'model_generation':1,'model_sha256':self.f.digest(model),'schema_hash':self.f.SCHEMAS[0]}
        header={'side':'Candidate','boot_epoch':1,'closing_ns':self.f.word(h,120),'excluded':True}
        rows=[raw[2048+i*6144:2048+(i+1)*6144] for i in range(3)]
        parsed=[self.f.retry_record(row,header,context) for row in rows]
        side=dict(header,producer_verification_sha256='00'*32,raw_bytes=raw,records=parsed)
        result=self.f.verify_excluded_side(side,model)
        self.assertEqual([(r['sequence'],r['state'],r['error']) for r in result['published']],
                         [(614,1,0),(615,3,3),(616,3,7)])
        self.assertEqual(result['failed_publications'][0]['started_ns'],0)
        self.assertFalse(result['accepted_training_sample_verified'])
        changed=bytearray(raw);changed[2048+6144+208]^=1
        with self.assertRaisesRegex(ValueError,'MLP'):
            self.f.verify_excluded_side(dict(side,raw_bytes=bytes(changed)),model)
        with self.assertRaisesRegex(ValueError,'execution'):
            self.f.retry_record(rows[1],dict(header,excluded=False),context)
        changed=bytearray(rows[1]);struct.pack_into('<Q',changed,424,2)
        with self.assertRaisesRegex(ValueError,'nonterminal'):
            self.f.retry_record(changed,header,context)

    def test_actual_full01_committed_excluded_side_preserves_absent_coverage_and_zero_canonical(self):
        root=Path(__file__).resolve().parents[1]
        capture=root/'artifacts/v016-focus-a03-a10-20261109-r10/a03-full-frontier-01'
        if not (capture/'disk.raw').is_file():self.skipTest('immutable Full01 disk fixture absent')
        from check_v13_disk import committed_volume, BLOCK
        from check_v13_filesystem import inspect_committed
        model=(capture/'model.bin').read_bytes()
        context=dict(boot_epoch=1,model_generation=1,model_sha256=self.f.digest(model),
            schema_hash=self.f.SCHEMAS[0],schema_hashes=self.f.SCHEMAS,
            node_id=self.f.sha(capture/'node-a.pub'))
        # Read only committed metadata and the known 445760-byte lr file.
        # No whole-disk hash, VM, source mutation or sample import is involved.
        with committed_volume(capture/'disk.raw') as (read,metadata):
            volume=inspect_committed(read,metadata)
            node=volume['files']['/lr-0000000000000001-0000']
            self.assertEqual(node['size'],445760)
            raw=bytearray()
            for _,start,count in node['extents']:
                for block in range(start,start+count):
                    raw+=read(block)[:min(BLOCK,node['size']-len(raw))]
            self.assertEqual(self.f.digest(raw),node['sha256'])
        baseline=self.f.frontier_side(raw,context)
        side=self.f.frontier_side(raw[baseline['length']:],context)
        self.assertTrue(side['excluded']);self.assertFalse(side['coverage_present'])
        self.assertEqual((side['exclusion_error_plus1'],side['verification_error_plus1']),(16,16))
        result=self.f.verify_excluded_side(side,model)
        self.assertEqual(len(result['failed_publications']),2)
        self.assertEqual(side['producer_verification_sha256'],'00'*32)
        bad=bytearray(side['raw_bytes']);bad[416]=1
        with self.assertRaisesRegex(ValueError,'canonical'):self.f.frontier_side(bad,context)
        bad=bytearray(side['raw_bytes']);struct.pack_into('<Q',bad,672,side['first_ns'])
        with self.assertRaisesRegex(ValueError,'coverage'):self.f.frontier_side(bad,context)

    def test_matching_uses_real_chronology_and_discards_only_failed_attempt_pairing(self):
        # Protocol-only fixtures exercise the real matching function. The
        # separate actual raw test above owns failed-record/MLP verification;
        # the existing R7 test owns the complete successful Trial arithmetic.
        base={'boot_epoch':1,'family':[1,1],'target':[12,1],'workload_sha256':'w',
              'initial_image_sha256':'i','frozen_other_domains_sha256':'f','schema_hashes':['s'],
              'node_id':'n','relative_arrivals':[[1,0]],'raw_bytes':b'protocol-fixture'}
        def side(trial,seed,kind,excluded=False):return dict(base,trial_id=trial,
            capture_generation=trial+8,seed=seed,side=kind,excluded=excluded)
        sides=[side(1,1,'Baseline'),side(2,1,'Candidate',True),side(3,1,'Baseline'),
               side(4,1,'Candidate'),side(5,2,'Baseline'),side(6,2,'Candidate')]
        with patch.object(self.f,'numeric_frontier_side'),patch.object(self.f,'verify_excluded_side'):
            r=self.f.match_retry_sides(sides,bytes(2772))
            self.assertEqual([p['baseline']['trial_id'] for p in r['pairs']],[3,5])
            self.assertEqual(r['superseded_baselines'][0]['baseline']['trial_id'],1)
            self.assertEqual(r['excluded'][0]['trial_id'],2)
            self.assertFalse(r['global_refusal_free'])
            for bad in (sides[1:],sides[:2]+sides[3:],sides[:-1],sides[:2]+sides[:2]+sides[2:]):
                with self.assertRaises(ValueError):self.f.match_retry_sides(bad,bytes(2772))
            changed=copy.deepcopy(sides);changed[3]['initial_image_sha256']='different'
            with self.assertRaisesRegex(ValueError,'identity'):
                self.f.match_retry_sides(changed,bytes(2772))


if __name__=='__main__':unittest.main()


