"""Synthetic bounded-data protocol fixtures; never source replay authority."""
import copy
from pathlib import Path
import struct
import tempfile
import unittest
import v16_a03_data as data


class ExplicitProfileAdmission(unittest.TestCase):
    def test_profile2_has_separate_closed_admission(self):
        manifest=dict(schema_version=1,contract='v16-learning-collection-build-v2',status='BUILT_NOT_RUN',collection_profile='coreset-data-one-pair',profile_id=2,bounded_data_schema=2)
        self.assertEqual(data.require_data_profile(manifest),'coreset-data-one-pair')
        for key,value in (('collection_profile','coreset-one-pair'),('profile_id',1),('profile_id',True),('collection_profile','full'),('contract','normal'),('contract','v16-learning-collection-build-v1'),('bounded_data_schema',1),('bounded_data_schema',None)):
            changed=dict(manifest);changed[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):data.require_data_profile(changed)

    def test_strict_profile_tools_and_new_identity_remain_distinct(self):
        import v16_a03_focus as strict
        self.assertNotEqual(data.VERSION,strict.VERSION)
        self.assertNotEqual(data.CHECKER_VERSION,strict.CHECKER_VERSION)
        self.assertEqual(data.MAX_ATTEMPTS,6)
        self.assertEqual(data.HOST_TIMEOUT_SECONDS,600)



def put(raw,at,*values):struct.pack_into('<'+'Q'*len(values),raw,at,*values)

def reference(trial,prep=False):
    raw=bytearray(96);put(raw,0,1,trial,0 if prep else trial,80+trial,1,0,1024 if prep else 4096);raw[56:88]=bytes([trial])*32;return bytes(raw)

def ledger_fixture(superseded=False):
    raw=bytearray(8192);outcomes=[(2,5),(1,1),(2,3),(1,4)] if superseded else [(2,1),(2,3),(1,4)]
    excluded=1;count=len(outcomes);verified=count-excluded
    put(raw,0,2,0x4359424441543136,2,2,25,count,6,1,0,1,excluded,verified,count,1,0,1,1,1,99,1,4096)
    raw[168:200]=b'S'*32;put(raw,200,42,1,count-1,count,count,count,1000)
    for index,(kind,outcome) in enumerate(outcomes):
        trial=index+1;at=(32+56*index)*8;prep=outcome==1 and not superseded
        put(raw,at,trial,trial,1,kind,0 if prep else trial,10 if outcome==1 else 0,7 if outcome==1 else 0,outcome,7 if prep else 31,7 if prep else 31,1,1)
        if outcome!=1:raw[at+96:at+128]=bytes([trial+20])*32
        raw[at+(28 if prep else 16)*8:at+(40 if prep else 28)*8]=reference(trial,prep)
        put(raw,at+52*8,trial,10+trial,20+trial if outcome==1 else 0,0)
    witness=bytearray(1024);witness[:16]=b'CYXIA_SAMPLE_16\0';put(witness,32,count-1,count);witness[48:80]=bytes([count+19])*32;witness[80:112]=bytes([count+20])*32;put(witness,112,1,2,1);put(witness,368,8)
    raw[368*8:496*8]=witness;raw[496*8:500*8]=__import__('hashlib').sha256(witness).digest()
    raw[500*8:512*8]=reference(count-1);raw[512*8:524*8]=reference(count)
    return raw

class BoundedLedger(unittest.TestCase):
    def test_real_witness_ids_select_only_final_pair_after_exclusion(self):
        result=data.decode_data_ledger(ledger_fixture())
        self.assertEqual(result['selected_trials'],[2,3]);self.assertEqual(result['attempt_count'],3)
        self.assertEqual(result['status'],'SAMPLE_COLLECTED');self.assertEqual(result['attempts'][0]['outcome'],'excluded')
        result=data.decode_data_ledger(ledger_fixture(True));self.assertEqual(result['attempts'][0]['outcome'],'superseded_baseline')
        self.assertEqual(result['selected_trials'],[3,4])

    def test_wrong_pair_missing_exclusion_unclosed_bound_errors_are_rejected(self):
        cases=[(5*8,7),(6*8,7),(8*8,1),(9*8,0),(14*8,1),(15*8,0),(16*8,0),(17*8,0),(25*8,0),(26*8,0),(27*8,1),(30*8,2),(32*8,7),((32+5)*8,2),((32+6)*8,8),((32+8)*8,0),((32+11)*8,0)]
        for at,value in cases:
            raw=ledger_fixture();put(raw,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):data.decode_data_ledger(raw)
        raw=ledger_fixture();raw[(32+28)*8:(32+40)*8]=bytes(96)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)
        raw=ledger_fixture();raw[500*8:512*8]=reference(1,True)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)



class ActualErrorSchema(unittest.TestCase):
    def test_retry_codes_are_bound_to_actual_current_source_enums(self):
        result=data.error_schema(Path(__file__).resolve().parents[1])
        self.assertEqual(result['domain']['Busy'],10);self.assertEqual(result['domain']['NotReady'],20)
        self.assertEqual(result['domain']['Stale'],4);self.assertNotIn(4,data.RETRY_DOMAIN)
        self.assertEqual(result['learning']['DataIncomplete'],7);self.assertEqual(result['learning']['Deadline'],16)
        self.assertEqual(result['learning']['Unknown'],17)
    def test_preparation_original_error_zero_is_not_a_retry_wildcard(self):
        raw=ledger_fixture();put(raw,(32+5)*8,0)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)



def supplement_fixture(bank):
    w=struct.unpack('<1024Q',bank);raw=bytearray(4096)
    put(raw,0,data.DATA_MAGIC,2,2,w[5],6,w[7],w[27],w[28],w[30],w[10],w[11],w[12],w[25],w[26],w[13],0)
    raw[128:2816]=bank[32*8:368*8];raw[2816:3872]=bank[368*8:500*8];raw[3872:4064]=bank[500*8:524*8];raw[4064:4096]=bank[524*8:528*8]
    bank[168:200]=__import__('hashlib').sha256(raw).digest();return bytes(raw)

def failed_terminal(stopped=False):
    raw=bytearray(8192);put(raw,0,2,data.DATA_MAGIC,2,2,27 if stopped else 26,6,6,0,1,1,6,0,6,0,0,1,1,1,99,1,4096)
    raw[168:200]=b'S'*32;put(raw,200,42,1,0,0,6,6,1000)
    for i in range(6):
        trial=i+1;at=(32+56*i)*8
        put(raw,at,trial,trial,1,2,0,2 if stopped and i==5 else 10,7,1,7,7,1,1)
        raw[at+224:at+320]=reference(trial,True);put(raw,at+52*8,0,10+trial,20+trial,2 if stopped and i==5 else 0)
    if stopped:put(raw,524*8,6,2,26,6)
    return raw

class TerminalAndSupplement(unittest.TestCase):
    def test_closed_exhaustion_and_nonretryable_stop_never_become_samples(self):
        exhausted=data.decode_data_ledger(failed_terminal());self.assertEqual(exhausted['status'],'EXHAUSTED');self.assertFalse(exhausted['stored'])
        stopped=data.decode_data_ledger(failed_terminal(True));self.assertEqual(stopped['status'],'STOPPED');self.assertIsNone(stopped['witness'])
        raw=failed_terminal();put(raw,4*8,25)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)
        raw=failed_terminal();put(raw,9*8,0)
        self.assertIsNone(data.data_terminal_candidate(raw))

    def test_exact_durable_supplement_matches_all_attempts_and_final_paid_ticket(self):
        bank=ledger_fixture(True);supp=supplement_fixture(bank);ledger=data.decode_data_ledger(bank)
        data.verify_supplement(supp,ledger)
        for at in (0,24,48,96,104,128,2816,3840,3872,3968,4095):
            changed=bytearray(supp);changed[at]^=1
            with self.subTest(at=at),self.assertRaises(ValueError):data.verify_supplement(changed,ledger)
        failed=failed_terminal();supp=supplement_fixture(failed);data.verify_supplement(supp,data.decode_data_ledger(failed))

    def test_reused_prep_id_overlapping_journal_and_poststore_trial_fail(self):
        for mutation in ('prep','range','poststore'):
            raw=ledger_fixture(True)
            if mutation=='prep':put(raw,(32+56+1)*8,1)
            elif mutation=='range':raw[(32+56+16)*8:(32+56+28)*8]=raw[(32+16)*8:(32+28)*8]
            else:put(raw,5*8,5)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):data.decode_data_ledger(raw)

class OwnErrorJournal(unittest.TestCase):
    def test_preparation_journal_error_cannot_be_changed_or_omitted(self):
        attempt=data.decode_data_ledger(ledger_fixture())['attempts'][0]
        raw=bytearray(1024);raw[:15]=b'CYXIA_PREP_1.3\0'
        put(raw,32,1,1,0x5245504c4159,1,1,1,2,1,0,11,21,25,10,0,25,0,0,0,0,0,0,0,0,0,0,0,0,0)
        raw[352:384]=b'M'*32;put(raw,416,1,1,1,0x5245504c4159,1,0,1024,0)
        context=dict(model_sha256=(b'M'*32).hex())
        parsed=data.parse_attempt_journal(raw,attempt,'preparation',context)
        self.assertTrue(parsed['original_domain_error_verified']);self.assertFalse(parsed['native_replay_authority_reconstructed'])
        for at,value in ((32,2),(64,2),(128,11),(464,2048),(1000,1)):
            changed=bytearray(raw);put(changed,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):data.parse_attempt_journal(changed,attempt,'preparation',context)



class DiagnosticAndResourceCustody(unittest.TestCase):
    def test_new_root_config_baseline_widths_and_each_paused_read_are_required(self):
        self.assertEqual(data.FOCUS_DIAGNOSTICS['replay_root'],('REPLAY_ROOT_EVIDENCE',256))
        self.assertEqual(data.FOCUS_DIAGNOSTICS['replay_config'],('REPLAY_CONFIG_EVIDENCE',256))
        self.assertEqual(data.FOCUS_DIAGNOSTICS['baseline_publication'],('BASELINE_PUBLICATION_FIRST_CAUSE',3072))
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();rows=[dict(direction='receive',message={'QMP':{}})];number=0
            def command(name,args=None,result=None):
                nonlocal number
                number+=1;message=dict(execute=name,id=number)
                if args is not None:message['arguments']=args
                rows.extend([dict(direction='send',message=message),dict(direction='receive',message={'id':number,'return':{} if result is None else result})])
            command('cont');command('stop');command('query-status',result={'status':'paused'})
            locations={}
            for i,(key,(_,width)) in enumerate(data.FOCUS_DIAGNOSTICS.items()):
                path=root/('diagnostic-'+key+'.bin');path.write_bytes(bytes(width));locations[key]=dict(pa=0x40200000+i*4096,size=width)
                command('pmemsave',dict(val=locations[key]['pa'],size=width,filename=str(path)))
            command('quit');context=dict(diagnostic_symbols=locations)
            self.assertEqual(set(data.verify_focus_diagnostic_reads(rows,root,context)),set(data.FOCUS_DIAGNOSTICS))
            for key in ('replay_root','replay_config','baseline_publication'):
                changed=copy.deepcopy(rows);read=next(r for r in changed if r['direction']=='send' and r['message'].get('arguments',{}).get('filename')==str(root/('diagnostic-'+key+'.bin')));index=changed.index(read);del changed[index:index+2]
                with self.subTest(key=key),self.assertRaises(ValueError):data.verify_focus_diagnostic_reads(changed,root,context)

    def test_expected_exclusion_counters_do_not_hide_global_resource_faults(self):
        replay=bytearray(512);put(replay,0,2,0x435952504c593133,6);put(replay,11*8,3,10)
        control=bytearray(4096);data.fatal_evidence(replay,control)
        put(control,0,0x435958444f4d3031,1);put(control,25*8,1)
        with self.assertRaises(ValueError):data.fatal_evidence(replay,control)
        control=bytearray(4096);tasks=bytearray(256);put(tasks,0,0x43595441534b0001);put(tasks,2*8,2)
        with self.assertRaises(ValueError):data.fatal_evidence(replay,control,tasks)
        put(control,160*8,0x43594f5053540001,1,1);put(control,191*8,2)
        with self.assertRaises(ValueError):data.fatal_evidence(replay,control)

    def test_new_baseline_cause_is_passive_and_bound_per_trial(self):
        self.assertFalse(data.decode_focus_diagnostic('baseline_publication',bytes(3072))['authorizes_replay'])
        raw=bytearray(3072);put(raw,0,2,0x4359425043413136,1,1,1,0x43595355424d0001,1,9,0,2,10)
        put(raw,32*8,2,100,110,1,1,7,100,2,3,5);raw[42*8:46*8]=b'P'*32;put(raw,46*8,10,0,1,6,6,0,3)
        fact=data.decode_focus_diagnostic('baseline_publication',raw)
        self.assertTrue(fact['slots'][0]['observed']);self.assertEqual(fact['slots'][0]['trial_id'],1)
        for at,value in ((3*8,2),(47*8,1),(53*8,1)):
            changed=bytearray(raw);put(changed,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):data.decode_focus_diagnostic('baseline_publication',changed)



class BoundedRunnerLifecycle(unittest.TestCase):
    def test_live_terminal_hint_requires_full_stopped_bank_and_exact_final_copies(self):
        import run_v16_a03_data as runner
        import time
        from transport import FrameDecoder
        class Qmp:
            paused=False
            def execute(self,name,args=None):
                if name=='cont':self.paused=False
                elif name=='stop':self.paused=True
                elif name=='query-status':return {'status':'paused' if self.paused else 'running'}
                elif name=='ringbuf-read':return ''
                return {}
        class Proc:
            def poll(self):return None
        qmp=Qmp();symbols={key:dict(pa=i*1000000,size=size) for i,(key,(_,size)) in enumerate(data.BANKS.items())}
        calls=[];ledger=ledger_fixture();replay=bytearray(512);put(replay,0,2,0x435952504c593133,25,1,2,0);put(replay,80,2,1);put(replay,136,3,1,1);put(replay,25*8,1)
        def save(name,address,size):
            calls.append(name)
            if name.startswith('probe-') or name in {key+'.bin' for key in data.BANKS}:self.assertTrue(qmp.paused)
            key=next(key for key,location in symbols.items() if location['pa']==address)
            if key=='bounded_data':return ledger
            if key=='replay':return replay
            raw=bytearray(size)
            if key=='runtime':put(raw,16,2)
            return raw
        result=runner.observe_pair(qmp,save,symbols,Proc(),time.monotonic()+1,FrameDecoder(),bytearray(),bytearray())
        self.assertEqual(result['status'],'SAMPLE_COLLECTED');self.assertTrue(qmp.paused)
        self.assertIn('bounded_data.bin',calls);self.assertIn('probe-01-bounded_data.bin',calls)

    def test_finalization_failure_does_not_mask_original_error_or_promote_timeout(self):
        import run_v16_a03_data as runner
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();build=root/'build';build.mkdir();output=root/'capture'
            (build/'node-a.elf').write_bytes(b'fixture');(build/'build-manifest.json').write_text('{}');(build/'base-build-manifest.json').write_text('{}')
            context=dict(paths=dict(source_root=str(root),build_manifest=str(build/'build-manifest.json'),formatter=str(root/'formatter'),qemu_binary=str(root/'qemu'),qemu_source=str(root)),symbols={},artifacts={'node-a.elf':runner.sha(build/'node-a.elf')},tools={},source_map={})
            original=runner.write_json
            def prepare(*args):
                (output/'disk.raw').write_bytes(b'fixture');raise ValueError('original interrupted native failure')
            def write(path,value):
                if path.name=='process-exit.json':raise OSError('secondary record failure')
                return original(path,value)
            with patch.object(runner,'trusted_context',return_value=context),patch.object(runner,'symbol',return_value={'va':1,'size':1}),patch.object(runner,'loaded_bytes',return_value=b'model'),patch.object(runner,'prepare_disk',side_effect=prepare),patch.object(runner,'write_json',side_effect=write):
                result=runner.run(build/'build-manifest.json',output,source_root=root,formatter=root/'formatter',qemu=root/'qemu',qemu_source=root)
            self.assertIn('original interrupted',result['error']);self.assertEqual(result['status'],'FAIL')
            self.assertEqual(result['collection_status'],'INTERRUPTED');self.assertTrue(result['unresolved_obligations_may_remain'])
            self.assertFalse(result['capture_complete']);self.assertTrue(result['cleanup_errors'])



class AuthenticAbsentCallbackOperands(unittest.TestCase):
    def test_baseline_freshness_failure_has_no_invented_core_masks(self):
        raw=bytearray(3072);put(raw,0,2,0x4359425043413136,1,1,1,0x43595355424d0001,1,9,0,2,10)
        put(raw,32*8,2,100,60000100,0,1,7,100,2,3,5);raw[42*8:46*8]=b'P'*32
        put(raw,46*8,10,0,1,0,0,0,1)
        fact=data.decode_focus_diagnostic('baseline_publication',raw)['slots'][0]
        self.assertEqual(fact['requested_mask'],0);self.assertEqual(fact['current_mask'],0)
        self.assertFalse(fact['authorizes_replay'])



class CommittedJournalGraph(unittest.TestCase):
    def fixture(self,root):
        import hashlib
        from test_v16_a03_focus import core_fixture
        b,model=core_fixture(False);c,_=core_fixture(True)
        bank=bytearray(8192);put(bank,0,2,data.DATA_MAGIC,2,2,25,2,6,1,0,1,0,2,2,1,0,1,1,1,99,1,4096);put(bank,200,42,1,1,2,2,2,100000000000)
        references=[];nodes={};blocks={};block=1
        for i,raw in enumerate((b,c)):
            trial=i+1;ref=bytearray(96);put(ref,0,1,trial,trial,81+i,1,0,len(raw));ref[56:88]=hashlib.sha256(raw).digest();references.append(bytes(ref))
            at=(32+56*i)*8;put(bank,at,trial,trial,1,2 if i==0 else 1,trial,0,0,3+i,31,31,1,1);bank[at+96:at+128]=raw[416:448];bank[at+128:at+224]=ref;put(bank,at+52*8,trial,10+trial,0,0)
            count=(len(raw)+4095)//4096;nodes['/lr-0000000000000001-%04x'%i]=dict(inode=81+i,generation=1,size=len(raw),durable_write_seq=1,sha256=hashlib.sha256(raw).hexdigest(),extents=[(0,block,count)])
            for j in range(count):blocks[block+j]=raw[j*4096:(j+1)*4096].ljust(4096,b'\0')
            block+=count
        witness=bytearray(1024);witness[:16]=b'CYXIA_SAMPLE_16\0';put(witness,32,1,2);witness[48:80]=b[416:448];witness[80:112]=c[416:448];put(witness,112,1,2,1);put(witness,368,8)
        bank[368*8:496*8]=witness;bank[496*8:500*8]=hashlib.sha256(witness).digest();bank[500*8:512*8]=references[0];bank[512*8:524*8]=references[1]
        supplement=supplement_fixture(bank);nodes['/ld-0000000000000001']=dict(inode=99,generation=1,size=4096,durable_write_seq=1,sha256=hashlib.sha256(supplement).hexdigest(),extents=[(0,block,1)]);blocks[block]=supplement
        disk=root/'disk.raw';disk.write_bytes(b'host committed-volume fixture')
        context=dict(disk_sha256=data.sha(disk),disk_uuid='fixture',boot_epoch=1,model_generation=1,model_sha256=hashlib.sha256(model).hexdigest(),schema_hash=data.SCHEMAS[0],schema_hashes=data.SCHEMAS,node_id=(b'N'*32).hex())
        return bank,disk,context,nodes,blocks

    def test_every_committed_object_range_hash_is_bound_and_missing_or_extra_data_rejected(self):
        from contextlib import contextmanager
        from unittest.mock import patch
        import check_v13_disk,check_v13_filesystem
        with tempfile.TemporaryDirectory() as temporary:
            bank,disk,context,nodes,blocks=self.fixture(Path(temporary));ledger=data.decode_data_ledger(bank)
            @contextmanager
            def volume(path):yield (lambda index:blocks[index]),{}
            def inspect(*args):return dict(uuid='fixture',boot_epoch=1,files=nodes,directories={})
            with patch.object(check_v13_disk,'committed_volume',side_effect=volume),patch.object(check_v13_filesystem,'inspect_committed',side_effect=inspect):
                journals,selected=data.read_committed_data(disk,context,ledger)
                self.assertEqual(set(selected),{'selected_baseline','selected_candidate'});self.assertEqual(len(journals),2)
                original=nodes.pop('/lr-0000000000000001-0000')
                with self.assertRaises(ValueError):data.read_committed_data(disk,context,ledger)
                nodes['/lr-0000000000000001-0000']=original
                old=ledger['attempts'][0]['regular']['sha256'];ledger['attempts'][0]['regular']['sha256']='00'*32
                with self.assertRaises(ValueError):data.read_committed_data(disk,context,ledger)
                ledger['attempts'][0]['regular']['sha256']=old
                nodes['/lp-0000000000000001-0000']=dict(original,inode=123)
                with self.assertRaises(ValueError):data.read_committed_data(disk,context,ledger)



class HardFaultSchemaTwo(unittest.TestCase):
    def test_busy_then_recovered_io_cannot_be_success_or_exhaustion(self):
        for phase in (25,26):
            raw=ledger_fixture() if phase==25 else failed_terminal()
            put(raw,(32+55)*8,18);put(raw,524*8,1,18,100,10)
            with self.subTest(phase=phase),self.assertRaises(ValueError):data.decode_data_ledger(raw)
        raw=failed_terminal(True);put(raw,(32+55)*8,2);put(raw,524*8,1,2,21,6)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)

    def test_later_hard_io_preserves_first_busy_and_stops_at_last_actual_trial(self):
        raw=failed_terminal();put(raw,4*8,27);put(raw,(32+5*56+55)*8,18);put(raw,524*8,6,18,100,10)
        ledger=data.decode_data_ledger(raw)
        self.assertEqual(ledger['status'],'STOPPED');self.assertFalse(ledger['collection_succeeded'])
        self.assertEqual(ledger['attempts'][-1]['original_domain_error_code'],10)
        self.assertEqual(ledger['attempts'][-1]['hard_domain_error_code'],18)
        self.assertEqual(ledger['hard_stop']['trial_id'],6)
        for at,value in ((524*8,5),(525*8,10),(526*8,0),((32+5*56+55)*8,0)):
            changed=bytearray(raw);put(changed,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):data.decode_data_ledger(changed)

    def test_stored_before_fatal_is_retained_without_collected_sample_credit(self):
        raw=ledger_fixture();put(raw,4*8,27);put(raw,(32+2*56+55)*8,18);put(raw,524*8,3,18,100,24|(1<<63))
        ledger=data.decode_data_ledger(raw)
        self.assertTrue(ledger['stored']);self.assertFalse(ledger['collection_succeeded'])
        self.assertEqual(ledger['credited_samples'],0);self.assertEqual(ledger['selected_trials'],[2,3])
        put(raw,527*8,24)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)

    def test_old_schema_absence_is_not_evidence_of_no_hard_fault(self):
        raw=ledger_fixture();put(raw,2*8,1)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)



def matching_replay(ledger):
    raw=bytearray(512);put(raw,0,2,0x435952504c593133,ledger['phase'],1,2,0)
    put(raw,10*8,ledger['verified'],ledger['excluded']);put(raw,17*8,ledger['archived'],1,int(ledger['stored']),0,0)
    put(raw,25*8,int(ledger['stored']));return raw

class CrossBankTerminal(unittest.TestCase):
    def test_native_terminal_phase_counts_pair_and_closure_are_joint_facts(self):
        for bank in (ledger_fixture(),failed_terminal(),failed_terminal(True)):
            ledger=data.decode_data_ledger(bank);replay=matching_replay(ledger)
            self.assertTrue(data.verify_replay_terminal(replay,ledger))
            for word,value in ((2,24),(10,99),(11,99),(17,99),(19,1-int(ledger['stored'])),(20,1),(9,1),(13,1),(14,1),(15,1),(16,1),(63,1),(12,7),(21,7),(18,4),(25,1-int(ledger['stored']))):
                changed=bytearray(replay);put(changed,word*8,value)
                with self.subTest(status=ledger['status'],word=word),self.assertRaises(ValueError):data.verify_replay_terminal(changed,ledger)

    def test_selected_stop_and_offline_final_use_the_same_consistency_guard(self):
        ledger=data.decode_data_ledger(ledger_fixture());replay=matching_replay(ledger)
        probe={key:bytes(size) for key,(_,size) in data.BANKS.items() if key!='config'}
        probe['replay']=replay;probe['bounded_data']=ledger_fixture();runtime=bytearray(8192);put(runtime,16,2);probe['runtime']=runtime
        self.assertTrue(data.stopped_data_ready(probe))
        put(replay,19*8,0);self.assertFalse(data.stopped_data_ready(probe))



class SupersededBaselineHardStop(unittest.TestCase):
    def test_verified_baseline_later_io_stays_unlabelled_superseded_stopped(self):
        raw=bytearray(8192);put(raw,0,2,data.DATA_MAGIC,2,2,27,1,6,0,0,1,0,1,1,0,0,1,1,1,99,1,4096)
        raw[168:200]=b'S'*32;put(raw,200,42,1,0,0,1,1,1000)
        put(raw,32*8,1,1,1,2,1,18,0,5,31,31,1,1);raw[(32+12)*8:(32+16)*8]=b'C'*32
        raw[(32+16)*8:(32+28)*8]=reference(1);put(raw,(32+52)*8,1,11,21,18);put(raw,524*8,1,18,21,10)
        ledger=data.decode_data_ledger(raw)
        self.assertEqual(ledger['status'],'STOPPED');self.assertFalse(ledger['collection_succeeded'])
        self.assertEqual(ledger['attempts'][0]['outcome'],'superseded_baseline');self.assertIsNone(ledger['witness'])
        put(raw,(32+7)*8,3)
        with self.assertRaises(ValueError):data.decode_data_ledger(raw)



class InterruptedDiagnosticAPI(unittest.TestCase):
    def test_original_timeout_custody_never_manufactures_a_closed_collection(self):
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for key,(_,width) in data.FOCUS_DIAGNOSTICS.items():(root/('diagnostic-'+key+'.bin')).write_bytes(bytes(width))
            (root/'diagnostic-bounded_data.bin').write_bytes(bytes(8192))
            artifacts=data.bounded_inventory(root)
            (root/'summary.json').write_text(json.dumps(dict(version=data.VERSION,status='FAIL',capture_complete=False,released_pair_observed=False,error='TimeoutError: original600s',artifacts=artifacts)))
            checked=dict(raw_inventory=data.bounded_inventory(root),trusted_context={'fixture':'checked caller'},diagnostic_reads={},boot_epoch=1)
            with patch.object(data,'_verify_data_capture_custody',return_value=checked) as base,patch.object(data,'trusted_context',return_value=checked['trusted_context']):
                result=data.verify_diagnostic_capture(root,source_root=root,build_manifest=root,formatter=root,qemu_binary=root,qemu_source=root)
            self.assertEqual(base.call_args.kwargs['terminal_contract'],'bounded-data-interrupted')
            self.assertEqual(result['status'],'FAIL');self.assertIn('original600s',result['original_failure'])
            self.assertTrue(result['unresolved_obligations_may_remain']);self.assertFalse(result['closed_bounded_collection_verified'])
            self.assertFalse(result['data_collection_verified']);self.assertFalse(result['capture_complete'])
            self.assertFalse(result['authorizes_replay']);self.assertEqual(result['samples'],0)

PREPARATION_MAGIC=0x4359505250473031
def preparation_fixture():
    raw=bytearray(6144)
    put(raw,0,12,PREPARATION_MAGIC,1,128,8,1,1,1,99,1,1,2,1,2,100,6,0,2,0,1,1,2,0,0,16,600,7,1,8,16,16,0)
    def record(at,ordinal,entry,kind,stage,result=1,error=0,before=0,end=0,after=0,flags=0,body=()):
        put(raw,at*8,ordinal,entry,kind|(stage<<8)|(result<<16)|(error<<18)|flags,before|(end<<10)|(after<<20),*body)
    record(32,1,110,1,1,3,10);record(48,2,120,1,1,3,10)
    record(64,3,130,3,5,before=8,flags=(1<<26)|(1<<27),body=(1,0,1,9,1,0,14,1,77,1,90,0))
    state=(1<<16)|(1<<26)|(1<<27)|(1<<28)
    body=(9,4,1,1,7,88,1,3,100,2000,140,state)
    for at in (80,96,112):record(at,4,140,4,6,before=8,end=16,flags=(1<<27)|(1<<28)|(1<<29),body=body)
    return raw

class PreparationProgressDiagnostics(unittest.TestCase):
    def test_new_contract_uses_independent_global_snapshots_and_exact_bank(self):
        self.assertEqual(data.VERSION,'v16-a03-coreset-data-one-pair-v3')
        self.assertEqual(data.CHECKER_VERSION,'v16-a03-bounded-data-checker-v3')
        self.assertEqual(data.DIAGNOSTIC_VERSION,'v16-a03-bounded-data-diagnostics-v2')
        self.assertIsNot(data.SCHEMAS,data.strict.SCHEMAS)
        self.assertIsNot(data.FOCUS_DIAGNOSTICS,data.strict.FOCUS_DIAGNOSTICS)
        self.assertNotIn('preparation_progress',data.strict.FOCUS_DIAGNOSTICS)
        self.assertEqual(data.FOCUS_DIAGNOSTICS['preparation_progress'],('REPLAY_PREPARATION_PROGRESS',6144))

    def test_empty_partial_and_published_are_observations_without_authority(self):
        for raw,state in ((bytes(6144),'empty'),(struct.pack('<Q',1)+bytes(6136),'partial'),(preparation_fixture(),'published')):
            fact=data.decode_focus_diagnostic('preparation_progress',raw)
            self.assertEqual(fact['slots'][0]['state'],state);self.assertFalse(fact['authorizes_replay'])
            self.assertFalse(fact['outer_gate_refusals_observed'])
        slot=data.decode_focus_diagnostic('preparation_progress',preparation_fixture())['slots'][0]
        self.assertEqual(slot['preparation_id'],1);self.assertEqual(slot['counters']['advance'],2)
        self.assertEqual(slot['first_auth']['original_domain_error_code'],10)
        self.assertEqual(slot['first_blocker']['slot'],8)

    def test_published_abi_identity_bounds_flags_and_presence_are_strict(self):
        cases=((1,0),(2,2),(3,64),(4,0),(4,9),(4,10),(4,12),(4,24),(5,0),(6,0),(7,7),(8,0),(9,0),(10,2),(11,1),(13,0),(16,1),(31,1),(24,520),(24,7),(26,9),(27,4),(32+2,1<<63),(32+3,1<<63),(64+4,0),(80+2,4|(6<<8)|(1<<16)))
        for at,value in cases:
            raw=preparation_fixture();put(raw,at*8,value)
            with self.subTest(at=at,value=value),self.assertRaises(ValueError):data.decode_focus_diagnostic('preparation_progress',raw)
        raw=preparation_fixture();put(raw,0,0)
        with self.assertRaises(ValueError):data.decode_focus_diagnostic('preparation_progress',raw)
        with self.assertRaises(ValueError):data.decode_focus_diagnostic('preparation_progress',bytes(1024))

    def test_counter_first_last_current_time_and_identity_contradictions_fail(self):
        for at,value in ((15,7),(17,1),(32,2),(48,7),(48+1,601),(28,16),(29,24),(30,8)):
            raw=preparation_fixture();put(raw,at*8,value)
            # The latest snapshot is Auth only when it actually is last.
            if at==49:put(raw,15*8,2);put(raw,17*8,2);put(raw,19*8,0,0,0);put(raw,24*8,0,600,1,3|(10<<8),0,0,0);raw[64*8:128*8]=bytes(512)
            with self.subTest(at=at),self.assertRaises(ValueError):data.decode_focus_diagnostic('preparation_progress',raw)
        raw=preparation_fixture();raw[1024:2048]=raw[:1024]
        with self.assertRaises(ValueError):data.decode_focus_diagnostic('preparation_progress',raw)
        raw=preparation_fixture();raw[2048:3072]=raw[:1024];raw[:1024]=bytes(1024)
        with self.assertRaises(ValueError):data.decode_focus_diagnostic('preparation_progress',raw)

    def test_exact_max_counter_is_not_inferred_overflow_and_zero_operands_are_present(self):
        earlier=preparation_fixture();put(earlier,33*8,90)
        first=data.decode_focus_diagnostic('preparation_progress',earlier)['slots'][0]
        self.assertLess(first['first_auth']['service_entry_ns'],first['preparation_started_ns'])
        # A blocked slot0 and an observed predicate time0 are not absent rows.
        zero=preparation_fixture()
        for at in (80,96,112):
            put(zero,(at+3)*8,8<<10);put(zero,(at+4)*8,1)
            put(zero,(at+12)*8,0,1,0)
        blocker=data.decode_focus_diagnostic('preparation_progress',zero)['slots'][0]['first_blocker']
        self.assertEqual(blocker['slot'],0);self.assertTrue(blocker['predicate_present']);self.assertEqual(blocker['predicate_ns'],0)
        raw=bytearray(6144);maximum=(1<<64)-1
        put(raw,0,2,PREPARATION_MAGIC,1,128,8,1,1,1,99,1,1,2,1,2,100,maximum,0,maximum)
        put(raw,25*8,0,1,3|(10<<8))
        for at,ordinal in ((32,1),(48,maximum)):put(raw,at*8,ordinal,0,1|(1<<8)|(3<<16)|(10<<18))
        fact=data.decode_focus_diagnostic('preparation_progress',raw)['slots'][0]
        self.assertEqual(fact['counters']['auth_error'],maximum);self.assertEqual(fact['last_auth']['service_entry_ns'],0)
        put(raw,4*8,9)
        with self.assertRaisesRegex(ValueError,'flags.*0x9'):data.decode_focus_diagnostic('preparation_progress',raw)

    def test_symbol_width_alias_and_required_stopped_read_metadata(self):
        from unittest.mock import patch
        locations={name:dict(pa=0x40200000+i*8192,va=0x40200000+i*8192,size=width) for i,(_, (name,width)) in enumerate(data.FOCUS_DIAGNOSTICS.items())}
        name='REPLAY_PREPARATION_PROGRESS'
        with patch.object(data,'symbol',side_effect=lambda _,name:dict(locations[name])):
            self.assertIn('preparation_progress',data.focus_diagnostic_symbols(b'caller ELF fixture'))
            locations[name]['size']=1024
            with self.assertRaises(ValueError):data.focus_diagnostic_symbols(b'caller ELF fixture')
            locations[name]['size']=6144;locations[name]['pa']=next(iter(locations.values()))['pa']
            with self.assertRaises(ValueError):data.focus_diagnostic_symbols(b'caller ELF fixture')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();rows=[dict(direction='receive',message={'QMP':{}})];number=0;context=dict(diagnostic_symbols={})
            def command(name,args=None,result=None):
                nonlocal number
                number+=1;m=dict(execute=name,id=number)
                if args is not None:m['arguments']=args
                rows.extend([dict(direction='send',message=m),dict(direction='receive',message={'id':number,'return':{} if result is None else result})])
            command('cont');command('stop');command('query-status',result={'status':'paused'})
            for i,(key,(_,width)) in enumerate(data.FOCUS_DIAGNOSTICS.items()):
                path=root/('diagnostic-'+key+'.bin');path.write_bytes(bytes(width));pa=0x40200000+i*8192
                context['diagnostic_symbols'][key]=dict(pa=pa,size=width);command('pmemsave',dict(val=pa,size=width,filename=str(path)))
            command('quit');data.verify_focus_diagnostic_reads(rows,root,context)
            index=next(i for i,r in enumerate(rows) if r['message'].get('arguments',{}).get('filename')==str(root/'diagnostic-preparation_progress.bin'))
            for mutation in ('missing','pa','width','file','early','late'):
                changed=copy.deepcopy(rows)
                if mutation=='missing':del changed[index:index+2]
                elif mutation in ('early','late'):
                    read=changed[index:index+2];del changed[index:index+2];at=0 if mutation=='early' else len(changed);changed[at:at]=read
                else:changed[index]['message']['arguments'][{'pa':'val','width':'size','file':'filename'}[mutation]]={'pa':123,'width':1024,'file':str(root/'orphan.bin')}[mutation]
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):data.verify_focus_diagnostic_reads(changed,root,context)

    def test_parser_failure_keeps_raw_original_timeout_and_false_claims(self):
        import json
        from unittest.mock import patch
        import run_v16_a03_data as runner
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();locations={key:dict(pa=i*8192,size=width) for i,(key,(_,width)) in enumerate(data.FOCUS_DIAGNOSTICS.items())}
            bad=preparation_fixture();put(bad,4*8,9)
            def save(name,pa,width):
                raw=bytes(bad) if name=='diagnostic-preparation_progress.bin' else bytes(width)
                (root/name).write_bytes(raw);return raw
            result=runner.capture_diagnostics(save,locations)
            self.assertIn('preparation_progress',result['errors']);self.assertEqual((root/'diagnostic-preparation_progress.bin').read_bytes(),bad)
            (root/'diagnostic-bounded_data.bin').write_bytes(bytes(8192));artifacts=data.bounded_inventory(root)
            (root/'summary.json').write_text(json.dumps(dict(version=data.VERSION,status='FAIL',capture_complete=False,released_pair_observed=False,error='TimeoutError: original600s',artifacts=artifacts)))
            checked=dict(raw_inventory=data.bounded_inventory(root),trusted_context={'fixture':'checked caller'},diagnostic_reads={},boot_epoch=1)
            with patch.object(data,'_verify_data_capture_custody',return_value=checked),patch.object(data,'trusted_context',return_value=checked['trusted_context']):
                result=data.verify_diagnostic_capture(root,source_root=root,build_manifest=root,formatter=root,qemu_binary=root,qemu_source=root)
            self.assertIn('preparation_progress',result['diagnostic_parser_errors']);self.assertEqual(result['original_failure'],'TimeoutError: original600s')
            self.assertFalse(result['data_collection_verified']);self.assertFalse(result['authorizes_replay']);self.assertEqual(result['samples'],0)

if __name__=='__main__':unittest.main()
