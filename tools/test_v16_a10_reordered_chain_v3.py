"""Pure graph/semantic negative tests, no archive-controlled execution."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from v16_a10_reordered_chain_v3 import validate_plan, validate_resources, ROLES, PARENTS

class ChainV3(unittest.TestCase):
    def plan(self):
        p=dict(schema_version=3,test_id='A10',profile='reordered-before-write-recut-v3',seed={'sha256':'1'*64})
        for role in ROLES:
            p[role]=dict(directory='/private/tmp/'+role,summary_sha256='2'*64,parent=PARENTS[role],
                initial_sha256='3'*64,final_sha256='4'*64)
            if role.endswith('_cut'):
                p[role]['expected_write']=dict(cut=3,offset=512,length=512,data_sha256='5'*64)
                p[role]['selection']=dict(probe_summary_sha256='2'*64,category='overwrite-redo' if role=='overwrite_cut' else 'mount-replay-home')
        return p
    def test_exact_graph(self):validate_plan(self.plan())
    def test_closed_roles_and_no_commands(self):
        for change in (lambda p:p.update(command='bad'),lambda p:p['seed'].update(path='/bad'),
            lambda p:p['recovery_cut'].update(parent='recovery_probe'),lambda p:p.update(schema_version=True),
            lambda p:p['overwrite_cut']['selection'].update(category='boot-epoch')):
            p=self.plan();change(p)
            with self.assertRaises(ValueError):validate_plan(p)
    def test_caps_required_and_five_children(self):
        validate_resources(dict(max_children=5,max_runtime_seconds=9600,max_storage_bytes=8*1024**3))
        for limits in ({},dict(max_children=4,max_runtime_seconds=9600,max_storage_bytes=8*1024**3),
            dict(max_children=True,max_runtime_seconds=9600,max_storage_bytes=8*1024**3),
            dict(max_children=5,max_runtime_seconds=9599,max_storage_bytes=8*1024**3)):
            with self.assertRaises(ValueError):validate_resources(limits)


# The following fixtures are raw host data only. They deliberately confer no
# ELF/QMP/native admission. They exercise decoding, body mapping and ancestry.
import hashlib
import json
import struct
import tempfile
from check_v13_disk import BLOCK, COUNT, crc32c
from test_check_v13_boot_disk import checksum
from check_prototype_evidence import sha256
from v16_a10_reordered_chain_v3 import (validate_links, select_mount_replay_write,
    select_overwrite_write, read_requests, decode_overwrite_transaction, canonical_path)
from verify_v13_a10 import TRACE_MAGIC, EVENT_MAGIC, payload


def log_record(kind,txid,lsn,epoch,body,*,home=0,index=0,count=0):
    raw=bytearray(2*BLOCK if kind==2 else BLOCK)
    struct.pack_into('<IHHIIQQQQII',raw,0,0x43594c47,1,kind,64+len(body),crc32c(body),txid,lsn,epoch,home,index,count)
    raw[64:64+len(body)]=body
    header=checksum(raw[:64],56);raw[:64]=header
    return bytes(raw)


def transaction(images):
    begin=log_record(1,1,9,2,struct.pack('<IIQ',2,0,2*BLOCK))
    redos=[log_record(2,1,10+i,2,image,home=home,index=i,count=2) for i,(home,image) in enumerate(images)]
    ordered=hashlib.sha256(b''.join(struct.pack('<Q',home)+image for home,image in images)).digest()
    commit=log_record(3,1,12,2,struct.pack('<QQQII',1,9,11,2,0)+ordered)
    return begin+redos[0]+redos[1]+commit


def sb(generation=2,checkpoint=8,epoch=2):
    raw=bytearray(BLOCK);struct.pack_into('<IHHII',raw,0,0x43594653,1,80,BLOCK,COUNT)
    raw[16:32]=bytes(range(1,17));struct.pack_into('<3Q',raw,32,generation,checkpoint,epoch)
    struct.pack_into('<5I',raw,56,4098,4102,4118,256,0)
    return bytes(checksum(raw,76))


def request_capture(root, operations):
    directory=root/'nbd';directory.mkdir(exist_ok=True)
    (directory/'start.json').write_text(json.dumps({'trace_encoding':'raw'}))
    wire=bytearray();rows=[];mutation=0
    for identity,(kind,offset,body) in enumerate(operations,1):
        mutation+=1;length=len(body);at=len(wire)
        wire+=struct.pack('>IHHQQI',0x25609513,0,kind,identity,offset,length)
        if kind==1:wire+=body
        rows.append(dict(event='request',id=identity,kind=kind,handle=identity,offset=offset,length=length,
            wire_offset=at,mutation=mutation,scope='armed',data_sha256=hashlib.sha256(body).hexdigest()))
    # Synthetic reverse ACK list only exercises selector semantics. The separate
    # WRITE transport test obtains actual ACK order from a host-owned backend.
    rows += [dict(event='ack',id=i) for i in range(len(operations),0,-1)]
    (directory/'requests.bin').write_bytes(wire)
    (directory/'events.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
    return rows


def trace(root):
    binding=dict(mode=2,boot_epoch=1,nonce='1'*32,uuid='2'*32,
        image_sha256='3'*64,input_sha256='4'*64,source_sha256='5'*64)
    raw=bytearray(512+2*768)
    struct.pack_into('<7Q',raw,0,TRACE_MAGIC,1,768,2,0,1,2)
    for offset,key in ((56,'nonce'),(72,'uuid'),(120,'image_sha256'),(152,'input_sha256'),(184,'source_sha256')):
        value=bytes.fromhex(binding[key]);raw[offset:offset+len(value)]=value
    struct.pack_into('<4Q',raw,88,1,1,2,1)
    for ordinal,operation,writes,flushes in ((1,4,0,0),(2,5,6,2)):
        base=512+(ordinal-1)*768
        struct.pack_into('<12Q',raw,base,EVENT_MAGIC,ordinal,ordinal,1,1,1,ordinal,0,writes,flushes,
            4096 if operation==4 else 0,0)
        raw[base+96:base+128]=hashlib.sha256(payload(3) if operation==4 else b'').digest()
        frame=base+128
        struct.pack_into('<Q4H',raw,frame,0x435946494c453031,1,640,operation,0)
        struct.pack_into('<7Q',raw,frame+16,ordinal,1,1,1,1,0,4096 if operation==4 else 0)
        struct.pack_into('<IHH',raw,frame+72,4096 if operation==4 else 0,0,0)
        struct.pack_into('<q5Q',raw,frame+80,0,4096 if operation==4 else 0,4,1,3,3)
    (root/'binding.json').write_text(json.dumps(binding));(root/'trace.bin').write_bytes(raw)


class RawSemanticsV3(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='a10-v3-semantic-');self.root=Path(self.tmp.name).resolve()
        self.images=[(7000,b'x'*BLOCK),(7001,b'z'*BLOCK)]
        self.tx=transaction(self.images)
    def tearDown(self):self.tmp.cleanup()

    def recovery(self):
        initial=self.root/'initial.raw'
        with initial.open('wb') as stream:
            stream.truncate(BLOCK*COUNT);stream.seek(0);stream.write(sb());stream.write(sb())
            stream.seek(2*BLOCK);stream.write(self.tx)
        operations=[(1,home*BLOCK+i*512,image[i*512:(i+1)*512]) for home,image in self.images for i in range(8)]
        operations.append((3,0,b''))
        next_sb=sb(3,12,3)
        operations += [(1,BLOCK+i*512,next_sb[i*512:(i+1)*512]) for i in range(8)]
        operations += [(3,0,b''),(1,2*BLOCK,b'boot-epoch'.ljust(512,b'\0'))]
        request_capture(self.root,operations)
        return initial,operations

    def test_selects_initial_committed_home_not_later_boot_epoch(self):
        initial,operations=self.recovery();selected=select_mount_replay_write(self.root,initial)
        self.assertEqual(selected['cut'],16)
        self.assertEqual(selected['offset'],7001*BLOCK+7*512)
        self.assertEqual(selected['data_sha256'],hashlib.sha256(b'z'*512).hexdigest())
        self.assertNotEqual(selected['offset'],2*BLOCK)

    def test_replay_rejects_changed_body_fence_order_or_superblock(self):
        initial,operations=self.recovery()
        bad_cases=[]
        wrong=list(operations);wrong[0]=(1,operations[0][1],b'y'*512);bad_cases.append(wrong)
        wrong=list(operations);wrong[16]=(1,2*BLOCK,b'boot-epoch'.ljust(512,b'\0'));bad_cases.append(wrong)
        wrong=list(operations);wrong[17],wrong[18]=wrong[18],wrong[17];bad_cases.append(wrong)
        wrong=list(operations);wrong[25]=(1,2*BLOCK,b'boot-epoch'.ljust(512,b'\0'));bad_cases.append(wrong)
        wrong=list(operations);wrong[0],wrong[8]=wrong[8],wrong[0];bad_cases.append(wrong)
        for operations in bad_cases:
            request_capture(self.root,operations)
            with self.subTest(operations=operations[0][:2]),self.assertRaises(ValueError):
                select_mount_replay_write(self.root,initial)

    def test_replay_refuses_uncommitted_or_empty_parent(self):
        initial,operations=self.recovery()
        with initial.open('r+b') as stream:stream.seek(7*BLOCK);stream.write(bytes(BLOCK))
        with self.assertRaisesRegex(ValueError,'no committed'):select_mount_replay_write(self.root,initial)

    def test_raw_body_receipt_mapping_refuses_hash_and_header_corruption(self):
        self.recovery();directory=self.root/'nbd'
        raw=(directory/'requests.bin').read_bytes();corrupted=bytearray(raw);corrupted[28]^=1
        (directory/'requests.bin').write_bytes(corrupted)
        with self.assertRaisesRegex(ValueError,'body/receipt'):read_requests(self.root)
        (directory/'requests.bin').write_bytes(raw+b'x')
        with self.assertRaisesRegex(ValueError,'trailing'):read_requests(self.root)

    def test_overwrite_selects_decoded_redo_and_requires_commit_digest(self):
        trace(self.root)
        operations=[(1,2*BLOCK+i*512,self.tx[i*512:(i+1)*512]) for i in range(40)]
        operations += [(3,0,b'')]+[(1,2*BLOCK+i*512,self.tx[i*512:(i+1)*512]) for i in range(40,48)]+[(3,0,b'')]
        request_capture(self.root,operations)
        selected=select_overwrite_write(self.root)
        self.assertEqual(selected['cut'],31)
        self.assertEqual(selected['offset'],2*BLOCK+30*512)
        blocks=[self.tx[i:i+BLOCK] for i in range(0,len(self.tx),BLOCK)]
        self.assertEqual([r['home'] for r in decode_overwrite_transaction(blocks)],[7000,7001])
        changed=list(blocks);bad=bytearray(changed[-1]);bad[100]^=1;changed[-1]=bytes(bad)
        with self.assertRaises(ValueError):decode_overwrite_transaction(changed)

    def test_path_alias_and_symlink_rejected(self):
        target=self.root/'target';target.write_bytes(b'x');link=self.root/'alias';link.symlink_to(target)
        with self.assertRaises(ValueError):canonical_path(str(link))
        with self.assertRaises(ValueError):canonical_path(str(self.root)+'/../'+self.root.name+'/target')


class AncestryV3(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='a10-v3-graph-');self.root=Path(self.tmp.name).resolve()
        self.seed=self.root/'seed.raw';self.seed.write_bytes(b'seed')
        self.plan=ChainV3().plan();self.plan['seed']['sha256']=sha256(self.seed)
        common=dict(source_sha256='a'*64,build_sha256='b'*64,image_sha256='c'*64,qemu={'binary_sha256':'d'*64})
        self.records={}
        for index,role in enumerate(ROLES):
            p=self.plan[role];p['directory']=str(self.root/role)
            parent=PARENTS[role];p['initial_sha256']=self.plan['seed']['sha256'] if parent=='seed' else self.plan[parent]['final_sha256']
            context=dict(capture_root=p['directory'],backing_path=p['directory']+'/disk.raw',
                initial_source=str(self.seed) if parent=='seed' else self.plan[parent]['directory']+'/disk.raw',
                version='a10-reordered-write-native-v3' if role.endswith('_cut') else 'a10-native-v1',
                backend_run_id=role,endpoints={kind:p['directory']+'/'+kind for kind in ('nbd','qmp','gdb')})
            events={kind:dict(monotonic_ns=100*index+i+1) for i,kind in enumerate(
                ('identity-before','backend-open','spawn','final-disk','identity-after'))}
            self.records[role]=dict(directory=p['directory'],context=context,identity=dict(common,initial_sha256=p['initial_sha256']),
                nonce=role,binding={'uuid':'uuid'},model_sha256='e'*64,lifecycle=events,
                inputs=dict(mode={'prepare':1,'overwrite_probe':2,'overwrite_cut':2}.get(role,3),
                    cut=3 if role.endswith('_cut') else 0,phase='before',unflushed='reverse-half',reverse_replies=True,
                    initial_disk_sha256=p['initial_sha256']),summary=dict(status='NOT_RUN' if role.endswith('_cut') else 'PASS',
                    native_mode_verified=not role.endswith('_cut'),native_reordered_write_cut_custody_verified=role.endswith('_cut'),
                    nbd_trace=dict(disk_final_sha256=p['final_sha256'],reordered_replies=True)))
    def tearDown(self):self.tmp.cleanup()
    def check(self,records=None,session=True):
        return validate_links(self.plan,records or self.records,self.seed,same_host_monotonic_session=session)
    def test_fixed_graph_preserves_partial_status(self):
        result=self.check();self.assertTrue(result['strict_partial_chain_verified'])
        self.assertEqual(result['legacy_mandatory_slots'],0);self.assertEqual(result['native_acceptance_status'],'NOT_RUN')
    def test_repaired_probe_output_never_substitutes_parent_even_equal_bytes(self):
        for role,probe in [('overwrite_cut','overwrite_probe'),('recovery_cut','recovery_probe')]:
            records=copy.deepcopy(self.records);records[role]['context']['initial_source']=self.plan[probe]['directory']+'/disk.raw'
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'ancestry'):self.check(records)
    def test_identity_nonce_endpoint_and_order_mismatches(self):
        mutations=[('identity','source_sha256','0'*64),('identity','build_sha256','0'*64),
            ('identity','image_sha256','0'*64),('identity','qemu',{}),('binding','uuid','other'),
            ('context','backend_run_id','prepare'),('inputs','mode',True),('inputs','phase','after-ack'),
            ('inputs','unflushed','drop'),('inputs','reverse_replies',False)]
        for owner,key,value in mutations:
            records=copy.deepcopy(self.records);records['recovery_cut'][owner][key]=value
            with self.subTest(owner=owner,key=key),self.assertRaises(ValueError):self.check(records)
        for change in (lambda r:r['recovery_cut'].update(nonce='prepare'),
            lambda r:r['recovery_cut'].update(model_sha256='0'*64),
            lambda r:r['recovery_cut']['context'].update(endpoints=r['overwrite_cut']['context']['endpoints']),
            lambda r:r['recovery_cut']['lifecycle']['identity-before'].update(monotonic_ns=1),
            lambda r:r['recovery_cut']['summary'].update(native_reordered_write_cut_custody_verified=False)):
            records=copy.deepcopy(self.records);change(records)
            with self.assertRaises(ValueError):self.check(records)
        for value in (False,1,'true',None):
            with self.subTest(session=value),self.assertRaises(ValueError):self.check(session=value)




class DriverControlV3(unittest.TestCase):
    """Mock only native admission/producers to test orchestration and abort.

    No fixture here becomes a native verdict: the final checker is replaced by
    an explicit diagnostic result with strict_partial_chain_verified=False.
    Raw selectors and native transport are covered by separate real-byte tests.
    """
    def setUp(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import run_v16_a10_reordered_chain_v3 as driver
        self.driver=driver;self.tmp=tempfile.TemporaryDirectory(prefix='a10-v3-driver-')
        self.root=Path(self.tmp.name).resolve();self.seed=self.root/'seed.raw'
        with self.seed.open('wb') as stream:stream.truncate(512*1024**2)
        self.prepare=self.root/'prepare';self.prepare.mkdir()
        for name in ('initial.raw','disk.raw'):
            with (self.prepare/name).open('wb') as stream:stream.truncate(512*1024**2)
        (self.prepare/'summary.json').write_text('{}')
        self.build=self.root/'build.json';self.build.write_text(json.dumps(dict(code_source_map={'fixture':'host-only'},
            builder_sha256=sha256(driver.ROOT/'tools/build_unified.py'))))
        self.qemu=self.root/'fixture-binary';self.qemu.write_bytes(b'not executed')
        self.calls=[];self.checked=[];self.stop_at=None
        def admitted(root,**kwargs):
            self.checked.append(str(root))
            return SimpleNamespace(inputs=dict(mode=1,cut=0,initial_disk_sha256=sha256(self.seed)),
                summary=dict(status='PASS',native_mode_verified=True),context=dict(initial_source=str(self.seed)))
        def capture(build,parent,output,**kwargs):
            self.calls.append((Path(output).name,Path(parent),kwargs))
            output.mkdir()
            (output/'raw-failure-retained').write_bytes(b'host-control-fixture')
            if Path(output).name==self.stop_at:raise RuntimeError('synthetic native producer failure after its own cleanup')
            for name in ('initial.raw','disk.raw'):
                with (output/name).open('wb') as stream:stream.truncate(512*1024**2)
            (output/'summary.json').write_text('{}')
            return {'status':'fixture-only'}
        def final(plan,**kwargs):
            validate_plan(plan)
            self.assertEqual([role for role,_,_ in self.calls],list(ROLES[1:]))
            expected={'overwrite_probe':self.prepare/'disk.raw','overwrite_cut':self.prepare/'disk.raw',
                'recovery_probe':self.root/'out/overwrite_cut/disk.raw',
                'recovery_cut':self.root/'out/overwrite_cut/disk.raw',
                'final_recovery':self.root/'out/recovery_cut/disk.raw'}
            for role,parent,values in self.calls:
                self.assertEqual(parent,expected[role]);self.assertIs(values['reverse_replies'],True)
                self.assertEqual(values['timeout'],1920)
            return dict(strict_partial_chain_verified=False,host_orchestration_fixture=True)
        selected=dict(cut=31,offset=512,length=512,data_sha256='5'*64)
        self.patches=[patch.object(driver,'code_source_map',return_value={'fixture':'host-only'}),
            patch.object(driver,'tool_closure',return_value={'fixture':'host-only'}),
            patch.object(driver,'qemu_identity',return_value={'fixture':'host-only'}),
            # Native producers are mocked here; make their host admission
            # input explicit too, independently of the developer's free disk.
            patch.object(driver.shutil,'disk_usage',return_value=SimpleNamespace(free=16*1024**3)),
            patch.object(driver,'verify_native_child',side_effect=admitted),
            patch.object(driver,'verify_native_reordered_write_child',side_effect=admitted),
            patch.object(driver,'run_clean',side_effect=capture),patch.object(driver,'run_cut',side_effect=capture),
            patch.object(driver,'select_overwrite_write',return_value=selected),
            patch.object(driver,'select_mount_replay_write',return_value=selected),
            patch.object(driver,'verify_chain',side_effect=final)]
        for active in self.patches:active.start()
    def tearDown(self):
        for active in reversed(self.patches):active.stop()
        self.tmp.cleanup()
    def run_driver(self,**changes):
        args=dict(prepare=self.prepare,initial_disk=self.seed,output=self.root/'out',source_root=self.driver.ROOT,
            build_manifest=self.build,qemu_binary=self.qemu,qemu_source=self.root,same_host_monotonic_session=True,
            resource_caps=dict(max_children=5,max_runtime_seconds=9600,max_storage_bytes=8*1024**3))
        args.update(changes);return self.driver.run(**args)
    def test_fixed_five_calls_use_damaged_parent_and_prelaunch_selector(self):
        result=self.run_driver()
        self.assertTrue(result['host_orchestration_fixture'])
        self.assertFalse(result['strict_partial_chain_verified'])
        plan=json.loads((self.root/'out/plan.json').read_text());validate_plan(plan)
        self.assertEqual(plan['recovery_cut']['parent'],'overwrite_cut')
        self.assertEqual(result['completed_roles'],list(ROLES[1:]))
        self.assertEqual(result['legacy_mandatory_slots'],0)
        self.assertTrue(result['accounting_complete'])
        self.assertIsInstance(result['retained_allocated_bytes'],int)
        self.assertNotIn('accounting_error',result)
    def test_first_failure_preserves_raw_child_and_prevents_later_launches(self):
        self.stop_at='overwrite_cut'
        with self.assertRaisesRegex(RuntimeError,'producer failure'):self.run_driver()
        self.assertEqual([role for role,_,_ in self.calls],['overwrite_probe','overwrite_cut'])
        self.assertTrue((self.root/'out/overwrite_cut/raw-failure-retained').is_file())
        report=json.loads((self.root/'out/campaign-summary.json').read_text())
        self.assertFalse(report['strict_partial_chain_verified'])
        self.assertEqual(report['completed_roles'],['overwrite_probe'])
        self.assertIn('producer failure',report['error'])
        # The selected WRITE and its clean-probe summary are retained before a
        # failing cut starts. No completed probe disk becomes its parent.
        plan=json.loads((self.root/'out/plan.json').read_text())
        self.assertEqual(plan['overwrite_cut']['expected_write']['cut'],31)
        self.assertEqual(plan['overwrite_cut']['selection']['probe_summary_sha256'],plan['overwrite_probe']['summary_sha256'])
    def test_invalid_final_accounting_preserves_primary_and_failure_summary(self):
        from unittest.mock import patch
        import os
        from v16_a10_reordered_write_v3 import bounded_inventory
        for kind,message in (('empty','extra inventory directory'),('fifo','special file'),('cap','entry bound')):
            with self.subTest(kind=kind):
                primary=RuntimeError('primary child failure '+kind)
                output=self.root/('out-'+kind)
                def failing(build,parent,child,**kwargs):
                    self.calls.append((Path(child).name,Path(parent),kwargs));child.mkdir()
                    (child/'raw-failure-retained').write_bytes(b'preserved')
                    if kind=='empty':(child/'extra-empty').mkdir()
                    elif kind=='fifo':os.mkfifo(child/'fifo')
                    else:(child/'extra-file').write_bytes(b'x')
                    raise primary
                def limited(root,**kwargs):
                    return bounded_inventory(root,**kwargs,**({'max_entries':2} if kind=='cap' else {}))
                with patch.object(self.driver,'run_clean',side_effect=failing),patch.object(self.driver,'bounded_inventory',side_effect=limited):
                    with self.assertRaises(RuntimeError) as caught:self.run_driver(output=output)
                self.assertIs(caught.exception,primary)
                report=json.loads((output/'campaign-summary.json').read_text())
                self.assertEqual(report['error'],'RuntimeError: '+str(primary))
                self.assertFalse(report['accounting_complete'])
                self.assertIsNone(report['retained_allocated_bytes'])
                self.assertIn(message,report['accounting_error'])
                self.assertEqual(report['status'],'FAIL')
                self.assertFalse(report['strict_partial_chain_verified'])
                self.assertTrue((output/'overwrite_probe/raw-failure-retained').is_file())
                self.assertEqual(len(self.calls),1);self.calls.clear()
    def test_final_accounting_failure_cannot_return_success(self):
        from unittest.mock import patch
        original=self.driver.verify_chain.side_effect
        def completed(plan,**kwargs):
            result=original(plan,**kwargs)
            # Simulate a finalizer-only race after native verification. This
            # remains a host-control fixture and confers no native verdict.
            (self.root/'out/overwrite_probe/extra-empty').mkdir()
            result['strict_partial_chain_verified']=True
            return result
        with patch.object(self.driver,'verify_chain',side_effect=completed):
            with self.assertRaisesRegex(ValueError,'extra inventory directory'):self.run_driver()
        report=json.loads((self.root/'out/campaign-summary.json').read_text())
        self.assertEqual(report['status'],'FAIL')
        self.assertFalse(report['strict_partial_chain_verified'])
        self.assertFalse(report['accounting_complete'])
        self.assertIsNone(report['retained_allocated_bytes'])
    def test_caps_or_missing_clock_session_fail_before_native_dispatch(self):
        for change in (dict(same_host_monotonic_session=False),dict(resource_caps={}),
            dict(resource_caps=dict(max_children=6,max_runtime_seconds=9600,max_storage_bytes=8*1024**3))):
            with self.assertRaises(ValueError):self.run_driver(**change)
        self.assertEqual(self.calls,[])
    def test_insufficient_host_storage_fails_before_native_dispatch(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from v16_a10_reordered_chain_v3 import MIN_STORAGE
        with patch.object(self.driver.shutil,'disk_usage',return_value=SimpleNamespace(free=MIN_STORAGE-1)):
            with self.assertRaisesRegex(ValueError,'insufficient available campaign storage'):
                self.run_driver()
        self.assertEqual(self.calls,[])

class InventoryBoundsV3(unittest.TestCase):
    """Host filesystem adversaries, with no VM or native admission claim."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='a10-v3-inventory-')
        self.root=Path(self.tmp.name).resolve()
    def tearDown(self):self.tmp.cleanup()
    def inventory(self,**kwargs):
        from v16_a10_reordered_write_v3 import bounded_inventory
        return list(bounded_inventory(self.root,**kwargs))
    def test_empty_and_exact_entry_file_boundaries(self):
        self.assertEqual(self.inventory(max_entries=1,max_files=1),[])
        (self.root/'a').write_bytes(b'a')
        self.assertEqual(len(self.inventory(max_entries=1,max_files=1)),1)
        (self.root/'b').write_bytes(b'b')
        with self.assertRaisesRegex(ValueError,'entry bound'):self.inventory(max_entries=1)
        with self.assertRaisesRegex(ValueError,'file bound'):self.inventory(max_files=1)
    def test_directory_and_depth_boundaries_include_empty_directories(self):
        (self.root/'a').mkdir();(self.root/'b').mkdir()
        self.assertEqual(self.inventory(max_dirs=2),[])
        with self.assertRaisesRegex(ValueError,'directory bound'):self.inventory(max_dirs=1)
        (self.root/'a/c').mkdir()
        self.assertEqual(self.inventory(max_depth=2),[])
        (self.root/'a/c/d').mkdir()
        with self.assertRaisesRegex(ValueError,'depth bound'):self.inventory(max_depth=2)
    def test_streaming_stops_at_cap_before_consuming_remainder(self):
        from unittest.mock import patch
        import os
        for name in ('a','b','c'):(self.root/name).write_bytes(b'x')
        with os.scandir(self.root) as stream:entries=list(stream)
        consumed=[]
        class LimitedStream:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __iter__(self):
                for entry in entries:
                    consumed.append(entry.name)
                    if len(consumed)>2:raise AssertionError('traversed past rejection bound')
                    yield entry
        with patch('os.scandir',return_value=LimitedStream()):
            with self.assertRaisesRegex(ValueError,'entry bound'):self.inventory(max_entries=1)
        self.assertEqual(len(consumed),2)
    def test_symlink_special_file_and_root_symlink_refused(self):
        import os
        (self.root/'alias').symlink_to(self.root)
        with self.assertRaisesRegex(ValueError,'symlink'):self.inventory()
        (self.root/'alias').unlink();os.mkfifo(self.root/'fifo')
        with self.assertRaisesRegex(ValueError,'special file'):self.inventory()
        (self.root/'fifo').unlink()
        with tempfile.TemporaryDirectory() as other:
            alias=Path(other)/'alias';alias.symlink_to(self.root)
            from v16_a10_reordered_write_v3 import bounded_inventory
            with self.assertRaisesRegex(ValueError,'root'):list(bounded_inventory(alias))
    def test_closed_layout_refuses_extra_empty_dir_before_descent(self):
        (self.root/'nbd').mkdir();(self.root/'nbd/start.json').write_bytes(b'{}')
        self.assertEqual(len(self.inventory(allowed_files={'nbd/start.json'})),1)
        (self.root/'untrusted-empty').mkdir()
        with self.assertRaisesRegex(ValueError,'extra.*directory'):
            self.inventory(allowed_files={'nbd/start.json'})
        (self.root/'untrusted-empty').rmdir();(self.root/'nbd/extra').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError,'extra.*file'):
            self.inventory(allowed_files={'nbd/start.json'})
    def test_hard_caps_cannot_be_disabled_or_enlarged(self):
        for key,value in (('max_entries',True),('max_entries',0),('max_entries',8193),
            ('max_dirs',129),('max_files',8193),('max_depth',9)):
            with self.subTest(key=key,value=value),self.assertRaisesRegex(ValueError,'invalid inventory cap'):
                self.inventory(**{key:value})
    def test_ten_thousand_entries_stop_at_reviewed_hard_cap(self):
        from unittest.mock import patch
        import os
        (self.root/'file').write_bytes(b'x')
        with os.scandir(self.root) as stream:entry=next(stream)
        consumed=[]
        class LargeStream:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __iter__(self):
                for index in range(10000):
                    consumed.append(index)
                    if len(consumed)>8193:raise AssertionError('consumed oversized tree')
                    yield entry
        with patch('os.scandir',return_value=LargeStream()):
            with self.assertRaisesRegex(ValueError,'entry bound'):self.inventory()
        self.assertEqual(len(consumed),8193)
    def test_campaign_usage_refuses_unknown_empty_directory_and_fifo(self):
        from run_v16_a10_reordered_chain_v3 import usage
        import os
        self.assertEqual(usage(self.root),0)
        child=self.root/'overwrite_probe';child.mkdir()
        (child/'disk.raw').write_bytes(b'x')
        self.assertEqual(usage(self.root),(child/'disk.raw').stat().st_blocks*512)
        (child/'extra-empty').mkdir()
        with self.assertRaisesRegex(ValueError,'extra.*directory'):usage(self.root)
        (child/'extra-empty').rmdir();os.mkfifo(child/'fifo')
        with self.assertRaisesRegex(ValueError,'special file'):usage(self.root)

if __name__=='__main__':unittest.main()
