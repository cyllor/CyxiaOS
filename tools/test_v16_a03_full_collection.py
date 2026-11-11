"""Host boundary regressions; fixture counters are not native evidence."""
import importlib
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def probe(*, paired=216, phase=17, data_phase=11, excluded=0, archived=None,
          owner_clear=1, profile=0):
    w = [0]*64
    training = [8]*18 if paired == 216 else [2]+[0]*17
    validation = [4]*18 if paired == 216 else [0]*18
    verified = 432 if paired == 216 else 4
    for k,v in {0:2,1:0x435952504c593133,2:phase,3:16 if paired==216 else 1,
                4:2 if paired==216 else 1,5:0 if paired==216 else 2,6:2,
                7:verified+excluded+1,10:verified,11:excluded,
                17:verified+excluded if archived is None else archived,
                18:data_phase,19:paired,60:999}.items(): w[k]=v
    w[24:42]=training;w[42:60]=validation
    c=[0]*64
    for k,v in {0:2,1:0x43594c434f4c3136,2:1,3:profile,4:phase,
                6:w[3],7:w[4],8:w[5],9:verified,10:w[17],11:paired,
                13:owner_clear,14:1,47:999}.items(): c[k]=v
    result={'replay':struct.pack('<64Q',*w),'collection':struct.pack('<64Q',*c),
            'control':bytes((512+64*640)*8),'tasks':bytes(256),'learning':bytes(1024),
            'boot':bytes(512),'runtime':bytes(8192)}
    r=bytearray(result['runtime']);struct.pack_into('<Q',r,16,2);result['runtime']=bytes(r)
    return result


def changed(raw, index, value):
    v=bytearray(raw);struct.pack_into('<Q',v,index*8,value);return bytes(v)


class Boundaries(unittest.TestCase):
    def setUp(self):
        try:self.f=importlib.import_module('v16_a03_full_collection')
        except ModuleNotFoundError:self.fail('full collection entry is missing; only two-group observers exist')

    def test_two_groups_and_later_family_are_progress_not_terminal(self):
        p=probe(paired=2,phase=0,data_phase=1)
        self.assertIsNone(self.f.terminal_hint(p,'collected'))
        self.assertIsNone(self.f.terminal_boundary(p,'validated'))
        p['replay']=changed(p['replay'],3,2)
        self.f.fatal_evidence(p)
        self.assertIsNone(self.f.terminal_hint(p,'validated'))

    def test_full_native_terminal_accepts_focused_complete_flag_zero(self):
        p=probe()
        result=self.f.terminal_boundary(p,'validated')
        self.assertEqual(result['paired'],216)
        self.assertEqual(result['training_per_family'],[8]*18)
        self.assertEqual(result['validation_per_family'],[4]*18)
        self.assertTrue(result['validation_handoff_observed'])
        self.assertFalse(result['final_credit_release_verified'])
        self.assertFalse(result['active_model_verified'])

    def test_collection_does_not_mislabel_training_or_active(self):
        p=probe(data_phase=2)
        self.assertIsNone(self.f.terminal_boundary(p,'validated'))
        result=self.f.terminal_boundary(p,'collected')
        self.assertFalse(result['validation_handoff_observed'])
        self.assertIsNone(self.f.terminal_boundary(probe(owner_clear=0),'collected'))

    def test_terminal_cannot_retain_a_native_owner_error(self):
        p=probe();p['replay']=changed(p['replay'],12,8)
        self.assertIsNone(self.f.terminal_boundary(p,'validated'))

    def test_artifact_root_link_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'capture';root.mkdir();(root/'one').write_bytes(b'one')
            link=Path(t)/'link';link.symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):self.f.bounded_inventory(link)
            import os
            os.link(root/'one',root/'two')
            with self.assertRaises(ValueError):self.f.bounded_inventory(root)

    def test_nonce_aliases_cannot_reuse_the_same_binary_identity(self):
        check=getattr(self.f,'unique_identity',None)
        self.assertTrue(callable(check),'node identity canonicalization is missing')
        seen=set();check('ab'*16,seen,'nonce')
        for invalid in ('AB'*16,'ab '*16,'ab'*16,'00'*16):
            with self.assertRaises(ValueError):check(invalid,seen,'nonce')

    def test_preparation_and_late_journals_do_not_erase_regular_successes(self):
        check=getattr(self.f,'verify_journal_counts',None)
        self.assertTrue(callable(check),'separate journal counter validation is missing')
        rows=[dict(kind='regular',excluded=False)]*432
        rows+=[dict(kind='regular',excluded=True),dict(kind='preparation',excluded=True),dict(kind='late',excluded=True)]
        boundary=dict(verified=432,excluded=2,archived=435)
        check(rows,boundary)
        for broken in (rows[:-1],rows[:-2],rows[1:]):
            with self.assertRaises(ValueError):check(broken,boundary)

    def test_each_family_and_archive_retirement_are_required(self):
        for bank,index,value in [('replay',24,7),('replay',59,3),('replay',20,1),
                                 ('replay',3,1),('replay',5,1),
                                 ('replay',17,431),('collection',3,1),('collection',5,1),
                                 ('collection',12,1),('collection',14,0)]:
            p=probe();p[bank]=changed(p[bank],index,value)
            self.assertIsNone(self.f.terminal_boundary(p,'validated'),(bank,index))
        self.assertIsNotNone(self.f.terminal_boundary(probe(excluded=2,archived=435),'validated'))

    def test_regular_exclusion_and_preparation_cleanup_can_continue(self):
        p=probe(paired=2,phase=19,data_phase=1,excluded=1)
        p['replay']=changed(p['replay'],12,8)
        self.f.fatal_evidence(p)
        self.assertIsNone(self.f.terminal_hint(p,'validated'))
        p['replay']=changed(p['replay'],2,18)
        with self.assertRaisesRegex(ValueError,'collector'):self.f.fatal_evidence(p)
        p=probe(data_phase=12);p['replay']=changed(p['replay'],21,9)
        with self.assertRaisesRegex(ValueError,'rejected'):self.f.fatal_evidence(p)

    def test_fatal_tasks_optimizer_and_learning_faults_remain_fatal(self):
        for index in (2,3):
            p=probe();p['tasks']=changed(p['tasks'],index,1)
            with self.assertRaisesRegex(ValueError,'quarantine|overrun'):self.f.fatal_evidence(p)
        p=probe()
        for i,v in [(160,0x43594f5053540001),(161,1),(162,1),(191,2)]:
            p['control']=changed(p['control'],i,v)
        with self.assertRaisesRegex(ValueError,'optimization'):self.f.fatal_evidence(p)
        p=probe();p['learning']=changed(p['learning'],10,1)
        with self.assertRaisesRegex(ValueError,'learning worker'):self.f.fatal_evidence(p)

    def test_torn_and_unpublished_runtime_are_not_terminal(self):
        for bank,index,value in [('replay',0,3),('collection',0,3),('boot',2,1),
                                 ('runtime',2,0),('runtime',2,3)]:
            p=probe();p[bank]=changed(p[bank],index,value)
            self.assertIsNone(self.f.terminal_boundary(p,'validated'))
        self.assertIsNotNone(self.f.terminal_boundary(probe(),'validated'))

    def test_launch_has_two_distinct_disks_images_macs_and_socket_roles(self):
        a=self.f.launch_argv('/qemu',Path('/capture/node-a'),'/qa','/ga',1234,'a')
        b=self.f.launch_argv('/qemu',Path('/capture/node-b'),'/qb','/gb',1234,'b')
        self.assertIn('socket,id=net0,listen=127.0.0.1:1234',a)
        self.assertIn('socket,id=net0,connect=127.0.0.1:1234',b)
        self.assertIn('/capture/node-a/node-a.elf',a)
        self.assertIn('/capture/node-b/node-b.elf',b)
        self.assertIn('virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:02',b)
        self.assertNotIn('-icount',a+b)

    def test_large_transcript_keeps_strict_json_and_finite_timeout(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'transcript.json';pad=' '* (5*1024**2)
            p.write_text('[{}]'+pad)
            self.assertEqual(self.f.read_transcript(p),[{}])
            for raw in ('[{"x":1,"x":2}]','[NaN]','[1e999]'):
                p.write_text(raw)
                with self.assertRaises(ValueError):self.f.read_transcript(p)
        for value in (float('inf'),float('nan'),True,4,259201):
            with self.assertRaises(ValueError):self.f.validate_timeout(value)
        self.f.validate_timeout(172800)


class Transcript(unittest.TestCase):
    setUp=Boundaries.setUp
    def fixture(self, root, stages):
        rows=[{'direction':'receive','message':{'QMP':{}}}];identity=0
        symbols={k:{'pa':0x50000000+i*0x100000} for i,k in enumerate(self.f.BANKS)}
        def command(name,args=None,result=None):
            nonlocal identity
            identity+=1;m={'execute':name,'id':identity}
            if args is not None:m['arguments']=args
            rows.extend([dict(direction='send',message=m),dict(direction='receive',message={'id':identity,'return':{} if result is None else result})])
        def save(name,address,value):
            (root/name).write_bytes(value)
            command('pmemsave',dict(val=address,size=len(value),filename=str(root/name)))
        command('qmp_capabilities');command('query-cpus-fast',result=[]);command('query-memory-size-summary')
        save('dtb-header.bin',0x40000000,bytes(40));save('platform.dtb',0x40000000,bytes(40))
        save('config-observed.bin',symbols['config']['pa'],bytes(512));command('cont')
        for number,state in enumerate(stages,1):
            if number>1:command('cont')
            command('stop');command('query-status',result={'status':'paused'})
            values={k:state.get(k,bytes(size)) for k,(_,size) in self.f.BANKS.items()}
            for confirm in (False,True):
                for key,value in values.items():
                    save(f'probe-{number:02d}-'+('confirm-' if confirm else '')+key+'.bin',symbols[key]['pa'],value)
            for key,value in values.items():(root/(key+'.bin')).write_bytes(value)
        command('quit')
        self.save_rows(root,rows)
        return dict(node_symbols={'a':symbols}),dict(cpus=[],memory={}),bytes(40),rows

    def save_rows(self,root,rows):
        (root/'qmp-transcript.json').write_text(json.dumps(rows))
        for direction,file in [('send','qmp-sent.bin'),('receive','qmp-received.bin')]:
            (root/file).write_bytes(b''.join(json.dumps(r['message']).encode()+b'\n' for r in rows if r['direction']==direction))

    def test_real_qmp_checker_requires_exact_double_read_and_wire(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();context,platform,dtb,rows=self.fixture(root,[probe()])
            banks,serial,stops=self.f.verify_node_qmp(root,context,'a',platform,dtb)
            self.assertEqual(stops,1);self.assertEqual(serial,b'')
            self.assertEqual(self.f.terminal_boundary(banks)['paired'],216)
            original=(root/'probe-01-confirm-replay.bin').read_bytes()
            (root/'probe-01-confirm-replay.bin').write_bytes(changed(original,19,215))
            with self.assertRaisesRegex(ValueError,'paused bytes'):self.f.verify_node_qmp(root,context,'a',platform,dtb)
            (root/'probe-01-confirm-replay.bin').write_bytes(original)
            (root/'qmp-sent.bin').write_bytes(b'{}\n')
            with self.assertRaisesRegex(ValueError,'raw QMP'):self.f.verify_node_qmp(root,context,'a',platform,dtb)

    def test_fatal_earlier_stopped_round_cannot_be_hidden_by_clean_final(self):
        early=probe(paired=2,phase=0,data_phase=1);early['tasks']=changed(early['tasks'],2,1)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();context,platform,dtb,_=self.fixture(root,[early,probe()])
            with self.assertRaisesRegex(ValueError,'quarantine|overrun'):
                self.f.verify_node_qmp(root,context,'a',platform,dtb)

    def test_already_complete_leader_cannot_resume(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();context,platform,dtb,_=self.fixture(root,[probe(),probe()])
            with self.assertRaisesRegex(ValueError,'already-complete'):
                self.f.verify_node_qmp(root,context,'a',platform,dtb)

    def test_torn_earlier_round_can_resume_and_wrong_address_is_rejected(self):
        early=probe();early['boot']=changed(early['boot'],2,1)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();context,platform,dtb,rows=self.fixture(root,[early,probe()])
            self.assertEqual(self.f.verify_node_qmp(root,context,'a',platform,dtb)[2],2)
            request=next(r['message'] for r in rows if r['direction']=='send' and
                         r['message'].get('arguments',{}).get('filename','').endswith('probe-02-runtime.bin'))
            request['arguments']['val']+=4096;self.save_rows(root,rows)
            with self.assertRaisesRegex(ValueError,'physical range'):
                self.f.verify_node_qmp(root,context,'a',platform,dtb)


class WholeCapture(unittest.TestCase):
    """Host custody integration; native ABI and journal decoding are separate tests."""
    setUp=Boundaries.setUp

    @staticmethod
    def save(path,value):
        path.write_text(json.dumps(value))

    def freeze_input(self,folder,context,inputs):
        f=self.f;self.save(folder/'input.json',inputs);node=inputs['node']
        config=struct.pack('<4Q',f.CONFIG_MAGIC,1,0,0)+bytes.fromhex(inputs['nonce'])+bytes.fromhex(context['artifacts'][f'node-{node}.elf'])+bytes.fromhex(f.sha(folder/'input.json'))+bytes.fromhex(f.sha(folder.parent/'source-manifest.json'))+bytes(368)
        for name in ('config.bin','config-observed.bin','probe-01-config.bin','probe-01-confirm-config.bin'):
            (folder/name).write_bytes(config)
        self.save(folder/'config-injection.json',dict(request_hex=f.config_write_packet(config,context['node_symbols'][node]['config']['pa']).hex(),received_hex='2b244f4b233961',ack_hex='2b'))

    def fixture(self,root):
        f=self.f
        for name in ('build-manifest.json','base-build-manifest.json','source-manifest.json'):
            self.save(root/name,{})
        for name in ('node-a.elf','node-b.elf'):(root/name).write_bytes(name.encode())
        context=dict(build_sha256=f.sha(root/'build-manifest.json'),
            base_build_sha256=f.sha(root/'base-build-manifest.json'),source_map={},tools={},
            artifacts={name:f.sha(root/name) for name in ('node-a.elf','node-b.elf')},
            paths=dict(formatter='/host-fixture/formatter',qemu_binary='/host-fixture/qemu'),
            model_sha256=hashlib.sha256(b'fixture model').hexdigest(),node_symbols={})
        self.save(root/'capture.json',dict(version=f.VERSION,until='validated',timeout_seconds=600,nodes=['a','b']))
        for i,node in enumerate(('a','b'),1):
            folder=root/('node-'+node);folder.mkdir();state=probe()
            state['boot']=changed(state['boot'],6,1)
            transcript=Transcript();transcript.f=f
            ctx,_,_,_=transcript.fixture(folder,[state])
            context['node_symbols'][node]=ctx['node_symbols']['a']
            inputs=dict(version=f.VERSION,until='validated',timeout_seconds=600,poll_seconds=5,
                serial_seconds=5,nonce=f'{i:032x}',disk_uuid=f'{i+10:032x}',disk_origin={'kind':'fresh'},
                mode=0,collection_profile='full',node=node,max_stopped_attempts=64)
            self.freeze_input(folder,context,inputs)
            image=f'node-{node}.elf';(folder/image).write_bytes((root/image).read_bytes())
            (folder/'model.bin').write_bytes(b'fixture model')
            dtb=struct.pack('>2I',0xd00dfeed,40)+bytes(32)
            for name in ('dtb-header.bin','platform.dtb'):(folder/name).write_bytes(dtb)
            self.save(folder/'formatter-command.json',dict(argv=[context['paths']['formatter'],str(folder/'disk.raw'),inputs['disk_uuid']]))
            with (folder/'disk.raw').open('wb') as disk:disk.truncate(f.DISK_BYTES)
            disk=dict(bytes=f.DISK_BYTES,sha256=f.sha(folder/'disk.raw'))
            for name in ('disk-before.json','disk-after.json'):self.save(folder/name,disk)
            (folder/'format.log').write_bytes(b'host fixture format')
            self.save(folder/'process-exit.json',dict(schema=1,pid=100+i,peer_pid=100+i,returncode=0,
                forced=False,quit_ok=True,eof=True,errors=[],started_ns=1,exited_ns=2))
            qmp=f'/host-fixture/{node}q.sock';gdb=f'/host-fixture/{node}g.sock'
            self.save(folder/'launch.json',dict(port=1234,qmp=qmp,gdb=gdb,symbols=context['node_symbols'][node],
                argv=f.launch_argv(context['paths']['qemu_binary'],folder,qmp,gdb,1234,node)))
            platform=dict(cpus=[{'cpu-index':j} for j in range(4)],memory={'base-memory':1024**3})
            self.save(folder/'platform.json',platform)
            rows=json.loads((folder/'qmp-transcript.json').read_text())
            for j,row in enumerate(rows):
                if row.get('direction')=='send' and row['message']['execute'] in ('query-cpus-fast','query-memory-size-summary'):
                    rows[j+1]['message']['return']=platform['cpus' if row['message']['execute']=='query-cpus-fast' else 'memory']
            transcript.save_rows(folder,rows)
            for name in ('serial.bin','serial.txt'):(folder/name).write_bytes(b'')
        self.save(root/'native-context.json',context)
        exports=root/'collection-archives';exports.mkdir()
        self.save(exports/'manifest.json',dict(version=f.VERSION,nodes={'a':{},'b':{}},scope='Committed journal bytes/framing only; labels and complete numeric replay unverified'))
        return context

    def test_whole_host_chain_and_reused_media_rejection(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();context=self.fixture(root)
            def archives(path,**kwargs):
                return dict(manifest={},exports={},journals=[] if path.parent.name=='node-b' else [dict(kind='regular',excluded=False)]*432)
            paths=dict(source_root=root,build_manifest=root/'build-manifest.json',formatter=root,
                qemu_binary=root,qemu_source=root)
            with patch.object(self.f,'trusted_context',return_value=context),patch.object(self.f,'closure',return_value={}),patch.object(self.f,'verify_samples'),patch.object(self.f,'inspect_journals',side_effect=archives):
                result=self.f.verify_capture(root,**paths)
                self.assertTrue(result['full_collection_verified'])
                self.assertFalse(result['model_trained']);self.assertFalse(result['A03_complete'])
                folder=root/'node-b';process=self.f.read_json(folder/'process-exit.json')
                self.save(folder/'process-exit.json',dict(process,returncode=1))
                with self.assertRaisesRegex(ValueError,'quit/EOF/wait0'):self.f.verify_capture(root,**paths)
                self.save(folder/'process-exit.json',process)
                inputs=self.f.read_json(folder/'input.json');before=self.f.read_json(folder/'disk-before.json')
                origin=dict(kind='handoff',parent_nonce='ff'*16,parent_receipt_sha256='ab'*32,
                    disk_sha256=before['sha256'],parent_exited_ns=1)
                self.freeze_input(folder,context,dict(inputs,disk_origin=origin))
                from boot_reboot_contract import HANDOFF_LOG
                (folder/'format.log').write_bytes(HANDOFF_LOG)
                with self.assertRaisesRegex(ValueError,'fresh independent media'):
                    self.f.verify_capture(root,**paths)


if __name__=='__main__':unittest.main()
