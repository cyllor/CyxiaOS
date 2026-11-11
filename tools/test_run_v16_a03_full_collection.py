"""Host lifecycle fixtures only; no native collection, sample import or training."""
import importlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


def changed(raw, index, value):
    result=bytearray(raw);struct.pack_into('<Q',result,index*8,value);return bytes(result)


def protocol_probe(module, paired=216, family=(16,2), data_phase=11):
    result={key:bytes(size) for key,(_,size) in module.BANKS.items()}
    terminal=paired==216;verified=paired*2
    w=[0]*64
    for key,value in {0:2,1:0x435952504c593133,2:17 if terminal else 0,
            3:family[0],4:family[1],5:0 if terminal else min(paired,11),6:2,
            7:verified+1,10:verified,17:verified,18:data_phase if terminal else 1,
            19:paired}.items():w[key]=value
    w[24:42]=[8]*18 if terminal else [min(paired,8)]+[0]*17
    w[42:60]=[4]*18 if terminal else [0]*18
    c=[0]*64
    for key,value in {0:2,1:0x43594c434f4c3136,2:1,4:w[2],6:w[3],7:w[4],8:w[5],
            9:verified,10:verified,11:paired,13:1,14:1,47:999}.items():c[key]=value
    result['replay']=struct.pack('<64Q',*w);result['collection']=struct.pack('<64Q',*c)
    result['runtime']=changed(result['runtime'],2,2)
    return result


class Harness:
    """Fake QMP transports exercise the production observer and real bank checks."""
    def __init__(self,module,root,states,*,torn_attempts=0,fatal_b=False,mismatch=False):
        self.module=module;self.states=states;self.events=[];self.cursor=0;self.attempt=0
        self.torn_attempts=torn_attempts;self.fatal_b=fatal_b;self.mismatch=mismatch
        self.guests=[]
        harness=self
        class Proc:
            def __init__(self,pid):self.pid=pid;self.returncode=None
            def poll(self):return self.returncode
        class Qmp:
            def __init__(self,node):self.node=node;self.paused=True;self.transcript=[]
            def execute(self,name,args=None):
                harness.events.append((self.node,name))
                if name=='cont':self.paused=False
                elif name=='stop':
                    self.paused=True
                    if self.node=='a':harness.attempt+=1
                elif name=='query-status':
                    if not all(g.qmp.paused for g in harness.guests):
                        raise AssertionError('status queried before both stop commands')
                    return {'status':'paused'}
                return '' if name=='ringbuf-read' else {}
        for index,node in enumerate(('a','b')):
            folder=root/('node-'+node);folder.mkdir()
            symbols={key:{'pa':1000+i*4096} for i,key in enumerate(module.BANKS)}
            guest=module.Guest(node,folder,symbols,proc=Proc(100+index),qmp=Qmp(node),started_ns=1)
            def save(name,address,size,guest=guest):
                key=next(key for key,value in guest.symbols.items() if value['pa']==address)
                live=name.startswith('pending-')
                if not live and not all(g.qmp.paused for g in harness.guests):
                    raise AssertionError('physical diagnostic before stop-all')
                harness.events.append((guest.node,name))
                state=harness.states[min(harness.cursor if live else max(0,harness.cursor-1),len(harness.states)-1)]
                value=state[key][:size]
                if key=='boot' and not live and harness.attempt<=harness.torn_attempts:
                    value=changed(value,2,1)
                if key=='tasks' and guest.node=='b' and harness.fatal_b:value=changed(value,2,1)
                if harness.mismatch and 'confirm-boot' in name:value=changed(value,2,4)
                (guest.folder/name).write_bytes(value)
                if live and guest.node=='b' and key==list(module.LIVE_BANKS)[-1]:harness.cursor+=1
                return value
            guest.save=save;self.guests.append(guest)


class Observer(unittest.TestCase):
    def setUp(self):self.p=importlib.import_module('run_v16_a03_full_collection')

    def test_two_three_and_later_families_continue_until_all_216_pairs(self):
        with tempfile.TemporaryDirectory() as temp:
            states=[protocol_probe(self.p,2,(1,1)),protocol_probe(self.p,3,(1,1)),
                protocol_probe(self.p,3,(2,1)),protocol_probe(self.p)]
            h=Harness(self.p,Path(temp),states);progress=[]
            with patch.object(self.p.time,'sleep'):
                result=self.p.observe(h.guests,self.p.time.monotonic()+5,progress=progress.append)
            self.assertEqual(result['terminal']['paired'],216)
            self.assertTrue(result['terminal']['validation_handoff_observed'])
            self.assertEqual(result['stopped_attempts'],1)
            self.assertEqual([v['nodes']['a']['paired'] for v in progress],[2,3,3,216])
            self.assertEqual(progress[2]['nodes']['a']['family'],[2,1])
            self.assertEqual([event for event in h.events if event[1]=='stop'],[('a','stop'),('b','stop')])
            for guest in h.guests:
                reads=[name for node,name in h.events if node==guest.node and name.startswith('probe-')]
                self.assertEqual(len(reads),2*len(self.p.BANKS))
                for key in self.p.BANKS:
                    self.assertEqual((guest.folder/(key+'.bin')).read_bytes(),states[-1][key])
                    self.assertEqual((guest.folder/('probe-01-confirm-'+key+'.bin')).read_bytes(),states[-1][key])

    def test_torn_stopped_boot_resumes_both_and_preserves_both_rounds(self):
        with tempfile.TemporaryDirectory() as temp:
            h=Harness(self.p,Path(temp),[protocol_probe(self.p)],torn_attempts=1)
            with patch.object(self.p.time,'sleep'):
                result=self.p.observe(h.guests,self.p.time.monotonic()+5)
            self.assertEqual(result['stopped_attempts'],2)
            for guest in h.guests:
                self.assertEqual(h.events.count((guest.node,'cont')),2)
                self.assertEqual(struct.unpack_from('<Q',(guest.folder/'probe-01-boot.bin').read_bytes(),16)[0],1)
                self.assertEqual(struct.unpack_from('<Q',(guest.folder/'probe-02-boot.bin').read_bytes(),16)[0],0)

    def test_peer_fatal_stops_both_before_any_failure_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            h=Harness(self.p,Path(temp),[protocol_probe(self.p,3,(2,1))],fatal_b=True)
            with self.assertRaisesRegex(ValueError,'quarantine|overrun'):
                self.p.observe(h.guests,self.p.time.monotonic()+5)
            self.assertTrue(all(g.qmp.paused for g in h.guests))
            self.assertFalse(any(name.startswith('probe-') for _,name in h.events))
            result=dict(status='FAIL',capture_complete=False,full_collection_verified=False,
                validation_handoff_observed=False,error='first fatal reason')
            closed=[]
            def close(proc,sock,qmp,**kwargs):
                closed.append(qmp.node)
                return dict(errors=[],forced=False,returncode=0,quit_ok=True,eof=True)
            with patch.object(self.p,'close_owned',side_effect=close):
                self.p.cleanup_guests(h.guests,result)
            self.assertEqual(closed,['a','b']);self.assertEqual(result['error'],'first fatal reason')
            first_diagnostic=next(i for i,(_,name) in enumerate(h.events) if name.startswith('failure-'))
            self.assertIn(('a','stop'),h.events[:first_diagnostic]);self.assertIn(('b','stop'),h.events[:first_diagnostic])

    def test_changed_paused_bytes_fail_and_leave_both_stopped(self):
        with tempfile.TemporaryDirectory() as temp:
            h=Harness(self.p,Path(temp),[protocol_probe(self.p)],mismatch=True)
            with self.assertRaisesRegex(ValueError,'stopped bytes changed'):
                self.p.observe(h.guests,self.p.time.monotonic()+5)
            self.assertTrue(all(g.qmp.paused for g in h.guests))

    def test_collected_can_stop_before_validation_and_progress_is_only_changed_state(self):
        with tempfile.TemporaryDirectory() as temp:
            h=Harness(self.p,Path(temp),[protocol_probe(self.p,2,(1,1)),
                protocol_probe(self.p,2,(1,1)),protocol_probe(self.p,data_phase=2)])
            progress=[]
            with patch.object(self.p.time,'sleep'):
                result=self.p.observe(h.guests,self.p.time.monotonic()+5,until='collected',progress=progress.append)
            self.assertEqual(len(progress),2)
            self.assertFalse(result['terminal']['validation_handoff_observed'])


class Lifecycle(unittest.TestCase):
    def setUp(self):self.p=importlib.import_module('run_v16_a03_full_collection')

    def test_one_owned_cleanup_failure_does_not_skip_peer_or_replace_first_error(self):
        with tempfile.TemporaryDirectory() as temp:
            h=Harness(self.p,Path(temp),[protocol_probe(self.p)])
            result=dict(status='FAIL',capture_complete=False,full_collection_verified=False,
                validation_handoff_observed=False,error='initial failure')
            calls=[]
            def close(proc,sock,qmp,**kwargs):
                calls.append(qmp.node)
                if qmp.node=='a':raise OSError('first socket failed')
                return dict(errors=[],forced=False,returncode=0,quit_ok=True,eof=True)
            with patch.object(self.p,'close_owned',side_effect=close):
                self.p.cleanup_guests(h.guests,result)
            self.assertEqual(calls,['a','b']);self.assertEqual(result['error'],'initial failure')
            self.assertFalse(result['capture_complete'])

    def test_final_write_failure_revokes_success_and_cli_exit(self):
        for label in ('inventory','summary'):
            result=dict(status='FULL_COLLECTION_VERIFIED',capture_complete=True,
                full_collection_verified=True,validation_handoff_observed=True,error='original failure')
            def fail():raise OSError('disk full')
            with patch.object(self.p.sys,'stderr',new_callable=io.StringIO) as errors:
                self.p.finalize_capture(result,label,fail)
                self.assertEqual(result['error'],'original failure')
                self.assertFalse(result['capture_complete']);self.assertFalse(result['full_collection_verified'])
                self.assertFalse(result['validation_handoff_observed'])
                if label=='summary':self.assertIn('summary persistence failed',errors.getvalue())
            argv=[]
            for name in ('source-root','build-manifest','output','formatter','qemu-binary','qemu-source'):
                argv.extend(['--'+name,'/unused-host-fixture'])
            with patch.object(self.p,'run',return_value=result),patch.object(self.p.sys,'stdout',new_callable=io.StringIO):
                self.assertEqual(self.p.main(argv),1)

    def test_final_inventory_byte_change_revokes_verified_capture_and_cli_exit(self):
        # Exercise main -> run and real file inventories at the return seam.
        # Native/source admission is a stub here, never native success evidence.
        inventory=self.p.bounded_inventory
        for mutate in (False,True):
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);output=root/'capture';verifications=[];finals=[]
                context={'paths':{key:str(root) for key in
                    ('source_root','build_manifest','formatter','qemu_binary','qemu_source')}}
                def prepare(folder,context,paths,**kwargs):
                    (folder/'raw-evidence.bin').write_bytes(b'original-evidence')
                    return []
                def verify(folder,**kwargs):
                    result=dict(capture_complete=True,full_collection_verified=True,
                        validation_handoff_observed=True,archive_files={},archive_manifest={},
                        captured_inventory=inventory(folder))
                    verifications.append(result)
                    return result
                def final_inventory(folder):
                    if mutate:(folder/'raw-evidence.bin').write_bytes(b'replaced-evidence')
                    result=inventory(folder);finals.append(result)
                    return result
                argv=[]
                for name in ('source-root','build-manifest','formatter','qemu-binary','qemu-source'):
                    argv.extend(['--'+name,str(root)])
                argv.extend(['--output',str(output),'--native-lock',str(root/'native.lock')])
                with patch.object(self.p,'trusted_context',return_value=context),\
                        patch.object(self.p,'idle_native_host'),patch.object(self.p,'prepare_capture',side_effect=prepare),\
                        patch.object(self.p,'observe',return_value={'stopped_attempts':1}),\
                        patch.object(self.p,'verify_capture',side_effect=verify),\
                        patch.object(self.p,'bounded_inventory',side_effect=final_inventory),\
                        patch.object(self.p.socket,'socket') as listener,\
                        patch.object(self.p.sys,'stdout',new_callable=io.StringIO) as stdout:
                    listener.return_value.__enter__.return_value.getsockname.return_value=('127.0.0.1',1234)
                    code=self.p.main(argv)
                self.assertEqual(len(verifications),2);self.assertEqual(len(finals),1)
                verified=verifications[-1]['captured_inventory']['raw-evidence.bin']
                final=finals[-1]['raw-evidence.bin']
                self.assertEqual(verified['bytes'],final['bytes'])
                self.assertEqual(verified==final,not mutate)
                self.assertEqual(code,int(mutate),'changed evidence retained a successful CLI exit')
                summary=json.loads((output/'summary.json').read_text())
                printed=json.loads(stdout.getvalue())
                for field in ('capture_complete','full_collection_verified','validation_handoff_observed'):
                    self.assertEqual(summary[field],not mutate,field)
                    self.assertEqual(printed[field],not mutate,field)
                self.assertEqual(summary['status'],'FAIL' if mutate else 'FULL_COLLECTION_VERIFIED')

    def test_timeout_rejects_nonfinite_bool_and_out_of_bound_before_host_actions(self):
        with patch.object(self.p,'native_lease') as lease:
            for value in (float('nan'),float('inf'),float('-inf'),True,4,259201,10**1000):
                with self.subTest(value=value),self.assertRaises(ValueError):
                    self.p.run('/unused','/unused',source_root='/unused',formatter='/unused',
                        qemu_binary='/unused',qemu_source='/unused',timeout=value)
            lease.assert_not_called()

    def test_progress_write_is_atomic_and_rejects_nonfinite_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'progress.json'
            self.p.atomic_json(path,{'paired':2});self.p.atomic_json(path,{'paired':3})
            self.assertEqual(json.loads(path.read_text()),{'paired':3})
            with self.assertRaises(ValueError):self.p.atomic_json(path,{'bad':float('nan')})
            self.assertEqual(json.loads(path.read_text()),{'paired':3})

    def test_temporary_socket_directory_survives_both_owned_closes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);output=root/'capture';h=Harness(self.p,root,[protocol_probe(self.p)])
            context={'paths':{key:str(root) for key in
                ('source_root','build_manifest','formatter','qemu_binary','qemu_source')}}
            socket_paths={};closed=[];prepared=[]
            def prepare(folder,context,paths,**kwargs):
                prepared.append(kwargs);return h.guests
            def launch(guest,paths,socket_root,port,deadline,errors):
                endpoint=Path(socket_root)/(guest.node+'.sock');endpoint.write_bytes(b'owned fixture')
                socket_paths[guest.node]=endpoint
            def observe(guests,deadline,**kwargs):
                self.assertEqual(set(socket_paths),{'a','b'})
                raise KeyboardInterrupt('operator stop')
            def close(proc,sock,qmp,**kwargs):
                self.assertTrue(all(path.exists() for path in socket_paths.values()))
                closed.append(qmp.node)
                return dict(errors=[],forced=False,returncode=0,quit_ok=True,eof=True)
            with patch.object(self.p,'trusted_context',return_value=context),\
                    patch.object(self.p,'idle_native_host'),patch.object(self.p,'prepare_capture',side_effect=prepare),\
                    patch.object(self.p,'launch_guest',side_effect=launch),patch.object(self.p,'observe',side_effect=observe),\
                    patch.object(self.p,'close_owned',side_effect=close),patch.object(self.p,'verify_capture') as verify,\
                    patch.object(self.p,'bounded_inventory',return_value={}),patch.object(self.p.socket,'socket') as listener:
                listener.return_value.__enter__.return_value.getsockname.return_value=('127.0.0.1',1234)
                result=self.p.run(root,output,source_root=root,formatter=root,qemu_binary=root,qemu_source=root,
                    native_lock=root/'native.lock')
            self.assertEqual(closed,['a','b']);self.assertIn('KeyboardInterrupt: operator stop',result['error'])
            self.assertFalse(result['capture_complete']);verify.assert_not_called()
            self.assertEqual(prepared,[{'timeout':172800,'until':'validated'}])
            self.assertFalse(any(path.exists() for path in socket_paths.values()))
            self.assertEqual(result['native_acceptance_status'],'NOT_RUN')
            self.assertFalse(result['full_dataset_verified']);self.assertFalse(result['model_trained'])
            self.assertFalse(result['active_model_verified']);self.assertFalse(result['A03_complete'])


if __name__=='__main__':unittest.main()
