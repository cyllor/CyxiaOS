"""Acceptance rejects plausible-looking partial, stale and over-budget evidence."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from verify_unified import ROOT, attest_qemu, bind_build, capture, sha, validate, validate_rejection

def bundle(owner=False):
    u=[0]*512;d=[0]*512;r=[0]*1024
    u[:6]=[0x435958554e493031,1,100,1,1000,1000]
    u[30]=1
    events=[1,2,3,0x211,0x212,0x219];u[6]=len(events)
    for i,e in enumerate(events):u[32+2*i]=e
    u[8]=u[9]=int(owner);u[10]=100*int(owner);u[11]=100*int(owner);u[12]=100*int(owner)
    d[0]=0x43595844594e3133;d[1]=2
    for i,target in enumerate((6,2)):
        t=[0]*16;t[1]=i+1;t[2]=1000+i*1000;t[3]=t[2]+1;t[4]=t[5]=target;t[6]=15^target;t[9]=63;t[15]=1
        d[16+i*16:32+i*16]=t
    r[0]=0x43595852554e3133;r[2]=2;r[4]=62500000;r[14]=10;r[19]=r[20]=20;r[28]=4;r[32]=1
    return dict(UNIFIED_EVIDENCE=struct.pack('<512Q',*u),DYNAMIC_V13_EVIDENCE=struct.pack('<512Q',*d),RUNTIME_V13_EVIDENCE=struct.pack('<1024Q',*r))

def change(b,name,index,value):
    data=bytearray(b[name]);struct.pack_into('<Q',data,index*8,value);b[name]=bytes(data)

def service_events(events):
    return b''.join(f'UNIFIED_SERVICE event={event} arg1=0 arg2=0 ms={i}\n'.encode()
                    for i,event in enumerate(events))

class Acceptance(unittest.TestCase):
    def test_patched_qemu_requires_exact_source_attestation(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'qemu';binary=source/'build/qemu-system-aarch64'
            binary.parent.mkdir(parents=True);binary.write_bytes(b'qemu')
            files=('include/hw/core/cpu.h','cpu-common.c','accel/tcg/cpu-exec.c','target/arm/cpregs-pmu.c')
            for name in files:
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
            hashes={name:sha(source/name) for name in files}
            def output(command,**_):
                if command[-1]=='--version':return 'QEMU emulator version 10.2.2 (v10.2.2-dirty)\n'
                return 'f8ed81651e61d9c2166df6121ce2af0f44f06b3e\n'
            status=''.join(f' M {name}\n' for name in files)
            with patch('verify_unified.PATCHED_QEMU_SOURCE_SHA256',hashes), \
                 patch('verify_unified.subprocess.check_output',side_effect=output), \
                 patch('verify_unified.subprocess.run') as run:
                run.return_value.stdout=status;run.return_value.returncode=0
                proof=attest_qemu(binary,source)
                self.assertEqual(proof['qemu_source_commit'],'f8ed81651e61d9c2166df6121ce2af0f44f06b3e')
                (source/files[0]).write_text('substituted')
                with self.assertRaisesRegex(ValueError,'patched QEMU source differs'):
                    attest_qemu(binary,source)
            with patch('verify_unified.subprocess.check_output',return_value='QEMU emulator version 10.2.2 (v10.2.2-dirty)\n'):
                with self.assertRaisesRegex(ValueError,'source attestation'):
                    attest_qemu(binary,None)
    def test_joint_checks_cannot_accept_partial_evidence(self):
        original=[bundle(),bundle(True)]
        self.assertEqual(len(validate([b'',b''],original,[4,4])),2)
        for name,index,value in [('DYNAMIC_V13_EVIDENCE',1,1),('DYNAMIC_V13_EVIDENCE',25,31),('UNIFIED_EVIDENCE',36,0),('RUNTIME_V13_EVIDENCE',38,1),('RUNTIME_V13_EVIDENCE',32,2),('UNIFIED_EVIDENCE',6,201),('UNIFIED_EVIDENCE',12,625001),('UNIFIED_EVIDENCE',8,0),('UNIFIED_EVIDENCE',30,0),('UNIFIED_EVIDENCE',31,1)]:
            b=copy.deepcopy(original);change(b[1],name,index,value)
            with self.subTest(name=name,index=index),self.assertRaises(ValueError):validate([b'',b''],b,[4,4])
    def test_service_restart_requires_one_real_fault_and_a_healthy_peer(self):
        restarted=[bundle(),bundle(True)]
        events=[1,2,3,0x211,0x212,1,2,3,0x212,0x219]
        # Node b keeps its existing service context. Reconnecting authenticates
        # again, but does not re-enter _start or reconstruct the driver.
        peer_events=[1,2,3,0x211,0x212,3,0x212,0x219]
        for item,observed in zip(restarted,(events,peer_events)):
            words=list(struct.unpack('<512Q',item['UNIFIED_EVIDENCE']))
            words[6]=len(observed);words[32:]=[0]*480
            for i,event in enumerate(observed):words[32+i*2]=event
            item['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        words=list(struct.unpack('<512Q',restarted[0]['UNIFIED_EVIDENCE']))
        words[13:15]=[11,0x212];words[22]=1;words[30:32]=[2,1]
        restarted[0]['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        serial=[service_events(events[:5])+b'UNIFIED_EL0_FAULT generation=1 last_op=11 last_arg0=530 kind=7\nUNIFIED_SERVICE_RESTART boot=1 generation=2\n'+service_events(events[5:]),b'']
        self.assertEqual(len(validate(serial,restarted,[4,4],expect='service-restart')),2)
        changed=copy.deepcopy(restarted);change(changed[0],'UNIFIED_EVIDENCE',31,0)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
        changed=copy.deepcopy(restarted);change(changed[0],'UNIFIED_EVIDENCE',14,2)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
        changed=copy.deepcopy(restarted);change(changed[1],'UNIFIED_EVIDENCE',30,2);change(changed[1],'UNIFIED_EVIDENCE',31,1)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
        for position in (5,6):
            changed=copy.deepcopy(restarted);change(changed[1],'UNIFIED_EVIDENCE',32+2*position,0)
            with self.subTest(missing_peer_event=peer_events[position]),self.assertRaisesRegex(ValueError,'reconcile to READY'):
                validate(serial,changed,[4,4],expect='service-restart')
    def test_no_ack_cannot_be_mislabelled_successful_handoff(self):
        with self.assertRaises(ValueError):validate([b'DYNAMIC_V13_RECONCILE']*2,[bundle(),bundle(True)],[4,4],expect='no-stop-ack')
    def test_old_ready_events_cannot_certify_a_restarted_service(self):
        restarted=[bundle(),bundle(True)]
        events=[1,2,3,0x211,0x212,1,2,3,0x212,0x219]
        for item in restarted:
            words=list(struct.unpack('<512Q',item['UNIFIED_EVIDENCE']))
            words[6]=len(events);words[32:]=[0]*480
            for i,event in enumerate(events):words[32+i*2]=event
            item['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        for index,value in ((13,11),(14,0x212),(22,1),(30,2),(31,1)):
            change(restarted[0],'UNIFIED_EVIDENCE',index,value)
        old=service_events(events)
        fault=b'UNIFIED_EL0_FAULT generation=1 last_op=11 last_arg0=530 kind=7\n'
        restart=b'UNIFIED_SERVICE_RESTART boot=1 generation=2\n'
        # A previous connection supplied all aggregate counters. Generation 2
        # has started, but has not yet authenticated or reconciled its peer.
        for after in ([],[1,2,3],[0x212,1,2,3]):
            with self.subTest(after=after),self.assertRaisesRegex(ValueError,'post-restart'):
                validate([old+fault+restart+service_events(after),old],restarted,[4,4],expect='service-restart')
        after=service_events([1,2,3,0x212])
        self.assertEqual(len(validate([old+fault+restart+after,old],restarted,[4,4],expect='service-restart')),2)
        with self.assertRaisesRegex(ValueError,'fault boundary'):
            validate([old+restart+fault+after,old],restarted,[4,4],expect='service-restart')
        with self.assertRaisesRegex(ValueError,'same-boot'):
            validate([old+fault+restart.replace(b'generation=2',b'generation=20')+after,old],restarted,[4,4],expect='service-restart')
    def test_negative_cannot_hide_admitted_authority(self):
        with self.assertRaises(ValueError):validate_rejection([b'']*2,[bundle(),bundle(True)],[4,4],'wrong-pin')
    def test_rejection_requires_initialized_custody_and_complete_budget_evidence(self):
        original=bundle()
        words=list(struct.unpack('<512Q',original['UNIFIED_EVIDENCE']))
        words[6]=3;words[32:]=[0]*480
        for i,event in enumerate((1,2,4)):words[32+i*2]=event
        original['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        self.assertEqual(len(validate_rejection([b'']*2,[original]*2,[4,4],'wrong-pin')),2)
        for name,index,value in [('RUNTIME_V13_EVIDENCE',2,3),('RUNTIME_V13_EVIDENCE',17,1),('RUNTIME_V13_EVIDENCE',39,625001),('UNIFIED_EVIDENCE',11,1),('UNIFIED_EVIDENCE',12,1),('UNIFIED_EVIDENCE',34,0x103),('UNIFIED_EVIDENCE',34,0x10000),('UNIFIED_EVIDENCE',34,0)]:
            mutated=copy.deepcopy(original);change(mutated,name,index,value)
            with self.subTest(name=name,index=index,value=value),self.assertRaises(ValueError):
                validate_rejection([b'']*2,[mutated]*2,[4,4],'wrong-pin')
    def test_leave_requires_durable_leave_event(self):
        with self.assertRaises(ValueError):validate([b'']*2,[bundle(),bundle(True)],[4,4],expect='leave')
    def test_build_binding_rejects_stale_source_and_substituted_images(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);names=('node-a.elf','node-b.elf','node-a.pub','node-b.pub','task.elf')
            files=[root/n for n in names]
            for i,f in enumerate(files):f.write_bytes(bytes([i+1])*32)
            nodes={n:{'node_id':sha(files[i+2]),'peer_node_id':sha(files[3-i])} for i,n in enumerate(('a','b'))}
            data=dict(schema_version=1,status='BUILT_NOT_RUN',code_source_map={'a.rs':'original'},code_source_sha256='code',builder_sha256=sha(ROOT/'tools/build_unified.py'),profiles={'fault':'normal','service_fault':'none','service_fault_nodes':{'a':'none','b':'none'},'leave':False},own_private_key_only_verified=True,nodes=nodes,artifacts={n:{'sha256':sha(f),'bytes':32} for n,f in zip(names,files)})
            manifest=root/'build.json';manifest.write_text(json.dumps(data))
            def check():return bind_build(manifest,files[0],files[1],files[2:4],files[4],'normal')
            with patch('verify_unified.code_source_map',return_value={'a.rs':'original'}):
                self.assertEqual(check()['code_source_sha256'],'code')
                files[1].write_bytes(bytes(32))
                with self.assertRaisesRegex(ValueError,'artifact differs'):check()
            with patch('verify_unified.code_source_map',return_value={'a.rs':'modified'}):
                with self.assertRaisesRegex(ValueError,'different source'):check()
    def test_build_binding_requires_the_exact_service_fault_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);names=('node-a.elf','node-b.elf','node-a.pub','node-b.pub','task.elf')
            files=[root/n for n in names]
            for i,f in enumerate(files):f.write_bytes(bytes([i+1])*32)
            nodes={n:{'node_id':sha(files[i+2]),'peer_node_id':sha(files[3-i])} for i,n in enumerate(('a','b'))}
            data=dict(schema_version=1,status='BUILT_NOT_RUN',code_source_map={'a.rs':'original'},code_source_sha256='code',builder_sha256=sha(ROOT/'tools/build_unified.py'),profiles={'fault':'normal','service_fault':'after-start','service_fault_nodes':{'a':'after-start','b':'none'},'leave':False},own_private_key_only_verified=True,nodes=nodes,artifacts={n:{'sha256':sha(f),'bytes':32} for n,f in zip(names,files)})
            manifest=root/'build.json';manifest.write_text(json.dumps(data))
            with patch('verify_unified.code_source_map',return_value={'a.rs':'original'}):
                self.assertEqual(bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-start')['profiles']['service_fault'],'after-start')
                with self.assertRaisesRegex(ValueError,'service-fault profile'):
                    bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-completion')
                data['profiles']['service_fault_nodes']={'a':'after-start','b':'after-start'}
                manifest.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError,'node scope'):
                    bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-start')
    def test_live_progress_retries_torn_publication_without_pausing_guest(self):
        commands=[]
        class Qmp:
            sequence=2
            def execute(self,command,args):
                commands.append(command)
                if args['size']==8:data=struct.pack('<Q',self.sequence)
                else:
                    self.sequence=4
                    words=[0]*1024;words[2]=4;words[14]=7
                    data=struct.pack('<1024Q',*words)
                Path(args['filename']).write_bytes(data)
        with tempfile.TemporaryDirectory() as temp:
            result=capture([{'qmp':Qmp(),'folder':Path(temp)}],[{'RUNTIME_V13_EVIDENCE':{'pa':4096,'size':8192}}],resume=True)
            self.assertEqual(struct.unpack('<1024Q',result[0]['RUNTIME_V13_EVIDENCE'])[14],7)
            self.assertEqual(commands,['pmemsave']*6)

if __name__=='__main__':unittest.main()
