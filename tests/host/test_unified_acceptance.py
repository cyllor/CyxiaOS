"""Acceptance rejects plausible-looking partial, stale and over-budget evidence."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from verify_unified import ROOT, bind_build, capture, sha, validate, validate_rejection

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

class Acceptance(unittest.TestCase):
    def test_joint_checks_cannot_accept_partial_evidence(self):
        original=[bundle(),bundle(True)]
        self.assertEqual(len(validate([b'',b''],original,[4,4])),2)
        for name,index,value in [('DYNAMIC_V13_EVIDENCE',1,1),('DYNAMIC_V13_EVIDENCE',25,31),('UNIFIED_EVIDENCE',36,0),('RUNTIME_V13_EVIDENCE',38,1),('RUNTIME_V13_EVIDENCE',32,2),('UNIFIED_EVIDENCE',6,201),('UNIFIED_EVIDENCE',12,625001),('UNIFIED_EVIDENCE',8,0),('UNIFIED_EVIDENCE',30,0),('UNIFIED_EVIDENCE',31,1)]:
            b=copy.deepcopy(original);change(b[1],name,index,value)
            with self.subTest(name=name,index=index),self.assertRaises(ValueError):validate([b'',b''],b,[4,4])
    def test_service_restart_requires_real_fault_exact_generation_and_second_ready(self):
        restarted=[bundle(),bundle(True)]
        for item in restarted:
            words=list(struct.unpack('<512Q',item['UNIFIED_EVIDENCE']))
            events=[1,2,3,0x211,0x212,1,2,3,0x212,0x219]
            words[6]=len(events);words[13:15]=[11,0x212];words[22]=1
            words[30:32]=[2,1];words[32:]=[0]*480
            for i,event in enumerate(events):words[32+i*2]=event
            item['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        serial=[b'UNIFIED_EL0_FAULT generation=1 last_op=11 last_arg0=530 kind=7\nUNIFIED_SERVICE_RESTART boot=1 generation=2\n']*2
        self.assertEqual(len(validate(serial,restarted,[4,4],expect='service-restart')),2)
        changed=copy.deepcopy(restarted);change(changed[0],'UNIFIED_EVIDENCE',31,0)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
        changed=copy.deepcopy(restarted);change(changed[0],'UNIFIED_EVIDENCE',14,2)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
    def test_no_ack_cannot_be_mislabelled_successful_handoff(self):
        with self.assertRaises(ValueError):validate([b'DYNAMIC_V13_RECONCILE']*2,[bundle(),bundle(True)],[4,4],expect='no-stop-ack')
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
            data=dict(schema_version=1,status='BUILT_NOT_RUN',code_source_map={'a.rs':'original'},code_source_sha256='code',builder_sha256=sha(ROOT/'tools/build_unified.py'),profiles={'fault':'normal','leave':False},own_private_key_only_verified=True,nodes=nodes,artifacts={n:{'sha256':sha(f),'bytes':32} for n,f in zip(names,files)})
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
            data=dict(schema_version=1,status='BUILT_NOT_RUN',code_source_map={'a.rs':'original'},code_source_sha256='code',builder_sha256=sha(ROOT/'tools/build_unified.py'),profiles={'fault':'normal','service_fault':'after-start','leave':False},own_private_key_only_verified=True,nodes=nodes,artifacts={n:{'sha256':sha(f),'bytes':32} for n,f in zip(names,files)})
            manifest=root/'build.json';manifest.write_text(json.dumps(data))
            with patch('verify_unified.code_source_map',return_value={'a.rs':'original'}):
                self.assertEqual(bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-start')['profiles']['service_fault'],'after-start')
                with self.assertRaisesRegex(ValueError,'service-fault profile'):
                    bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-completion')
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
