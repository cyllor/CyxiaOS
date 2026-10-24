from pathlib import Path
import copy
import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from verify_unified_disk import verify_pair
ROOT=Path(__file__).resolve().parents[2]


def sha(b):return hashlib.sha256(b).digest()
def event(n,tag,b):return (b'CXE1'+struct.pack('<Q',n)+bytes([tag])+b).hex()
def renumber(records):
    for n in range(1,len(records)):
        b=bytearray.fromhex(records[n]);b[4:12]=struct.pack('<Q',n);records[n]=b.hex()


class DurableProofs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        temp=Path(self.temp.name);keys=[];public=[]
        for name in ('a','b'):
            key=ROOT/f'crates/cluster-transport/tests/fixtures/{name}-test-key.der';keys.append(key)
            public.append(subprocess.check_output(['openssl','pkey','-inform','DER','-in',str(key),'-pubout','-outform','DER'])[-32:])
        order=sorted(range(2),key=lambda i:sha(public[i]));keys=[keys[i] for i in order];self.public=[public[i] for i in order];self.keys=keys;nodes=list(map(sha,self.public))
        config=b'\x01\0\0\0'+sha(b'CyxiaOS paired native v1')+b''.join(nodes)+struct.pack('<QQ',1,1)+b'A'*32+b'B'*32+sha(b'CX-RPC-native-schema-1')+sha(b'pure-vector-sum-only')+struct.pack('<Q',1)
        formation=sha(b'CX-FORM-v1'+config);cluster=sha(b'CX-CLUSTER-v1'+formation)
        msg=temp/'message';msg.write_bytes(b'CX-CONFIRM-v1'+formation);signatures=[]
        for key in keys:
            signatures.append(subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(key),'-in',str(msg)]))
        proof=config+formation+b''.join(signatures)
        self.input=struct.pack('<4q',1,2,3,4);self.package=sha(b'actual-pure-package-elf')
        terms=b'C'*16+struct.pack('<HII',100,16,60000)+self.package+sha(self.input)
        request=sha(b'CX-CONTRACT-v1'+cluster+nodes[0]+nodes[1]+terms)
        base=terms+request+b'R'*16+struct.pack('<QQ',1,1)
        remote=base+struct.pack('<Q',0)+b'\x02';owner=base+struct.pack('<Q',60001)+b'\x02'
        remote_close=terms+request+b'R'*16+struct.pack('<QQQ',1,2,0)+b'\x05';owner_close=terms+request+b'R'*16+struct.pack('<QQQ',1,2,60001)+b'\x05'
        key=cluster+b'C'*16+b'T'*16+struct.pack('<Q',1);body=struct.pack('<q',10);result_hash=sha(body)
        started=key+b'\0'+sha(self.input)+bytes(32)+b'\0'+struct.pack('<I',0)
        terminal=key+b'\x01'+sha(self.input)+result_hash
        done=terminal+b'\0'+struct.pack('<I',8)+body;received=terminal+b'\x01'+struct.pack('<I',8)+body
        self.disks=[]
        for i in (0,1):
            uuid=bytes([i+1])*16;records=[(b'CXID1'+uuid+nodes[i]+nodes[1-i]).hex()]
            records += [event(1,1,struct.pack('<Q',1)+bytes([65+i])*32+struct.pack('<Q',0)),event(2,2,config+signatures[i]),event(3,3,proof)]
            if i==0:records += [event(4,10,remote),event(5,14,key+sha(self.input)),event(6,5,received),event(7,10,remote_close)]
            else:records += [event(4,4,owner),event(5,5,started),event(6,5,done),event(7,6,key+result_hash),event(8,4,owner_close)]
            self.disks.append(dict(uuid=uuid.hex(),boot_epoch=1,cluster_records=records))
    def verify(self,disks=None):return verify_pair(disks or self.disks,self.public,task_input=self.input,package_hash=self.package)
    def test_valid_independently_signed_closed_unique_execution(self):
        r=self.verify();self.assertTrue(r['durable_cluster_verified']);self.assertEqual(r['unique_started'],1)
    def test_offline_custody_reboot_preserves_proofs_without_new_authority(self):
        from verify_unified import validate_offline_custody
        after=copy.deepcopy(self.disks)
        for disk in after:disk['boot_epoch']=2
        self.assertTrue(validate_offline_custody(self.disks,after,self.public,self.package)['pure_task_done_verified'])
        after[0]['cluster_records'].pop()
        with self.assertRaisesRegex(ValueError,'changed durable cluster history'):
            validate_offline_custody(self.disks,after,self.public,self.package)
    def test_durable_request_intent_precedes_observed_grant(self):
        d=copy.deepcopy(self.disks);grant=bytes.fromhex(d[0]['cluster_records'][4])[13:]
        intent=bytearray(grant);intent[122:138]=bytes(16);intent[162]=0
        d[0]['cluster_records'].insert(4,event(4,11,bytes(intent)));renumber(d[0]['cluster_records'])
        self.assertTrue(self.verify(d)['durable_cluster_verified'])
    def test_persisted_leave_signatures_precede_unlock(self):
        d=copy.deepcopy(self.disks);proof=bytes.fromhex(d[0]['cluster_records'][3])[13:]
        formation=proof[252:284];cluster=sha(b'CX-CLUSTER-v1'+formation);nodes=b''.join(map(sha,self.public))
        grant=bytes.fromhex(d[0]['cluster_records'][4])[13:];terminal=bytes.fromhex(d[0]['cluster_records'][6])[13:]
        obligations=sha(b'CX-OBLIGATIONS-v1'+grant[:16]+grant[90:122]+b'\x01'+terminal[105:137])
        record=cluster+struct.pack('<Q',1)+b'L'*16+nodes+obligations*2
        path=Path(self.temp.name)/'leave';path.write_bytes(b'CX-LEAVE-v1'+record)
        sigs=[subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(key),'-in',str(path)]) for key in self.keys]
        for i in (0,1):
            d[i]['cluster_records'] += [event(0,7,b'L'*16),event(0,13,record+sigs[i]),event(0,8,record+b''.join(sigs))];renumber(d[i]['cluster_records'])
        r=self.verify(d);self.assertTrue(r['durable_cluster_verified']);self.assertEqual([n['member'] for n in r['nodes']],['standalone','standalone'])
    def test_formation_epoch_must_be_exactly_max_frozen_plus_one(self):
        d=copy.deepcopy(self.disks);original=bytes.fromhex(d[0]['cluster_records'][3])[13:]
        cfg=bytearray(original[:252]);cfg[244:252]=struct.pack('<Q',2);formation=sha(b'CX-FORM-v1'+cfg)
        msg=Path(self.temp.name)/'gap';msg.write_bytes(b'CX-CONFIRM-v1'+formation)
        sigs=[subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(key),'-in',str(msg)]) for key in self.keys]
        for i in (0,1):d[i]['cluster_records']=d[i]['cluster_records'][:2]+[event(2,2,bytes(cfg)+sigs[i]),event(3,3,bytes(cfg)+formation+b''.join(sigs))]
        with self.assertRaisesRegex(ValueError,'formation epoch'):self.verify(d)
    def test_recipient_requires_durable_expected_task_key_before_result(self):
        d=copy.deepcopy(self.disks);del d[0]['cluster_records'][5];renumber(d[0]['cluster_records'])
        with self.assertRaisesRegex(ValueError,'expected TaskKey'):self.verify(d)
    def test_result_cannot_substitute_unknown_task_with_matching_input_hash(self):
        d=copy.deepcopy(self.disks);b=bytearray.fromhex(d[0]['cluster_records'][6]);b[13+48:13+64]=b'Z'*16;d[0]['cluster_records'][6]=b.hex()
        with self.assertRaisesRegex(ValueError,'expected TaskKey'):self.verify(d)
    def test_actual_ed25519_signature_tamper_rejected(self):
        d=copy.deepcopy(self.disks);b=bytearray.fromhex(d[0]['cluster_records'][3]);b[-1]^=1;d[0]['cluster_records'][3]=b.hex()
        with self.assertRaisesRegex(ValueError,'signature'):self.verify(d)
    def test_terminal_body_hash_tamper_rejected(self):
        d=copy.deepcopy(self.disks);b=bytearray.fromhex(d[1]['cluster_records'][6]);b[-1]^=1;d[1]['cluster_records'][6]=b.hex()
        with self.assertRaisesRegex(ValueError,'hash'):self.verify(d)
    def test_close_without_durable_ack_rejected(self):
        d=copy.deepcopy(self.disks);del d[1]['cluster_records'][7];renumber(d[1]['cluster_records'])
        with self.assertRaisesRegex(ValueError,'ACK'):self.verify(d)
    def test_duplicate_started_history_rejected(self):
        d=copy.deepcopy(self.disks);d[1]['cluster_records'].insert(6,d[1]['cluster_records'][5]);renumber(d[1]['cluster_records'])
        with self.assertRaisesRegex(ValueError,'duplicate STARTED'):self.verify(d)


if __name__=='__main__':unittest.main()
