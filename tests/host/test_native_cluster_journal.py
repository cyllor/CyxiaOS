"""Strict native-v2 journal vectors; host-only, never native admission evidence."""
import copy
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from doctor import ROOT
from verify_unified_disk import verify_records,verify_pair


def sha(data):return hashlib.sha256(data).digest()
def key(n,g=1):return struct.pack('<QQ',n,g)
def event(n,tag,body):return b'CXE1'+struct.pack('<Q',n)+bytes([tag])+body


class NativeJournal(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        folder=Path(self.temp.name);keys=[];public=[]
        for name in ('a','b'):
            path=ROOT/f'crates/cluster-transport/tests/fixtures/{name}-test-key.der';keys.append(path)
            public.append(subprocess.check_output(['openssl','pkey','-inform','DER','-in',str(path),'-pubout','-outform','DER'])[-32:])
        order=sorted(range(2),key=lambda i:sha(public[i]));keys=[keys[i] for i in order];self.public=[public[i] for i in order]
        self.nodes=list(map(sha,self.public));self.public_map=dict(zip(self.nodes,self.public))
        self.input=struct.pack('<4q',1,2,3,4);self.package=sha(b'actual-pure-package-elf')
        cfg=b'\x01\0\0\0'+sha(b'CyxiaOS paired native v1')+b''.join(self.nodes)+struct.pack('<QQ',1,1)+b'A'*32+b'B'*32+sha(b'CX-RPC-native-schema-2')+sha(b'pure-vector-sum-only')+struct.pack('<Q',1)
        formation=sha(b'CX-FORM-v1'+cfg);self.cluster=sha(b'CX-CLUSTER-v1'+formation)
        message=folder/'message';message.write_bytes(b'CX-CONFIRM-v1'+formation)
        signatures=[subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(k),'-in',str(message)]) for k in keys]
        proof=cfg+formation+b''.join(signatures)
        self.disks=[]
        for i in (0,1):
            uuid=bytes([i+1])*16
            records=[b'CXID2'+uuid+self.nodes[i]+self.nodes[1-i],event(1,1,struct.pack('<Q',1)+bytes([65+i])*32+struct.pack('<Q',0)),event(2,2,cfg+signatures[i]),event(3,3,proof)]
            self.disks.append(dict(uuid=uuid.hex(),boot_epoch=1,cluster_records=[x.hex() for x in records]))

    def placement(self,*,choice=0,apply=False):
        peer=key(max(1,int.from_bytes(self.nodes[1][:8],'little')))
        stamp=struct.pack('<QQQH',1,1,1,0)+key(9) if apply else bytes(42)
        return key(9)+sha(self.input)+self.package+struct.pack('<HIHH',100,16,183,1)+b'\1'+peer+bytes([choice,int(apply)])+stamp+struct.pack('<Q',100)

    def add_local(self):
        intent=b'CXDP2\0'+self.placement()+struct.pack('<H',len(self.input))+self.input
        receipt=b'CXDP2\1'+self.placement()+b'\0'+key(12,3)
        self.disks[0]['cluster_records'][1:1]=[intent.hex(),receipt.hex()]

    def checked(self,i=0):return verify_records(self.disks[i],self.public_map,self.input,self.package)

    def app(self,*,payload=None,key_value=None):
        payload=self.input if payload is None else payload
        body=b'CXAPP1'+self.package+key(42,3)+struct.pack('<Q',7)+(key_value or key(9))+struct.pack('<QQ',50,len(payload))+payload
        return body+sha(body)

    def add_peer_execution(self):
        intent=self.placement(choice=1,apply=True)
        record=b'CXDP2\0'+intent+struct.pack('<H',len(self.input))+self.input
        self.disks[0]['cluster_records'].insert(1,record.hex())
        cid=sha(b'CX-PLACEMENT-v2'+self.cluster+self.nodes[0]+key(9)+sha(self.input)+self.package)[:16]
        terms=cid+struct.pack('<HII',100,16,60000)+self.package+sha(self.input)
        request=sha(b'CX-CONTRACT-v1'+self.cluster+self.nodes[0]+self.nodes[1]+terms)
        base=terms+request+b'R'*16+struct.pack('<QQ',1,1)
        remote=base+struct.pack('<Q',0)+b'\x02';owner=base+struct.pack('<Q',60001)+b'\x02'
        remote_close=terms+request+b'R'*16+struct.pack('<QQQ',1,2,0)+b'\x05'
        owner_close=terms+request+b'R'*16+struct.pack('<QQQ',1,2,60001)+b'\x05'
        task=self.cluster+cid+b'T'*16+struct.pack('<Q',1);payload=struct.pack('<q',10);digest=sha(payload)
        started=task+b'\0'+sha(self.input)+bytes(32)+b'\0'+struct.pack('<I',0)
        terminal=task+b'\1'+sha(self.input)+digest
        done=terminal+b'\0'+struct.pack('<I',8)+payload
        received=terminal+b'\1'+struct.pack('<I',8)+payload
        pending=bytearray(remote);pending[122:138]=bytes(16);pending[162]=0
        receipt=b'CXDP2\1'+intent+b'\1'+key(max(1,int.from_bytes(self.nodes[1][:8],'little')))+key(max(1,int.from_bytes(cid[:8],'little')),max(1,int.from_bytes(cid[8:],'little')))
        self.disks[0]['cluster_records'] += [event(4,11,bytes(pending)).hex(),event(5,10,remote).hex(),event(6,14,task+sha(self.input)).hex(),receipt.hex(),event(7,5,received).hex(),event(8,10,remote_close).hex()]
        self.disks[1]['cluster_records'] += [event(4,4,owner).hex(),event(5,5,started).hex(),event(6,5,done).hex(),event(7,6,task+digest).hex(),event(8,4,owner_close).hex()]

    def test_native_identity_schema_and_mixed_journal_are_strictly_decoded(self):
        self.add_local();result=self.checked()
        self.assertEqual(result['member'],'bound')
        self.assertEqual(result['native_journal']['local_receipts'],1)
        self.assertEqual(len(result['proofs']),1)

    def test_no_started_task_is_never_promoted_to_pair_acceptance(self):
        self.add_local();self.checked()
        with self.assertRaisesRegex(ValueError,'expected exactly one unique STARTED'):
            verify_pair(self.disks,self.public,task_input=self.input,package_hash=self.package)

    def test_complete_native_peer_intent_expected_task_result_ack_and_close(self):
        self.add_peer_execution()
        result=verify_pair(self.disks,self.public,task_input=self.input,package_hash=self.package)
        self.assertTrue(result['durable_cluster_verified'])
        self.assertEqual(result['unique_started'],1)

    def test_rejected_receipt_cannot_coexist_with_executed_outgoing_contract(self):
        self.add_peer_execution()
        rows=self.disks[0]['cluster_records']
        for index,row in enumerate(rows):
            data=bytes.fromhex(row)
            if data.startswith(b'CXDP2\1'):
                rows[index]=(data[:165]+b'\2'+struct.pack('<H',11)).hex()
        with self.assertRaisesRegex(ValueError,'native rejected receipt contradicts durable outgoing contract'):
            verify_pair(self.disks,self.public,task_input=self.input,package_hash=self.package)

    def test_native_label_cannot_hide_legacy_contract_without_native_intent(self):
        self.add_peer_execution()
        self.disks[0]['cluster_records']=[x for x in self.disks[0]['cluster_records'] if not bytes.fromhex(x).startswith(b'CXDP2')]
        with self.assertRaisesRegex(ValueError,'native outgoing contract lacks matching placement intent'):
            self.checked()

    def test_application_full_hash_identity_and_placement_payload_are_checked(self):
        self.add_local();self.disks[0]['cluster_records'].insert(1,self.app().hex())
        self.assertEqual(self.checked()['native_journal']['application_records'],1)
        for mutation in ('hash','zero-actor','different-payload','reused-actor-sequence'):
            with self.subTest(mutation=mutation):
                old=copy.deepcopy(self.disks);rows=self.disks[0]['cluster_records'];data=bytearray.fromhex(rows[1])
                if mutation=='hash':data[-1]^=1
                elif mutation=='zero-actor':data[38:54]=bytes(16);data[-32:]=sha(data[:-32])
                elif mutation=='different-payload':data=bytearray(self.app(payload=struct.pack('<4q',2,3,4,5)))
                else:rows.insert(2,self.app(key_value=key(10)).hex())
                rows[1]=data.hex()
                with self.assertRaises(ValueError):self.checked()
                self.disks=old

    def test_conflicting_receipt_and_receipt_without_intent_fail_closed(self):
        self.add_local();original=copy.deepcopy(self.disks)
        data=bytearray.fromhex(self.disks[0]['cluster_records'][2]);data[-16:]=key(13,3)
        self.disks[0]['cluster_records'].insert(3,data.hex())
        with self.assertRaisesRegex(ValueError,'conflicting native placement receipt'):self.checked()
        self.disks=original;del self.disks[0]['cluster_records'][1]
        with self.assertRaisesRegex(ValueError,'native receipt lacks matching prior intent'):self.checked()

    def test_peer_receipt_without_expected_started_custody_is_never_authority(self):
        self.add_peer_execution()
        self.disks[0]['cluster_records']=[x for x in self.disks[0]['cluster_records'] if not (bytes.fromhex(x).startswith(b'CXE1') and bytes.fromhex(x)[12]in(5,10,11,14))]
        with self.assertRaisesRegex(ValueError,'native PEER receipt lacks durable matching STARTED TaskKey custody'):self.checked()

    def test_native_namespace_cannot_be_silently_skipped(self):
        self.add_local()
        for mutation in ('payload','receipt','unknown','trailing','sequence','package','peer'):
            with self.subTest(mutation=mutation):
                old=copy.deepcopy(self.disks);rows=self.disks[0]['cluster_records']
                index=1;data=bytearray.fromhex(rows[index])
                if mutation=='payload':data[-1]^=1
                elif mutation=='receipt':index=2;data=bytearray.fromhex(rows[index]);data[-16:]=bytes(16)
                elif mutation=='unknown':data[:5]=b'CXDP9'
                elif mutation=='trailing':data+=b'\0'
                elif mutation=='sequence':index=3;data=bytearray.fromhex(rows[index]);data[4]=2
                elif mutation=='package':data[6+16+32]^=1
                elif mutation=='peer':data[6+91]^=1
                rows[index]=data.hex()
                with self.assertRaises(ValueError):self.checked()
                self.disks=old

    def test_changed_identity_and_signed_config_are_not_relabelled(self):
        for mutation in ('uuid','local','schema','signature','magic'):
            with self.subTest(mutation=mutation):
                old=copy.deepcopy(self.disks);rows=self.disks[0]['cluster_records'];index=0;data=bytearray.fromhex(rows[0])
                if mutation=='uuid':data[5]^=1
                elif mutation=='local':data[21]^=1
                elif mutation=='magic':data[4]=ord('9')
                else:
                    index=3;data=bytearray.fromhex(rows[3]);data[13+180 if mutation=='schema' else -1]^=1
                rows[index]=data.hex()
                with self.assertRaises(ValueError):self.checked()
                self.disks=old


if __name__=='__main__':unittest.main()
