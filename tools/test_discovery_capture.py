import struct
import unittest
import os
import pathlib
import shutil
import subprocess
import tempfile
from verify_v13_tcp import checksum
from verify_unified_capture import validate_capture
from test_verify_unified_capture import capture, packet
from discovery_capture import validate_discovery_capture

NODES={1:bytes([1])*32,2:bytes([2])*32}
def udp(node, *, body=None, source_port=8444, destination_port=8444):
    body=body if body is not None else b'CXD1\x01\0\x3c\0'+NODES[node]+struct.pack('<HH',40001 if node==1 else 8443,0)+bytes([node+7])*16
    ips=bytes([10,42,0,node,10,42,0,255])
    segment=bytearray(struct.pack('>HHHH',source_port,destination_port,8+len(body),0)+body)
    segment[6:8]=checksum(ips+b'\0\x11'+len(segment).to_bytes(2,'big')+segment).to_bytes(2,'big')
    ip=bytearray(b'\x45\0'+(20+len(segment)).to_bytes(2,'big')+b'\0\0\x40\0\x40\x11\0\0'+ips)
    ip[10:12]=checksum(ip).to_bytes(2,'big')
    return b'\xff'*6+bytes([2,0,0,0,0,node])+b'\x08\0'+ip+segment
def pcap(frames):
    return b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)+b''.join(struct.pack('<IIII',0,i,len(f),len(f))+f for i,f in enumerate(frames))
class DiscoveryCaptureTests(unittest.TestCase):
    def test_actual_smoltcp_delayed_arp_keeps_selected_nonce_after_new_hint(self):
        root=pathlib.Path(__file__).resolve().parents[1]
        cargo=shutil.which('cargo') or str(pathlib.Path.home()/'.cargo/bin/cargo')
        with tempfile.TemporaryDirectory() as directory:
            output=pathlib.Path(directory)/'discovery.pcap'
            result=subprocess.run([cargo,'test','--locked','--offline','-p','cyxia-cluster-transport','--test','discovery_network',
                                   'delayed_arp_across_announcements_keeps_the_original_selected_attempt','--','--exact'],
                                  cwd=root,env=dict(os.environ,CYXIA_DISCOVERY_TEST_PCAP=str(output)),capture_output=True)
            self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
            bank={'local_node':NODES[1].hex(),'peer_node':NODES[2].hex(),
                  'selected':{'ipv4':'10.42.0.2','port':8443,'node':NODES[2].hex(),'nonce':(bytes([9])*16).hex()}}
            proof=validate_discovery_capture(output.read_bytes(),NODES,bank)
            self.assertEqual(len(proof['announcements']),5)
    def test_actual_udp_precedes_selected_syn_and_requires_explicit_peer_hints(self):
        raw=pcap([udp(1),udp(2),packet(1,100,0,2),packet(2,200,101,18)])
        result=validate_discovery_capture(raw,NODES)
        self.assertEqual(len(result['announcements']),2)
        self.assertEqual(result['selections'][0]['peer_ipv4'],'10.42.0.2')
        self.assertFalse(result['membership_verified'])
        with self.assertRaisesRegex(ValueError,'before.*discovery'):
            validate_discovery_capture(pcap([packet(1,100,0,2),udp(2)]),NODES)
        with self.assertRaisesRegex(ValueError,'NodeID'):
            validate_discovery_capture(raw,{1:NODES[1],2:bytes([7])*32})
    def test_unknown_or_corrupt_udp_is_rejected_not_ignored(self):
        for frame in [udp(1,body=b'unknown'),udp(1,source_port=53),udp(1,destination_port=53)]:
            with self.assertRaises(ValueError):validate_discovery_capture(pcap([frame]),NODES)
        bad=bytearray(udp(1));bad[-1]^=1
        with self.assertRaisesRegex(ValueError,'checksum'):validate_discovery_capture(pcap([bad]),NODES)
    def test_general_tls_capture_accepts_only_canonical_discovery_and_keeps_tls_checks(self):
        pre=pcap([udp(1),udp(2)])
        result=validate_capture(pre+capture()[24:])
        self.assertEqual(len(result['discovery']),2)
        self.assertTrue(result['tls_hello_policy_verified'])
        with self.assertRaises(ValueError):validate_capture(pcap([udp(1,body=b'unknown')])+capture()[24:])
    def test_replayed_nonce_and_changed_candidate_cannot_fake_selected_generation(self):
        with self.assertRaisesRegex(ValueError,'nonce'):
            validate_discovery_capture(pcap([udp(1),udp(1),udp(2),packet(1,100,0,2)]),NODES)
        raw=pcap([udp(1),udp(2),packet(1,100,0,2)])
        bank={'local_node':NODES[1].hex(),'peer_node':NODES[2].hex(),
              'selected':{'ipv4':'10.42.0.2','port':8443,'node':NODES[2].hex(),'nonce':(bytes([9])*16).hex()}}
        self.assertEqual(len(validate_discovery_capture(raw,NODES,bank)['selections']),1)
        bank['selected']['nonce']=(bytes([6])*16).hex()
        with self.assertRaisesRegex(ValueError,'candidate.*capture'):
            validate_discovery_capture(raw,NODES,bank)
        body=b'CXD1\x01\0\x3c\0'+NODES[2]+struct.pack('<HH',8443,0)+bytes([6])*16
        with self.assertRaisesRegex(ValueError,'subsequent SYN'):
            validate_discovery_capture(raw+pcap([udp(2,body=body)])[24:],NODES,bank)
if __name__=='__main__':unittest.main()
