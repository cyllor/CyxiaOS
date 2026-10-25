import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from verify_v13_tcp import BODY, TOTAL, MAGIC, checksum, validate, validate_capture, bind_captures


def stream(node):
    data = bytearray(b'CYXTCP13' + bytes([1, 0, node, 3-node, 0, 0, 0, 0]))
    data += (1).to_bytes(8, 'little') + bytes([node]) * 16 + bytes([node+10]) * 16
    data += BODY.to_bytes(4, 'little') + bytes(4)
    data += bytes(((i*17)&255)^node^((i>>8)&255) for i in range(BODY))
    data += b'CYXACK13' + BODY.to_bytes(8, 'little')
    return data


def packet(node, sequence, ack, flags, payload=b''):
    mac = bytes([2,0,0,0,0,3-node,2,0,0,0,0,node,8,0])
    addresses = bytes([10,42,0,node,10,42,0,3-node])
    ports = (40001,8443) if node == 1 else (8443,40001)
    tcp = bytearray(struct.pack('>HHIIBBHHH', *ports, sequence, ack, 0x50, flags, 32768, 0, 0) + payload)
    struct.pack_into('>H', tcp, 16, checksum(addresses + b'\0\6' + len(tcp).to_bytes(2,'big') + tcp))
    ip = bytearray(bytes([0x45,0]) + (20+len(tcp)).to_bytes(2,'big') + bytes(4) + bytes([64,6,0,0]) + addresses)
    struct.pack_into('>H', ip, 10, checksum(ip))
    return mac + ip + tcp


def capture(*, ack=True, retransmit=False, conflict=False, bad_handshake=False, early_ack=False, bad_arp=False):
    packets = []
    bases = [0xfffffff0, 37001]  # First TCP sequence wraps during the transfer.
    for node in (1,2):
        own = bytes([2,0,0,0,0,node]); peer = bytes([2,0,0,0,0,3-node])
        packets.append((bytes([255])*6 if node == 1 else peer) + own + b'\10\6'
                       + b'\0\1\10\0\6\4' + (0 if bad_arp else node).to_bytes(2,'big')
                       + own + bytes([10,42,0,node]) + (bytes(6) if node == 1 else peer)
                       + bytes([10,42,0,3-node]))
    packets.extend([packet(1,bases[0],0,2),
                    packet(2,bases[1],(bases[0]+1)&0xffffffff,2 if bad_handshake else 18),
                    packet(1,(bases[0]+1)&0xffffffff,(bases[1]+1)&0xffffffff,16)])
    final_acks=[packet(node,(bases[node-1]+TOTAL+1)&0xffffffff,(bases[2-node]+TOTAL+1)&0xffffffff,16) for node in (1,2)]
    if early_ack:
        packets.extend(final_acks)
    for node in (1,2):
        body = stream(node)
        for at in range(0,len(body),1400):
            packets.append(packet(node,(bases[node-1]+1+at)&0xffffffff,0,16,body[at:at+1400]))
        if retransmit or conflict:
            body[99] ^= int(conflict)
            packets.append(packet(node,(bases[node-1]+1)&0xffffffff,0,16,body[:1400]))
    if ack and not early_ack:
        packets.extend(final_acks)
    out = bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for item in packets:
        out += struct.pack('<4I',0,0,len(item),len(item)) + item
    return out


def evidence():
    serial, pages = [], []
    for node in (1,2):
        local = struct.unpack('<2Q',bytes([node])*16)
        peer = struct.unpack('<2Q',bytes([3-node])*16)
        words = [MAGIC,1,1,node,3-node,1,*local,1,*peer,TOTAL,TOTAL,BODY,1,1500]+[0]*496
        pages.append(struct.pack('<512Q',*words))
        serial.append(b'\n'.join([*(f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode() for cpu in (1,2,3)),
            b'SMP_BOOT_OK a=4 b=15 c=0',b'STORAGE_V13_BOOT_DURABLE',b'ENTROPY_READY VIRTIO MECHANISM',
            f'TCP_V13_START node={node} peer={3-node} boot=1 EL1_TCP_PLAINTEXT_ONLY'.encode(),
            f'TCP_V13_READY node={node} peer={3-node} bytes={TOTAL}'.encode()]))
    return serial, pages


class NativeTcpEvidenceTests(unittest.TestCase):
    def test_reassembly_wraparound_and_identical_retransmission(self):
        report = validate_capture(capture(retransmit=True))
        self.assertEqual(report['stream_bytes'],[TOTAL,TOTAL])

    def test_missing_peer_ack_is_not_complete(self):
        with self.assertRaisesRegex(ValueError,'TCP-acknowledged'):
            validate_capture(capture(ack=False))

    def test_complete_ack_cannot_precede_peer_payload(self):
        with self.assertRaisesRegex(ValueError, 'after complete'):
            validate_capture(capture(early_ack=True))

    def test_invalid_arp_operation_cannot_prove_address_resolution(self):
        with self.assertRaisesRegex(ValueError, 'ARP identity/operation'):
            validate_capture(capture(bad_arp=True))

    def test_two_bare_syns_are_not_a_tcp_handshake(self):
        with self.assertRaisesRegex(ValueError,'SYN-ACK'):
            validate_capture(capture(bad_handshake=True))

    def test_conflicting_retransmission_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'conflicting'):
            validate_capture(capture(conflict=True))

    def test_checksum_and_truncation_rejected(self):
        data = capture()
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError,'checksum'):
            validate_capture(data)
        with self.assertRaises(ValueError):
            validate_capture(data[:-4])

    def test_native_evidence_scope_stays_tcp_only(self):
        serial,pages=evidence()
        result=validate(serial,pages,[4,4])
        self.assertTrue(result['native_tcp_verified'])
        self.assertFalse(result['native_cluster_verified'])
        self.assertFalse(result['tls_verified'])

    def test_native_boot_order_and_secondary_handshakes_are_required(self):
        serial,pages=evidence()
        serial[0]=serial[0].replace(b'SMP_CPU_ON a=1 b=1 c=0',b'')
        with self.assertRaises(ValueError):
            validate(serial,pages,[4,4])
        serial,pages=evidence()
        serial[0]=serial[0].replace(b'STORAGE_V13_BOOT_DURABLE',b'')+b'\nSTORAGE_V13_BOOT_DURABLE'
        with self.assertRaisesRegex(ValueError,'before durable'):
            validate(serial,pages,[4,4])

    def test_error_or_nonzero_reserved_evidence_never_passes(self):
        serial,pages=evidence()
        altered=bytearray(pages[0]);altered[128]=1;pages[0]=altered
        with self.assertRaises(ValueError):
            validate(serial,pages,[4,4])

    def test_both_captures_and_committed_disks_must_bind_same_session(self):
        import copy
        captured=validate_capture(capture())
        serial,pages=evidence(); observations=validate(serial,pages,[4,4])
        disks=[dict(uuid=i['filesystem'],boot_epoch=i['boot']) for i in captured['identities']]
        provisioned=[dict(uuid=d['uuid']) for d in disks]
        bind_captures([captured,captured],observations,disks,provisioned)
        altered=copy.deepcopy(captured);altered['identities'][0]['challenge']='different'
        with self.assertRaisesRegex(ValueError,'different challenges'):
            bind_captures([captured,altered],observations,disks,provisioned)
        disks[0]['boot_epoch']=2
        with self.assertRaisesRegex(ValueError,'committed disk'):
            bind_captures([captured,captured],observations,disks,provisioned)


if __name__=='__main__':
    unittest.main()
