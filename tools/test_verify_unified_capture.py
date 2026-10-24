import struct
import unittest
from verify_unified_capture import validate_capture
from verify_v13_tcp import checksum


def ext(kind, value):
    return struct.pack('>HH', kind, len(value)) + value


def hello(client=True, cipher=0x1301):
    extensions = ext(43, b'\x02\x03\x04' if client else b'\x03\x04')
    share = b'\x00\x1d\x00\x20' + bytes(range(32))
    extensions += ext(51, struct.pack('>H', len(share)) + share if client else share)
    if client:
        extensions += ext(13, b'\x00\x02\x08\x07')
    body = b'\x03\x03' + bytes(range(32)) + b'\0'
    body += struct.pack('>HH', 2, cipher) + b'\x01\0' if client else struct.pack('>H', cipher) + b'\0'
    body += struct.pack('>H', len(extensions)) + extensions
    msg = bytes([1 if client else 2]) + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + len(msg).to_bytes(2, 'big') + msg


def packet(node, sequence, ack, flags, payload=b''):
    peer = 3-node
    ips = bytes([10,42,0,node,10,42,0,peer])
    tcp = bytearray(struct.pack('>HHIIBBHHH', *( (40001,8443) if node==1 else (8443,40001)), sequence, ack, 80, flags, 32768, 0, 0) + payload)
    tcp[16:18] = checksum(ips+b'\0\x06'+len(tcp).to_bytes(2,'big')+tcp).to_bytes(2,'big')
    ip = bytearray(b'\x45\0'+(20+len(tcp)).to_bytes(2,'big')+b'\0\0\x40\0\x40\x06\0\0'+ips)
    ip[10:12] = checksum(ip).to_bytes(2,'big')
    return bytes([2,0,0,0,0,peer,2,0,0,0,0,node])+b'\x08\0'+ip+tcp


def capture(cipher=0x1301, conflict=False, gap=False):
    frames = [packet(1,100,0,2),packet(2,200,101,18),packet(1,101,201,16)]
    client, server = hello(cipher=cipher), hello(False)
    # Deliberately out of order and retransmitted; TCP reassembly must be real.
    frames += [packet(1,121 if not gap else 122,201,24,client[21:] if gap else client[20:]),packet(1,101,201,24,client[:20]),packet(1,101,201,24,(b'X' if conflict else client[:1])+client[1:20])]
    frames += [packet(2,201,101+len(client),24,server),packet(1,101+len(client),201+len(server),24,b'\x17\x03\x03\x00\x11'+b'\xa5'*17),packet(2,201+len(server),101+len(client),24,b'\x17\x03\x03\x00\x11'+b'\x5a'*17)]
    data = b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)
    return data+b''.join(struct.pack('<IIII',0,0,len(f),len(f))+f for f in frames)


class CaptureTests(unittest.TestCase):
    def test_real_reassembly_and_tls_policy_without_authentication_claim(self):
        result=validate_capture(capture())
        self.assertTrue(result['tls_hello_policy_verified'])
        self.assertFalse(result['tls_peer_authentication_verified'])
        self.assertEqual(result['sessions'][0]['cipher'],'TLS_AES_128_GCM_SHA256')
    def test_wrong_cipher_fails(self):
        with self.assertRaisesRegex(ValueError,'cipher'):
            validate_capture(capture(cipher=0x1302))
    def test_conflicting_retransmission_fails(self):
        with self.assertRaisesRegex(ValueError,'conflicting'):
            validate_capture(capture(conflict=True))
    def test_missing_byte_fails(self):
        with self.assertRaisesRegex(ValueError,'gap'):
            validate_capture(capture(gap=True))
    def test_bad_tcp_checksum_fails(self):
        data=bytearray(capture());data[-1]^=1
        with self.assertRaisesRegex(ValueError,'checksum'):
            validate_capture(bytes(data))


if __name__=='__main__':
    unittest.main()
