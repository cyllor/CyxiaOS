#!/usr/bin/env python3
"""Independent bounded PCAP/TCP/TLS hello audit; cannot decrypt/authenticate TLS."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct
from verify_v13_tcp import checksum


def require(value, message):
    if not value:
        raise ValueError(message)


def extensions(data: bytes) -> dict:
    out, at = {}, 0
    while at < len(data):
        require(at+4 <= len(data), 'truncated TLS extension')
        kind, length = struct.unpack_from('>HH', data, at)
        at += 4
        require(kind not in out and at+length <= len(data), 'duplicate/truncated TLS extension')
        out[kind] = data[at:at+length]
        at += length
    return out


def tls_stream(stream: bytes, client: bool) -> dict:
    at, handshake, encrypted = 0, bytearray(), 0
    while at < len(stream):
        require(at+5 <= len(stream), 'truncated TLS record')
        kind, version, length = struct.unpack_from('>BHH', stream, at)
        at += 5
        require(version in (0x0301,0x0303) and 0 < length <= 18432 and at+length <= len(stream), 'invalid TLS record')
        body = stream[at:at+length]
        at += length
        if kind == 22:
            require(encrypted == 0, 'plaintext handshake after encryption')
            handshake.extend(body)
        elif kind == 23:
            require(length >= 17 and handshake, 'invalid encrypted TLS record')
            encrypted += 1
        else:
            require(kind == 20 and body == b'\x01', 'unexpected plaintext TLS record')
    require(len(handshake) >= 4 and handshake[0] == (1 if client else 2), 'missing TLS hello')
    n = int.from_bytes(handshake[1:4], 'big')
    require(n == len(handshake)-4, 'invalid plaintext TLS hello length')
    body, at = handshake[4:], 34
    require(len(body) >= 35 and body[:2] == b'\x03\x03', 'invalid TLS legacy version')
    sid = body[at]
    at += 1+sid
    require(sid <= 32 and at+3 <= len(body), 'invalid TLS session identifier')
    if client:
        n = int.from_bytes(body[at:at+2], 'big')
        at += 2
        require(n == 2 and body[at:at+n] == b'\x13\x01', 'TLS client cipher policy')
        at += n
        require(body[at:at+2] == b'\x01\0', 'TLS client compression')
        at += 2
    else:
        require(body[at:at+3] == b'\x13\x01\0', 'TLS server cipher/compression policy')
        at += 3
    require(at+2 <= len(body), 'missing TLS extensions')
    n = int.from_bytes(body[at:at+2], 'big')
    at += 2
    require(at+n == len(body), 'TLS extension length')
    ex = extensions(body[at:])
    require(not any(k in ex for k in (35,41,42)), 'TLS resumption/early data offered')
    require(ex.get(43) == (b'\x02\x03\x04' if client else b'\x03\x04'), 'TLS1.3 version required')
    share = ex.get(51, b'')
    if client:
        require(share[:2] == b'\0\x24', 'TLS key share vector')
        share = share[2:]
        require(ex.get(13) == b'\0\x02\x08\x07', 'TLS Ed25519 signature policy')
    require(len(share) == 36 and share[:4] == b'\0\x1d\0\x20' and any(share[4:]), 'TLS X25519 key share required')
    require(encrypted > 0, 'no encrypted TLS records')
    return {'encrypted_records': encrypted, 'key_share': share[4:].hex(), 'stream_bytes': len(stream)}


def validate_capture(data: bytes) -> dict:
    require(24 <= len(data) <= 16*1024*1024, 'invalid capture size')
    order = {b'\xd4\xc3\xb2\xa1':'<', b'\xa1\xb2\xc3\xd4':'>'}.get(data[:4])
    require(order is not None, 'unsupported PCAP encoding')
    major,minor,_,_,snaplen,network = struct.unpack_from(order+'HHIIII',data,4)
    require((major,minor,network)==(2,4,1) and snaplen>=1514,'invalid PCAP header')
    at, sessions, current, packets = 24, [], None, 0
    while at < len(data):
        require(at+16<=len(data),'truncated capture record')
        _,_,length,original = struct.unpack_from(order+'IIII',data,at)
        at += 16
        require(14<=length<=1514 and length==original and at+length<=len(data),'invalid capture frame')
        frame = data[at:at+length]
        at += length
        packets += 1
        node = frame[11]
        require(node in (1,2) and frame[6:12]==bytes([2,0,0,0,0,node]),'unexpected source MAC')
        peer = 3-node
        require(frame[:6] in (bytes([2,0,0,0,0,peer]),b'\xff'*6),'unexpected destination MAC')
        if frame[12:14]==b'\x08\x06':
            require(len(frame)>=42 and frame[14:20]==b'\0\x01\x08\0\x06\x04','invalid ARP frame')
            continue
        require(frame[12:14]==b'\x08\0','unexpected Ethernet protocol')
        ip = frame[14:]
        require(len(ip)>=40 and ip[0]==0x45 and ip[9]==6,'invalid IPv4/TCP header')
        size = int.from_bytes(ip[2:4],'big')
        require(40<=size<=len(ip) and checksum(ip[:20])==0,'invalid IPv4 checksum/length')
        require(int.from_bytes(ip[6:8],'big')&0x3fff==0,'fragmented IPv4 unsupported')
        require(ip[12:20]==bytes([10,42,0,node,10,42,0,peer]),'unexpected IP identities')
        tcp = ip[20:size]
        require(checksum(ip[12:20]+b'\0\x06'+len(tcp).to_bytes(2,'big')+tcp)==0,'invalid TCP checksum')
        source,dest,sequence,ack = struct.unpack_from('>HHII',tcp)
        require((source,dest) in ((40001,8443),(8443,40001)),'unexpected TCP ports')
        flags,hlen = tcp[13],(tcp[12]>>4)*4
        require(20<=hlen<=len(tcp),'invalid TCP header length')
        client = source==40001
        slot = 0 if client else 1
        if flags&2:
            if client:
                require(flags==2 and ack==0,'invalid initiating SYN')
                if current is None or current['syn'][0]!=sequence or current['client']!=node:
                    current={'client':node,'syn':[sequence,None],'segments':[[],[]],'handshake':False}
                    sessions.append(current)
            else:
                require(current is not None and node!=current['client'] and flags==18 and ack==(current['syn'][0]+1)&0xffffffff,'invalid SYN-ACK')
                require(current['syn'][1] in (None,sequence),'conflicting SYN-ACK')
                current['syn'][1]=sequence
        require(current is not None and (node==current['client'])==client,'TCP session direction mismatch')
        if client and not flags&2 and flags&16 and current['syn'][1] is not None:
            current['handshake'] |= ack==(current['syn'][1]+1)&0xffffffff
        payload = tcp[hlen:]
        if payload:
            require(current['handshake'] and flags&16 and current['syn'][slot] is not None,'TCP data before handshake')
            offset=(sequence-current['syn'][slot]-1)&0xffffffff
            require(offset+len(payload)<=4*1024*1024,'TCP stream exceeds bound')
            current['segments'][slot].append((offset,payload))
    proofs=[]
    for session in sessions:
        if not any(session['segments']):
            continue
        directions=[]
        for slot in (0,1):
            segments=session['segments'][slot]
            size=max((off+len(payload) for off,payload in segments),default=0)
            stream,present=bytearray(size),bytearray(size)
            for off,payload in segments:
                for i,value in enumerate(payload,off):
                    require(not present[i] or stream[i]==value,'conflicting TCP retransmission')
                    stream[i]=value
                    present[i]=1
            require(size>0 and all(present),'TCP reassembly gap')
            directions.append(tls_stream(bytes(stream),slot==0))
        proofs.append({'client_node':session['client'],'cipher':'TLS_AES_128_GCM_SHA256','key_exchange':'X25519','directions':directions})
    require(proofs,'no TLS sessions captured')
    return {'frames':packets,'sessions':proofs,'tls_hello_policy_verified':True,
            'tls_peer_authentication_verified':False,'membership_verified':False,
            'scope':'PCAP exposes hello policy and encrypted records; serial, native isolation, and durable proof evidence required for authentication and membership'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    print(json.dumps(validate_capture(args.capture.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
