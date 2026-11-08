"""Independent canonical UDP discovery and subsequent TCP-target reconstruction.

The caller supplies trusted NodeIDs. Datagrams remain unauthenticated hints;
this audit cannot promote them, TLS bytes, or the diagnostic bank to membership.
"""
import struct
from verify_v13_tcp import checksum

def require(value,message):
    if not value:raise ValueError(message)

def capture_frames(data):
    require(24<=len(data)<=16*1024*1024,'invalid discovery capture size')
    order={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}.get(data[:4])
    require(order is not None,'unsupported PCAP encoding')
    major,minor,_,_,snap,network=struct.unpack_from(order+'HHIIII',data,4)
    require((major,minor,network)==(2,4,1) and snap>=1514,'invalid PCAP header')
    at,index=24,0
    while at<len(data):
        require(at+16<=len(data),'truncated capture record')
        _,usec,size,original=struct.unpack_from(order+'IIII',data,at);at+=16
        require(usec<1000000 and 14<=size<=1514 and size==original and at+size<=len(data),'invalid capture frame')
        yield index,data[at:at+size];at+=size;index+=1

def decode_discovery_datagram(frame,node):
    require(node in (1,2) and frame[6:12]==bytes([2,0,0,0,0,node]),'discovery MAC identity differs')
    require(frame[:6]==b'\xff'*6 and frame[12:14]==b'\x08\0','discovery must use Ethernet broadcast IPv4')
    ip=frame[14:]
    require(len(ip)>=28 and ip[0]==0x45 and ip[9]==17,'invalid discovery IPv4/UDP header')
    size=int.from_bytes(ip[2:4],'big')
    require(28<=size<=len(ip) and checksum(ip[:20])==0,'invalid discovery IPv4 checksum/length')
    require(int.from_bytes(ip[6:8],'big')&0x3fff==0,'fragmented discovery unsupported')
    require(ip[12:20]==bytes([10,42,0,node,10,42,0,255]),'discovery IP identity differs')
    udp=ip[20:size]
    source,dest,length,check=struct.unpack_from('>HHHH',udp)
    require((source,dest)==(8444,8444) and length==len(udp),'unknown UDP protocol/ports/length')
    require(check!=0 and checksum(ip[12:20]+b'\0\x11'+len(udp).to_bytes(2,'big')+udp)==0,'invalid discovery UDP checksum')
    body=udp[8:]
    require(len(body)==60 and len(body)<=256 and body[:8]==b'CXD1\x01\0\x3c\0' and body[42:44]==b'\0\0','unknown or malformed discovery datagram')
    port=int.from_bytes(body[40:42],'little')
    require(any(body[8:40]) and any(body[44:60]) and port>0,'invalid discovery NodeID/port/nonce')
    return {'source_node':node,'node':body[8:40].hex(),'ipv4':'.'.join(map(str,ip[12:16])),
            'port':port,'nonce':body[44:60].hex(),'wire_bytes':len(body)}

def validate_discovery_capture(data,nodes,bank=None):
    require(set(nodes)=={1,2} and all(isinstance(v,bytes) and len(v)==32 and any(v) for v in nodes.values()) and nodes[1]!=nodes[2],
            'explicit distinct trusted NodeIDs required')
    announcements,selections,latest,nonces=[],[],{},set()
    for index,frame in capture_frames(data):
        node=frame[11]
        require(node in (1,2) and frame[6:12]==bytes([2,0,0,0,0,node]),'source MAC differs')
        if frame[12:14]==b'\x08\x06':
            require(len(frame)>=42 and frame[14:20]==b'\0\x01\x08\0\x06\x04','invalid ARP frame')
            continue
        require(frame[12:14]==b'\x08\0','unexpected Ethernet protocol')
        if len(frame)>23 and frame[23]==17:
            record=decode_discovery_datagram(frame,node)
            require(record['node']==nodes[node].hex(),'discovery NodeID differs from trusted peer')
            key=(node,record['nonce']);require(key not in nonces,'replayed discovery nonce')
            require(len(announcements)<4096,'discovery capture exceeds bounded audit size')
            nonces.add(key);record['frame']=index;announcements.append(record);latest[node]=record
            continue
        ip=frame[14:]
        require(len(ip)>=40 and ip[0]==0x45 and ip[9]==6,'unexpected IP protocol')
        size=int.from_bytes(ip[2:4],'big');require(40<=size<=len(ip) and checksum(ip[:20])==0,'invalid TCP IP checksum/length')
        require(int.from_bytes(ip[6:8],'big')&0x3fff==0 and ip[12:20]==bytes([10,42,0,node,10,42,0,3-node]),'TCP IP identity differs')
        tcp=ip[20:size]
        require(checksum(ip[12:20]+b'\0\x06'+len(tcp).to_bytes(2,'big')+tcp)==0,'invalid TCP checksum')
        source,dest=struct.unpack_from('>HH',tcp)
        if tcp[13]&2:
            require(3-node in latest and node in latest,'TCP SYN before bilateral discovery hints')
            # A selected attempt is immutable. A newer broadcast can arrive
            # while ARP/SYN is delayed or retransmitting, and is not evidence
            # that this existing attempt selected the newer nonce/endpoint.
            hints=[a for a in announcements if a['source_node']==3-node and a['port']==dest
                   and a['ipv4']=='.'.join(map(str,ip[16:20])) and a['frame']<index]
            require(hints and any(a['source_node']==node and a['port']==source and a['frame']<index for a in announcements),
                    'SYN target differs from discovered endpoint')
            selections.append({'frame':index,'source_node':node,'peer_ipv4':hints[0]['ipv4'],
                               'peer_port':dest,'peer_node':hints[0]['node'],
                               'candidate_hints':hints.copy()})
    require(announcements and selections,'missing actual discovery/TCP selection')
    if bank is not None:
        require(bank.get('local_node') in [n.hex() for n in nodes.values()] and bank.get('peer_node') in [n.hex() for n in nodes.values()] and bank['local_node']!=bank['peer_node'],'bank NodeID differs')
        selected=bank.get('selected')
        require(selected and selected['node']==bank['peer_node'],'bank selected NodeID differs')
        require(any(all(selected[key]==a[key] for key in ('ipv4','port','node','nonce')) for a in announcements),'selected candidate absent from capture')
        local=next(k for k,v in nodes.items() if v.hex()==bank['local_node'])
        require(any(s['source_node']==local and s['peer_ipv4']==selected['ipv4'] and s['peer_port']==selected['port']
                    and any(a['nonce']==selected['nonce'] and a['node']==selected['node'] for a in s['candidate_hints'])
                    for s in selections),'selected candidate has no subsequent SYN in capture')
    return {'announcements':announcements,'selections':selections,'membership_verified':False,
            'scope':'wire discovery and subsequent TCP targets only; pinned TLS, durable dual proof, READY and native admission require independent evidence'}
