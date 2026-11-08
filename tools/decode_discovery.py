"""Decode latest public guest UDP candidate observations, never grant evidence."""
import argparse
import json
from pathlib import Path
import struct
MAGIC=0x4359444953433031
def require(value,message):
    if not value:raise ValueError(message)
def decode(data,*,boot=None):
    require(len(data)==512,'discovery bank size differs')
    w=struct.unpack('<64Q',data)
    if not any(w):return {'present':False,'native_acceptance_verified':False}
    require(w[0]>0 and w[0]%2==0,'incomplete discovery publication')
    require(w[1:3]==(MAGIC,1) and w[3]>0 and (boot is None or w[3]==boot),'discovery schema/boot differs')
    require(w[19]==0 and not any(w[42:]),'discovery reserved fields differ')
    require(w[7]<=w[6] and w[8]==w[9]+w[10] and w[11]<=8 and w[12]<=4 and w[12]<=w[13]<=4,'discovery counters/bounds differ')
    require(w[20]<=w[5] and w[37]<=w[5] and w[38] in (1,2,3) and 0<w[39]<=0xffffffff and 0<w[40]<=65535,'discovery time/state/address differs')
    raw=lambda at,n:struct.pack(f'<{n}Q',*w[at:at+n])
    local,peer=raw(23,4),raw(27,4)
    require(any(local) and any(peer) and local!=peer,'discovery NodeIDs differ')
    sent_nonce=raw(21,2)
    require((w[7]>0 and any(sent_nonce)) or (w[7]==0 and not any(sent_nonce) and w[20]==0),'discovery sent nonce differs')
    selected=None
    if w[14]:
        node,nonce=raw(33,4),raw(31,2)
        require(w[15]>0 and w[15]<=w[9] and 0<w[17]<=0xffffffff and 0<w[18]<=65535 and node==peer and any(nonce)
                and w[16]<=w[37]<=w[5] and w[37]-w[16]<6600 and w[12]>0,'discovery selected candidate differs')
        ip=w[17].to_bytes(4,'big')
        require(1<=ip[0]<=223 and ip[0]!=127,'discovery selected IP differs')
        selected={'attempt_generation':w[14],'candidate_generation':w[15],'received_ms':w[16],
                  'ipv4':'.'.join(map(str,ip)),'port':w[18],'node':node.hex(),'nonce':nonce.hex(),'selected_ms':w[37]}
    else:require(not any(w[14:19]) and not any(w[31:38]) and w[12]==0 and w[38]!=2,'discovery unselected fields differ')
    return {'present':True,'schema_version':1,'boot':w[3],'bound_connection_epoch':w[4],'observed_ms':w[5],
            'prepared':w[6],'sent':w[7],'received':w[8],'accepted':w[9],'rejected':w[10],
            'cache_size':w[11],'active_attempts':w[12],'max_attempts':w[13],
            'last_sent_ms':w[20],'last_sent_nonce':sent_nonce.hex(),'local_node':local.hex(),'peer_node':peer.hex(),
            'selected':selected,'transport_state':{1:'pending',2:'established',3:'terminal'}[w[38]],
            'local_ipv4':'.'.join(map(str,w[39].to_bytes(4,'big'))),'local_port':w[40],'next_announcement_ms':w[41],
            'complete_history':False,'native_acceptance_verified':False,
            'scope':'latest public candidate and actual-device observations; PCAP, TLS, durable proof, READY and native admission need independent reconstruction'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('snapshot',type=Path);p.add_argument('--boot',type=int)
    args=p.parse_args();print(json.dumps(decode(args.snapshot.read_bytes(),boot=args.boot),indent=2))
