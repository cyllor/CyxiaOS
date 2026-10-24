#!/usr/bin/env python3
"""Independent durable cluster proof/lifecycle verifier (OpenSSL Ed25519)."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from check_v13_disk import inspect


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).digest()


def signature(public, message, signed):
    require(len(public)==32 and len(signed)==64,'invalid Ed25519 signature shape')
    with tempfile.TemporaryDirectory(prefix='cyx-proof-') as temp:
        root=Path(temp)
        (root/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+public)
        (root/'message').write_bytes(message)
        (root/'signature').write_bytes(signed)
        result=subprocess.run(['openssl','pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(root/'public.der'),'-rawin','-in',str(root/'message'),'-sigfile',str(root/'signature')],capture_output=True,timeout=5)
        require(result.returncode==0,'Ed25519 proof signature verification failed')


def config(data):
    require(len(data)==252 and data[:4]==b'\x01\0\0\0','invalid canonical formation configuration')
    nodes=[data[36:68],data[68:100]]
    counters=struct.unpack_from('<QQ',data,100)
    nonces=[data[116:148],data[148:180]]
    epoch=struct.unpack_from('<Q',data,244)[0]
    require(nodes[0]<nodes[1] and min(counters)>0 and epoch>0 and all(any(n) for n in nonces),'invalid formation identities/counters/nonces')
    require(data[4:36]==sha(b'CyxiaOS paired native v1') and data[180:212]==sha(b'CX-RPC-native-schema-1') and data[212:244]==sha(b'pure-vector-sum-only'),'unexpected native formation trust/schema/policy')
    return dict(bytes=data,nodes=nodes,counters=counters,nonces=nonces,epoch=epoch,formation=sha(b'CX-FORM-v1'+data),cluster=sha(b'CX-CLUSTER-v1'+sha(b'CX-FORM-v1'+data)))


def verify_records(disk, public_map, task_input, package_hash):
    records=[bytes.fromhex(r) for r in disk['cluster_records']]
    require(records and len(records)<=32768,'missing/beyond-quota durable identity/events')
    identity=records[0]
    require(len(identity)==85 and identity[:5]==b'CXID1' and identity[5:21].hex()==disk['uuid'],'durable filesystem identity mismatch')
    local,peer=identity[21:53],identity[53:85]
    require(local!=peer and local in public_map and peer in public_map,'durable NodeID differs from provisioned Ed25519 public keys')
    require(disk['boot_epoch']>0,'invalid current BootEpoch')
    member,locked,last_epoch,peer_counter='standalone',None,0,0
    cfg,own_signature,proof=None,None,None
    leave_signed=None
    leave_id=None
    contracts,closed,results,started,acks={},{},{},{},{}
    expected_tasks={}
    proof_history=[]
    formation_locks={}
    for ordinal,record in enumerate(records[1:],1):
        require(len(record)>=13 and len(record)<=33200 and record[:4]==b'CXE1' and struct.unpack_from('<Q',record,4)[0]==ordinal,'non-monotonic durable event serial')
        tag,body=record[12],record[13:]
        if tag==1:
            require(len(body)==48 and member=='standalone','formation BEGIN outside standalone')
            counter,nonce,frozen=struct.unpack_from('<Q',body)[0],body[8:40],struct.unpack_from('<Q',body,40)[0]
            require(counter>(locked[0] if locked else 0) and any(nonce) and frozen==last_epoch,'formation counter/frozen epoch replay')
            locked=(counter,nonce,frozen)
        elif tag==2:
            require(len(body)==316 and member in ('standalone','confirmed') and locked,'CONFIRMED state/length')
            new=config(body[:252]);i=new['nodes'].index(local) if local in new['nodes'] else -1
            require(i>=0 and new['nodes'][1-i]==peer and new['counters'][i]==locked[0] and new['nonces'][i]==locked[1] and new['epoch']>locked[2] and new['counters'][1-i]>peer_counter,'CONFIRMED durable formation mismatch')
            if member=='confirmed':require(cfg['bytes']==new['bytes'] and own_signature==body[252:],'conflicting repeated CONFIRMED')
            signature(public_map[local],b'CX-CONFIRM-v1'+new['formation'],body[252:])
            formation_locks[new['formation']]=locked
            cfg,own_signature,member,last_epoch=new,body[252:],'confirmed',new['epoch']
        elif tag==3:
            require(len(body)==412 and member in ('confirmed','bound') and cfg and body[:252]==cfg['bytes'] and body[252:284]==cfg['formation'],'BOUND formation proof mismatch')
            for i,node in enumerate(cfg['nodes']):signature(public_map[node],b'CX-CONFIRM-v1'+cfg['formation'],body[284+64*i:348+64*i])
            require(body[284+64*cfg['nodes'].index(local):348+64*cfg['nodes'].index(local)]==own_signature,'BOUND own signature mismatch')
            if proof is not None:require(proof==body,'conflicting durable proof')
            proof,member,peer_counter=body,'bound',cfg['counters'][cfg['nodes'].index(peer)]
            proof_history.append(body)
        elif tag in (4,10,11):
            require(len(body)==163 and member=='bound' and cfg,'contract outside BOUND/invalid length')
            terms=body[:90];cid=terms[:16]
            cpu,pages,runtime=struct.unpack_from('<HII',terms,16)
            require(any(cid) and 0<cpu<=900 and pages>0 and 0<runtime<=60000,'invalid contract resource bounds')
            require(terms[58:90]==sha(task_input),'contract input hash mismatch')
            if package_hash is not None:require(terms[26:58]==package_hash,'contract package hash differs from actual package ELF')
            requester,owner=(local,peer) if tag in (10,11) else (peer,local)
            request=sha(b'CX-CONTRACT-v1'+cfg['cluster']+requester+owner+terms)
            owner_boot,grant,deadline=struct.unpack_from('<QQQ',body,138)
            state=body[162]
            require(body[90:122]==request and owner_boot>0 and grant>0 and ((tag==11 and state==0 and body[122:138]==bytes(16)) or (tag in (4,10) and state in (2,5) and any(body[122:138]))),'contract request hash/grant invalid')
            if tag==4:require(owner_boot<=disk['boot_epoch'] and deadline>0,'owner BootEpoch/deadline invalid')
            old=contracts.get(cid)
            if state in (0,2):
                require(cid not in closed,'regrant after durable close tombstone')
                if old:
                    require((old['state']==0 and state==2 and old['terms']==terms and old['request']==request) or (old['bytes']==body and old['tag']==(10 if tag==11 else tag)),'changed duplicate grant')
                contracts[cid]=dict(bytes=body,cluster=cfg['cluster'],state=state,tag=10 if tag==11 else tag,terms=terms,request=request,owner=owner,requester=requester,owner_boot=owner_boot,grant=grant,reservation=body[122:138])
            else:
                require(old is not None and old['state']==2 and old['tag']==tag and old['terms']==terms and old['request']==request and old['reservation']==body[122:138] and old['owner_boot']==owner_boot and grant==old['grant']+1,'close without matching grant or revoked epoch')
                require(all(r['state']!=0 for k,r in results.items() if k[32:48]==cid),'close with STARTED obligation')
                if tag==4:
                    require(all(k in acks for k,r in results.items() if k[32:48]==cid and not r['received']),'close before durable ACK')
                closed[cid]=dict(**old,close=body)
                del contracts[cid]
        elif tag==14:
            require(len(body)==104 and cfg and member=='bound','invalid expected TaskKey intent')
            key,input_hash=body[:72],body[72:]
            c=contracts.get(key[32:48])
            require(c is not None and c['tag']==10 and c['state']==2 and key[:32]==cfg['cluster'] and any(key[48:64]) and struct.unpack_from('<Q',key,64)[0]>0 and input_hash==c['terms'][58:90],'expected TaskKey lacks matching remote grant/input')
            require(key not in expected_tasks or expected_tasks[key]==input_hash,'conflicting expected TaskKey intent')
            expected_tasks[key]=input_hash
        elif tag==5:
            require(len(body)>=142 and member=='bound' and cfg,'invalid durable result shape')
            key,state=body[:72],body[72]
            input_hash,result_hash,received=body[73:105],body[105:137],body[137]
            length=struct.unpack_from('<I',body,138)[0];payload=body[142:]
            require(state in range(5) and received in (0,1) and length==len(payload) and length<=32768,'invalid durable result length/state')
            require(key[:32]==cfg['cluster'] and any(key[48:64]) and struct.unpack_from('<Q',key,64)[0]>0,'durable task key mismatch')
            contract=contracts.get(key[32:48])
            require(contract is not None and contract['state']==2 and contract['terms'][58:90]==input_hash and input_hash==sha(task_input),'result input hash/contract mismatch')
            old=results.get(key)
            if state==0:
                require(not received and contract['tag']==4 and key not in started and old is None,'duplicate STARTED durable task history')
                require(not payload and result_hash==bytes(32),'STARTED contains terminal data')
                started[key]=ordinal
            else:
                require(result_hash==sha(payload if state==1 else bytes([state])+payload),'terminal result hash mismatch')
                if state==1:
                    require(len(task_input)%8==0,'invalid expected pure input')
                    total=sum(struct.unpack('<'+'q'*(len(task_input)//8),task_input))
                    require(-(1<<63)<=total<1<<63 and payload==struct.pack('<q',total),'pure task output differs from independent execution')
                if received:
                    require(contract['tag']==10,'recipient custody on owner contract')
                    require(expected_tasks.get(key)==input_hash,'recipient result lacks durable expected TaskKey/input')
                else:
                    require(key in started and old and old['state']==0,'terminal without unique STARTED')
                if old and old['state']!=0:require(old['bytes']==body,'conflicting repeated terminal custody')
            results[key]=dict(bytes=body,state=state,hash=result_hash,payload=payload,received=bool(received),ordinal=ordinal)
        elif tag==6:
            require(len(body)==104,'invalid durable ACK length')
            key,hash_value=body[:72],body[72:]
            require(key in results and results[key]['state']!=0 and not results[key]['received'] and results[key]['hash']==hash_value,'ACK without durable executor result')
            acks[key]=hash_value
        elif tag==9:
            require(len(body)==48 and body[:16] in closed and closed[body[:16]]['request']==body[16:],'recovery close lacks durable tombstone')
        elif tag==12:
            require(len(body)==48 and body[:16] in contracts,'cancel without durable request intent')
            pending=contracts[body[:16]]
            require(pending['tag']==10 and pending['state']==0 and pending['request']==body[16:],'cancel after grant or changed request')
            del contracts[body[:16]]
        elif tag==13:
            require(len(body)==248 and member=='leaving' and cfg,'leave signature outside frozen leave state')
            claim=body[:184]
            require(claim[:32]==cfg['cluster'] and claim[32:40]==struct.pack('<Q',cfg['epoch']) and claim[56:120]==b''.join(cfg['nodes']),'leave signature record mismatch')
            require(leave_id is None or claim[40:56]==leave_id,'leave signature identifier differs from durable intent')
            index=cfg['nodes'].index(local)
            obligations=bytearray(b'CX-OBLIGATIONS-v1')
            for cid,c in sorted(closed.items()):
                if c['cluster']!=cfg['cluster']:continue
                terminal=next((r['hash'] for k,r in results.items() if k[:32]==cfg['cluster'] and k[32:48]==cid and r['state']!=0),None)
                obligations.extend(cid+c['request']+bytes([terminal is not None]))
                if terminal is not None:obligations.extend(terminal)
            require(claim[120+32*index:152+32*index]==sha(obligations),'leave signature obligation digest mismatch')
            signature(public_map[local],b'CX-LEAVE-v1'+claim,body[184:])
            require(leave_signed is None or leave_signed==body,'double-signed conflicting leave')
            leave_signed=body
        elif tag==7:
            require(len(body) in (0,16) and member in ('bound','leaving') and not contracts,'leave with live contract/invalid leave intent')
            if body:
                require(any(body) and leave_id in (None,body),'conflicting durable leave identifier')
                leave_id=body
            require(all(r['received'] or k in acks for k,r in results.items()),'leave before durable ACK')
            member='leaving'
        elif tag==8:
            require(len(body)==312 and member=='leaving' and cfg and body[:32]==cfg['cluster'] and body[32:40]==struct.pack('<Q',cfg['epoch']) and body[56:120]==b''.join(cfg['nodes']),'invalid durable leave proof')
            require(leave_signed is not None and leave_signed[:184]==body[:184] and leave_signed[184:]==body[184+64*cfg['nodes'].index(local):248+64*cfg['nodes'].index(local)],'leave unlock before durable own signature')
            for i,node in enumerate(cfg['nodes']):signature(public_map[node],b'CX-LEAVE-v1'+body[:184],body[184+64*i:248+64*i])
            member,cfg,own_signature,proof='standalone',None,None,None
        else:
            raise ValueError('unknown durable protocol event')
    require(proof_history,'missing durable BOUND proof')
    require(not contracts,'unclosed durable contract obligations')
    return dict(local=local,peer=peer,proofs=proof_history,expected_tasks=expected_tasks,formation_locks=formation_locks,started=started,results=results,acks=acks,closed=closed,member=member,events=len(records)-1)


def verify_pair(disks, publics, *, task_input=None, package_hash=None):
    require(len(disks)==len(publics)==2 and all(len(p)==32 for p in publics),'exactly two Ed25519 public keys/disks required')
    require(disks[0]['uuid']!=disks[1]['uuid'],'cloned filesystem UUID')
    public_map={sha(p):p for p in publics}
    require(len(public_map)==2,'cloned NodeIDs')
    if task_input is None:task_input=struct.pack('<4q',1,2,3,4)
    nodes=[verify_records(d,public_map,task_input,package_hash) for d in disks]
    require(nodes[0]['local']==nodes[1]['peer'] and nodes[1]['local']==nodes[0]['peer'],'disk pair identity mismatch')
    require(set(nodes[0]['proofs'])==set(nodes[1]['proofs']),'nodes hold different durable BOUND proofs')
    for proof in nodes[0]['proofs']:
        c=config(proof[:252])
        frozen=[n['formation_locks'][c['formation']][2] for n in nodes]
        require(c['epoch']==max(frozen)+1,'formation epoch must equal max frozen epoch plus one')
    starts=[(key,i) for i,n in enumerate(nodes) for key in n['started']]
    require(len(starts)==1,'expected exactly one unique STARTED across both disks')
    for key,executor in starts:
        owner,recipient=nodes[executor],nodes[1-executor]
        require(key in owner['results'] and key in recipient['results'],'missing durable result custody')
        a,b=owner['results'][key],recipient['results'][key]
        require(not a['received'] and b['received'] and a['state']!=0 and a['state']==b['state'] and a['hash']==b['hash'] and a['payload']==b['payload'],'cross-node durable result mismatch')
        require(owner['acks'].get(key)==a['hash'],'missing durable executor ACK')
        cid=key[32:48]
        require(cid in owner['closed'] and cid in recipient['closed'],'missing paired durable close')
        x,y=owner['closed'][cid],recipient['closed'][cid]
        require(x['terms']==y['terms'] and x['request']==y['request'] and x['reservation']==y['reservation'] and x['owner_boot']==y['owner_boot'],'paired contract commitment mismatch')
    return dict(durable_cluster_verified=True,scope='independent journal/file CRC + pinned Ed25519 formation proof + unique task/result/ACK/close history; live TLS/READY and worker execution require separate native evidence',nodes=[dict(node=n['local'].hex(),peer=n['peer'].hex(),events=n['events'],member=n['member']) for n in nodes],unique_started=len(starts),expected_task_key_verified=True,pure_task_done_verified=all(nodes[i]['results'][key]['state']==1 for key,i in starts),result_states=[nodes[i]['results'][key]['state'] for key,i in starts],proof_sha256=[sha(p).hex() for p in nodes[0]['proofs']],task_keys=[key.hex() for key,_ in starts],result_hashes=[nodes[i]['results'][key]['hash'].hex() for key,i in starts],package_hash_verified=package_hash is not None)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--disk',type=Path,action='append',required=True)
    p.add_argument('--public',type=Path,action='append',required=True)
    p.add_argument('--package',type=Path)
    args=p.parse_args()
    result=verify_pair([inspect(p) for p in args.disk],[p.read_bytes() for p in args.public],package_hash=hashlib.sha256(args.package.read_bytes()).digest() if args.package else None)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
