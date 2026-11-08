"""Bounded native-placement v2 journal decoding; no record grants execution."""
import hashlib
import struct


def require(value,message):
    if not value:raise ValueError(message)


def sha(data):return hashlib.sha256(data).digest()
def node_key(node):return (max(1,int.from_bytes(node[:8],'little')),1)


class Reader:
    def __init__(self,data):self.data,self.at=data,0
    def take(self,n):
        end=self.at+n;require(end<=len(self.data),'truncated native journal')
        result=self.data[self.at:end];self.at=end;return result
    def uint(self,n):return int.from_bytes(self.take(n),'little')
    def key(self):return (self.uint(8),self.uint(8))
    def end(self):require(self.at==len(self.data),'trailing native journal bytes')


class NativeJournal:
    def __init__(self,peer,package_hash):
        self.peer,self.package_hash=peer,package_hash
        self.intents,self.receipts,self.apps,self.actors={},{},{},{}

    def intent(self,r):
        start=r.at;key=r.key();payload=r.take(32);package=r.take(32)
        cpu,pages,isa,abi=r.uint(2),r.uint(4),r.uint(2),r.uint(2)
        flag,peer=r.uint(1),r.key();choice,applied=r.uint(1),r.uint(1)
        stamp=r.take(42);decided=r.uint(8)
        require(all(key) and 1<=cpu<=900 and pages>0 and isa>0 and abi>0,
                'invalid native placement resources/key')
        require(flag in (0,1) and (peer==(0,0) if flag==0 else peer==node_key(self.peer)),
                'native placement peer identity mismatch')
        require(choice in (0,1) and (choice==0 or flag==1),'invalid native placement choice')
        boot,controller,plan,action,target_id,target_generation=struct.unpack('<QQQHQQ',stamp)
        require((applied==0 and not any(stamp)) or (applied==1 and min(boot,controller,plan)>0
                and (target_id,target_generation)==key),'invalid native placement ApplyId')
        require(self.package_hash is None or package==self.package_hash,'native placement package mismatch')
        return dict(key=key,payload=payload,package=package,cpu=cpu,pages=pages,isa=isa,abi=abi,
                    peer=peer if flag else None,choice=choice,decided=decided,raw=r.data[start:r.at])

    def placement(self,data):
        r=Reader(data);require(r.take(5)==b'CXDP2','invalid native placement magic')
        kind=r.uint(1);intent=self.intent(r);key=intent['key']
        if kind==0:
            size=r.uint(2)
            require(0<size<=3984 and size%8==0,'invalid native placement input length')
            payload=r.take(size);require(sha(payload)==intent['payload'],'native placement input hash mismatch')
            r.end();old=self.intents.get(key)
            require(old is None or (old[0]['raw']==intent['raw'] and old[1]==payload),'conflicting native placement intent')
            require(old is not None or len(self.intents)<4096,'native placement history capacity')
            self.intents[key]=(intent,payload)
        elif kind==1:
            outcome=r.uint(1)
            if outcome==0:
                target=r.key();require(intent['choice']==0 and all(target),'invalid native LOCAL receipt')
                value=(0,target)
            elif outcome==1:
                peer,target=r.key(),r.key()
                require(intent['choice']==1 and peer==intent['peer'] and all(target),'invalid native PEER receipt')
                value=(1,peer,target)
            elif outcome==2:
                code=r.uint(2);require(1<=code<=20,'invalid native rejection code');value=(2,code)
            else:raise ValueError('unknown native placement receipt')
            r.end();old=self.intents.get(key)
            require(old is not None and old[0]['raw']==intent['raw'],'native receipt lacks matching prior intent')
            require(key not in self.receipts or self.receipts[key]==value,'conflicting native placement receipt')
            self.receipts[key]=value
        else:raise ValueError('unknown native placement record kind')

    def application(self,data):
        require(134<=len(data)<=4110,'invalid native application journal length')
        require(data[:6]==b'CXAPP1' and sha(data[:-32])==data[-32:],'native application journal hash/magic mismatch')
        package=data[6:38];r=Reader(data[38:-32]);actor,sequence,key=r.key(),r.uint(8),r.key()
        submitted,size=r.uint(8),r.uint(8)
        require(all(actor) and sequence>0 and all(key) and 0<size<=3984 and size%8==0,
                'invalid native application request')
        payload=r.take(size);r.end()
        require(self.package_hash is None or package==self.package_hash,'native application package mismatch')
        require((actor,sequence) not in self.actors or self.actors[(actor,sequence)]==key,
                'native application actor/sequence reused')
        require(key not in self.apps or self.apps[key]==data,'conflicting native application key')
        require(key in self.apps or len(self.apps)<4096,'native application history capacity')
        require(key in self.apps or key not in self.intents,'native application journal follows placement intent')
        self.actors[(actor,sequence)]=key;self.apps[key]=data

    def observe(self,data):
        if data.startswith(b'CXDP2'):self.placement(data)
        elif data.startswith(b'CXAPP1'):self.application(data)
        else:raise ValueError('unknown native journal namespace')

    def contract(self,intent,cluster,local):
        cid=sha(b'CX-PLACEMENT-v2'+cluster+local+struct.pack('<QQ',*intent['key'])
                +intent['payload']+intent['package'])[:16]
        return cid,tuple(max(1,int.from_bytes(cid[i:i+8],'little')) for i in (0,8))

    def finish(self,proofs,local,expected_tasks,closed):
        for key,data in self.apps.items():
            if key in self.intents:
                intent,payload=self.intents[key]
                require(payload==data[94:-32] and intent['package']==data[6:38]
                        and (intent['cpu'],intent['pages'],intent['isa'],intent['abi'],intent['peer'])
                        ==(100,16,183,1,node_key(self.peer)),'application/placement request mismatch')
        for key,outcome in self.receipts.items():
            if outcome[0]!=1:continue
            intent,_=self.intents[key];matched=False
            for proof in proofs:
                cluster=sha(b'CX-CLUSTER-v1'+proof[252:284])
                cid,contract_key=self.contract(intent,cluster,local)
                if contract_key==outcome[2] and any(k[32:48]==cid and h==intent['payload']
                        for k,h in expected_tasks.items()):matched=True
            require(matched,'native PEER receipt lacks durable matching STARTED TaskKey custody')
        for cid,contract in closed.items():
            if contract['tag']!=10:continue
            terms=contract['terms'];matched=False
            for intent,_ in self.intents.values():
                expected,contract_key=self.contract(intent,contract['cluster'],local)
                if (intent['choice']==1 and expected==cid and terms[26:58]==intent['package']
                        and terms[58:90]==intent['payload'] and struct.unpack_from('<HI',terms,16)
                        ==(intent['cpu'],intent['pages'])):
                    outcome=self.receipts.get(intent['key'])
                    require(outcome is None or (outcome[0]==1 and outcome[2]==contract_key),
                            'native rejected receipt contradicts durable outgoing contract')
                    matched=True
            require(matched,'native outgoing contract lacks matching placement intent')
        return dict(profile='native-placement-v2',placement_intents=len(self.intents),
                    application_records=len(self.apps),local_receipts=sum(v[0]==0 for v in self.receipts.values()),
                    peer_receipts=sum(v[0]==1 for v in self.receipts.values()),
                    rejected_receipts=sum(v[0]==2 for v in self.receipts.values()),
                    pending_intents=len(set(self.intents)-set(self.receipts)),execution_verified=False)
