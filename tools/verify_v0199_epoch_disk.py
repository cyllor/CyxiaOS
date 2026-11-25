#!/usr/bin/env python3
"""Two fresh native QEMU processes, one dedicated scratch image.

The dedicated formatted baseline-v1 test volume exercises full mount
structure, four protected objects, replay/checkpoint, and paired durable
boot/role generation. Never accepts an existing disk path or production
authority. No production G0/G4 claim.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import verify_smp

BLOCK=4096
CAPACITY=512*1024*1024
UUID=b'CYX-TEST-MOUNT!!'
MARKER=b'CYXIA_V0199_MOUNT_FIXTURE_ONLY'
HOME=7000
BOOT_HOME=7002
RECEIPTS_HOME=7003
ACL_HOME=7010
ROOT_HOME=7014
MAGIC=0x435945504f434831
PATCH=Path(__file__).resolve().parent/'qemu/cyxia-per-vcpu-pmu.patch'

def crc(b):
    c=0xffffffff
    for byte in b:
        c^=byte
        for _ in range(8):
            c=(c>>1)^(0x82f63b78 if c&1 else 0)
    return c^0xffffffff

def put(b,at,fmt,*v):
    struct.pack_into('<'+fmt,b,at,*v)

def superblock(generation=1,checkpoint=0,log_epoch=1):
    b=bytearray(BLOCK)
    put(b,0,'IHHII',0x43594653,1,80,4096,131072)
    b[16:32]=UUID
    put(b,32,'QQQIIIIII',generation,checkpoint,log_epoch,4098,4102,4118,256,0,0)
    put(b,76,'I',crc(b))
    return bytes(b)

def state(txid):
    b=bytearray(BLOCK)
    put(b,0,'IHH',0x43595353,2,248)
    b[8:24]=UUID
    put(b,24,'QQQQQQ',txid+1,1,1,1,0,(txid+1)//2)
    put(b,80,'Q',1)
    b[88:120]=bytes([0x5a])*32
    generations=[1]*16
    generations[1]=1+txid//2
    put(b,120,'16Q',*generations)
    put(b,72,'I',crc(b))
    return bytes(b)

def boot_store(epoch):
    b=bytearray(BLOCK)
    put(b,0,'IHH',0x43594245,1,40)
    b[8:24]=UUID
    put(b,24,'Q',epoch)
    put(b,32,'I',crc(b))
    return bytes(b)

def seal(b,kind,length,txid,lsn,log_epoch):
    put(b,0,'IHHIIQQQ',0x43594c47,1,kind,length,crc(b[64:length]),txid,lsn,log_epoch)
    put(b,56,'I',crc(b[:64]))
    return bytes(b)

def transaction(txid):
    # Independent canonical two-home boot and one-home role restart log.
    if txid%2:
        begin_lsn=7*(txid//2)+1
        images=[(HOME,state(txid)),(BOOT_HOME,boot_store((txid+1)//2))]
    else:
        begin_lsn=7*(txid//2-1)+5
        images=[(HOME,state(txid))]
    n=len(images)
    log_epoch=(txid+1)//2+1
    b=bytearray(BLOCK);put(b,64,'IIQ',n,0,BLOCK*n)
    redos=[];h=hashlib.sha256()
    for i,(home,image) in enumerate(images):
        r=bytearray(2*BLOCK);put(r,40,'QII',home,i,n);r[64:64+BLOCK]=image
        h.update(struct.pack('<Q',home)+image)
        redos.append(seal(r,2,4160,txid,begin_lsn+i+1,log_epoch))
    c=bytearray(BLOCK);put(c,64,'QQQII',txid,begin_lsn,begin_lsn+n,n,0)
    c[96:128]=h.digest()
    return seal(b,1,80,txid,begin_lsn,log_epoch)+b''.join(redos)+seal(c,3,128,txid,begin_lsn+n+1,log_epoch)

def inode(kind=0,generation=0,size=0,physical=0,count=0):
    b=bytearray(256);put(b,0,'IHHQ',0x4359494e,kind,0,generation)
    if kind:
        put(b,16,'QQHHIQ',size,0,int(bool(count)),0,0,1)
        if count:put(b,48,'III',0,physical,count)
    put(b,252,'I',crc(b));return bytes(b)

def fixed_metadata():
    bitmap=bytearray(4*BLOCK)
    for k in list(range(4118))+list(range(HOME,ROOT_HOME+1)):
        bitmap[k//8]|=1<<(k%8)
    inodes=[inode(2,1,128,ROOT_HOME,1),inode(1,1,len(MARKER),HOME+1,1),
            inode(1,1,BLOCK,BOOT_HOME,1),inode(1,1,7*BLOCK,RECEIPTS_HOME,7),
            inode(1,1,4*BLOCK,ACL_HOME,4),inode(1,1,BLOCK,HOME,1)]
    inodes+= [inode()]*(256-len(inodes))
    index=bytearray(BLOCK)
    put(index,0,'IHH',0x43595349,4,64);index[8:24]=UUID
    put(index,24,'QQ',0,1)
    for i in range(16):put(index,64+i*24,'IIQQ',0,0,0,i+1)
    put(index,4092,'I',crc(index))
    acl=bytearray(4*BLOCK)
    for i in range(256):
        b=bytearray(64)
        if i==0:owner,system=1<<14,0
        elif i==1:owner,system=1<<8,0
        elif 2<=i<=5:owner,system=0,(1<<8)|(1<<9)|(1<<13)
        else:owner,system=0,0
        live=int(i<6)
        put(b,0,'IIQQQIIQIII',i,live,live,live,live,owner,system,live,0,0,0)
        put(b,60,'I',crc(b));acl[i*64:(i+1)*64]=b
    root=bytearray(BLOCK);name=b'fixture'
    put(root,0,'IHHQ',1,len(name),0,1);root[16:16+len(name)]=name
    put(root,124,'I',crc(root[:128]))
    return {4098:bytes(bitmap),4102:b''.join(inodes),
            RECEIPTS_HOME:bytes(6*BLOCK)+bytes(index),ACL_HOME:bytes(acl),
            ROOT_HOME:bytes(root),HOME+1:MARKER.ljust(BLOCK,bytes(1))}

def create_disk(path):
    assert crc(b'123456789')==0xe3069283 and len(UUID)==16
    with path.open('xb') as f:
        f.truncate(CAPACITY)
        for block,data in fixed_metadata().items():
            f.seek(block*BLOCK);f.write(data)
        f.seek(HOME*BLOCK);f.write(state(0))
        f.seek(BOOT_HOME*BLOCK);f.write(boot_store(0))
        # Publish both initial headers after writing the entire format.
        # Host fsync is only fixture setup, never counted as guest FLUSH.
        import os
        f.flush();os.fsync(f.fileno())
        f.seek(0);f.write(superblock()*2);f.flush();os.fsync(f.fileno())

def check_disk(path,epoch,out):
    require=verify_smp.require
    checkpoint=superblock(epoch+1,7*(epoch-1),epoch+1)
    with path.open('rb') as f:
        original=f.read(2*BLOCK)
        expected=superblock()+checkpoint if epoch==1 else checkpoint+superblock(2,0,2)
        require(original==expected,'alternating checkpoint bytes differ from reference')
        log=f.read(10*BLOCK)
        expected=transaction(2*epoch-1)+transaction(2*epoch)
        require(log==expected,'current-epoch redo differs from independent reference')
        # Entire non-journal metadata must remain byte-for-byte unchanged.
        for block,data in fixed_metadata().items():
            f.seek(block*BLOCK)
            require(f.read(len(data))==data,'fixed metadata/ACL/receipt changed at '+str(block))
        f.seek(HOME*BLOCK);home=f.read(3*BLOCK)
        require(home==state(2*(epoch-1))+MARKER.ljust(BLOCK,bytes(1))+boot_store(epoch-1),
                'checkpointed home differs from latest prior commit')
    (out/'superblocks.bin').write_bytes(original)
    (out/'redo-blocks.bin').write_bytes(log)
    (out/'home-and-marker.bin').write_bytes(home)

class EpochFixture:
    scratch_epoch_disk=True
    completion=b'V0199_EPOCH_DISK_FIXTURE_PASS production=false\n'
    def __init__(self,epoch,qemu_hash,patch_hash,role7_hash):
        self.epoch=epoch;self.qemu_hash=qemu_hash;self.role7_hash=role7_hash
        verify_smp.require(verify_smp.sha(PATCH)==patch_hash,'accounting patch mismatch')
    def verify_qemu(self,binary,version):
        verify_smp.require(version.splitlines()[0].startswith('QEMU emulator version 10.2.2')
                           and verify_smp.sha(binary)==self.qemu_hash,'pinned QEMU mismatch')
    def profile(self,elf):
        # Independently bind the actual loaded diagnostic code to the
        # immutable executable bytes of this exact verified kernel ELF.
        start=verify_smp.symbol(elf,'smp_user_start')['pa']
        end=verify_smp.symbol(elf,'smp_user_end')['pa']
        verify_smp.require(start%BLOCK==0 and 0<end-start<=BLOCK,'D02 ELF code extent')
        matches=[]
        for seg in verify_smp.inspect_elf(elf)['loads']:
            delta=start-seg['pa']
            if 0<=delta and delta+end-start<=seg['size']:
                matches.append(elf[seg['offset']+delta:seg['offset']+delta+end-start])
        verify_smp.require(len(matches)==1,'D02 code not uniquely backed by ELF')
        self.d02_code=(start,end-start,hashlib.sha256(matches[0]).digest())
        return verify_smp.profile(elf)
    @staticmethod
    def metadata():
        return dict(scope='v0199-native-formatted-v1-mount-fixture',production_g0=False,
                    durable_boot_epoch=False,production_filesystem_verified=False,g4_127_ids_passed=False)
    @staticmethod
    def success():
        return dict(native_state_redo_flush_fixture_verified=True,native_smp_mechanism_verified=False)
    def validate(self,serial,page,cpu_count):
        require=verify_smp.require
        require(cpu_count==4 and len(page)==4096,'wrong topology/evidence extent')
        w=struct.unpack('<512Q',page)
        e=self.epoch
        txid=2*e
        replay=e-1
        flushes=6+replay
        require(w[:11]==(MAGIC,7,1,e-1,e,txid-1,txid+1,txid,7*e,8,flushes),
                'wrong durable boot/service transition identity')
        require(w[11]>=4096 and w[12:14]==(11+12*replay,HOME),'missing actual full-log scan or block I/O counts')
        require(page[14*8:18*8]==hashlib.sha256(state(txid)).digest(),'native afterimage digest mismatch')
        old,new,old_root,new_root,esr,far=w[18:24]
        require((old,new)==(e,e+1) and old_root and new_root and old_root!=new_root
                and old_root%4096==new_root%4096==0,'missing native replacement generation/root')
        require(esr>>26==0x20 and esr&0x3f==7 and far==0x2f000,'not an actual guard instruction abort')
        stopped=f'V0199_EPOCH_CLIENT_STOPPED a={old} b={old_root} c={esr}\n'.encode()
        restarted=f'V0199_EPOCH_CLIENT_RELOADED a={new} b={new_root} c={e}\n'.encode()
        require(serial.count(stopped)==1 and serial.count(restarted)==1
                and serial.index(stopped)<serial.index(restarted),'native stop/reload evidence mismatch')
        old_stack,new_stack,stack_bytes,old_clock,old_snapshot,new_clock,new_snapshot,old_score,old_severity,new_score,new_severity=w[24:35]
        require(old_stack and old_stack%4096==0 and new_stack==old_stack and stack_bytes==32768,
                'wrong private role7 stack or reclaimed backing')
        require(min(old_clock,old_snapshot,new_clock,new_snapshot)>0,'role7 did not execute real ABI3 calls')
        require((old_score,old_severity,new_score,new_severity)==(342,2,342,2),
                'role7 integer operator evidence differs from independent reference')
        require(page[35*8:39*8]==self.role7_hash,'role7 verified package digest mismatch')
        for generation in (old,new):
            line=f'V0199_EPOCH_ROLE7_OPERATOR a={generation} b=342 c=2\n'.encode()
            require(serial.count(line)==1,'role7 operator UART/QMP disagreement')
        require(w[39:43]==(2*replay,2*replay,7*replay,1),'wrong merged recovery chain evidence')
        recovery=f'V0199_EPOCH_REPLAY_HOME a={2*replay} b={2*replay} c=1\n'.encode()
        require(serial.count(recovery)==1,'full redo recovery UART/QMP mismatch')
        require(page[43*8:47*8]==hashlib.sha256(boot_store(e)).digest() and w[47]==BOOT_HOME,
                'independent BootEpochStore committed image mismatch')
        require(w[48:60]==(e+1,e+1,7*replay,1-replay,replay,6,15,1,13,0,2,2),
                'complete mount structure or checkpoint evidence mismatch')
        checkpoint=f'V0199_MOUNT_CHECKPOINT a={e+1} b={e+1} c={7*replay}\n'.encode()
        require(serial.count(checkpoint)==1 and serial.count(b'V0199_MOUNT_STRUCTURE a=6 b=15 c=1\n')==1,
                'mount/checkpoint UART and QMP mismatch')
        frame_count,meta,meta_bytes,control,control_bytes,progress,progress_bytes,arena,fw,free,reserved,allocated,quarantined,permanent,page_pa,generation,scrubs,redo,boot_redo,used=w[60:80]
        require((frame_count,meta_bytes,control_bytes,progress_bytes,arena)==(262144,10*1024*1024,8*1024*1024,8*1024*1024,16384),
                'incorrect formal RAM inventory or pool sizes')
        spans=[(meta,meta_bytes),(control,control_bytes),(progress,progress_bytes),(page_pa,BLOCK)]
        for i,(base,length) in enumerate(spans):
            require(base%BLOCK==0 and 0x44000000<=base<base+length<=0x80000000,
                    'inventory span outside actual ordinary RAM')
            require(all(base+length<=p or p+n<=base for p,n in spans[:i]),'overlapping protected pool/frame spans')
        require(reserved==allocated==quarantined==0 and free+permanent==frame_count
                and permanent==arena+fw+2560+2048+2048 and generation==2 and scrubs==2,
                'RAM ledger or actual page lifecycle mismatch')
        require(control<=old_root<control+control_bytes and control<=new_root<control+control_bytes
                and control<=old_stack<old_stack+32768<=control+control_bytes,
                'native role7 backing is not in the actual control pool')
        require(redo==progress and boot_redo==progress+16384 and used==40960,
                'redo buffers are not in the actual progress pool')
        require(serial.count(f'V0199_FRAME_LEDGER a=262144 b={permanent} c={free}\n'.encode())==1,
                'frame ledger UART/memory mismatch')
        magic,baseline,bc,bmax,bcpu,applied,ac,amax,acpu,limit,chars,before,after,version,start,finished,first_cpu,written,rlen,retained,sampled,accepted=w[80:102]
        require(magic==0x4359443135465831 and w[102:104]==(0,0),'missing real D15 effect record')
        base_payload=b'V0199_D15_BASELINE actual ordinary UART frame 0123456789abcdef\n'
        applied_payload=b'V0199_D15_APPLIED actual ordinary UART frame 0123456789abcdef\n'
        require(serial.count(base_payload)==serial.count(applied_payload)==1
                and serial.index(base_payload)<serial.index(applied_payload),'actual queued UART frames lost, duplicated or reordered')
        require((baseline,applied)==(28+len(base_payload),28+len(applied_payload))
                and written==baseline+applied and 0<bmax<=8<amax<=32 and limit==32
                and 0<chars<=limit and before-after==chars and before==applied
                and version==1 and bc>=((baseline+7)//8) and ac>=((applied+31)//32)
                and bcpu>0 and acpu>=first_cpu>0 and sampled<=accepted<=start<=finished
                and retained==1 and rlen==98,'D15 actual hardware effect/cost conservation mismatch')
        require(serial.count(f'V0199_D15_EFFECT a={bmax} b={amax} c=1\n'.encode())==1,
                'D15 UART effect summary mismatch')
        snapshot=page[104*8:137*8]
        rules=page[137*8:148*8]
        plan=page[148*8:148*8+212]
        decision=page[175*8:207*8]
        report=page[207*8:207*8+rlen]
        require(page[148*8+212:175*8]==bytes(4) and page[207*8+rlen:220*8]==bytes(6),
                'nonzero D15 evidence padding')
        require(struct.unpack_from('<IHH',snapshot)==(0x4359534e,3,72)
                and struct.unpack_from('<7Q',snapshot,8)==(1,e,1,1,15,1,sampled)
                and struct.unpack_from('<HHI',snapshot,64)==(15,12,0),'wrong live D15 snapshot scope')
        fields=[]
        for i in range(12):
            fid,present,value=struct.unpack_from('<HB5xQ',snapshot,72+i*16)
            require(fid==16+i and present in (0,1) and (present or value==0),'noncanonical D15 snapshot')
            require(snapshot[72+i*16+3:72+i*16+8]==bytes(5),'snapshot reserved bytes')
            fields.append(value if present else None)
        require(fields[:8]==[None]*8 and fields[8]==applied,'D15 real queue depth or absent fields changed')
        expected_rules=bytearray(88)
        put(expected_rules,0,'IHHQIIQ',0x43595255,2,32,1,1,88,0)
        put(expected_rules,32,'IHHQHHHHII',1,15,1,15,0,1,1,0,56,0)
        put(expected_rules,64,'HB5xQ',1,3,1)
        put(expected_rules,80,'HHI',2,0,0)
        require(rules==bytes(expected_rules),'frozen diagnostic rules differ')
        h=hashlib.sha256(b'CYX/REGISTERED-CANDIDATES/v0199')
        h.update(hashlib.sha256(b'CYX/D15-FIXTURE-ORDINALS/0=1,1=8,2=32,3=64').digest())
        h.update(snapshot);h.update(bytes(1))
        for v in fields[8:12]+[1,applied,1]:
            h.update(bytes([v is not None]));h.update(struct.pack('<Q',0 if v is None else v))
        h.update(struct.pack('<H',4))
        for i,v in enumerate((1,8,32,64)):h.update(struct.pack('<HBH',i,2,v))
        candidate_hash=h.digest()
        require(plan[176:208]==candidate_hash and plan[208:212]==struct.pack('<HH',2,32)
                and struct.unpack_from('<IHHIHH6Q',plan)==(0x43594c31,2,64,212,1,0,1,0,0,1,1,sampled+10_000_000_000),
                'D15 exact plan differs from approved rule/snapshot')
        require(decision[160:192]==hashlib.sha256(rules).digest()
                and decision[192:224]==hashlib.sha256(plan).digest()
                and decision[224:256]==candidate_hash
                and struct.unpack_from('<10Q',decision,8)==(e,1,1,1,1,15,1,1,1,1)
                and struct.unpack_from('<HHH',decision,92)==(0,15,1)
                and decision[98:102]==bytes(4)
                and struct.unpack_from('<HH',decision,102)==(2,65535)
                and struct.unpack_from('<IHH',decision,152)==(4,2,0),'D15 decision is not exact RULE_ONLY fallback')
        require(struct.unpack_from('<QQQHHHHQQQQiIQ',report)==(e,1,1,0,15,1,0,15,1,1,1,0,2,finished)
                and report[80:96]==bytes(16) and report[96:]==struct.pack('<H',32),
                'D15 ApplyReport does not match actual retained effect')
        # D07 uses the next sequence in the same protected registry and
        # gate. Independently recompute the timer grid and verify the real
        # comparator values, status-confirmed wakeups and exact report.
        (magic7,freq,b_req,b_prog,b_cmp,b_wake,h_req,h_prog,h_cmp,h_wake,
         s_req,s_prog,s_cmp,s_wake,s_start,s_done,s_sample,s_accept,s_version,
         s_rlen,s_retained,slack,coalesce,serial7)=w[220:244]
        require(magic7==0x4359443037465831 and freq>0 and 1_000_000_000%freq==0,
                'missing actual D07 timer evidence')
        tick=1_000_000_000//freq
        require((slack,coalesce,s_version,s_rlen,s_retained,serial7)==(80_000,200,2,98,2,2),
                'D07 policy or effect identity mismatch')
        q=coalesce*1000
        expected_soft=min(((s_req+q-1)//q)*q,s_req+slack)
        require(b_req==b_prog==b_cmp*tick and h_req==h_prog==h_cmp*tick
                and s_prog==s_cmp*tick==expected_soft and s_req<s_prog<=s_req+slack
                and b_wake>=b_prog and h_wake>=h_prog and s_wake>=s_prog
                and b_wake<=s_sample<=s_accept<=h_wake<=s_start<=s_done<=s_wake
                and s_accept<=s_sample+100_000_000 and s_start<s_sample+10_000_000_000,
                'D07 actual comparator, slack, hard deadline or wake evidence mismatch')
        require(serial.count(f'V0199_D07_EFFECT a={s_req} b={s_prog} c={s_wake}\n'.encode())==1,
                'D07 UART and stopped-memory evidence mismatch')
        ss=page[244*8:277*8];rr=page[277*8:288*8]
        pp=page[288*8:288*8+212];dd=page[315*8:347*8]
        ar=page[347*8:347*8+s_rlen]
        require(page[288*8+212:315*8]==bytes(4) and page[347*8+s_rlen:360*8]==bytes(6),
                'nonzero D07 evidence padding')
        require(struct.unpack_from('<IHH',ss)==(0x4359534e,3,72)
                and struct.unpack_from('<7Q',ss,8)==(2,e,1,1,7,1,s_sample)
                and struct.unpack_from('<HHI',ss,64)==(7,12,0),'wrong D07 snapshot scope')
        sf=[]
        for i in range(12):
            fid,present,value=struct.unpack_from('<HB5xQ',ss,72+i*16)
            require(fid==16+i and present in (0,1) and (present or value==0)
                    and ss[72+i*16+3:72+i*16+8]==bytes(5),'noncanonical D07 snapshot')
            sf.append(value if present else None)
        require(sf==[None]*8+[1,None,80,None],'D07 actual registered timer/slack or missing sample changed')
        expected7=bytearray(88)
        put(expected7,0,'IHHQIIQ',0x43595255,2,32,2,1,88,0)
        put(expected7,32,'IHHQHHHHII',2,7,1,7,0,1,1,0,56,0)
        put(expected7,64,'HB5xQ',1,3,1)
        put(expected7,80,'HHI',2,0,0)
        require(rr==bytes(expected7),'D07 diagnostic rule bytes differ')
        dh=hashlib.sha256(b'CYX/REGISTERED-CANDIDATES/v0199')
        dh.update(hashlib.sha256(b'CYX/D07-FIXTURE-ORDINALS/0=0,1=50,2=200,3=1000').digest())
        dh.update(ss);dh.update(bytes(1))
        for v in sf[8:12]+[0,1,1]:
            dh.update(bytes([v is not None]));dh.update(struct.pack('<Q',0 if v is None else v))
        dh.update(struct.pack('<H',4))
        for i,v in enumerate((0,50,200,1000)):dh.update(struct.pack('<HBH',i,2,v))
        d7hash=dh.digest()
        require(pp[176:208]==d7hash and pp[208:212]==struct.pack('<HH',2,200)
                and struct.unpack_from('<IHHIHH6Q',pp)==(0x43594c31,2,64,212,1,0,2,1,0,1,2,s_sample+10_000_000_000)
                and struct.unpack_from('<IHHHHI8Q',pp,64)==(0x43595031,2,144,7,1,4,1,2,2,7,1,1,1,s_sample+100_000_000)
                and pp[144:176]==bytes(32),'D07 plan differs from exact current rule/snapshot')
        require(dd[160:192]==hashlib.sha256(rr).digest() and dd[192:224]==hashlib.sha256(pp).digest()
                and dd[224:256]==d7hash and struct.unpack_from('<10Q',dd,8)==(e,1,2,2,2,7,1,1,1,2)
                and struct.unpack_from('<IHHH',dd,88)==(2,0,7,1) and dd[98:102]==bytes(4)
                and struct.unpack_from('<HH',dd,102)==(2,65535)
                and struct.unpack_from('<IHH',dd,152)==(4,2,0),'D07 decision not exact RULE_ONLY')
        require(struct.unpack_from('<QQQHHHHQQQQiIQ',ar)==(e,1,2,0,7,1,0,7,1,1,2,0,2,s_done)
                and ar[80:96]==bytes(16) and ar[96:]==struct.pack('<H',200),
                'D07 ApplyReport differs from actual retained comparator effect')
        # Writable owner metadata is within the exact pre-reserved control
        # pool, following the 8 role backings, 16 three-page table sets and
        # 128KiB stable-copy scratch; no extra physical pool.
        magic_pool,owners,owner_bytes,loader_end=w[360:364]
        expected_loader_end=8*(65536+32768)+16*3*4096+131072
        require(magic_pool==0x435944504f4f4c31 and loader_end==expected_loader_end
                and owners==control+loader_end and owners%4096==0
                and 0<owner_bytes<=1024*1024 and owner_bytes%4096==0
                and owners+owner_bytes<=control+control_bytes,'invalid native effect metadata arena')
        last=0
        for i,cap in enumerate((65536,65536,65536,65536,98304)):
            off,size=w[364+i*2:366+i*2]
            require(off%8==0 and last<=off and 0<size<=cap and off+size<=owner_bytes,
                    'overlapping or out-of-pool native owner table')
            last=off+size
        task_off,task_size,proof_off,proof_size,unused=w[374:379]
        require(task_off%8==0 and last<=task_off and 0<task_size<=65536
                and task_off+task_size<=proof_off and proof_size==2048
                and proof_off+proof_size<=owner_bytes and unused==0,
                'D02 owner/proof outside reserved control pool')
        magic2,base_win,apply_win,base_count,apply_count,version2,sample2,accept2,completed2,rlen2,retained2,used2=w[379:391]
        require(magic2==0x4359443032465831 and base_win<apply_win
                and (base_count,apply_count,version2,rlen2,retained2,used2)==(2,4,3,98,3,2006)
                and sample2<=accept2<sample2+100_000_000 and accept2<=completed2,
                'D02 token windows or report custody mismatch')
        require(w[395]%BLOCK==0 and 0x40000000<=w[395]<0x44000000
                and 0<w[396]<=BLOCK and (w[395],w[396])==self.d02_code[:2],
                'invalid D02 diagnostic package extent or ELF mismatch')
        require(serial.count(b'V0199_D02_EFFECT a=2 b=4 c=3\n')==1,'missing actual D02 UART evidence')
        require(all(v==0 for v in w[397:]),'nonzero reserved evidence')
        expected=f'V0199_EPOCH_DISK_COMMITTED a={e-1} b={e} c={flushes}\n'.encode()
        require(serial.count(expected)==1 and serial.count(self.completion)==1,'UART and QMP evidence disagree')
        return dict(previous_boot_epoch=e-1,boot_epoch=e,state_generation=txid+1,txid=txid,
                    commit_lsn=7*e,actual_flush_completions=flushes,block_reads=w[11],block_writes=w[12],
                    full_log_scan_verified=True,prior_commits_replayed=2*replay,
                    distinct_home_blocks_replayed=2*replay,home_replay_flushes=1,
                    formatted_v1_structure_verified=True,system_objects_verified=4,acl_slots_verified=256,
                    checkpoint_generation=e+1,checkpoint_log_epoch=e+1,checkpoint_lsn=7*replay,
                    native_checkpoint_flush_verified=True,
                    native_d15_effect_fixture_verified=True,d15_baseline_max_chars=bmax,d15_approved_max_chars=amax,
                    d15_baseline_pump_cpu_ns=bcpu,d15_approved_pump_cpu_ns=acpu,d15_feedback_records=retained,
                    production_d15_el0_control_verified=False,
                    native_d07_effect_fixture_verified=True,d07_soft_deferral_ns=s_prog-s_req,
                    d07_hard_deferral_ns=h_prog-h_req,d07_soft_actual_wake_ns=s_wake,
                    d07_feedback_records=s_retained,production_d07_business_scheduler_verified=False,
                    d02_baseline_creations=base_count,d02_approved_creations=apply_count,
                    d02_fixture_feedback_records=retained2,native_d02_effect_fixture_verified=False,
                    production_d02_task_loader_verified=False,
                    frame_count=frame_count,frame_meta_bytes=meta_bytes,frame_meta_pa=meta,
                    control_pool_pa=control,progress_pool_pa=progress,ordinary_free_frames=free,
                    effect_owner_pool_pa=owners,effect_owner_pool_bytes=owner_bytes,
                    effect_owner_pool_bounds_verified=True,
                    permanent_frames=permanent,frame_meta_physical_dump_verified=False,
                    paired_boot_epoch_redo_verified=True,
                    previous_service_generation=old,new_service_generation=new,old_root=old_root,new_root=new_root,
                    native_diagnostic_restart_verified=True,role7_abi3_package_verified=True,
                    role7_package_sha256=self.role7_hash.hex(),private_stack_bytes=stack_bytes,
                    role7_operator_results=[old_score,new_score],production_service_restart_verified=False)

    def capture_extra(self,qmp,out,page):
        # This hook runs after validate(), with all four CPUs stopped.
        # Read the actual full FrameMeta table, not just guest counters.
        w=struct.unpack('<512Q',page)
        _,meta,meta_bytes,control,control_bytes,progress,progress_bytes,arena,fw,free,_,_,_,permanent,page_pa,generation,*_=w[60:80]
        path=out/'frame-meta.bin'
        qmp.execute('pmemsave',{'val':meta,'size':meta_bytes,'filename':str(path)})
        raw=path.read_bytes()
        require=verify_smp.require
        require(len(raw)==262144*40,'incomplete FrameMeta physical dump')
        fixed=[(0x40000000,arena*BLOCK),(meta,meta_bytes),(control,control_bytes),(progress,progress_bytes)]
        counts=[0,0];extra=0
        for i,row in enumerate(struct.iter_unpack('<IIQQIIII',raw)):
            pa=0x40000000+i*BLOCK
            owner,flags,owner_generation,frame_generation,refs,pins,dma,shares=row
            require(owner==0xffffffff and owner_generation==refs==pins==dma==shares==0,
                    'unexpected live owner/reference in stopped inventory')
            named=any(base<=pa<base+n for base,n in fixed)
            if named:
                require(flags==4 and frame_generation==0,'named fixed region is not permanently reserved')
            elif pa==page_pa:
                require(flags==0 and frame_generation==generation,'reclaimed frame generation/clean state missing')
            elif flags==4:
                require(frame_generation==0,'unexpected retired frame')
                extra+=1
            else:
                require(flags==8 and frame_generation==0,'unexpected ordinary frame state')
            counts[int(flags==4)]+=1
        require(counts==[free,permanent] and extra==fw,'physical per-frame conservation differs from guest evidence')
        sample=out/'reclaimed-frame.bin'
        qmp.execute('pmemsave',{'val':page_pa,'size':BLOCK,'filename':str(sample)})
        require(sample.read_bytes()==bytes(BLOCK),'secret page was not actually zero after reclaim')
        # Read the actual stopped-guest owner arena. Independently match
        # BOTH exact decision and ApplyReport byte strings inside its
        # designated feedback table. No Rust struct ABI is inferred.
        owners,owner_bytes=w[361:363]
        off,size=w[372:374]
        owner_path=out/'effect-owners.bin'
        qmp.execute('pmemsave',{'val':owners,'size':owner_bytes,'filename':str(owner_path)})
        owner_raw=owner_path.read_bytes()
        require(len(owner_raw)==owner_bytes,'incomplete effect owner physical dump')
        custody=owner_raw[off:off+size]
        for d,r in ((page[175*8:207*8],page[207*8:207*8+w[98]]),
                    (page[315*8:347*8],page[347*8:347*8+w[239]])):
            require(len(d)==256 and len(r)==98 and custody.count(d)==1 and custody.count(r)==1,
                    'actual feedback table missing or duplicating exact retained effect bytes')
        # D02 actual business-core context proof: six completed creations,
        # ABI3 EXIT and private EL0 writes, original policy versions, exact
        # raw snapshot/decision/report, and actual post-retirement pages.
        proof_off,proof_size=w[376:378]
        proof=owner_raw[proof_off:proof_off+proof_size]
        require(hashlib.sha256(proof).digest()==page[391*8:395*8]
                and proof[w[390]:]==bytes(proof_size-w[390]),'D02 proof digest/padding mismatch')
        rows=list(struct.iter_unpack('<16Q',proof[:768]))
        require(len(rows)==6,'missing native D02 creation rows')
        previous=0
        pages=rows[0][3:8]
        require(len(set(pages))==5 and all(p%BLOCK==0 and 0x40000000<=p<0x44000000 for p in pages)
                and w[395] not in pages,'invalid private diagnostic pages')
        for i,row in enumerate(rows,1):
            serial,task,cpu,*_=row
            marker,count,kind,esr,syscall,began,done,cost=row[8:16]
            window=w[380] if i<=2 else w[381]
            require((serial,task,cpu)==(i,0xd0203,1) and row[3:8]==pages
                    and (marker,count,kind,esr,syscall)==(0xd0200000+i,16,8,0x56000000,1)
                    and previous<=began<=done and began//100_000_000==done//100_000_000==window
                    and cost>0,'D02 actual CPU1 task/trap/completion evidence mismatch')
            previous=done
        require(rows[1][14]<=w[385]<=w[386]<=rows[2][13]
                and rows[2][14]==w[387] and rows[-1][14]<w[385]+10_000_000_000,
                'D02 actual execution not within original policy window')
        snap=proof[768:1032];rules=proof[1032:1120];plan=proof[1120:1332]
        decision=proof[1332:1588];report=proof[1588:1686];package=proof[1686:1718]
        # Independent reconstruction of the exact CPU1 constructor ticket.
        # Its acknowledgement must bind actual boot, request/package/group,
        # original admission time/version and request digest, not just a
        # sequential slot number echoed by CPU0.
        for i,row in enumerate(rows,1):
            at=1718+(i-1)*48
            started,policy=struct.unpack_from('<2Q',proof,at)
            require(policy==(0 if i<=2 else 3)
                    and (0 if i==1 else rows[i-2][14])<=started<=row[13]
                    and started//100_000_000==row[13]//100_000_000,
                    'D02 asynchronous ticket timing or original policy mismatch')
            rd=hashlib.sha256(b'CYX/D02-NATIVE-FIXTURE/v0199'
                +struct.pack('<2Q',self.epoch,i)+package).digest()
            ticket=struct.pack('<12Q',self.epoch,1,0xd0201,1,i,0xd0202,1,2,1,i,started,policy)+rd
            require(hashlib.sha256(b'CYX/D02-STARTED/v0199'+ticket).digest()==proof[at+16:at+48],
                    'D02 business worker exact ticket acknowledgement mismatch')
        require(struct.unpack_from('<IHH',snap)==(0x4359534e,3,72)
                and struct.unpack_from('<7Q',snap,8)==(3,self.epoch,1,1,2,1,w[385])
                and struct.unpack_from('<HHI',snap,64)==(2,12,0),'D02 exact observation scope mismatch')
        fields=[]
        for i in range(12):
            at=72+i*16
            fid,present,value=struct.unpack_from('<HB5xQ',snap,at)
            require(fid==16+i and present in (0,1) and (present or value==0)
                    and snap[at+3:at+8]==bytes(5),'D02 snapshot field format')
            fields.append(value if present else None)
        require(fields==[None]*8+[None,3,None,5],'D02 actual thread/queued observation mismatch')
        expected=bytearray(88)
        put(expected,0,'IHHQIIQ',0x43595255,2,32,3,1,88,0)
        put(expected,32,'IHHQHHHHII',3,2,1,2,0,1,1,0,56,0)
        put(expected,64,'HB5xQ',4,3,1)
        put(expected,80,'HHI',2,0,0)
        require(rules==bytes(expected),'D02 diagnostic rules mismatch')
        h=hashlib.sha256(b'CYX/REGISTERED-CANDIDATES/v0199')
        h.update(hashlib.sha256(b'CYX/D02-FIXTURE-ORDINALS/0=1,1=2,2=4,3=8').digest())
        h.update(snap);h.update(bytes(1))
        for v in fields[8:12]+[1,5,1]:
            h.update(bytes([v is not None]));h.update(struct.pack('<Q',0 if v is None else v))
        h.update(struct.pack('<H',4))
        for i,v in enumerate((1,2,4,8)):h.update(struct.pack('<HBH',i,2,v))
        digest=h.digest()
        sample=w[385]
        require(struct.unpack_from('<IHHIHH6Q',plan)==(0x43594c31,2,64,212,1,0,3,2,0,1,3,sample+10_000_000_000)
                and struct.unpack_from('<IHHHHI8Q',plan,64)==(0x43595031,2,144,2,1,4,1,3,3,2,1,1,1,sample+100_000_000)
                and plan[144:176]==bytes(32) and plan[176:208]==digest
                and plan[208:]==struct.pack('<HH',2,4),'D02 published plan differs from exact rule/snapshot')
        require(struct.unpack_from('<10Q',decision,8)==(self.epoch,1,3,3,3,2,1,1,1,3)
                and struct.unpack_from('<IHHH',decision,88)==(3,0,2,1)
                and decision[98:102]==bytes(4) and struct.unpack_from('<HH',decision,102)==(2,65535)
                and struct.unpack_from('<IHH',decision,152)==(4,2,0)
                and decision[160:192]==hashlib.sha256(rules).digest()
                and decision[192:224]==hashlib.sha256(plan).digest() and decision[224:256]==digest,
                'D02 decision/causal policy mismatch')
        require(struct.unpack_from('<QQQHHHHQQQQiIQ',report)==(self.epoch,1,3,0,2,1,0,2,1,1,3,0,2,rows[2][14])
                and report[80:96]==bytes(16) and report[96:]==struct.pack('<H',4)
                and custody.count(decision)==custody.count(report)==1,'D02 actual report/feedback mismatch')
        code_path=out/'d02-package.bin'
        qmp.execute('pmemsave',{'val':w[395],'size':w[396],'filename':str(code_path)})
        require(hashlib.sha256(code_path.read_bytes()).digest()==package==self.d02_code[2],
                'D02 actual package differs from exact ELF bytes')
        for i,pa in enumerate(pages):
            path=out/f'd02-retired-page-{i}.bin'
            qmp.execute('pmemsave',{'val':pa,'size':BLOCK,'filename':str(path)})
            require(path.read_bytes()==bytes(BLOCK),'D02 retired mapping/data/stack was not scrubbed')
        return dict(frame_meta_physical_dump_verified=True,frame_meta_sha256=hashlib.sha256(raw).hexdigest(),
                    reclaimed_page_zero_verified=True,effect_owner_pool_dump_verified=True,
                    effect_owner_pool_sha256=hashlib.sha256(owner_raw).hexdigest(),
                    native_d02_effect_fixture_verified=True,d02_retired_pages_verified=True,
                    d02_actual_cpu1_creations=6,d02_async_ticket_acknowledgements_verified=6,
                    d02_diagnostic_package_sha256=package.hex())

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--role7',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--qemu-sha256',required=True)
    p.add_argument('--patch-sha256',required=True)
    a=p.parse_args()
    out=a.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    disk=out/'scratch.raw'
    result=dict(status='FAIL',scope='formatted v1 mount/recovery fixture; no production authority',boots=[])
    try:
        create_disk(disk)
        previous=verify_smp.sha(disk)
        for epoch in (1,2):
            capture=out/f'boot-{epoch}'
            summary=verify_smp.run(a.elf,capture,45,4,acceptance=EpochFixture(epoch,a.qemu_sha256,a.patch_sha256,hashlib.sha256(a.role7.read_bytes()).digest()),
                                   ram_mib=1024,scratch_disk=disk)
            result['boots'].append(summary)
            verify_smp.require(summary['status']=='PASS' and summary.get('forced_process_stop'),
                               'native append or forced process stop failed')
            verify_smp.require(summary.get('scratch_disk_before_sha256')==previous,'disk changed between processes')
            check_disk(disk,epoch,capture)
            previous=verify_smp.sha(disk)
            verify_smp.require(summary.get('scratch_disk_after_sha256')==previous,'disk changed after capture')
        verify_smp.require(len(result['boots'])==2 and all(
            b.get('observations',{}).get('native_d02_effect_fixture_verified') is True
            for b in result['boots']),'missing D02 actual physical proof')
        result['cross_process_boot_epoch_fixture_verified']=True
        result['cross_process_service_generation_fixture_verified']=True
        result['cross_process_merged_home_replay_fixture_verified']=True
        result['cross_process_paired_boot_epoch_fixture_verified']=True
        result['cross_process_formatted_mount_checkpoint_verified']=True
        result['native_d15_actual_effect_fixture_verified']=True
        result['native_d07_actual_effect_fixture_verified']=True
        result['native_d02_actual_effect_fixture_verified']=True
        result['status']='PASS'
    except (OSError,ValueError,RuntimeError) as e:
        result['status']='FAIL'
        result['error']=str(e)
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':
    raise SystemExit(main())
