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
            ROOT_HOME:bytes(root),HOME+1:MARKER.ljust(BLOCK,b'\\0')}

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
        require(home==state(2*(epoch-1))+MARKER.ljust(BLOCK,b'\\0')+boot_store(epoch-1),
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
    @staticmethod
    def profile(elf):
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
        require(w[:11]==(MAGIC,6,1,e-1,e,txid-1,txid+1,txid,7*e,8,flushes),
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
        require(all(v==0 for v in w[60:]),'nonzero reserved evidence')
        expected=f'V0199_EPOCH_DISK_COMMITTED a={e-1} b={e} c={flushes}\n'.encode()
        require(serial.count(expected)==1 and serial.count(self.completion)==1,'UART and QMP evidence disagree')
        return dict(previous_boot_epoch=e-1,boot_epoch=e,state_generation=txid+1,txid=txid,
                    commit_lsn=7*e,actual_flush_completions=flushes,block_reads=w[11],block_writes=w[12],
                    full_log_scan_verified=True,prior_commits_replayed=2*replay,
                    distinct_home_blocks_replayed=2*replay,home_replay_flushes=1,
                    formatted_v1_structure_verified=True,system_objects_verified=4,acl_slots_verified=256,
                    checkpoint_generation=e+1,checkpoint_log_epoch=e+1,checkpoint_lsn=7*replay,
                    native_checkpoint_flush_verified=True,
                    paired_boot_epoch_redo_verified=True,
                    previous_service_generation=old,new_service_generation=new,old_root=old_root,new_root=new_root,
                    native_diagnostic_restart_verified=True,role7_abi3_package_verified=True,
                    role7_package_sha256=self.role7_hash.hex(),private_stack_bytes=stack_bytes,
                    role7_operator_results=[old_score,new_score],production_service_restart_verified=False)

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
        result['status']='PASS'
        result['cross_process_boot_epoch_fixture_verified']=True
        result['cross_process_service_generation_fixture_verified']=True
        result['cross_process_merged_home_replay_fixture_verified']=True
        result['cross_process_paired_boot_epoch_fixture_verified']=True
        result['cross_process_formatted_mount_checkpoint_verified']=True
    except (OSError,ValueError,RuntimeError) as e:
        result['error']=str(e)
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':
    raise SystemExit(main())
