#!/usr/bin/env python3
"""Two fresh native QEMU processes, one dedicated scratch image.

This is not a formatted production filesystem. The fixture only exercises
canonical state redo, two real VirtIO FLUSH completions and boot-epoch
recovery. Never accepts an existing disk path. No production G0/G4 claim.
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
UUID=b'CYX-TEST-EPOCH!!'
MARKER=b'CYXIA_V0199_EPOCH_SCRATCH_ONLY'
HOME=7000
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

def superblock():
    b=bytearray(BLOCK)
    put(b,0,'IHHII',0x43594653,1,80,4096,131072)
    b[16:32]=UUID
    put(b,32,'QQQIIIIII',1,0,1,4098,4102,4118,256,0,0)
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

def seal(b,kind,length,txid,lsn):
    put(b,0,'IHHIIQQQ',0x43594c47,1,kind,length,crc(b[64:length]),txid,lsn,1)
    put(b,56,'I',crc(b[:64]))
    return bytes(b)

def transaction(epoch):
    image=state(epoch)
    begin_lsn=epoch*3-2
    b=bytearray(BLOCK);put(b,64,'IIQ',1,0,BLOCK)
    r=bytearray(2*BLOCK);put(r,40,'QII',HOME,0,1);r[64:64+BLOCK]=image
    c=bytearray(BLOCK);put(c,64,'QQQII',epoch,begin_lsn,begin_lsn+1,1,0)
    c[96:128]=hashlib.sha256(struct.pack('<Q',HOME)+image).digest()
    return seal(b,1,80,epoch,begin_lsn)+seal(r,2,4160,epoch,begin_lsn+1)+seal(c,3,128,epoch,begin_lsn+2)

def create_disk(path):
    assert crc(b'123456789')==0xe3069283 and len(UUID)==16
    with path.open('xb') as f:
        f.truncate(CAPACITY)
        f.seek(0);f.write(superblock()*2)
        f.seek(HOME*BLOCK);f.write(state(0));f.write(MARKER.ljust(BLOCK,b'\0'))
        f.flush()

def check_disk(path,epoch,out):
    require=verify_smp.require
    with path.open('rb') as f:
        original=f.read(2*BLOCK)
        require(original==superblock()*2,'superblocks unexpectedly modified')
        log=f.read(16*BLOCK)
        expected=b''.join(transaction(i) for i in range(1,2*epoch+1)).ljust(16*BLOCK,b'\0')
        require(log==expected,'actual on-disk redo differs from independent reference')
        f.seek(HOME*BLOCK);home=f.read(2*BLOCK)
        require(home==state(0)+MARKER.ljust(BLOCK,b'\0'),'home/fixture marker changed')
    (out/'superblocks.bin').write_bytes(original)
    (out/'redo-blocks.bin').write_bytes(log)
    (out/'home-and-marker.bin').write_bytes(home)

class EpochFixture:
    scratch_epoch_disk=True
    completion=b'V0199_EPOCH_DISK_FIXTURE_PASS production=false\n'
    def __init__(self,epoch,qemu_hash,patch_hash):
        self.epoch=epoch;self.qemu_hash=qemu_hash
        verify_smp.require(verify_smp.sha(PATCH)==patch_hash,'accounting patch mismatch')
    def verify_qemu(self,binary,version):
        verify_smp.require(version.splitlines()[0].startswith('QEMU emulator version 10.2.2')
                           and verify_smp.sha(binary)==self.qemu_hash,'pinned QEMU mismatch')
    @staticmethod
    def profile(elf):
        return verify_smp.profile(elf)
    @staticmethod
    def metadata():
        return dict(scope='v0199-native-scratch-epoch-redo',production_g0=False,
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
        require(w[:11]==(MAGIC,2,1,e-1,e,txid-1,txid+1,txid,txid*3,2+4*(txid-1),4),
                'wrong durable boot/service transition identity')
        require(w[11]>=32 and w[12:14]==(8,HOME),'missing actual block I/O counts')
        require(page[14*8:18*8]==hashlib.sha256(state(txid)).digest(),'native afterimage digest mismatch')
        old,new,old_root,new_root,esr,far=w[18:24]
        require((old,new)==(e,e+1) and old_root and new_root and old_root!=new_root
                and old_root%4096==new_root%4096==0,'missing native replacement generation/root')
        require(esr>>26==0x20 and esr&0x3f==7 and far==0x2f000,'not an actual guard instruction abort')
        stopped=f'V0199_EPOCH_CLIENT_STOPPED a={old} b={old_root} c={esr}\n'.encode()
        restarted=f'V0199_EPOCH_CLIENT_RELOADED a={new} b={new_root} c={e}\n'.encode()
        require(serial.count(stopped)==1 and serial.count(restarted)==1
                and serial.index(stopped)<serial.index(restarted),'native stop/reload evidence mismatch')
        require(all(v==0 for v in w[24:]),'nonzero reserved evidence')
        expected=f'V0199_EPOCH_DISK_COMMITTED a={e-1} b={e} c=4\n'.encode()
        require(serial.count(expected)==1 and serial.count(self.completion)==1,'UART and QMP evidence disagree')
        return dict(previous_boot_epoch=e-1,boot_epoch=e,state_generation=txid+1,txid=txid,
                    commit_lsn=txid*3,actual_flush_completions=4,block_reads=w[11],block_writes=w[12],
                    previous_service_generation=old,new_service_generation=new,old_root=old_root,new_root=new_root,
                    native_diagnostic_restart_verified=True,production_service_restart_verified=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--qemu-sha256',required=True)
    p.add_argument('--patch-sha256',required=True)
    a=p.parse_args()
    out=a.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    disk=out/'scratch.raw'
    result=dict(status='FAIL',scope='scratch epoch redo; not a production filesystem',boots=[])
    try:
        create_disk(disk)
        previous=verify_smp.sha(disk)
        for epoch in (1,2):
            capture=out/f'boot-{epoch}'
            summary=verify_smp.run(a.elf,capture,45,4,acceptance=EpochFixture(epoch,a.qemu_sha256,a.patch_sha256),
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
    except (OSError,ValueError,RuntimeError) as e:
        result['error']=str(e)
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':
    raise SystemExit(main())
