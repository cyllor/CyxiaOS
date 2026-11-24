#!/usr/bin/env python3
"""Independent QMP/UART evidence for eight distinct native ABI3 bootstrap packages.

Scope is intentionally NOT production G0, durable boot, control-policy APPLY,
or G4/G5. No test label is accepted as a resource execution receipt.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import verify_smp

ROLES=(6,7,2,8,9,3,10,11)
MAGIC=0x43595838424f4f54
PATCH=Path(__file__).resolve().parent/'qemu/cyxia-per-vcpu-pmu.patch'
class Bringup:
    completion=b'V0199_EIGHT_PACKAGE_BOOTSTRAP_PASS cpus=4 roles=8 production=false\n'
    def __init__(self, packages:Path, qemu_sha256:str, patch_sha256:str):
        self.expected={role:hashlib.sha256((packages/f'v0199-role-{role}.elf').read_bytes()).digest()
                       for role in ROLES}
        verify_smp.require(len(set(self.expected.values()))==8,'role packages are not distinct')
        self.qemu_sha256=qemu_sha256
        verify_smp.require(hashlib.sha256(PATCH.read_bytes()).hexdigest()==patch_sha256,
                           'wrong PMU accounting patch')
    def verify_qemu(self,binary:Path,version:str):
        verify_smp.require(version.splitlines()[0].startswith('QEMU emulator version 10.2.2'),
                           'wrong pinned QEMU version')
        verify_smp.require(hashlib.sha256(binary.read_bytes()).hexdigest()==self.qemu_sha256,
                           'wrong accounting-enabled QEMU binary')
    @staticmethod
    def profile(elf:bytes):
        return verify_smp.profile(elf)
    @staticmethod
    def metadata():
        return dict(scope='v0199-eight-distinct-native-bootstrap-packages',
                    production_g0=False,durable_boot_epoch=False,
                    real_services_tested=False,real_apply_receipts=False,
                    production_role_restart_verified=False,
                    g4_127_ids_passed=False,g5_arch_passed=False)
    @staticmethod
    def success():
        return dict(native_eight_package_bootstrap_verified=True,production_g0=False)
    def validate(self,serial:bytes,page:bytes,cpu_count:int):
        require=verify_smp.require
        require(cpu_count==4 and len(page)==4096,'wrong guest topology/evidence extent')
        words=struct.unpack('<512Q',page)
        require(words[:10]==(MAGIC,2,1,15,1,14,8,0,0,0),'wrong scope/unfinished bootstrap')
        require(serial.count(self.completion)==1 and b'SMP_ERROR' not in serial
                and b'BOOTSTRAP_OVERRUN' not in serial and b'FAIL' not in serial,'guest fault')
        def rows(tag):
            pat=re.compile(re.escape(tag)+r' a=(\d+) b=(\d+) c=(\d+)')
            matches=[]
            for line in serial.decode('ascii').splitlines():
                if line.startswith(tag+' '):
                    match=pat.fullmatch(line)
                    require(match is not None,'malformed '+tag)
                    matches.append(tuple(map(int,match.groups())))
            return matches
        boot=rows('V0199_BOOTSTRAP_ROLE');charges=rows('V0199_BOOTSTRAP_CHARGE')
        require(len(boot)==8 and len(charges)==8,'eight independent packages did not all run')
        roots=set();spans=[];selectors=set();details=[]
        for index,role in enumerate(ROLES):
            at=128+index*20
            rid,root,image,stack,entry,selector,clocks,calls,yields,actual,turns,result,guard,preemptions=words[at:at+14]
            digest=page[(at+14)*8:(at+18)*8]
            require(rid==role and digest==self.expected[role],'loaded package identity mismatch')
            require(root and root%4096==0 and root not in roots and image and image%4096==0
                    and stack==image+65536 and 0x10000<=entry<0x20000 and entry%4==0
                    and guard==0,'invalid private root, image, stack or guard')
            roots.add(root);spans.append((image,stack+32768))
            require(clocks>=2 and calls>=2 and turns>=1 and actual>0,'missing real ABI3 or CPU charge')
            restricted=role in (6,7,2,11)
            require((selector!=0)==restricted,'unexpected cap issued before durable readiness')
            if selector:
                require(selector not in selectors,'aliased capability selector')
                selectors.add(selector)
            require(result==((1<<64)-13 if restricted else 0),'unready service fabricated a successful result')
            require(boot[index]==(role,root,clocks) and charges[index]==(role,actual,turns),
                    'UART and stopped guest evidence disagree')
            details.append(dict(role=role,package_sha256=digest.hex(),ttbr0=root,
                                stack_bytes=32768,clocks=clocks,role_calls=calls,
                                actual_cpu_ns=actual,turns=turns,timer_preemptions=preemptions))
        for i,(a,b) in enumerate(spans):
            require(all(not(a<=r<b) for r in roots),'page-table root overlaps role backing')
            require(all(b<=x or y<=a for x,y in spans[:i]),'shared private role backing')
        reloads=rows('V0199_PACKAGE_RELOAD')
        require(len(reloads)==8,'missing actual fault and reload evidence')
        old_roots=set()
        for i,role in enumerate(ROLES):
            at=304+i*12
            rid,old,new,old_root,new_root,old_cap,new_cap,esr,far,cost,scrubbed,ready=words[at:at+12]
            require((rid,old,new,scrubbed,ready)==(role,1,2,98304,1),
                    'wrong local restart identity or full backing scrub')
            require(old_root and old_root%4096==0 and old_root not in old_roots
                    and old_root not in roots and new_root==details[i]['ttbr0'],
                    'old root not retired or replacement root aliased')
            old_roots.add(old_root)
            require(esr>>26==0x20 and esr&0x3f==7 and far==0x2f000,
                    'not a real EL0 guard instruction abort')
            require(0<cost<=8_000_000,'recovery was not debited in its own reservation')
            require((old_cap==new_cap==0) or (old_cap and new_cap and old_cap!=new_cap),
                    'old issued capability was reused')
            require(reloads[i]==(role,old_root,new_root),'reload UART/QMP mismatch')
        business=rows('V0199_BOOTSTRAP_BUSINESS')
        require(len(business)==3,'missing independent business progress')
        for slot in range(1,4):
            affinity,progress,control,irqs=words[16+slot*4:20+slot*4]
            require(affinity==slot and progress>=2 and control==0 and irqs>0,
                    'business CPU did not remain business-only')
            # The reported progress was sampled immediately before gate close.
            reported=business[slot-1]
            require(reported[0]==slot and 2<=reported[1]<=progress and reported[2]==0,
                    'business progress evidence mismatch')
        return dict(guest_cpus=4,fixed_control_cpu=0,business_cpu_mask=14,
                    distinct_native_packages=8,private_stack_bytes=32768,
                    native_diagnostic_package_reloads=8,durable_role_restarts=False,
                    roles=details,production_g0=False,real_services_tested=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--packages',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--qemu-sha256',required=True)
    p.add_argument('--patch-sha256',required=True)
    a=p.parse_args()
    result=verify_smp.run(a.elf,a.output,45,4,acceptance=Bringup(a.packages,a.qemu_sha256,a.patch_sha256))
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':
    raise SystemExit(main())
