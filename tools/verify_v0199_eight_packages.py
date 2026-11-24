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
def relative_count(elf:bytes,sidecar:bytes)->int:
    require=verify_smp.require
    require(len(elf)>=64 and elf[:6]==b'\x7fELF\x02\x01','invalid role ELF')
    shoff=struct.unpack_from('<Q',elf,40)[0]
    entsize,count=struct.unpack_from('<HH',elf,58)
    require(entsize==64 and 0<count and shoff+entsize*count<=len(elf),'invalid role section table')
    relas=[]
    for i in range(count):
        _,kind,flags,addr,off,size,link,info,align,entry=struct.unpack_from('<IIQQQQIIQQ',elf,shoff+i*64)
        require(kind not in (9,19) or size==0,'unexpected REL/RELR')
        if kind==4 and size:
            require(not relas and entry==24 and size%24==0 and flags&2 and off+size<=len(elf),
                    'invalid allocated RELA table')
            relas=list(struct.iter_unpack('<QQq',elf[off:off+size]))
    require(len(relas)<=512 and len({r[0] for r in relas})==len(relas)
            and all(o%8==0 and info==1027 for o,info,a in relas),'invalid relative relocation inventory')
    canonical=b'CyxiaOS-v0199-relative-sidecar'+struct.pack('<I',len(relas))+b''.join(
        struct.pack('<QQq',*r) for r in relas)
    require(sidecar==canonical,'ELF and authenticated sidecar disagree')
    return len(relas)

class Bringup:
    completion=b'V0199_EIGHT_PACKAGE_BOOTSTRAP_PASS cpus=4 roles=8 production=false\n'
    def __init__(self, packages:Path, qemu_sha256:str, patch_sha256:str):
        self.expected={role:hashlib.sha256((packages/f'v0199-role-{role}.elf').read_bytes()).digest()
                       for role in ROLES}
        verify_smp.require(len(set(self.expected.values()))==8,'role packages are not distinct')
        self.relocations={role:relative_count(
            (packages/f'v0199-role-{role}.elf').read_bytes(),
            (packages/f'v0199-role-{role}.relative.bin').read_bytes()) for role in ROLES}
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
        require(words[:10]==(MAGIC,7,1,15,1,14,8,0,0,0),'wrong scope/unfinished bootstrap')
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
            asid=words[at+18]
            require(asid==0x98+index and words[at+19]==self.relocations[role],'incorrect ASID or relocation count')
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
                                stack_bytes=32768,asid=asid,relative_relocations=self.relocations[role],clocks=clocks,role_calls=calls,
                                actual_cpu_ns=actual,turns=turns,timer_preemptions=preemptions))
        for i,(a,b) in enumerate(spans):
            require(all(not(a<=r<b) for r in roots),'page-table root overlaps role backing')
            require(all(b<=x or y<=a for x,y in spans[:i]),'shared private role backing')
        reloads=rows('V0199_PACKAGE_RELOAD')
        require(len(reloads)==8,'missing actual fault and reload evidence')
        survivors=rows('V0199_RESTART_SURVIVORS')
        starts=rows('V0199_RESTART_BEGIN')
        faults=rows('V0199_RESTART_GUARD_FAULT')
        require(rows('V0199_BOOTSTRAP_INITIAL_ROLES')==[(8,0,0)],'missing initial eight-role milestone')
        require(len(survivors)==len(starts)==len(faults)==8,'missing isolated-survivor progress evidence')
        old_roots=set()
        recovery_cpu_ns=0
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
            recovery_cpu_ns+=cost
            require((old_cap==new_cap==0) or (old_cap and new_cap and old_cap!=new_cap),
                    'old issued capability was reused')
            require(reloads[i]==(role,old_root,new_root),'reload UART/QMP mismatch')
            require(starts[i]==(role,old,old_root) and faults[i]==(role,esr,far),
                    'restart start/fault UART and memory mismatch')
            mask,*deltas=words[400+i*9:409+i*9]
            require(mask==(255^(1<<i)) and deltas[i]==0
                    and all(delta>0 for j,delta in enumerate(deltas) if j!=i),
                    'a surviving EL0 role did not progress with faulted peer stopped')
            require(survivors[i]==(role,mask,sum(deltas)),
                    'survivor SVC UART and memory mismatch')
            phase=[f'V0199_RESTART_BEGIN a={role} b={old} c={old_root}',
                   f'V0199_RESTART_GUARD_FAULT a={role} b={esr} c={far}',
                   f'V0199_RESTART_SURVIVORS a={role} b={mask} c={sum(deltas)}',
                   f'V0199_PACKAGE_RELOAD a={role} b={old_root} c={new_root}']
            positions=[serial.index((line+'\n').encode('ascii')) for line in phase]
            require(positions==sorted(set(positions)),'restart phases out of order')
        live_mask=words[472]
        live_deltas=words[473:481]
        require(live_mask==255 and all(delta>0 for delta in live_deltas),
                'all eight replacement contexts did not progress in one live round')
        require(rows('V0199_BOOTSTRAP_ALL_LIVE')==[(8,live_mask,sum(live_deltas))],
                'all-live UART and memory mismatch')
        last_reload=f'V0199_PACKAGE_RELOAD a={ROLES[-1]} b={reloads[-1][1]} c={reloads[-1][2]}\n'.encode('ascii')
        require(serial.index(last_reload)<serial.index(b'V0199_BOOTSTRAP_ALL_LIVE '),
                'all-live round preceded final reload')
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
        elapsed,accounted,upper,crossings,start_ns,end_ns,*classes=words[481:493]
        require(0<elapsed==accounted==sum(classes) and all(cost>0 for cost in classes),
                'unclassified or duplicated CPU0 PMU time')
        require(classes[4]==recovery_cpu_ns,'recovery ledger disagrees with actual reloads')
        require(0<upper<=70_000_000 and start_ns<end_ns,
                'invalid aligned-window upper bound or sampled interval')
        require(rows('V0199_BOOTSTRAP_ACCOUNTING')==[(elapsed,accounted,upper)],
                'CPU0 accounting UART and stopped memory disagree')
        # Independent integer reference for the two test-only seed inputs:
        # operations scores 48 and 272 (selected 1), security score 342
        # (severity 2). Both original and replacement EL0 must produce them.
        probes=[]
        expected=[(6,48|(272<<16),1),(7,342,2)]
        for i,(role,packed,selected) in enumerate(expected):
            for generation in (1,2):
                at=493+i*8+(generation-1)*4
                require(words[at:at+4]==(0x43594d4c50524f42,generation,packed,selected),
                        'native EL0 integer model fixture output mismatch')
                probes.append((role,generation,packed))
        require(rows('V0199_MODEL_PROBE')==probes,'model fixture UART/QMP mismatch')
        require(all(v==0 for v in words[509:]),'nonzero reserved evidence')
        return dict(guest_cpus=4,fixed_control_cpu=0,business_cpu_mask=14,
                    distinct_native_packages=8,private_stack_bytes=32768,
                    native_diagnostic_package_reloads=8,native_survivor_role_progress_pairs=56,
                    post_restart_live_roles=8,
                    native_brain_operator_probes=4,trained_model_inference_verified=False,
                    sampled_cpu0_ns=elapsed,accounted_cpu0_ns=accounted,
                    control_window_upper_bound_ns=upper,coordination_gap_crossings=crossings,
                    class_cpu_ns=classes,accounting_interval_ns=[start_ns,end_ns],
                    exact_per_window_split=False,complete_production_accounting=False,
                    durable_role_restarts=False,
                    roles=details,production_g0=False,real_services_tested=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--packages',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--ram-mib',type=int,choices=(256,1024),default=256)
    p.add_argument('--qemu-sha256',required=True)
    p.add_argument('--patch-sha256',required=True)
    a=p.parse_args()
    result=verify_smp.run(a.elf,a.output,45,4,acceptance=Bringup(a.packages,a.qemu_sha256,a.patch_sha256),ram_mib=a.ram_mib)
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':
    raise SystemExit(main())
