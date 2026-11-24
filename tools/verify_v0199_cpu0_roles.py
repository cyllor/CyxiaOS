#!/usr/bin/env python3
"""Independent pinned-QEMU check of V0.19.9 CPU0 eight-EL0-role *mechanism*.

This never certifies that eight real application roles, AI controllers,
SVC ABI3, or 127 G4 stable IDs have reached production acceptance.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct

import verify_smp


ROLE_IDS=(6,7,2,8,9,3,10,11)
MAGIC=0x4359_5856_3139_3939
COMPLETION=b"V0199_CPU0_EL0_ROLE_FIXTURE_PASS cpus=4 roles=8\n"


class NativeRoles:
    completion=COMPLETION

    def profile(self,elf:bytes)->dict:
        return verify_smp.profile(elf)

    @staticmethod
    def metadata()->dict:
        return {
            "scope":"native-v0199-cpu0-eight-role-mechanism-fixture",
            "full_native_role_services":False,
            "real_abi3_syscall_dispatch":False,
            "g4_127_ids_passed":False,
            "g5_arch_passed":False,
            "host_physical_isolation_verified":False,
        }

    @staticmethod
    def success()->dict:
        return {
            "native_cpu0_eight_isolated_ttbr_fixture_verified":True,
            "full_native_role_services":False,
            "g4_127_ids_passed":False,
            "g5_arch_passed":False,
        }

    @staticmethod
    def validate(serial:bytes,page:bytes,cpu_count:int)->dict:
        verify_smp.require(cpu_count==4,"QMP did not prove four real guest CPUs")
        verify_smp.require(len(page)==4096,"short native-owned evidence page")
        words=struct.unpack("<512Q",page)
        verify_smp.require(words[:8]==(
            MAGIC,1,1,15,1,14,8,0
        ),"no final fixed CPU0/three business completion evidence")
        verify_smp.require(b"SMP_ERROR" not in serial and b"FAIL" not in serial,
                           "guest reported fault")
        lines=serial.decode("ascii").splitlines()
        verify_smp.require(lines.count(
            "V0199_CPU0_EL0_ROLE_FIXTURE_PASS cpus=4 roles=8"
        )==1,"missing/duplicate complete native role marker")
        verify_smp.require(lines.count(
            "V0199_CPU0_EL0_ROLE_FIXTURE_SCOPE identical_fixture_code=true real_services=false"
        )==1,"mechanism fixture overclaims real services")
        def rows(name:str):
            pattern=re.compile(re.escape(name)+r" a=(\d+) b=(\d+) c=(\d+)")
            matched=[]
            for line in lines:
                if line.startswith(name+" "):
                    found=pattern.fullmatch(line)
                    verify_smp.require(found is not None,"malformed "+name)
                    matched.append(tuple(map(int,found.groups())))
            return matched
        verify_smp.require(rows("SMP_BOOT_OK")==[(4,15,0)],"invalid four-core boot marker")
        verify_smp.require(rows("SMP_CPU_ON")==[
            (1,1,0),(2,2,0),(3,3,0)
        ],"secondary CPU_ON proof missing")
        serial_roles=rows("V0199_CPU0_EL0_ROLE")
        verify_smp.require(len(serial_roles)==8,"not all eight native EL0 roles returned")
        roots=set()
        private=set()
        for index,expected in enumerate(ROLE_IDS):
            line=serial_roles[index]
            row=words[128+index*8:128+(index+1)*8]
            role_id,actor,root,private_page,endpoint,kind,esr,count=row
            verify_smp.require(line==(expected,root,count),
                               "role UART and independent memory evidence disagree")
            verify_smp.require(role_id==expected and actor==expected,
                               "invalid native role identity")
            verify_smp.require(root and root%4096==0 and root not in roots,
                               "role TTBR0 was reused or unaligned")
            verify_smp.require(private_page and private_page%4096==0
                               and private_page not in private,
                               "cross-role private data is shared")
            verify_smp.require(endpoint==0xC000+index
                               and kind==8
                               and esr>>26==0x15
                               and esr&0xffff==4
                               and count>0,
                               "role did not complete genuine bounded EL0 svc turn")
            roots.add(root)
            private.add(private_page)
        # Verify genuine EL0 trap syndromes and saved register-derived result;
        # this is not a full syscall dispatch or user-memory access test.
        svc_rows=rows("V0199_SVC_PREFLIGHT")
        verify_smp.require(len(svc_rows)==7,"missing actual SVC64 preflight cases")
        for case in range(7):
            idx,abi,esr,x8,accepted=words[224+case*5:229+case*5]
            expected_esr=0x56000004 if case==3 else 0x56000000
            expected_x8=0x51 if case==2 else (0x50 if case in (5,6) else 4)
            verify_smp.require((idx,abi,esr,x8,accepted)==(
                case,1 if case==4 else 3,expected_esr,expected_x8,int(case==0)),
                "wrong SVC64 exception or register preflight evidence")
            verify_smp.require(svc_rows[case]==(case,esr,accepted),
                               "SVC64 serial and guest memory disagree")
        copy_rows=rows("V0199_SVC_COPY")
        verify_smp.require(len(copy_rows)==4,"missing real user-leaf copy cases")
        for index in range(4):
            case,esr,accepted,ipa,opa,value=words[272+index*6:278+index*6]
            verify_smp.require((case,esr,accepted)==(7+index,0x56000000,int(index==0)),
                               "copy fixture accepted an unmapped or read-only range")
            if index==0:
                verify_smp.require(ipa==words[131]+64 and opa%4096==64
                                   and opa//4096!=ipa//4096 and value==0x1234
                                   and opa-64 not in roots and opa-64 not in private,
                                   "copy evidence does not identify private physical input/output")
            else:
                verify_smp.require((ipa,opa,value)==(0,0,0),"rejected copy wrote data")
            verify_smp.require(copy_rows[index]==(case,accepted,value),
                               "copy serial and memory evidence disagree")
        # Per-role real EL0 fault probes, not synthetic ESR tuples.
        fault_rows=rows("V0199_ROLE_FAULT")
        restart_rows=rows("V0199_ROLE_RESTART")
        verify_smp.require(len(fault_rows)==40 and len(restart_rows)==8,
                           "missing per-role fault/restart mechanism evidence")
        for index,role in enumerate(ROLE_IDS):
            for case,(ec,fsc,address) in enumerate([
                (0x24,0x0f,None),(0x24,0x07,0x40000),
                (0x24,0x4f,0x10000),(0x20,0x0f,0x20000),
                (0x24,0x47,0x2f000)]):
                at=304+index*15+case*3
                kind,esr,far=words[at:at+3]
                verify_smp.require(kind==8 and esr>>26==ec and esr&0x7f==fsc
                                   and (far>=1<<63 if address is None else far==address),
                                   "wrong native fault syndrome or address")
                verify_smp.require(fault_rows[index*5+case]==(role,case,esr),
                                   "role fault UART and guest memory differ")
            at=424+index*9
            rid,old,new,cleared,kind,esr,count,root,ready=words[at:at+9]
            verify_smp.require((rid,old,new,cleared,kind,count,ready)==(role,1,2,8192,8,16,1)
                               and esr==0x56000004 and root==words[128+index*8+2],
                               "static fixture did not scrub and reenter exact role")
            verify_smp.require(restart_rows[index]==(role,new,count),
                               "role restart UART and guest memory differ")
        serial_business=rows("V0199_CPU0_BUSINESS")
        verify_smp.require(len(serial_business)==3,"missing business progress")
        business_progress=0
        for slot in range(1,4):
            affinity,progress,control_turns,irqs=words[16+slot*4:20+slot*4]
            verify_smp.require(affinity==slot and progress>=2
                               and control_turns==0 and irqs>0,
                               "CPU1-3 did not keep business-only native progress")
            verify_smp.require(serial_business[slot-1]==(slot,progress,control_turns),
                               "business serial/guest memory mismatch")
            business_progress+=progress
        return {
            "guest_cpus":4,
            "fixed_control_cpu":0,
            "business_cpu_mask":14,
            "distinct_el0_role_address_spaces":8,
            "physical_svc64_register_preflight_cases":7,
            "physical_user_leaf_copy_cases":4,
            "physical_role_permission_fault_cases":40,
            "same_root_fixture_restarts":8,
            "production_role_restart_verified":False,
            "role_ids":list(ROLE_IDS),
            "business_progress_turns":business_progress,
            "real_services_tested":False,
            "evidence_kind":"guest-EL0-mechanism-fixture-only",
        }


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--timeout",type=float,default=45)
    args=parser.parse_args()
    try:
        result=verify_smp.run(
            args.elf,args.output,args.timeout,4,acceptance=NativeRoles()
        )
    except (OSError,ValueError,RuntimeError) as error:
        print(str(error),file=__import__("sys").stderr)
        return 1
    print(json.dumps(result,indent=2))
    return 0 if result["status"]=="PASS" else 1


if __name__=="__main__":
    raise SystemExit(main())
