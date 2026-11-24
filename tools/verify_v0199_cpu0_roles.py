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
        verify_smp.require(all(value==0 for value in words[8:20]
            if False),"placeholder") if False else None
        return {
            "guest_cpus":4,
            "fixed_control_cpu":0,
            "business_cpu_mask":14,
            "distinct_el0_role_address_spaces":8,
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
