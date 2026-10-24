#!/usr/bin/env python3
"""Verify real EL0 model inference/handoff under frozen synthetic telemetry.

Uses the existing bounded QMP/serial runner. PASS certifies this isolated native
profile, never the production desktop, full 16-domain model, or real-world gains.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import verify_smp as runner
from check_elf import inspect_elf, symbol

ROOT=Path(__file__).resolve().parents[1]
MODES={'none':0,'hang':1,'bad-mask':2,'snapshot-write':3,'model-write':4}
SCOPE='AI_SCOPE inference=EL0 telemetry=synthetic production_isolation=false physical_isolation=false'
require=runner.require

def loaded_symbol(elf,name):
    sym=symbol(elf,name)
    for seg in inspect_elf(elf)['loads']:
        offset=sym['pa']-seg['pa']
        if 0<=offset and offset+sym['size']<=seg['size']:
            return elf[seg['offset']+offset:seg['offset']+offset+sym['size']]
    raise ValueError('symbol lacks file bytes: '+name)

def expected_logits(pressure,latency,benefit,business):
    raw=(ROOT/'ports/control-service/core-head.bin').read_bytes()
    require(len(raw)==52 and raw[:8]==b'CYXMDL01','unknown model artifact')
    weights=struct.unpack('<22h',raw[8:]); x=[32767,pressure,latency,benefit,business]
    # Rust integer division truncates toward zero, not Python's negative floor.
    def score(w):
        s=sum(a*b for a,b in zip(w,x)); q=abs(s)//4096 * (-1 if s<0 else 1)
        return max(-32768,min(32767,q)) & 65535
    return [score(weights[i*5:i*5+5]) for i in range(3)]

class Acceptance:
    completion=b'AI_CONTROL_PASS cpus=4\n'
    def __init__(self,mode='none'):
        require(mode in MODES,'unknown fault profile')
        self.mode=MODES[mode];self.image_hash=None
    def profile(self,elf):
        marker=loaded_symbol(elf,'CYXIA_AI_PROFILE')
        require(len(marker)==64 and struct.unpack('<8Q',marker)==(1,self.mode,44,24,1,0,0,0),'wrong control profile')
        service=loaded_symbol(elf,'CONTROL_SERVICE_ELF')
        raw=(ROOT/'ports/control-service/core-head.bin').read_bytes()
        require(raw in service,'model bytes absent from embedded EL0 image')
        self.image_hash=hashlib.sha256(service).hexdigest()
        page=symbol(elf,'CONTROL_EVIDENCE')
        require(page['pa']%4096==0 and page['size']==4096,'invalid live control evidence page')
        return page
    def metadata(self):
        return {'scope':'native-el0-model-service' if self.mode==0 else 'native-controller-fault-containment',
            'fault_mode':self.mode,'model_driven':False,'native_el0_model_verified':False,
            'fault_containment_verified':False,'telemetry_source':'frozen-synthetic-test-windows',
            'production_isolation_verified':False,'full_16_domain_model_verified':False,
            'performance_benefit_verified':False,'embedded_service_sha256':self.image_hash,
            'model_sha256':runner.sha(ROOT/'ports/control-service/core-head.bin'),
            'schema_sha256':runner.sha(ROOT/'ports/control-service/schema.txt')}
    def success(self):
        return {'model_driven':self.mode==0,'native_el0_model_verified':self.mode==0,'fault_containment_verified':True}
    def validate(self,serial,page,cpu_count):
        require(cpu_count==4 and len(page)==4096,'expected four CPUs and a complete live page')
        w=struct.unpack('<512Q',page)
        require(w[:6]==(0x4359584149303031,1,1,self.mode,15,14),'uncommitted control evidence')
        require(w[24:32]==(0,)*8 and not any(w[224:]),'nonzero reserved evidence')
        require(w[16:20]==struct.unpack('<4Q',bytes.fromhex(runner.sha(ROOT/'ports/control-service/core-head.bin'))),'model hash mismatch')
        require(w[20:24]==struct.unpack('<4Q',bytes.fromhex(runner.sha(ROOT/'ports/control-service/schema.txt'))),'schema hash mismatch')
        require(b'FAIL' not in serial and b'SMP_ERROR' not in serial,'guest failure')
        lines=serial.decode('ascii').splitlines()
        require(lines.count('AI_CONTROL_PASS cpus=4')==1 and lines.count(SCOPE)==1,'wrong result/scope')
        def rows(label):
            result=[]
            for line in lines:
                if line.startswith(label+' '):
                    m=re.fullmatch(re.escape(label)+r' a=(\d+) b=(\d+) c=(\d+)',line)
                    require(m is not None,'malformed '+label);result.append(tuple(map(int,m.groups())))
            return result
        require(rows('SMP_CPU_ON')==[(1,1,0),(2,2,0),(3,3,0)] and rows('SMP_BOOT_OK')==[(4,15,0)],'missing actual boot handshakes')
        cpus=[w[32+i*16:48+i*16] for i in range(4)]
        require(cpus[0]==(0,)*16,'CPU0 ran user inference')
        require(rows('AI_CPU_EVIDENCE')==[(i,cpus[i][0],cpus[i][6]) for i in range(4)],'serial/physical evidence disagree')
        for c in cpus:require(c[10:]==(0,)*6,'nonzero CPU reserved fields')
        require(cpus[1][4]==0 and cpus[3][5]==0,'plane dispatch violation')
        require(cpus[3][4]>=8 and cpus[3][6]>=cpus[3][4],'no real business preemption')
        survived=rows('AI_BUSINESS_SURVIVED')
        require(len(survived)==1 and survived[0][1]==w[10] and w[10]>=8,'business stalled with control service')
        if self.mode==0:
            require(w[6:10]==(2,2,1,1) and w[11:16]==(7,2,13,0,6),'missing handoff/restart/replay checks')
            require(rows('SMP_SCALE_MODEL')==[(6,9,3),(2,13,5)],'wrong published core sets')
            require(rows('AI_CONTROLLER_RECOVERED')==[(2,8,7)],'old epoch was resumed')
            require(rows('AI_HELPER_DENIED_PUBLICATION')==[(2,3,0)],'helper became a second publisher')
            require(cpus[1][0]==7 and cpus[2][0]==1 and cpus[3][0]==0,'inference did not run only on dedicated CPUs')
            require(cpus[1][1]>=8 and cpus[1][2]>0 and cpus[2][2]>0,'missing real inference timing')
            require([cpus[i][7] for i in (1,2,3)]==[5,10,5],'missing permission probes')
            require(cpus[1][3]==0 and survived[0][2]==2,'controller was not recovered after real SVC failure')
            require(cpus[1][8]>>26==0x15 and cpus[1][8]&0xffff==0x431,'no actual EL0 result syscall')
            expected=[]
            for i in range(6):
                r=w[96+i*16:112+i*16]
                high=i<2; before=2 if i<2 else 6; after=6 if 1<=i<5 else 2
                desired=6 if high else 2
                require(r[:9]==(i+1,1,1 if i<2 else 3,before,desired,after,1 if high else 2,30000 if high else 1000,30000 if high else 1000),'wrong sampled decision identity')
                require(list(r[9:12])==expected_logits(r[7],r[8],28000 if high else 1000,2000),'EL0 output differs from independent integer model')
                require(r[12]==int(i in (1,5)) and r[13]==i+1 and r[15]>r[14],'hysteresis/action evidence mismatch')
                if i: require(r[14]==w[96+(i-1)*16+15], 'measurement windows overlap or skip')
                expected.append((i+1,desired,after))
            require(rows('AI_DECISION')==expected and not any(w[192:224]),'missing/extra decision records')
        else:
            require(w[6]==0 and w[8]==0 and w[9]==0 and w[11:16]==(2,0,13,2,0),'faulted service granted a migration')
            require(not any(w[96:224]) and rows('AI_DECISION')==[],'faulted service produced accepted decisions')
            reason={1:1,2:0,3:3,4:3}[self.mode]
            require(cpus[1][3]==reason and survived[0][2]==reason,'wrong injected fault result')
            require(cpus[1][0]==int(self.mode==2),'unexpected fault response count')
            if self.mode==1:require(cpus[1][6]>=1,'wedged service was not preempted')
            if self.mode==2:require(w[7]==1,'illegal mask not rejected')
            if self.mode in (3,4):
                require(cpus[1][8]>>26==0x24 and cpus[1][8]&0x7f==0x4f,'not a real read-only write permission fault')
                require(cpus[1][9]==0xa0000 if self.mode==3 else 0x80000<=cpus[1][9]<0xa0000,'wrong protected address')
        return {'control_sets':[2,6,2] if self.mode==0 else [2],
                'model_inferences':sum(c[0] for c in cpus),'controller_recoveries':w[9],
                'business_progress_during_failure':w[10],'fault_mode':self.mode,
                'timer_preemptions':sum(c[6] for c in cpus),'permission_fault_probes':sum(c[7] for c in cpus)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--fault',choices=MODES,default='none');p.add_argument('--timeout',type=float,default=30)
    args=p.parse_args()
    try:r=runner.run(args.elf,args.output,args.timeout,acceptance=Acceptance(args.fault))
    except (OSError,ValueError) as e:print(str(e));return 1
    print(json.dumps(r,indent=2));return 0 if r['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
