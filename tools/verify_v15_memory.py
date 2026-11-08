#!/usr/bin/env python3
"""A09 actual anonymous-page/cache-pressure contract; raw bytes alone are NOT_RUN."""
import struct
from check_prototype_evidence import require

MAGIC=0x4359584130394d45
WORDS=448
PAGES=4097
PRIVATE_VAS=(0x60000,0x61000,0x62000,0x63000,0x72000,0x80000,0x30000)
MASK=(1<<64)-1
PA_MASK=0x0000fffffffff000


def pattern(nonce,role,page,index):
    x=nonce[1]
    seed=nonce[0]^((x<<17)|(x>>47))&MASK
    return (seed ^ (role*0x9e3779b185ebca87) ^ (page*0xc2b2ae3d27d4eb4f) ^ (index*0x165667b19e3779f9))&MASK


def leaf_value(pa,writable,executable):
    return pa|3|(1<<6)|(1<<10)|(1<<11)|(3<<8)|(1<<53)|(0 if writable else 1<<7)|(0 if executable else 1<<54)


def verify_raw(banks,captures,config):
    require(len(banks)==3 and all(len(b)==WORDS*8 for b in banks) and len(config)==512,'missing actual zero/sentinel/pressure stages')
    identity=struct.unpack('<64Q',config)[4:18]
    require(any(identity[:2]),'missing run-specific memory identity')
    decoded=[struct.unpack('<%dQ'%WORDS,b) for b in banks]
    previous=None;private_roots=None;private_frames=None
    code_frames=None
    for stage,w in enumerate(decoded,1):
        require(w[:8]==(MAGIC,1,w[2],w[3],stage,2,0,0) and w[2]>0 and w[2]%2==0 and w[3]>0
                and w[8:22]==identity and not any(w[29:64]),'unsealed/mixed/wrong memory profile')
        require(w[22]%4096==0 and 0x40200000<=w[22]<w[22]+w[23]*4096<=0x44000000
                and w[23]==4096 and w[27]>0 and w[28]>0,'invalid actual file-cache backing')
        if previous:
            require(w[3]==previous[3] and w[22:24]==previous[22:24]
                    and all(w[n]>=previous[n] for n in (2,24,25,26,28)),'memory/cache facts regressed')
        roots=[];frames=[];keys=[];all_frames=[];tables=[]
        for role in (1,2):
            b=64+(role-1)*192;r=w[b:b+192]
            require(r[0]>0 and r[1]>0 and r[2:8]==(role,r[3],1,4,0,0)
                    and r[3]%4096==0 and 0x40200000<=r[3]<0x44000000 and not any(r[8:32]+r[176:]),
                    'invalid actual task/owner/root identity')
            roots.append(r[3]);keys.append(r[:2])
            if previous:
                require(r[:32]==previous[b:b+32] and r[32:32+(stage-1)*48]==previous[b+32:b+32+(stage-1)*48],
                        'previous task/anonymous snapshot was rewritten')
            require(not any(r[32+stage*48:176]),'future memory stage fabricated')
            s=r[32+(stage-1)*48:80+(stage-1)*48]
            require(s[0]>0 and s[0]%2==0 and s[1]>0 and s[2:5]==(stage,0,2560)
                    and 5<=s[14]<=s[15]==32 and not any(s[23:24]+s[35:]),'incomplete actual client/owner observation')
            require(s[6]==(PAGES if stage==3 and role==1 else 0),'pressure client did not verify all unique file pages')
            require(s[5]==(0 if stage==1 else 1),'missing actual client sentinel verification')
            get=lambda name:captures.get(f'{stage}-{role}-{name}')
            root,mid,leaf=(get(n+'.bin') for n in ('root','mid','leaf'))
            require(all(type(x) is bytes and len(x)==4096 for x in (root,mid,leaf)),'missing actual private page tables')
            root,mid,leaf=(struct.unpack('<512Q',x) for x in (root,mid,leaf))
            require(root[0]&3==mid[0]&3==3 and not any(root[1:]+mid[1:])
                    and 0x40200000<=root[0]&PA_MASK<0x44000000 and 0x40200000<=mid[0]&PA_MASK<0x44000000,
                    'invalid private table walk')
            require(root[0]==(root[0]&PA_MASK)|3 and mid[0]==(mid[0]&PA_MASK)|3,'unknown private table descriptor flags')
            # The collector derives and records these two addresses from the
            # previously stopped physical table, never a producer pointer list.
            require(captures.get(f'{stage}-{role}-table-addresses')==[r[3],root[0]&PA_MASK,mid[0]&PA_MASK],
                    'memory/table capture address differs from actual root walk')
            tables.extend([r[3],root[0]&PA_MASK,mid[0]&PA_MASK])
            require(tuple(leaf[va//4096] for va in PRIVATE_VAS)==s[16:23] and leaf[16:20]==s[24:28],
                    'bank PTE differs from independently captured table')
            current_code=tuple(p&PA_MASK for p in leaf[16:20])
            require(all(p&3==3 for p in leaf[16:20]) and current_code==tuple(current_code[0]+p*4096 for p in range(4)),
                    'missing or fragmented immutable client code')
            if code_frames is None:code_frames=current_code
            else:require(current_code==code_frames,'client executable identity changed across owners/stages')
            require(tuple(leaf[va//4096]&PA_MASK for va in PRIVATE_VAS)==s[28:35],
                    'actual memory-owner resident frames differ from PTE backing')
            allowed={0x20000,0x21000,0x30000,0x71000,0x72000}|set(range(0x80000,0x90000,4096))
            allowed|=set(range(0x39000,0x41000,4096))|set(range(0x60000,0x64000,4096))
            owner_frames=[]
            for index,pte in enumerate(leaf):
                if pte==0:continue
                va=index*4096;pa=pte&PA_MASK
                require(0x40200000<=pa<0x44000000,'user page outside reviewed kernel pool')
                require(not w[22]<=pa<w[22]+w[23]*4096,'user mapping aliases mutable file cache')
                if 0x10000<=va<0x14000:
                    require(pte==leaf_value(pa,False,True),'client code is not immutable RX')
                else:
                    require(va in allowed and pte==leaf_value(pa,va not in (0x20000,0x21000,0x72000),False),
                            'anonymous/input/stack page permissions invalid')
                    require(not w[22]<=pa<w[22]+w[23]*4096 and pa not in owner_frames,
                            'anonymous page aliases cache or another private VA')
                    owner_frames.append(pa)
            all_frames.append(set(owner_frames))
            for page,va in enumerate(PRIVATE_VAS):
                data=get(f'page{page}.bin')
                require(type(data) is bytes and len(data)==4096,'missing full anonymous page')
                pa=leaf[va//4096]&PA_MASK;require(pa!=0,'missing anonymous mapping')
                if page<4:
                    expected=bytes(4096) if stage==1 else struct.pack('<512Q',*(pattern(identity[:2],role,page,k) for k in range(512)))
                    require(data==expected,'anonymous zero/sentinel content was lost or leaked')
                if page==4:require(not any(data),'read-only fresh anonymous page is not zero')
                if page==6:
                    p=struct.unpack_from('<16Q',data)
                    require(p[:6]==(0x435958413039434c,role,stage,0,2560,0 if stage==1 else 1),
                            'actual stopped ordinary client stage differs from protected observation')
                    require((p[6]==PAGES if stage==3 and role==1 else p[6]==0 if role==2 or stage==1 else p[6]<=PAGES),
                            'actual stopped client did not complete the fixed 4097-page workload')
            frames.append(tuple(leaf[va//4096]&PA_MASK for va in PRIVATE_VAS))
        require(roots[0]!=roots[1] and keys[0]!=keys[1] and set(frames[0]).isdisjoint(frames[1]),'cross-owner anonymous/root alias')
        require(len(set(tables))==6 and all_frames[0].isdisjoint(all_frames[1])
                and all(set(tables).isdisjoint(f) for f in all_frames),'private tables or other task memory share writable backing')
        require(set(tables).isdisjoint(code_frames) and all(f.isdisjoint(code_frames) for f in all_frames),
                'private writable/table backing aliases immutable client code')
        require(all(not w[22]<=pa<w[22]+w[23]*4096 for pa in tables),
                'actual private page-table backing aliases mutable file cache')
        if private_roots is None:private_roots,private_frames=roots,frames
        else:require(roots==private_roots and frames==private_frames,'anonymous ownership/backing changed under cache pressure')
        previous=w
    a,b=decoded[1:]
    require(b[24]>a[24] and b[25]>a[25] and b[26]-a[26]>=PAGES*4096,'no actual cache eviction/read pressure')
    return dict(status='STRUCTURE_VALID',native_acceptance_status='NOT_RUN',test_id='A09',
                native_execution_verified=False,full_a09_verified=False,actual_cache_pressure_verified=False,
                scope='three-stage physical page contract only',
                tasks=2,anonymous_sentinel_pages=8,verified_unique_file_pages=PAGES,
                actual_cache_evictions=b[24]-a[24])


if __name__=='__main__':
    import argparse,json
    from pathlib import Path
    from memory_v15_custody import verify_native
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    for n in ('build','source-root','qemu-source'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(verify_native(a.directory,build=a.build,source_root=a.source_root,qemu_source=a.qemu_source),indent=2))
