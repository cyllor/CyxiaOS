#!/usr/bin/env python3
"""Resealed mutations of a real A09 receipt must fail semantic verification."""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
from check_prototype_evidence import read_json,sha256,require
from verify_v13_boot_receipt import _exchanges
from memory_v15_custody import verify_native


def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def word(root,name,index,delta=1):
    p=root/name;b=bytearray(p.read_bytes());value=struct.unpack_from('<Q',b,index*8)[0]
    struct.pack_into('<Q',b,index*8,value^delta);p.write_bytes(b)


def query(root,duplicate):
    p=root/'qmp-transcript.json';rows=read_json(p)
    greeting=next(r for r in rows if 'QMP' in r['message']);pairs=[]
    for request,response in _exchanges(rows):
        if request['execute']=='query-cpus-fast':
            if duplicate:pairs.extend([(request,response),(copy.deepcopy(request),copy.deepcopy(response))])
        else:pairs.append((request,response))
    rows=[greeting]
    for index,(request,response) in enumerate(pairs,1):
        request=copy.deepcopy(request);request['id']=index
        rows.extend([dict(direction='send',message=request),dict(direction='receive',message=dict(id=index,**{'return':response}))])
    write(p,rows)


def wrong_dtb(root):
    p=root/'platform.dtb';b=p.read_bytes();old=struct.pack('>2Q',0x40000000,1024**3)
    require(b.count(old)==1,'DTB memory fixture is not unique')
    p.write_bytes(b.replace(old,struct.pack('>2Q',0x40000000,512*1024**2)))


def wrong_poll_cadence(root):
    p=root/'input.json';inputs=read_json(p);inputs['poll_interval_ns']=10_000_000;write(p,inputs)


def audit(receipt,build,source_root,qemu_source):
    trusted=dict(build=build,source_root=source_root,qemu_source=qemu_source)
    baseline=verify_native(receipt,**trusted)
    require(baseline['native_acceptance_status']=='PASS' and baseline['test_id']=='A09','not a complete actual A09 native receipt')
    cases=[('zero-page-content',lambda r:word(r,'1-1-page0.bin',0)),
        ('retained-full-page-tail',lambda r:word(r,'3-2-page3.bin',511)),
        ('readonly-page-content',lambda r:word(r,'3-1-page4.bin',3)),
        ('anonymous-executable',lambda r:word(r,'3-1-leaf.bin',0x60,1<<54)),
        ('actual-owner-frame',lambda r:word(r,'3-memory.bin',64+128+28,4096)),
        ('run-identity',lambda r:word(r,'3-memory.bin',8)),
        ('incomplete-4097-pages',lambda r:word(r,'3-memory.bin',64+128+6)),
        ('incomplete-physical-progress',lambda r:word(r,'3-1-page6.bin',6)),
        ('no-cache-eviction',lambda r:(r/'3-memory.bin').write_bytes(
            (r/'3-memory.bin').read_bytes()[:24*8]+(r/'2-memory.bin').read_bytes()[24*8:25*8]+(r/'3-memory.bin').read_bytes()[25*8:])),
        ('executed-code',lambda r:word(r,'3-1-code0.bin',0)),
        ('delete-platform-query',lambda r:query(r,False)),
        ('duplicate-platform-query',lambda r:query(r,True)),
        ('wrong-dtb-memory',wrong_dtb),('wrong-frozen-poll-cadence',wrong_poll_cadence)]
    results=[]
    for name,mutate in cases:
        with tempfile.TemporaryDirectory(prefix='cyx-a09-audit-') as temp:
            root=Path(temp)/'receipt'
            # The large disk is read-only in all checks/cases. Mutated evidence
            # files are separate copies, so the original live capture is intact.
            def clone(a,b):
                if Path(a).name=='disk.raw':os.link(a,b)
                else:shutil.copy2(a,b)
            shutil.copytree(receipt,root,copy_function=clone);mutate(root)
            inventory=read_json(root/'inventory.json')
            inventory['files']={n:dict(bytes=(root/n).stat().st_size,sha256=sha256(root/n)) for n in inventory['files']}
            write(root/'inventory.json',inventory)
            try:verify_native(root,**trusted)
            except ValueError as error:results.append(dict(mutation=name,status='REJECTED',reason=str(error)))
            else:raise ValueError('tampered actual A09 receipt accepted: '+name)
    return dict(scope='semantic mutations of actual live A09 capture; not additional native executions',baseline=baseline,mutations=results)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('receipt','build','source-root','qemu-source','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();result=audit(a.receipt,a.build,a.source_root,a.qemu_source)
    write(a.output,result);print(json.dumps(result,indent=2))
