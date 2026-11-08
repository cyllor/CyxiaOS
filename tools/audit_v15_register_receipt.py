#!/usr/bin/env python3
"""Reseal mutations of a caller-selected live receipt; every mutation must fail."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import struct
import tempfile
from check_prototype_evidence import read_json,sha256,require
from verify_v13_boot_receipt import _exchanges
from verify_v15_registers import verify_native


def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def mutate_qmp(root,duplicate):
    p=root/'qmp-transcript.json';rows=read_json(p)
    greeting=next(r for r in rows if 'QMP' in r['message'])
    pairs=_exchanges(rows);changed=[]
    for request,response in pairs:
        if request['execute']=='query-cpus-fast':
            if duplicate:changed.extend([(request,response),(copy.deepcopy(request),copy.deepcopy(response))])
        else:changed.append((request,response))
    rows=[greeting]
    for index,(request,response) in enumerate(changed,1):
        request=copy.deepcopy(request);request['id']=index
        rows.extend([dict(direction='send',message=request),
                     dict(direction='receive',message={'id':index,'return':response})])
    write(p,rows)


def change_word(root,index,both=True):
    for name in (('first.bin','last.bin') if both else ('last.bin',)):
        p=root/name;b=bytearray(p.read_bytes());x=struct.unpack_from('<Q',b,index*8)[0]
        struct.pack_into('<Q',b,index*8,x^1);p.write_bytes(b)


def mutate_dtb(root):
    p=root/'platform.dtb';data=p.read_bytes();before=struct.pack('>2Q',0x40000000,1024**3)
    require(data.count(before)==1,'fixture RAM property not unique')
    p.write_bytes(data.replace(before,struct.pack('>2Q',0x40000000,512*1024**2)))


def audit(receipt,build,source,qemu):
    trusted=dict(build=build,source_root=source,qemu_source=qemu)
    baseline=verify_native(receipt,**trusted);require(baseline['register_subcase_status']=='PASS','not an actual native receipt')
    cases=[('delete-cpu-query',lambda r:mutate_qmp(r,False)),
           ('duplicate-cpu-query',lambda r:mutate_qmp(r,True)),
           ('wrong-dtb-memory',mutate_dtb),
           ('x19',lambda r:change_word(r,64+32+8+19)),
           ('simd-high',lambda r:change_word(r,64+32+8+39)),
           ('fpsr',lambda r:change_word(r,64+32+8+103)),
           ('fresh-zero',lambda r:change_word(r,64+6)),
           ('different-second-bank',lambda r:change_word(r,64+32+8+19,False))]
    results=[]
    for name,mutate in cases:
        with tempfile.TemporaryDirectory(prefix='cyx-register-audit-') as tmp:
            root=Path(tmp)/'receipt';shutil.copytree(receipt,root);mutate(root)
            inv=read_json(root/'inventory.json')
            inv['files']={n:dict(bytes=(root/n).stat().st_size,sha256=sha256(root/n)) for n in inv['files']}
            write(root/'inventory.json',inv)
            try:verify_native(root,**trusted)
            except ValueError as error:results.append(dict(mutation=name,status='REJECTED',reason=str(error)))
            else:raise ValueError('tampered receipt accepted: '+name)
    return dict(scope='mutations of actual live capture; not another native execution',
                baseline=baseline,mutations=results)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('receipt','build','source-root','qemu-source','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();result=audit(a.receipt,a.build,a.source_root,a.qemu_source)
    write(a.output,result);print(json.dumps(result,indent=2))
