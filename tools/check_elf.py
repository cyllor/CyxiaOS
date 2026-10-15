"""Strict ELF64 load validation for the pinned 256 MiB virt configuration."""
import json
from pathlib import Path
import struct
import sys
LIMIT=2**64

def inspect_elf(b):
    def need(ok,msg):
        if not ok: raise ValueError(msg)
    need(len(b)>=64,'truncated header')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',b)
    ident,kind,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phnum,shsize,shnum,shstr=h
    need(ident[:7]==b'\x7fELF\x02\x01\x01' and kind==2 and machine==183 and version==1,'not AArch64 executable')
    need(ehsize==64 and phsize==56 and 0<phnum<=32 and phoff>=64 and phoff+phnum*56<=len(b),'invalid program headers')
    loads=[]
    for i in range(phnum):
        typ,fl,off,va,pa,fs,ms,al=struct.unpack_from('<IIQQQQQQ',b,phoff+i*56)
        if typ!=1 or ms==0:continue
        need(fs<=ms and off+fs<=len(b) and pa+ms<LIMIT and va+ms<LIMIT,'segment overflow')
        need(0x40200000<=pa<pa+ms<=0x41000000,'load outside reserved kernel pool / DTB collision')
        need(not (fl&2 and fl&1),'writable executable segment')
        need(al in (0,1) or (al&(al-1)==0 and va%al==off%al),'invalid segment alignment')
        for s in loads:
            need(not (pa<s['pa']+s['mem'] and s['pa']<pa+ms),'physical overlap')
            need(not (va<s['va']+s['mem'] and s['va']<va+ms),'virtual overlap')
        loads.append(dict(pa=pa,va=va,mem=ms,size=fs,offset=off,flags=fl))
    need(any(s['flags']&1 and s['va']<=entry<s['va']+s['size'] for s in loads),'entry not executable')
    need(entry==0x40200000,'incorrect bare-metal entry')
    return dict(entry=entry,loads=loads)

def symbol(b,name):
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',b);off=h[6];size=h[11];count=h[12]
    if size!=64 or count>1024 or off+count*size>len(b):raise ValueError('bad sections')
    sections=[struct.unpack_from('<IIQQQQIIQQ',b,off+i*size) for i in range(count)]
    for s in sections:
        if s[1]!=2:continue
        strings=sections[s[6]];table=b[strings[4]:strings[4]+strings[5]]
        for p in range(s[4],s[4]+s[5],24):
            n,info,other,idx,value,length=struct.unpack_from('<IBBHQQ',b,p)
            if table[n:].split(b'\0',1)[0].decode('utf8')==name:
                for seg in inspect_elf(b)['loads']:
                    if seg['va']<=value and value+length<=seg['va']+seg['mem']:
                        return dict(va=value,pa=value-seg['va']+seg['pa'],size=length)
    raise ValueError('missing symbol '+name)
if __name__=='__main__':
    print(json.dumps(inspect_elf(Path(sys.argv[1]).read_bytes()),indent=2))
