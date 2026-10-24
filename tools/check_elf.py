"""Strict ELF64 load validation and versioned CyxiaOS boot profile."""
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
        if typ!=1:continue
        need(fs<=ms and off+fs<=len(b) and pa+ms<LIMIT and va+ms<LIMIT,'segment overflow')
        if ms==0:continue
        need(0x40200000<=pa<pa+ms<=0x44000000,'load outside reserved kernel pool / DTB collision')
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
    loads=inspect_elf(b)['loads']
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',b);off=h[6];size=h[11];count=h[12]
    if size!=64 or count>1024 or off+count*size>len(b):raise ValueError('bad sections')
    sections=[struct.unpack_from('<IIQQQQIIQQ',b,off+i*size) for i in range(count)]
    for s in sections:
        if s[1]!=2:continue
        if s[6]>=count or s[9]!=24 or s[5]%24 or s[4]+s[5]>len(b):
            raise ValueError('bad symbol table')
        strings=sections[s[6]];table=b[strings[4]:strings[4]+strings[5]]
        if strings[1]!=3 or strings[4]+strings[5]>len(b):
            raise ValueError('bad symbol string table')
        for p in range(s[4],s[4]+s[5],24):
            n,info,other,idx,value,length=struct.unpack_from('<IBBHQQ',b,p)
            if n>=len(table):raise ValueError('symbol name outside string table')
            end=table.find(b'\0',n)
            if end<0:raise ValueError('unterminated symbol name')
            if table[n:end]==name.encode('utf8'):
                for seg in loads:
                    if seg['va']<=value and value+length<=seg['va']+seg['mem']:
                        return dict(va=value,pa=value-seg['va']+seg['pa'],size=length)
    raise ValueError('missing symbol '+name)


def boot_profile(b):
    """Read the retained boot ABI symbol; legacy images have the 256 MiB ABI."""
    loads = inspect_elf(b)['loads']
    try:
        entry = symbol(b, 'CYXIA_BOOT_PROFILE')
    except ValueError as error:
        if str(error) == 'missing symbol CYXIA_BOOT_PROFILE':
            return dict(version=0, ram_mib=256, heap_pages=2048)
        raise
    if entry['size'] != 24:
        raise ValueError('invalid boot profile size')
    for segment in loads:
        delta = entry['pa'] - segment['pa']
        if 0 <= delta and delta+24 <= segment['size']:
            version, ram_mib, heap_pages = struct.unpack_from('<QQQ', b, segment['offset']+delta)
            if version != 1 or (ram_mib, heap_pages) not in ((256, 2048), (512, 4096), (1024, 2048)):
                raise ValueError('unsupported boot profile')
            return dict(version=version, ram_mib=ram_mib, heap_pages=heap_pages)
    raise ValueError('boot profile is not backed by loaded bytes')
if __name__=='__main__':
    print(json.dumps(inspect_elf(Path(sys.argv[1]).read_bytes()),indent=2))
