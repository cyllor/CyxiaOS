"""Strict ELF64 load validation and versioned CyxiaOS boot profile."""
import json
from pathlib import Path
import struct
import sys
try:
    from . import elf64
except ImportError:
    import elf64

def inspect_elf(b):
    def need(ok,msg):
        if not ok: raise ValueError(msg)
    need(len(b)>=64,'truncated header')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',b)
    ident,kind,machine,version,entry=h[:5]
    need(ident[:7]==b'\x7fELF\x02\x01\x01' and kind==2 and machine==183 and version==1,'not AArch64 executable')
    decoded=elf64.decode(b)
    loads=[]
    for segment in decoded['segments']:
        if segment['type']!=1:continue
        fl,off,va,pa,fs,ms,al=(segment[key] for key in ('flags','offset','va','pa','size','mem','align'))
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
    return elf64.symbol(b,name,loads)


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
