"""Compile the current ordinary A09 client without shared Cargo/OUT_DIR state."""
from pathlib import Path
import struct
import subprocess
import tempfile
from doctor import RUST_BIN,env
from check_prototype_evidence import require


def user_code(data):
    require(len(data)>=64,'truncated ordinary client ELF')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    require(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:5]==(2,183,1,0x10000)
            and h[9]==56 and 0<h[10]<=8,'wrong ordinary client ELF')
    loads=[]
    for i in range(h[10]):
        at=h[5]+i*56;require(at+56<=len(data),'client ELF program table bounds')
        p=struct.unpack_from('<IIQQQQQQ',data,at)
        if p[0]==1:
            require(p[1]==5 and p[3]==0x10000 and p[5]==p[6] and 0<p[5]<=16384
                    and p[2]+p[5]<=len(data),'wrong immutable client load segment')
            loads.append(data[p[2]:p[2]+p[5]])
    require(len(loads)==1,'multiple ordinary client load segments')
    return loads[0]+bytes(16384-len(loads[0]))


def current_code(source):
    # Match the build script's spelling as well as its compiler flags: panic
    # locations embedded in .rodata retain the kernel/../user source path.
    source=Path(source).resolve(strict=True)/'kernel/../user/prototype-memory-client'
    # Match the actual build.rs standalone compiler flags. Compare the loaded
    # segment rather than debug/symbol sections, which the loader never maps.
    with tempfile.TemporaryDirectory(prefix='cyx-a09-current-client-') as temp:
        out=Path(temp)/'client.elf'
        args=[str(RUST_BIN/'rustc'),str(source/'main.rs'),'--edition=2024','--target',
            'aarch64-unknown-none-softfloat','--crate-name','cyxia_memory_client',
            '-C','opt-level=2','-C','panic=abort','-C','overflow-checks=yes',
            '-C','relocation-model=static','-C','link-arg=--build-id=none',
            '-C','link-arg=-zmax-page-size=4096','-C','link-arg=-T'+str(source/'linker.ld'),'-o',str(out)]
        result=subprocess.run(args,env=env(),capture_output=True,timeout=30)
        require(result.returncode==0,'current ordinary A09 client does not compile: '+result.stderr.decode('utf-8','replace'))
        return user_code(out.read_bytes())


if __name__=='__main__':
    import argparse,hashlib,json
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('build','source-root','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();actual=user_code((a.build/'memory-client-a.elf').read_bytes());expected=current_code(a.source_root)
    result=dict(scope='current source versus actual archived load segment',status='PASS' if actual==expected else 'FAIL',
        expected_code_sha256=hashlib.sha256(expected).hexdigest(),actual_code_sha256=hashlib.sha256(actual).hexdigest())
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(0 if actual==expected else 2)
