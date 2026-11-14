import argparse
from pathlib import Path
import subprocess
from doctor import ROOT,RUST_BIN,TARGET,env,inspect
from check_elf import inspect_elf

def build(profile='dev',selftest=True):
    if not inspect()['ready']:raise RuntimeError('Pinned environment mismatch; run tools/doctor.py')
    args=[str(RUST_BIN/'cargo'),'build','-p','cyxia-kernel','--target',TARGET]
    if selftest:args+=['--features','selftest']
    if profile=='release':args+=['--release']
    subprocess.run(args,cwd=ROOT,env=env(),check=True,timeout=180)
    p=ROOT/'target'/TARGET/('release' if profile=='release' else 'debug')/'cyxia-kernel'
    inspect_elf(p.read_bytes());return p
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--profile',choices=['dev','release'],default='dev')
    p.add_argument('--production',action='store_true')
    p.add_argument('--arch',choices=['aarch64','x86_64'],default='x86_64')
    p.add_argument('--output',type=Path,help='new x86-64 build evidence directory')
    a=p.parse_args()
    if a.arch=='x86_64':
        if a.production:p.error('x86-64 currently implements the platform selftest; --production is unsupported')
        if a.output is None:p.error('x86-64 requires --output')
        import x86_64
        x86_64.build(a.output,profile=a.profile)
        print(a.output/'kernel.elf')
    else:
        if a.output is not None:p.error('--output is only supported for --arch x86_64')
        print(build(a.profile,not a.production))
