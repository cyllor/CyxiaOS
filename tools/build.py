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
    p=argparse.ArgumentParser();p.add_argument('--profile',choices=['dev','release'],default='dev');p.add_argument('--production',action='store_true');a=p.parse_args()
    print(build(a.profile,not a.production))
