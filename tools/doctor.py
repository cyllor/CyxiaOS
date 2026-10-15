"""Read-only, pinned M1 environment checks; no shell profile changes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
RUST_BIN = Path.home()/'.cargo/bin'
TARGET = 'aarch64-unknown-none-softfloat'
def env():
    return dict(os.environ, PATH=str(RUST_BIN)+os.pathsep+os.environ.get('PATH',''))
def run(args):
    p=subprocess.run(args,env=env(),capture_output=True,text=True,timeout=30)
    return p.stdout.strip() if p.returncode==0 else ''
def assess(facts):
    checks={
      'rust': {'ready': facts.get('rust','').startswith('rustc 1.95.0 ') or facts.get('rust')=='rustc 1.95.0'},
      'cargo': {'ready': facts.get('cargo','').startswith('cargo 1.95.0')},
      'qemu': {'ready': facts.get('qemu','').splitlines()[0:1] == ['QEMU emulator version 10.2.2']},
      'baremetal_target': {'ready':TARGET in facts.get('targets',[])},
      'llvm': {'ready': bool(facts.get('llvm'))}}
    checks['ready']=all(x['ready'] for x in checks.values()); checks['facts']=facts
    return checks
def llvm_dir():
    sysroot=run([str(RUST_BIN/'rustc'),'--print','sysroot'])
    host=next((x.split(': ',1)[1] for x in run([str(RUST_BIN/'rustc'),'-vV']).splitlines() if x.startswith('host: ')), '')
    return Path(sysroot)/'lib/rustlib'/host/'bin'
def inspect():
    qemu=shutil.which('qemu-system-aarch64',path=env()['PATH'])
    ld=llvm_dir()
    return assess(dict(rust=run([str(RUST_BIN/'rustc'),'--version']),cargo=run([str(RUST_BIN/'cargo'),'--version']),
      qemu=run([qemu,'--version']) if qemu else '', targets=run([str(RUST_BIN/'rustup'),'target','list','--installed']).splitlines(),
      llvm=all((ld/x).exists() for x in ['llvm-readobj','llvm-objdump','rust-lld']),rust_path=str(RUST_BIN/'rustc'),llvm_dir=str(ld),project=str(ROOT)))
if __name__=='__main__':
    result=inspect(); print(json.dumps(result,indent=2)); sys.exit(0 if result['ready'] else 1)
