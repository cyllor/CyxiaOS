"""Single M1 gate. Required failures always produce a nonzero result."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
try:
 from .doctor import ROOT,RUST_BIN,TARGET,env,inspect,llvm_dir
 from .check_dependencies import check
 from .check_elf import inspect_elf
 from .run_qemu import run
except ImportError:
 from doctor import ROOT,RUST_BIN,TARGET,env,inspect,llvm_dir
 from check_dependencies import check
 from check_elf import inspect_elf
 from run_qemu import run

def inspect_instructions(text):
 count=0
 for line in text.splitlines():
  m=re.match(r'\s*[0-9a-f]+:\s+(.*)',line)
  if not m:continue
  insn=re.sub(r'^(?:[0-9a-f]{2}\s+){4}', '', m.group(1)).strip()
  if insn.startswith(('.word','.xword','.long')):continue
  if '<unknown>' in insn or re.search(r'\b(?:[vqdshb][0-9]+|fpcr|fpsr)\b',insn) or re.match(r'f[a-z]',insn):raise ValueError('FP/SIMD/unknown instruction: '+line)
  count+=1
 if count==0:raise ValueError('no executable instructions inspected')
 return count

def verify(output):
 output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
 report={'status':'FAIL','ai_state':'NOT_IMPLEMENTED','checks':[]}
 def record(name,work):
  try:detail=work();report['checks'].append({'name':name,'status':'PASS','detail':detail});print(name+': PASS',flush=True);return detail
  except Exception as e:report['checks'].append({'name':name,'status':'FAIL','error':str(e)});print(name+': FAIL '+str(e),flush=True);raise
 def command(name,args):
  def action():
   with (output/(name+'.log')).open('w') as f:p=subprocess.run(args,cwd=ROOT,env=env(),stdout=f,stderr=subprocess.STDOUT,timeout=180)
   if p.returncode:raise RuntimeError('exit '+str(p.returncode)+'; see '+name+'.log')
   return {'argv':args,'log':name+'.log'}
  return record(name,action)
 try:
  facts=record('environment',inspect)
  if not facts['ready']:raise RuntimeError('environment not ready')
  command('format',[str(RUST_BIN/'cargo'),'fmt','--all','--','--check'])
  command('host-tests',[str(RUST_BIN/'cargo'),'test','--locked'])
  command('python-tests',[sys.executable,'-m','unittest','discover','-s','tests/host','-v'])
  command('host-clippy',[str(RUST_BIN/'cargo'),'clippy','--all-targets','--','-D','warnings'])
  for feature in [False,True]:
   command('target-clippy-'+str(feature),[str(RUST_BIN/'cargo'),'clippy','-p','cyxia-kernel','--target',TARGET]+(['--features','selftest'] if feature else [])+['--','-D','warnings'])
  record('dependencies',check)
  for profile in ['dev','release']:
   command('build-'+profile,[sys.executable,'tools/build.py','--profile',profile])
   elf=ROOT/'target'/TARGET/('debug' if profile=='dev' else 'release')/'cyxia-kernel'
   layout=record('elf-'+profile,lambda:inspect_elf(elf.read_bytes()))
   report['kernel_bytes_'+profile]=max(x['pa']+x['mem'] for x in layout['loads'])-0x40200000
   command('disassembly-'+profile,[str(llvm_dir()/'llvm-objdump'),'--disassemble','--no-show-raw-insn',str(elf)])
   record('no-fp-simd-'+profile,lambda:inspect_instructions((output/('disassembly-'+profile+'.log')).read_text()))
   for case in ['all','pressure']:
    def guest():
     r=run(elf,case,output/(profile+'-'+case),timeout=30)
     if r['status']!='PASS':raise RuntimeError(r.get('error','guest failed'))
     if case=='all' and not r['transport']['complete']:raise RuntimeError('normal boot log incomplete')
     return r
    record(profile+'-'+case,guest)
  command('build-production',[sys.executable,'tools/build.py','--profile','release','--production'])
  elf=ROOT/'target'/TARGET/'release/cyxia-kernel'
  def production():
   r=run(elf,'boot-entry',output/'production',timeout=10)
   if r['status']!='PASS':raise RuntimeError(r.get('error','boot failed'))
   return r
  record('production-boot',production)
  report['status']='PASS';report['kernel_state']='KERNEL_BASE_READY'
 except Exception as e:report['error']=str(e)
 report['evidence_sha256']={str(p.relative_to(output)):hashlib.sha256(p.read_bytes()).hexdigest() for p in output.rglob('*') if p.is_file() and p.name!='summary.json'}
 (output/'summary.json').write_text(json.dumps(report,indent=2))
 return report
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',default='artifacts/m1-final');a=p.parse_args();r=verify(a.output);print('M1: '+r['status']);raise SystemExit(0 if r['status']=='PASS' else 1)
