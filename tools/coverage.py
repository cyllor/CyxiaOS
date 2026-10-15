"""Host-mechanism LLVM coverage without extra Cargo plugins.
MMIO drivers, assembly, kernel and integration-test sources are excluded;
those require the separate QEMU gate. This is line coverage, not branch coverage.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
from doctor import ROOT,RUST_BIN,env,inspect,llvm_dir

def main(output):
 if not inspect()['ready']:raise RuntimeError('environment mismatch')
 out=Path(output).resolve()/str(time.time_ns());out.mkdir(parents=True)
 e=env();e.update(CARGO_TARGET_DIR=str(ROOT/'target/coverage'),CARGO_INCREMENTAL='0',CARGO_PROFILE_TEST_DEBUG='0',RUSTFLAGS='-C instrument-coverage -C debuginfo=0',LLVM_PROFILE_FILE=str(out/'%p-%m.profraw'))
 with (out/'build-and-tests.jsonl').open('w') as stdout,(out/'build.log').open('w') as stderr:
  subprocess.run([str(RUST_BIN/'cargo'),'test','--tests','--locked','--message-format=json'],cwd=ROOT,env=e,stdout=stdout,stderr=stderr,check=True,timeout=180)
 objects=[]
 for line in (out/'build-and-tests.jsonl').read_text().splitlines():
  try:r=json.loads(line)
  except ValueError:continue
  if r.get('reason')=='compiler-artifact' and r.get('executable') and r.get('profile',{}).get('test'):objects.append(r['executable'])
 llvm=llvm_dir();profiles=list(out.glob('*.profraw'))
 if not profiles or not objects:raise RuntimeError('missing instrumented evidence')
 subprocess.run([str(llvm/'llvm-profdata'),'merge','-sparse',*[str(x)for x in profiles],'-o',str(out/'merged.profdata')],check=True,timeout=30)
 args=[str(llvm/'llvm-cov'),'report','-instr-profile='+str(out/'merged.profdata')]
 for obj in objects:args+=['-object',obj]
 args+=['-ignore-filename-regex=/(rustc|rustlib)/|crates/driver-|/tests/']
 p=subprocess.run(args,check=True,text=True,capture_output=True,timeout=30);(out/'report.txt').write_text(p.stdout)
 total=next(line for line in p.stdout.splitlines() if line.startswith('TOTAL'))
 percentages=re.findall(r'(\d+\.\d+)%',total)
 if len(percentages)!=3:raise RuntimeError('unexpected LLVM report format')
 coverage=float(percentages[2]);result={'status':'PASS' if coverage>=80 else 'FAIL','line_coverage_percent':coverage,'scope':'host contracts, kernel-core, FDT, page-descriptor logic; excludes MMIO, kernel and assembly','report':str(out/'report.txt'),'command':args}
 (out/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2));return coverage>=80
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',default='artifacts/coverage');a=p.parse_args();raise SystemExit(0 if main(a.output) else 1)
