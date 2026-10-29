"""Actual Registry phase/result observation; native owner callbacks remain controlled."""
import json
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from test_governance_billing_priority import function

class SubmissionObservation(unittest.TestCase):
 def test_actual_registry_keeps_original_stage_result_and_clock_contract(self):
  policy=(ROOT/'crates/prototype/src/policy.rs').read_text();fixtures=(ROOT/'crates/prototype/tests/domain_policy.rs').read_text()
  source=(ROOT/'tests/host/submission_observation_harness.rs').read_text().replace('// ACTUAL_WIRE_FIXTURES','\n'.join(function(fixtures,s) for s in ['fn publisher()','fn binding()','fn candidates()','fn frame(']))
  observer=''
  if 'fn observed_submission(' in policy:
   observer='''fn observed_submission(&mut self,o:&policy::SubmissionObservation){self.seen.push(Seen{stage:o.stage as u8,result:o.result,id:o.id,version:o.version,published:o.published_ns,prepared:o.preparation_started});}'''
  source=source.replace('// ACTUAL_OBSERVER_OVERRIDE',observer)
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);(d/'harness.rs').write_text(source);(d/'Cargo.toml').write_text('[package]\nname="submission-observation"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-submission-observation'),'--','--test-threads=1']
   r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
   self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('5 passed; 0 failed',r.stdout)
   clone=d/'prototype';shutil.copytree(ROOT/'crates/prototype',clone,ignore=shutil.ignore_patterns('target','tests','__pycache__'))
   manifest=(clone/'Cargo.toml').read_text().replace('version.workspace = true','version = "0.1.0"').replace('edition.workspace = true','edition = "2024"').replace('path = "../arch-aarch64"','path = '+json.dumps(str(ROOT/'crates/arch-aarch64')))
   (clone/'Cargo.toml').write_text(manifest)
   fixture=(d/'Cargo.toml').read_text().replace(json.dumps(str(ROOT/'crates/prototype')),json.dumps(str(clone)));(d/'Cargo.toml').write_text(fixture)
   start=policy.index('        executor.observed_submission(&SubmissionObservation {');end=policy.index('        });',start)+len('        });')
   mutants=[
    (policy[:start]+policy[end:],'submission_observer_keeps_original_callback_failure_stage_before_cleanup','Registry submit did not report its original result stage'),
    (policy.replace('stage: observed_stage','stage: SubmissionStage::Complete'),'submission_observer_keeps_original_callback_failure_stage_before_cleanup','cleanup replaced the failed submission phase'),
    (policy.replace('result: result.map(|_| ())','result: Err(Error::Busy)'),'submission_observer_preserves_committed_receipt_after_final_cpu_overrun_and_duplicates','assertion `left == right` failed'),
   ]
   for mutant,case,message in mutants:
    self.assertNotEqual(mutant,policy);(clone/'src/policy.rs').write_text(mutant)
    r=subprocess.run(command+['--exact',case],cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
    self.assertNotEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn(message,r.stdout+r.stderr)

if __name__=='__main__':unittest.main()
