"""Actual Registry phase/result observation; native owner callbacks remain controlled."""
import json
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
if __name__=='__main__':unittest.main()
