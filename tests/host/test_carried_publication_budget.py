"""Carry real pre-submission CPU without changing protected clock samples."""
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

class CarriedPublicationBudget(unittest.TestCase):
 def test_actual_registry_carries_cost_through_every_budget_boundary(self):
  policy=(ROOT/'crates/prototype/src/policy.rs').read_text();fixtures=(ROOT/'crates/prototype/tests/domain_policy.rs').read_text()
  code=(ROOT/'tests/host/submission_observation_harness.rs').read_text().replace('// ACTUAL_WIRE_FIXTURES','\n'.join(function(fixtures,s) for s in ['fn publisher()','fn binding()','fn candidates()','fn frame(']))
  code=code.replace('// ACTUAL_OBSERVER_OVERRIDE','fn observed_submission(&mut self,o:&policy::SubmissionObservation){self.seen.push(Seen{stage:o.stage as u8,result:o.result,id:o.id,version:o.version,published:o.published_ns,prepared:o.preparation_started});}')
  extra=(ROOT/'tests/host/carried_publication_budget_harness.rs').read_text()
  call='r.submit_job(publisher(),wire,started,50_000_010,c,o)'
  if 'pub fn submit_job_debited' in policy:call='r.submit_job_debited(publisher(),wire,PublicationBudget{started,carried:debit},50_000_010,c,o)'
  code+='\n'+extra.replace('// DEBITED_SUBMIT',call)
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);(d/'harness.rs').write_text(code);(d/'Cargo.toml').write_text('[package]\nname="carried-publication-budget"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-carried-publication-budget'),'--','--test-threads=1','carried_publication_']
   run_env=env();run_env['RUST_MIN_STACK']='16777216'
   r=subprocess.run(command,cwd=ROOT,env=run_env,capture_output=True,text=True,timeout=120);self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('7 passed; 0 failed',r.stdout)
   clone=d/'prototype';shutil.copytree(ROOT/'crates/prototype',clone,ignore=shutil.ignore_patterns('target','tests','__pycache__'))
   manifest=(clone/'Cargo.toml').read_text().replace('version.workspace = true','version = "0.1.0"').replace('edition.workspace = true','edition = "2024"').replace('path = "../arch-aarch64"','path = '+json.dumps(str(ROOT/'crates/arch-aarch64')))
   (clone/'Cargo.toml').write_text(manifest);(d/'Cargo.toml').write_text((d/'Cargo.toml').read_text().replace(json.dumps(str(ROOT/'crates/prototype')),json.dumps(str(clone))))
   mutants=[
    ('.checked_add(self.carried.ns)','.checked_add(0)','carried publication CPU was ignored'),
    ('self.carried.cpu != self.started.cpu.cpu','false','invalid carried publication cost authorized'),
    ('budget.check(finished_ns)','publication_budget(started_ns, finished_ns)','postcommit check discarded carried publication CPU'),
    ('budget.check(commit_ns)?','publication_budget(started_ns, commit_ns)?','later check lost carried publication CPU'),
    ('budget.check(publish_ns)?','publication_budget(started_ns, publish_ns)?','assertion'),
   ]
   for old,new,message in mutants:
    self.assertTrue(old in policy,"missing mutation anchor: "+old);(clone/'src/policy.rs').write_text(policy.replace(old,new));negative=subprocess.run(command,cwd=ROOT,env=run_env,capture_output=True,text=True,timeout=120)
    self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr);self.assertIn(message,negative.stdout+negative.stderr)

if __name__=='__main__':unittest.main()
