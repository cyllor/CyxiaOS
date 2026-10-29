"""Actual completed job retirement and Root first-scope admission.

Reply validation/Registry commit/capture/resource owners are explicit boundaries;
this does not establish native timing or full unactivated export/release.
"""
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


def program():
    control=(ROOT/'kernel/src/domain_control.rs').read_text()
    replay=(ROOT/'kernel/src/domain_control/replay.rs').read_text()
    preparation=(ROOT/'kernel/src/domain_control/preparation.rs').read_text()
    source=(ROOT/'tests/host/first_candidate_rejection_harness.rs').read_text()
    source=source.replace('// ACTUAL_IDENTITY','use super::*;\n#[derive(Clone,Copy)]\n'+function(preparation,'pub struct Identity'))
    for marker,signature in [('JOB','struct Job {'),('COMPLETION','struct JobCompletion {')]:
        source=source.replace('// ACTUAL_'+marker,'#[derive(Clone,Copy)]\n'+function(control,signature))
    source=source.replace('// ACTUAL_FINISH_JOB',function(control,'fn finish_job('))
    source=source.replace('// ACTUAL_ABORT',function(control,'pub fn abort('))
    source=source.replace('// ACTUAL_TOKEN','#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'+function(replay,'pub struct Token'))
    bodies='\n'.join(function(replay,s) for s in ['fn fail(','pub(super) fn allows(','pub(super) fn first('])
    hook='pub(super) fn reject_first_job(_:u64,_:u64,_:&CandidateSet,_:Error) {}'
    if 'fn reject_first_job(' in replay:hook=function(replay,'pub(super) fn reject_first_job(')
    source=source.replace('// ACTUAL_OWNER_RETAIN_ERROR',function((ROOT/'kernel/src/learning_replay/owner.rs').read_text(),'fn retain_error('))
    source=source.replace('// ACTUAL_LIFECYCLE_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/domain_control/replay/lifecycle.rs'))+'] mod close_lifecycle;')
    return source.replace('// ACTUAL_ROOT_FUNCTIONS',bodies+'\n'+hook)


class FirstCandidateRejection(unittest.TestCase):
    def test_retired_first_failure_cannot_refresh_original_scope(self):
        original=program()
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);source=d/'harness.rs';source.write_text(original)
            (d/'Cargo.toml').write_text('[package]\nname="first-candidate-rejection"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-first-candidate-rejection'),'--','--test-threads=1']
            r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertIn('6 passed; 0 failed',r.stdout)
            hook='        replay::reject_first_job(s.boot, job.sequence, &job.set, error);'
            mutants=[(hook,'','retired first candidate left its captured scope open'),
                ('&& r.initial.is_none()','', 'unrelated or published obligation was failed: 2'),
                ('q.kind == TrialKind::Candidate','true', 'unrelated or published obligation was failed: 1'),
                ('&& sequence == set.snapshot.sequence','', 'unrelated or published obligation was failed: 10'),
                ('&& r.token.is_some_and(|token| token.boot_epoch == boot)','', 'unrelated or published obligation was failed: 4'),
                ('!job.read_only\n        && job.work.is_none()','!job.read_only', 'unrelated or published obligation was failed: 9'),
                ('!job.read_only\n        && job.work.is_none()','job.work.is_none()', 'unrelated or published obligation was failed: 8')]
            for old,new,message in mutants:
                self.assertIn(old,original)
                source.write_text(original.replace(old,new))
                r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
                self.assertNotEqual(r.returncode,0,old+"\n"+r.stdout+r.stderr)
                self.assertIn(message,r.stdout+r.stderr)


if __name__=='__main__':unittest.main()
