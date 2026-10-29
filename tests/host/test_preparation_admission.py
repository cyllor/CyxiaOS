"""Real early preparation decisions retain bounded reason/identity evidence."""
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


def execute(code,evidence,target):
    with tempfile.TemporaryDirectory() as tmp:
        d=Path(tmp);module=d/'evidence.rs'
        module.write_text(evidence+'\npub fn header()->[u64;512]{core::array::from_fn(get)}\n')
        code=code.replace('// EVIDENCE_MODULE','#[path='+json.dumps(str(module))+'] mod domain_evidence;')
        source=d/'harness.rs';source.write_text(code)
        (d/'Cargo.toml').write_text('[package]\nname="preparation-admission"\nversion="0.1.0"\nedition="2024"\n[[bin]]\nname="gate"\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
        command=[str(RUST_BIN/'cargo'),'run','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/('target/host-preparation-'+target))]
        return subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)


class PreparationAdmission(unittest.TestCase):
    def test_actual_post_submission_retains_original_stop_cost_and_identity(self):
        control=(ROOT/'kernel/src/domain_control.rs').read_text()
        evidence=(ROOT/'kernel/src/domain_evidence.rs').read_text()
        submit=function(control,'pub fn accept(')
        body=submit[submit.index('        let publication_ns ='):submit.index('        job.completion =')]
        origin='let optimization_was_stopped=false;'
        if 'let optimization_was_stopped =' in submit:
            origin=next(line.strip() for line in submit.splitlines() if 'let optimization_was_stopped =' in line)
        code=(ROOT/'tests/host/preparation_stop_harness.rs').read_text().replace('// ACTUAL_POST_SUBMISSION',body).replace('// ACTUAL_STOP_ORIGIN',origin)
        r=execute(code,evidence,'stop')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('actual publication stop provenance passed',r.stdout)

    def test_actual_early_gate_reports_reason_without_new_queries(self):
        control=(ROOT/'kernel/src/domain_control.rs').read_text()
        replay=(ROOT/'kernel/src/domain_control/replay.rs').read_text()
        evidence=(ROOT/'kernel/src/domain_evidence.rs').read_text()
        projection='pub(super) fn preparation_admission(_: &State,_:u64,_:u64){}'
        if 'fn preparation_admission(' in replay:projection=function(replay,'pub(super) fn preparation_admission(')
        code=(ROOT/'tests/host/preparation_admission_harness.rs').read_text()
        code=code.replace('// ACTUAL_NEXT_LOCKED',function(control,'fn next_locked_inner('))
        code=code.replace('// ACTUAL_ROOT_PROJECTION',projection)
        r=execute(code,evidence,'admission')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('actual preparation admission gate passed',r.stdout)


if __name__=='__main__':unittest.main()
