"""Original pre-Job first preparation must own a bounded retry identity."""
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
 c=(ROOT/'kernel/src/domain_control.rs').read_text();r=(ROOT/'kernel/src/domain_control/replay.rs').read_text()
 code=(ROOT/'tests/host/first_preparation_custody_harness.rs').read_text()
 code=code.replace('// PREPARATION_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/domain_control/preparation.rs'))+'] mod preparation;')
 bank=c[c.index('struct PreparationRejections('):c.index(');',c.index('struct PreparationRejections('))+2]+'\nstatic DOMAIN_PREPARATION_REJECTIONS:PreparationRejections=PreparationRejections([const{AtomicU64::new(0)};648]);\nstatic mut PREPARATION_REJECTIONS:preparation::Rejections=preparation::Rejections::new();'
 code=code.replace('// ACTUAL_REJECTION_BANK',bank)
 code=code.replace('// ACTUAL_PREPARATION_FUNCTIONS','\n'.join(function(c,x) for x in ['fn next_locked(','fn retire_preparation(','fn preparation_identity(','fn preparation_snapshot(']))
 normal=function(c,'fn next_normal(');prefix=normal[:normal.index('        let core_preparation =')]
 # All real exits through model gate; later resource/encoding branches are an
 # explicit boundary. Successful encoding validates carried CPU, then clears
 # Pending exactly as the real encode_job_inner success does.
 suffix='''
        if MODE.load(Ordering::Acquire)==4 {break 'families;}
        if let Some(p)=s.preparation {assert_eq!(p.total(p.identity,now(),timer::cpu_elapsed_ns(cpu_started)),Ok(22),"encoding lost carried preparation cost");}
        s.job=true;s.preparation=None;return Ok(true);
    }
    if s.preparation.is_some(){return Err(Error::NotReady)}
    Ok(false)
}
'''
 code=code.replace('// ACTUAL_NORMAL_PREFIX',prefix+suffix)
 bodies='\n'.join(function(r,x) for x in ['fn fail(','pub(super) fn allows(','pub struct Prefix','impl Drop for Prefix','fn activate(','pub(super) fn first(','pub(super) fn reject_preparation('])
 if 'fn first_preparation(' in r:bodies+='\n'+function(r,'pub(super) fn first_preparation(')
 code=code.replace('// ACTUAL_ROOT_FUNCTIONS',bodies)
 return code

class FirstPreparationCustody(unittest.TestCase):
 def test_original_first_prejob_attempt_is_bounded_without_refreshing_scope(self):
  code=program()
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);(d/'harness.rs').write_text(code);(d/'Cargo.toml').write_text('[package]\nname="first-preparation-custody"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-first-preparation-custody'),'--','--test-threads=1']
   result=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
   self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertIn('6 passed; 0 failed',result.stdout)
   creation=function(code,'if s.preparation.is_none()\n            && replay::first_preparation(')
   mutants=[
    (creation,'','first preparation escaped without custody'),
    ('preparation::Pending::first_candidate(','preparation::Pending::new(','blocked candidate first ignored'),
    ('if pending.is_first_candidate() {','if false {','blocked candidate first ignored'),
    ('&& r.first.is_none_or(|first| first == snapshot)','', 'foreign first predicate accepted: 7'),
    ('&& snapshot.taken_ns >= q.not_before_ns','', 'foreign first predicate accepted: 5'),
    ('pending.charge(timer::cpu_elapsed_ns(cpu_started))','Ok::<(),Error>(())','assertion'),
    ('replay::reject_preparation(pending.identity, pending.snapshot, reason);','', 'assertion'),
    ('Some(*error)','None','assertion'),
   ]
   for old,new,message in mutants:
    self.assertIn(old,code);(d/'harness.rs').write_text(code.replace(old,new));negative=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
    self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr);self.assertIn(message,negative.stdout+negative.stderr)

if __name__=='__main__':unittest.main()
