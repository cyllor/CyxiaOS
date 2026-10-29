"""A C worker must borrow the actual task gate once before Registry effects."""
import json,re
from pathlib import Path
import subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from test_governance_billing_priority import function

def program():
 task=(ROOT/'kernel/src/domain_tasks.rs').read_text();pub=(ROOT/'kernel/src/domain_tasks/publication.rs').read_text();code=(ROOT/'tests/host/active_scheduler_publication_harness.rs').read_text()
 code=code.replace('// OWNER_GATE_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/domain_tasks/owner_gate.rs'))+'] mod owner_gate;')
 pieces=[re.search(r'^static LOCK:.*;$',task,re.M)[0],re.search(r'struct Guard(?:\s*;|\s*\{[^}]*\})',task)[0]]
 pieces += [function(task,s) for s in ['impl Drop for Guard','fn acquire_guard()','fn locked<R>','fn locked_with_guard<R>']]
 code=code.replace('// OWNER_GATE_BODY','\n'.join(pieces))
 validate=function(task,'fn validate_locked(');arms='\n'.join(function(validate,s) for s in ['Action::CpuWeight(_) | Action::SpawnTokens(_) =>','Action::BackgroundBudget(budget) =>'])
 current=function(task,'fn current_locked(');cpu_arm=current[current.index('        1 =>'):current.index('        2 =>')];background_arm=current[current.index('        13 =>'):current.index('        _ =>')]
 bodies=function(task,'fn group_index(')+'\nfn validate_locked(s:&State,action:Action,target:ObjectKey,now:u64)->Result<(),Error>{action.validate()?;match action{'+arms+',_=>Err(Error::Unsupported)}}\nfn current_locked(s:&State,domain:u16,target:ObjectKey,now:u64)->Result<Action,Error>{match domain{'+cpu_arm+background_arm+'_=>Err(Error::Unsupported)}}\n'+function(task,'fn scheduling_dependencies_locked(')
 code=code.replace('// ACTUAL_LOCKED_BRANCHES',bodies)
 if 'struct SchedulerPublication' in pub:
  body='\n'.join(function(pub,s) for s in ['pub(crate) struct SchedulerPublication','pub(crate) fn reserve_scheduler_publication(','impl SchedulerPublication'])
 else:body='''struct SchedulerPublication;fn reserve_scheduler_publication(_:Action)->Result<Option<SchedulerPublication>,Error>{Ok(None)}impl SchedulerPublication{fn validate(&self,_:Action,_:ObjectKey,_:u64)->Result<(),Error>{Err(Error::Unsupported)}fn current(&self,_:u16,_:ObjectKey)->Result<Action,Error>{Err(Error::Unsupported)}fn legal_options(&self,_:&[Option<Action>],_:ObjectKey,_:u64,_:&mut[Option<Action>])->Result<usize,Error>{Err(Error::Unsupported)}fn prerequisites(&self,_:Action,_:ObjectKey)->Result<[Option<domain_control::Prerequisite>;2],Error>{Err(Error::Unsupported)}}'''
 code=code.replace('// SCHEDULER_PUBLICATION_BODY',body)
 control=(ROOT/'kernel/src/domain_control.rs').read_text();extra=(ROOT/'tests/host/active_selection_harness.rs').read_text()
 selection='\n'.join(function(control,x) for x in ['fn locate(','fn locate_family(','fn tiers(','fn categorical(','fn validate_selection('])
 call='validate_selection(owner,family(),action,target,at)'
 if 'fn validate_selection_with(' in control:
  selection+='\n'+function(control,'fn validate_selection_with(')
  call='validate_selection_with(owner,action,target,at,||view.current(action.domain(),target),|options,out|view.legal_options(options,target,at,out))'
 extra=extra.replace('// ACTUAL_SELECTION_BODIES',selection).replace('// BORROWED_SELECTION',call)
 return code+'\n'+extra

class ActiveSchedulerPublication(unittest.TestCase):
 def test_actual_task_guard_borrow_preserves_owner_rules(self):
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);code=program();(d/'harness.rs').write_text(code);(d/'Cargo.toml').write_text('[package]\nname="active-scheduler-publication"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-active-scheduler-publication'),'--','--test-threads=1','active_scheduler_']
   r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120);self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('4 passed; 0 failed',r.stdout)
   mutants=[
    ('validate_locked(self.state, action, target, now_ns())','locked(|state| validate_locked(state, action, target, now_ns()))','legal query reentered'),
    ('current_locked(self.state, domain, target, now_ns())','locked(|state| current_locked(state, domain, target, now_ns()))','current query reentered'),
    ('allowed & (1u64 << cpu) == 0','false','invalid Active task publication role'),
    ('cpu::slot() != self.cpu','false','borrow changed its control CPU identity'),
   ]
   for old,new,message in mutants:
    self.assertTrue(old in code,'missing mutation anchor: '+old);(d/'harness.rs').write_text(code.replace(old,new));negative=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
    self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr);self.assertIn(message,negative.stdout+negative.stderr)

 def test_borrowed_owner_keeps_the_complete_ordinary_selection_algorithm(self):
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);(d/'harness.rs').write_text(program());(d/'Cargo.toml').write_text('[package]\nname="active-scheduler-selection"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-active-scheduler-selection'),'--','--test-threads=1','active_selection_']
   r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120);self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('4 passed; 0 failed',r.stdout)
if __name__=='__main__':unittest.main()
