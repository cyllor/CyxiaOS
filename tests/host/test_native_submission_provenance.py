"""Actual Native Executor callbacks + Registry, controlled resource/role/commit boundary."""
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

class NativeSubmissionProvenance(unittest.TestCase):
 def test_actual_native_callbacks_keep_failure_origin_separate_from_registry(self):
  control=(ROOT/'kernel/src/domain_control.rs').read_text();fixture=(ROOT/'crates/prototype/tests/domain_policy.rs').read_text()
  program=(ROOT/'tests/host/native_submission_harness.rs').read_text().replace('// WIRE_FIXTURES','\n'.join(function(fixture,s) for s in ['fn publisher()','fn binding()','fn candidates()','fn frame(']))
  program=program.replace('// NATIVE_CLOCK',function(control,'impl policy::Clock for NativeClock')).replace('// REPLACEMENT_PREDICATE',function(control,'fn execution_blocks_replacement(')).replace('// SCOPE_TRAIT',function(control,'trait PublicationScope'))
  struct=function(control,'struct Executor<');body=function(control,"impl<S: PublicationScope> policy::Executor for Executor<'_, S>")
  # Real precommit and scope.commit. Root/Desired/history effects after it are
  # represented by a counted effect, not treated as actual resource custody.
  start=body.index('replay::published(');start=body.rfind('\n',0,start)+1
  before=body.rfind('self.provenance.at(',0,start)
  if before>=0 and 'RootPublish' in body[before:start]:start=body.rfind('\n',0,before)+1
  end=body.index('self.owner.prepared_count = 0;',start);end=body.rfind('\n',0,end)+1
  body=body[:start]+'            EFFECTS.fetch_add(1,Ordering::AcqRel);\n'+body[end:]
  program=program.replace('// NATIVE_EXECUTOR',struct).replace('// NATIVE_IMPL',body)
  module=ROOT/'kernel/src/domain_control/submission.rs'
  if module.exists():
   program=program.replace('// FACTS_MODULE','#[path='+json.dumps(str(module))+'] mod submission;')
  else:program=program.replace('// FACTS_MODULE','mod submission{#[derive(Clone,Copy)]pub struct Facts;impl Facts{pub fn words(self,_:Result<u64,super::Error>,_:bool)->[u64;27]{[0;27]}}}')
  enabled='provenance:submission::Facts::new(1,false,[2,2,3,3],true),' if 'provenance:' in struct else ''
  getter='fn get_facts(e:&Executor<Scope>)->submission::Facts{e.provenance}' if enabled else 'fn get_facts(_:&Executor<Scope>)->submission::Facts{submission::Facts}'
  program=program.replace('// FACTS_INITIALIZER',enabled).replace('// GET_FACTS',getter)
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);(d/'harness.rs').write_text(program);(d/'Cargo.toml').write_text('[package]\nname="native-submission-provenance"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-native-submission-provenance'),'--','--test-threads=1']
   r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
   self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('3 passed; 0 failed',r.stdout)
 def test_actual_record_tail_preserves_first_completion_and_slot_identity(self):
  evidence=(ROOT/'kernel/src/domain_evidence.rs').read_text()
  if 'pub fn submission(' not in evidence:evidence+='\npub fn submission(_:usize,_:u64,_:[u64;27]){}\n'
  evidence+='\npub fn tail(slot:usize)->[u64;27]{core::array::from_fn(|i|get(base(slot)+612+i))}\npub fn input_hash(slot:usize)->[u64;4]{core::array::from_fn(|i|get(base(slot)+608+i))}\n'
  body=r'''#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
pub mod cpu{pub fn slot()->usize{0}}
mod domain_platform{pub fn now_ns()->u64{0}}
// EVIDENCE_MODULE
fn row(sequence:u64)->[u64;27]{let mut w=[0;27];w[0]=0x43595355424d0001;w[1]=1;w[2]=8;w[4]=2;w[5]=10;w[7]=2;w[20]=sequence;w[21]=1;w}
fn begin(slot:usize,sequence:u64){let mut input=[0;512];input[2]=sequence;input[8]=1;input[9]=1;input[10]=12;input[11]=1;evidence::begin(slot,&input,[1;32]);}
#[test]fn submission_tail_is_first_completion_only_and_reuse_keeps_original_input_hash(){
 begin(3,51);let first=row(51);evidence::submission(3,51,first);
 assert_eq!(evidence::tail(3),first,"original submission completion facts were not retained");let hash=evidence::input_hash(3);
 let mut later=first;later[7]=14;evidence::submission(3,51,later);assert_eq!(evidence::tail(3),first,"delivery retry replaced original completion facts");
 assert_eq!(evidence::input_hash(3),hash);assert_eq!(hash,[0x0101010101010101;4]);
 begin(3,52);evidence::submission(3,51,first);assert_eq!(evidence::tail(3),[0;27],"old completion acquired a reused record");
 evidence::submission(3,52,row(52));assert_eq!(evidence::tail(3),row(52));
}
#[test]fn submission_tail_rejects_foreign_sequence_bad_schema_and_disabled_facts(){
 begin(5,51);evidence::submission(5,52,row(52));assert_eq!(evidence::tail(5),[0;27],"foreign completion acquired the current record");
 evidence::submission(5,51,row(52));assert_eq!(evidence::tail(5),[0;27],"foreign observation echo acquired the current record");
 let mut bad=row(51);bad[0]=7;evidence::submission(5,51,bad);assert_eq!(evidence::tail(5),[0;27],"bad diagnostic schema acquired the current record");
 evidence::submission(5,51,[0;27]);assert_eq!(evidence::tail(5),[0;27]);evidence::submission(999,51,row(51));
 evidence::submission(5,51,row(51));assert_eq!(evidence::tail(5),row(51),"valid completion was lost after foreign attempts");
}
'''
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);(d/'evidence.rs').write_text(evidence);(d/'harness.rs').write_text(body.replace('// EVIDENCE_MODULE','#[path='+json.dumps(str(d/'evidence.rs'))+'] mod evidence;'))
   (d/'Cargo.toml').write_text('[package]\nname="submission-record-tail"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
   command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-submission-record-tail'),'--','--test-threads=1']
   r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120);self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('3 passed; 0 failed',r.stdout)
if __name__=='__main__':unittest.main()
