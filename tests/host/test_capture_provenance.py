"""Actual paid-observation source and strict schema2 counterexamples."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import struct

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from decode_capture_provenance import decode
from test_governance_billing_priority import function


def fixture():
    w=[0]*128
    w[:13]=[0x4359535243450001,2,2,7,11,5,1,1,0,1,0,1,3]
    w[16:34]=[13,2,13,2,2,0,2,1,100,100,1,0,0,0,0,0,0,0]
    return w


class CaptureProvenance(unittest.TestCase):
    def test_decoder_preserves_partial_scope_and_rejects_impossible_producer_states(self):
        self.assertEqual(decode(bytes(1024)),{'present':False,'attribution_complete':False})
        w=fixture();packed=lambda v:struct.pack('<128Q',*v)
        result=decode(packed(w),(7,11,5))
        self.assertFalse(result['attribution_complete']);self.assertFalse(result['admission_known']);self.assertFalse(result['completion_known'])
        self.assertEqual(result['sources'][0]['offered_owner'],[13,2])
        self.assertEqual(result['sources'][0]['direct_source'],[13,2])
        self.assertIsNone(result['sources'][0]['task_identity'])
        self.assertEqual(result['sources'][0]['first_start_cpu_ticks'],100)
        for absent in ['record_calls','accepted_calls','capacity_calls','other_error_calls']:
            self.assertNotIn(absent,result)
        for absent in ['start_ns','end_ns','result','sample_result','raw_duration_ns','first_capacity_interval_ns']:
            self.assertNotIn(absent,result['sources'][0])
        unknown=fixture();unknown[7:9]=[0,1];unknown[16:20]=[99,8,0,0];unknown[26]=0
        self.assertIsNone(decode(packed(unknown))['sources'][0]['direct_source'])
        # One bounded overflow observation may itself have unknown identity;
        # aggregate known/unresolved counts must remain possible, not complete.
        overflow=fixture();overflow[6:12]=[5,3,2,5,1,4];overflow[14]=1
        for i,site in enumerate([3,4,2],start=1):
            overflow[16+i*24:40+i*24]=overflow[16:40];overflow[22+i*24]=site
        overflow[88:92]=[99,8,0,0];overflow[98]=0
        overflow[112:128]=[99,8,0,0,2,0,5,200,0,0,0,0,0,0,0,0]
        self.assertIsNone(decode(packed(overflow))['overflow_observation']['direct_source'])
        malformed=[]
        for at,value in [(1,1),(2,3),(3,0),(11,5),(13,9),(15,9),(9,2),(18,99),(22,1),(26,0),(27,2),(28,77),(33,65536),(34,9),(40,9),(112,9),(24,101)]:
            bad=fixture();bad[at]=value;malformed.append((at,bad))
        bad=fixture();bad[7:9]=[0,1];malformed.append(('direct total excludes actual direct row',bad))
        bad=fixture();bad[10]=1;malformed.append(('overflow without sample',bad))
        bad=fixture();bad[23]=0;malformed.append(('empty populated bucket',bad))
        bad=fixture();bad[6:12]=[2,2,0,2,0,2];bad[40:64]=bad[16:40];malformed.append(('duplicate bucket',bad))
        bad=overflow.copy();bad[112]=13;bad[114:116]=[13,2];bad[120]=1;malformed.append(('impossible unresolved total',bad))
        bad=overflow.copy();bad[121]=0;bad[122]=77;malformed.append(('absent overflow identity carries caller',bad))
        for label,bad in malformed:
            with self.subTest(label=label),self.assertRaises(ValueError):decode(packed(bad))
        with self.assertRaisesRegex(ValueError,'run identity mismatch'):decode(packed(w),(7,11,6))

    def test_actual_observer_counterexamples_compile_and_fail_behaviorally(self):
        original=(ROOT/'kernel/src/learning_evidence/provenance.rs').read_text()
        bridge=(ROOT/'kernel/src/learning_evidence.rs').read_text()
        harness=(ROOT/'crates/prototype/tests/native_capture_provenance.rs').read_text()
        execution=(ROOT/'kernel/src/domain_tasks/execution.rs').read_text()
        # Explicit test-only paid-credit/physical-cleanup/membership boundary.
        # The companion cost test runs the original service sample and real
        # Scheduler debit; here collector/identity copy/interval storage stay real.
        start=harness.index('            bridge::measure_paid_task(',harness.index('let run = begin(2);'))
        end=harness.index('            assert_eq!(',start)
        harness=harness[:start]+'            assert_eq!(task_boundary::cleanup_example(),Ok(()));\n'+harness[end:]
        harness+='''
mod task_boundary {
    use cyxia_prototype::domains::{Error,ObjectKey};
    struct Task {parent:ObjectKey,spawn_id:u64,key:ObjectKey,recipe:u16}
    struct State {tasks:[Task;1]}
    mod replay {use super::*;pub fn work_source(parent:ObjectKey,id:u64,recipe:u16)->Option<ObjectKey>{
        (parent==ObjectKey{id:70,generation:8} && id==9 && recipe==2).then_some(ObjectKey{id:13,generation:1})}}
    fn cleanup_inner(_: &mut State,_:usize)->Result<(),Error>{crate::domain_platform::at(crate::OBS+200_000_037);Ok(())}
    pub fn cleanup_example()->Result<(),Error>{let mut s=State{tasks:[Task{parent:ObjectKey{id:70,generation:8},spawn_id:9,key:ObjectKey{id:4097,generation:6},recipe:2}]};cleanup(&mut s,0)}
'''+function(execution,'fn capture_task_identity(')+'\n'+function(execution,'fn cleanup(')+'\n}\n'
        harness=harness.replace('crate::learning_evidence::','crate::bridge::')
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);bank=d/'provenance.rs';evidence=d/'learning_evidence.rs';h=d/'test.rs'
            bridge=bridge.replace('"learning_evidence/','"'+str(ROOT/'kernel/src/learning_evidence')+'/')
            bridge=bridge.replace(str(ROOT/'kernel/src/learning_evidence/provenance.rs'),str(bank));evidence.write_text(bridge)
            harness=harness.replace('"../../../kernel/src/domain_tasks/cancellation.rs"',json.dumps(str(ROOT/'kernel/src/domain_tasks/cancellation.rs')))
            harness=harness.replace('"../../../kernel/src/learning_evidence.rs"',json.dumps(str(evidence)));h.write_text(harness)
            (d/'Cargo.toml').write_text('[package]\nname="capture-provenance-counterexamples"\nversion="0.1.0"\nedition="2024"\n[[test]]\nname="provenance"\npath="test.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
            cmd=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-capture-provenance'),'--','--nocapture']
            def run(source):
                bank.write_text(source)
                return subprocess.run(cmd,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            r=run(original);self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            for source,failure in [
                (original.replace('let b = &TRACE_SOURCE_EVIDENCE;','return;\n    let b = &TRACE_SOURCE_EVIDENCE;'),'source provenance missing paid observation header'),
                (original.replace('e.offered.id,','0,'),'left == right'),
                (original.replace('id: 0,','id: 99,',1),'offered alias was fabricated as resolved source'),
                (original.replace('let b = &TRACE_SOURCE_EVIDENCE;','let _ = crate::domain_platform::now_ns();\n    let b = &TRACE_SOURCE_EVIDENCE;'),'diagnostic probe added a clock read'),
                (original.replace('i.caller.generation,','0,'),'TaskGuard caller/request/child identity was not copied'),
            ]:
                self.assertNotEqual(source,original);r=run(source);output=r.stdout+r.stderr
                self.assertNotEqual(r.returncode,0,output);self.assertIn('Finished `test`',output);self.assertIn(failure,output)
            wrong=harness.replace('caller: task.parent,','caller: task.key,');self.assertNotEqual(wrong,harness);h.write_text(wrong)
            r=run(original);output=r.stdout+r.stderr
            self.assertNotEqual(r.returncode,0,output);self.assertIn('Finished `test`',output);self.assertIn('TaskGuard caller/request/child identity was not copied',output)
            h.write_text(harness);r=run(original);self.assertEqual(r.returncode,0,r.stdout+r.stderr)

if __name__=='__main__':unittest.main()
