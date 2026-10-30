"""Real cleanup/service-I/O sampling and Scheduler debit, controlled PMCC costs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import re

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from test_governance_billing_priority import function

class PaidCaptureCost(unittest.TestCase):
    def test_recorder_cost_is_in_original_capture_and_submitted_debit(self):
        bridge=(ROOT/'kernel/src/learning_evidence.rs').read_text()
        provenance=(ROOT/'kernel/src/learning_evidence/provenance.rs').read_text()
        tasks=(ROOT/'kernel/src/domain_tasks.rs').read_text()
        execution=(ROOT/'kernel/src/domain_tasks/execution.rs').read_text()
        harness=(ROOT/'tests/host/capture_paid_cost_harness.rs').read_text()
        bodies='\n'.join(function(execution,s) for s in ['fn capture_task_identity(','fn cleanup(','pub fn service_io_piece<R>'])
        bodies+='\n'+function(tasks,'pub fn service_segment<R>')+'\n'+function(tasks,'pub(crate) fn finish_cpu_interval(')
        harness=harness.replace('// ACTUAL_PAID_BODIES',bodies).replace('crate::learning_evidence::','crate::bridge::')
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);b=d/'learning_evidence.rs';p=d/'provenance.rs';h=d/'test.rs'
            bridge=bridge.replace('"learning_evidence/','"'+str(ROOT/'kernel/src/learning_evidence')+'/')
            bridge=bridge.replace(str(ROOT/'kernel/src/learning_evidence/provenance.rs'),str(p));b.write_text(bridge)
            # This controlled PMCC cost models the real writer instructions;
            # source collector/samples/cleanup/service-I/O/Scheduler stay real.
            signature='pub(super) fn completed(e: Completion) {'
            if signature not in provenance: signature='pub(super) fn observed(e: Observation) {'
            self.assertIn(signature,provenance)
            p.write_text(provenance.replace(signature,signature+'\n    crate::recorder_cost();'))
            harness=harness.replace('"../../../kernel/src/domain_tasks/cancellation.rs"',json.dumps(str(ROOT/'kernel/src/domain_tasks/cancellation.rs')))
            harness=harness.replace('"../../../kernel/src/learning_evidence.rs"',json.dumps(str(b)));h.write_text(harness)
            (d/'Cargo.toml').write_text('[package]\nname="capture-paid-cost"\nversion="0.1.0"\nedition="2024"\n[[test]]\nname="paid-cost"\npath="test.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\n[workspace]\n')
            cmd=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-capture-paid-cost'),'--','--nocapture']
            def run(case,source=bridge,code=harness):
                b.write_text(source);h.write_text(code)
                e=env();e['CYXIA_SOURCE_COST_CASE']=case
                return subprocess.run(cmd,cwd=ROOT,env=e,capture_output=True,text=True,timeout=120)
            for case in ['cleanup','io','io_resume','generic','completion','import']:
                with self.subTest(case=case):
                    r=run(case)
                    self.assertEqual(r.returncode,0,case+'\n'+r.stdout+r.stderr)
            # Compile-valid mutations recreate the precise post-sample defect.
            helper=function(bridge,'pub(crate) fn measure_paid_task<R>')
            self.assertEqual(helper.count('let result = body(entry);'),1)
            late=helper.replace('let result = body(entry);','let result = body(None);')
            sample='let (first_ns, last_ns, _) = finish_cpu_interval(cpu_started);'
            self.assertEqual(late.count(sample),1)
            late=late.replace(sample,sample+'''\n    observe_paid_entry(&attempt,cpu_started,|| (2,Some(TaskIdentity {
                site:2,caller:cyxia_prototype::domains::ObjectKey{id:70,generation:8},request:9,
                child:cyxia_prototype::domains::ObjectKey{id:4097,generation:6},recipe:2,
            })));''')
            io=function(harness,'pub fn service_io_piece<R>')
            late_io,count=re.subn(r'\s*if let Some\(attempt\) = capture\.as_ref\(\) \{\s*crate::bridge::observe_service_io\(attempt, cpu_started\);\s*\}','',io)
            self.assertEqual(count,2)
            sample_io='let (first_ns, finished_ns, actual_ns) = finish_cpu_interval(cpu_started);'
            self.assertEqual(late_io.count(sample_io),2)
            late_io=late_io.replace(sample_io,sample_io+'\n if let Some(attempt)=capture.as_ref(){crate::bridge::observe_service_io(attempt,cpu_started);}')
            finish=function(bridge,'pub fn finish_attempt(')
            original_record='''Ok(token) => capture
                .record(token, attempt.core, first_ns, last_ns)
                .map_err(Error::from),'''
            self.assertEqual(finish.count(original_record),1)
            added=finish.replace(original_record,'''Ok(token) => {
                let result=capture.record(token,attempt.core,first_ns,last_ns).map_err(Error::from);
                provenance::observed(provenance::Observation {run:capture.config().unwrap().key,
                    offered:attempt.owner,direct:None,class:attempt.class,core:attempt.core,
                    started:0,site:5,identity:None});
                result
            },''')
            for case,source,code,failure in [
                ('cleanup',bridge.replace(helper,late),harness,'recorder17ns escaped original physical capture interval'),
                ('io',bridge,harness.replace(io,late_io),'recorder17ns escaped the actual submitted Scheduler debit'),
                ('completion',bridge.replace(finish,added),harness,'completion added uncharged diagnostic CPU'),
                ('import',bridge.replace(finish,added),harness,'import added uncharged diagnostic CPU'),
            ]:
                self.assertTrue(source!=bridge or code!=harness)
                r=run(case,source,code);output=r.stdout+r.stderr
                self.assertNotEqual(r.returncode,0,output)
                self.assertIn('Finished `test`',output,'negative control must compile: '+output)
                self.assertIn(failure,output)
            r=run('cleanup');self.assertEqual(r.returncode,0,r.stdout+r.stderr)

if __name__=='__main__':unittest.main()
