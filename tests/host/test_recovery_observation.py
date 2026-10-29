"""Actual recovery phase/backend provenance; no native liveness claim."""
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


class RecoveryObservation(unittest.TestCase):
    def test_actual_paid_task_predicates_and_cleanup_match_supervisor_custody(self):
        from test_paid_lifecycle_progress import program
        execution=(ROOT/'kernel/src/domain_tasks/execution.rs').read_text()
        service=(ROOT/'kernel/src/domain_services.rs').read_text()
        evidence=(ROOT/'kernel/src/domain_evidence.rs').read_text()
        code=program().split('const TASKS:usize=4;',1)[0]
        # Keep the existing support boundaries/setup/helpers, omit old tests.
        support=(ROOT/'tests/host/paid_lifecycle_support.rs').read_text().split('#[test]',1)[0]
        code+='\n'+support
        # Task-independent domain_platform is already in the billing fixture.
        extra=(ROOT/'tests/host/recovery_predicate_support.rs').read_text()
        extra=extra.replace('mod domain_platform{pub fn now_ns()->u64{super::now_ns()}}','')
        signatures=['fn recovery_index(','pub fn close_admission(','pub fn readonly_drained(', 'pub fn request_stop(', 'pub fn stopped(', 'pub fn running(']
        if 'struct RecoveryPredicate' in execution:signatures+=['struct RecoveryPredicate','impl RecoveryPredicate']
        extra=extra.replace('// ACTUAL_RECOVERY_TASK_BODIES','\n'.join(function(execution,s) for s in signatures))
        extra=extra.replace('// KERNEL_RECOVERY_BACKEND',function(service,'struct Recovery {')+'\n'+function(service,'impl RecoveryBackend for Recovery'))
        # Recovery creation/EL0 return are explicit facades in this predicate
        # regression; no all-true drained/stopped/running substitutions.
        code=code.replace('authorize_service_turn, service_baseline_progress};','authorize_service_turn, service_baseline_progress, close_admission, readonly_drained, request_stop, stopped, running};\n    pub fn start_generation(k:super::ObjectKey,n:u64,a:super::ApplyId)->Result<(),super::Error>{super::construct_recovery_generation(k,n,a)}')
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);module=d/'evidence.rs'
            module.write_text(evidence+'\npub fn header()->[u64;512]{core::array::from_fn(get)}\npub fn clear_recovery(){for i in 256..512{put(i,0)}}\n')
            extra=extra.replace('// EVIDENCE_MODULE','#[path='+json.dumps(str(module))+'] mod domain_evidence;')
            source=d/'harness.rs';source.write_text(code+'\n'+extra)
            (d/'Cargo.toml').write_text('[package]\nname="recovery-predicates"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'test','--offline','--lib','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-recovery-predicates'),'--','--test-threads=1','recovery_predicates_']
            r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertIn('2 passed; 0 failed',r.stdout)

    def test_actual_supervisor_and_kernel_backend_keep_phase_result_and_single_issue(self):
        service=(ROOT/'kernel/src/domain_services.rs').read_text()
        evidence=(ROOT/'kernel/src/domain_evidence.rs').read_text()
        code=(ROOT/'tests/host/recovery_observation_harness.rs').read_text()
        code=code.replace('// KERNEL_RECOVERY_BACKEND',function(service,'struct Recovery {')+'\n'+function(service,'impl RecoveryBackend for Recovery'))
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);module=d/'evidence.rs'
            module.write_text(evidence+'\npub fn header()->[u64;512]{core::array::from_fn(get)}\npub fn clear_recovery(){for i in 256..512{put(i,0)}}\n')
            code=code.replace('// EVIDENCE_MODULE','#[path='+json.dumps(str(module))+'] mod domain_evidence;')
            source=d/'harness.rs';source.write_text(code)
            (d/'Cargo.toml').write_text('[package]\nname="recovery-observation"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='+json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'test','--offline','--lib','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(ROOT/'target/host-recovery-observation'),'--','--test-threads=1','recovery_observation_']
            r=subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=120)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertIn('3 passed; 0 failed',r.stdout)


if __name__=='__main__':unittest.main()
