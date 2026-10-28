"""Real task-gate protection, then production admission and authorization.

Host clocks/CPU identity are explicit; no native timing claim is made.
"""
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class PaidOwnerTurn(unittest.TestCase):
    def test_real_gate_preserves_paid_turn_without_renewing_its_epoch(self):
        gate = (ROOT / 'kernel/src/domain_tasks/owner_gate.rs').read_text()
        # Before the API exists this no-op adapter permits a behavioral RED,
        # rather than making an absent method the test's failure condition.
        adapter = '' if 'fn protect_service_until(' in gate else '''
impl owner_gate::Permit<'_> {
    fn protect_service_until(&self, _: u64, _: u64) -> bool { false }
}
'''
        template = (ROOT / 'tests/host/paid_owner_turn_harness.rs').read_text()
        template = template.replace('// OWNER_GATE_MODULE', '#[path=' + json.dumps(str(
            ROOT / 'kernel/src/domain_tasks/owner_gate.rs')) + '] mod owner_gate;')
        template = template.replace('// BEFORE_API_ADAPTER', adapter)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rust = directory / 'harness.rs'
            binary = directory / 'test'
            rust.write_text(template)
            command = [str(RUST_BIN / 'rustc'), '--edition=2024', '--test', str(rust), '-o', str(binary)]
            compiled = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                      text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('6 passed; 0 failed', result.stdout)
            mutants = [
                ('if now < protected {',
                 'if now < protected && self.gate.waiting.load(Ordering::Acquire) != 0 {',
                 'paid_turn_also_excludes_a_peer_arriving_after_release',
                 'late peer stole the paid turn'),
                ('        self.waiting.fetch_and(!(1 << cpu), Ordering::AcqRel);',
                 '        self.epoch_start.store(now, Ordering::Relaxed);\n'
                 '        self.waiting.fetch_and(!(1 << cpu), Ordering::AcqRel);',
                 'repeated_credits_and_reborrows_cannot_refresh_the_epoch_cap',
                 'another credit renewed ahead of an existing peer'),
            ]
            for old, new, case, failure in mutants:
                self.assertEqual(gate.count(old), 1)
                mutant = directory / 'mutant.rs'
                mutant.write_text(gate.replace(old, new))
                rust.write_text(template.replace(str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs'),
                                                str(mutant)))
                compiled = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                          text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                negative = subprocess.run([str(binary), '--test-threads=1', '--exact', case],
                                          capture_output=True, text=True, timeout=30)
                self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
                self.assertIn(failure, negative.stdout + negative.stderr)

    def test_production_admission_and_authority_use_the_same_bounded_preference(self):
        source = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        pieces = [re.search(r'^static LOCK:.*;$', source, re.M)[0],
                  function(source, 'struct Guard'), function(source, 'impl Drop for Guard'),
                  function(source, 'fn acquire_guard()'), function(source, 'fn locked<R>'),
                  function(source, 'pub struct Credit'), function(source, 'fn admit_service('),
                  function(source, 'pub fn begin_service_segment()'),
                  function(source, 'fn revalidate_unstarted('),
                  function(source, 'pub fn revalidate_service_segment()'),
                  function(source, 'pub(crate) struct PaidServiceWitness'),
                  function(source, 'fn service_witness_locked('),
                  function(source, 'pub fn authorize_service_turn()')]
        for signature in ['impl Guard', 'fn locked_with_guard<R>']:
            if signature in source:
                pieces.append(function(source, signature))
        pieces.insert(0, '#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs'))
                      + '] mod owner_gate;')
        pieces.insert(0, '#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/service_authority.rs'))
                      + '] mod service_authority;')
        template = (ROOT / 'tests/host/paid_owner_admission_harness.rs').read_text().replace(
            '// PRODUCTION_BODIES', '\n'.join(pieces))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'harness.rs').write_text(template)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="paid-owner-admission"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-paid-owner-admission'),
                '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                    text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('2 passed; 0 failed', result.stdout)
            hook = '        guard.protect_service_dispatch(d);'
            self.assertEqual(template.count(hook), 1)
            (directory / 'harness.rs').write_text(template.replace(hook, ''))
            negative = subprocess.run(command + ['--exact',
                'actual_admission_authorizes_after_old_turn_end_and_settles_exact_work'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('fresh service grant lost its paid authorization turn',
                          negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
