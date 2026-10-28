"""Production service authority with independent wall and CPU observations."""
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


class ServiceExecutionClock(unittest.TestCase):
    def test_original_service_reservation_is_execution_credit_not_a_wall_lease(self):
        source = (ROOT / 'kernel/src/domain_tasks/service_authority.rs').read_text()
        # Keep the old authority body executable for behavioral RED before
        # its view gains an execution observation. No budget behavior is added.
        if 'pub execution_ns:' not in source:
            source = source.replace('    pub settlement_pending: bool,',
                '    pub settlement_pending: bool,\n    pub execution_ns: Option<u64>,')
        template = (ROOT / 'tests/host/service_execution_clock_harness.rs').read_text()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            authority = directory / 'authority.rs'
            authority.write_text(source)
            (directory / 'harness.rs').write_text(template.replace('// AUTHORITY_MODULE',
                '#[path=' + json.dumps(str(authority)) + '] mod service_authority;'))
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="service-execution-clock"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-service-execution-clock'),
                '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                    text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('4 passed; 0 failed', result.stdout)
            condition = 'if execution_ns >= d.reserved_ns {'
            self.assertEqual(source.count(condition), 1)
            authority.write_text(source.replace(condition,
                'if now >= d.started_ns.saturating_add(d.reserved_ns) {'))
            negative = subprocess.run(command + ['--exact',
                'host_pause_within_original_window_does_not_spend_cpu_credit'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('service CPU reservation was converted into a 2.5 ms wall lease',
                          negative.stdout + negative.stderr)

    def test_production_witness_keeps_one_counter_origin_and_settles_exact_cpu(self):
        source = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        facade = (ROOT / 'tests/host/paid_owner_admission_harness.rs').read_text().split('// PRODUCTION_BODIES')[0]
        if 'static CPU_WORK:' not in facade:
            facade = facade.replace('static NOW:', 'static CPU_WORK: AtomicU64 = AtomicU64::new(1_000);\nstatic NOW:')
        if 'pub fn cpu_ticks()' not in facade:
            facade = facade.replace('pub fn frequency() -> u64 { 1_000_000_000 }',
                'pub fn frequency() -> u64 { 1_000_000_000 }\n'
                '    pub fn cpu_ticks() -> u64 { super::CPU_WORK.load(super::Ordering::Acquire) }\n'
                '    pub fn cpu_ns(ticks: u64) -> u64 { ticks }')
        facade = facade.replace('optional: Option<CpuDebit> }',
            'optional: Option<CpuDebit>, cpu_started: Option<u64> }')
        pieces = [re.search(r'^static LOCK:.*;$', source, re.M)[0]]
        for signature in ['struct Guard', 'impl Guard', 'impl Drop for Guard', 'fn acquire_guard()',
                          'fn locked<R>', 'fn locked_with_guard<R>', 'pub struct Credit', 'fn admit_service(',
                          'pub fn begin_service_segment()', 'pub(crate) struct PaidServiceWitness',
                          'fn service_witness_locked(', 'pub fn authorize_service_turn()']:
            body = function(source, signature)
            if signature == 'pub fn begin_service_segment()' and 'cpu_started' not in body:
                # Metadata-only adapter lets the old witness execute. It
                # continues ignoring the observation and fails behaviorally.
                body = body.replace('s.active[0] = Some(Active {',
                    's.active[0] = Some(Active { cpu_started: Some(timer::cpu_ticks()),')
            pieces.append(body)
        pieces.insert(0, '#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs'))
                      + '] mod owner_gate;')
        pieces.insert(0, '#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/service_authority.rs'))
                      + '] mod service_authority;')
        template = (ROOT / 'tests/host/service_credit_binding_harness.rs').read_text().replace(
            '// OWNER_FACADE', facade).replace('// PRODUCTION_BODIES', '\n'.join(pieces))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'harness.rs').write_text(template)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="service-credit-binding"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-service-credit-binding'),
                '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                    text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('2 passed; 0 failed', result.stdout)
            mutant, count = re.subn(r'\.checked_sub\(started\)\s*\.ok_or\(Error::Range\)\?',
                '.saturating_sub(started)', template)
            self.assertEqual(count, 1)
            (directory / 'harness.rs').write_text(mutant)
            negative = subprocess.run(command + ['--exact',
                'missing_or_regressed_counter_origin_fails_without_changing_dispatch_custody'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('PMU rollback became zero execution cost', negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
