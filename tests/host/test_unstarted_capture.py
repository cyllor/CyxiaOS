"""Real scheduler cancellation must not manufacture an unfinished CPU event."""
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


class UnstartedCapture(unittest.TestCase):
    def test_non_test_local_peer_and_prewarm_custody_survive_busy_and_refund_failure(self):
        source = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        template = (ROOT / 'tests/host/unstarted_custody_harness.rs').read_text()
        pieces = [re.search(r'^static LOCK:.*;$', source, re.M)[0]]
        pieces += [re.search(rf'^const {name}: u64 = .*;$', source, re.M)[0] for name in
                   ['BUILTIN_WINDOW_HEADROOM_NS', 'BUILTIN_MIN_GRANT_NS', 'DYNAMIC_EL0_MIN_GRANT_NS']]
        for name in ['owner_gate', 'service_authority']:
            pieces.append('#[path=' + json.dumps(str(ROOT / f'kernel/src/domain_tasks/{name}.rs'))
                          + f'] mod {name};')
        for signature in ['struct Guard', 'impl Guard', 'impl Drop for Guard', 'fn acquire_guard()',
                          'fn locked<R>', 'fn locked_with_guard<R>', 'pub struct Credit',
                          'fn admit_service(', 'pub fn begin_service_segment()', 'fn begin_file_credit(',
                          'fn throttle(', 'fn refresh_throttled(', 'pub fn begin_builtin(',
                          'fn revalidate_unstarted(', 'pub fn revalidate_service_segment()',
                          'pub(crate) struct PaidServiceWitness', 'fn service_witness_locked(',
                          'pub fn authorize_service_turn()']:
            body = function(source, signature)
            if signature == 'pub struct Credit':
                body = '#[derive(Clone, Copy)]\n' + body
            pieces.append(body)
        capture_start = min(source.index('#[path = "domain_tasks/capture_credit.rs"]'),
                            source.index('#[path = "domain_tasks/cancellation.rs"]'))
        capture = source[capture_start:source.index('fn throttle(')]
        pieces.append(capture.replace('"domain_tasks/', '"' + str(ROOT / 'kernel/src/domain_tasks') + '/'))
        warm = (ROOT / 'crates/prototype/tests/native_prewarm.rs').read_text()
        platform = warm[warm.index('pub mod domain_control {'):warm.index('pub mod learning_evidence {')]
        platform = platform.replace('pub mod domain_control {', '''pub mod domain_control {
    pub struct Prerequisite { pub domain: u16, pub target: super::ObjectKey }
    pub fn admit_dependency(_: Prerequisite, _: u64, _: u64) -> Result<(), super::Error> { Ok(()) }
''')
        modules = '\n'.join('#[path=' + json.dumps(str(ROOT / f'kernel/src/{name}.rs'))
                            + f'] mod {name};' for name in ['learning_evidence', 'learning_prewarm'])
        peer = (ROOT / 'crates/peer-billing/tests/native_attempt.rs').read_text()
        # The same platform fixture executes unchanged production Attempt and
        # Ledger, now linked to the real non-cfg(test) local OwnerAttempt.
        peer = peer[peer.index('use core::sync::atomic::'):peer.index('#[test]')]
        peer = peer.replace('mod ledger;', 'mod ledger;').replace('"../../../kernel/src/',
            '"' + str(ROOT / 'kernel/src') + '/')
        peer = peer.replace('    Some(16)', '    Some(14)')
        peer = peer.replace('fn family()', 'pub(super) fn family()')
        peer = peer.replace('CpuInterval, OBSERVATION_NS', 'CpuInterval')
        peer = peer.replace('static LEDGER:', 'pub(super) static LEDGER:')
        peer = peer.replace('fn reset()', 'pub(super) fn reset()')
        peer = peer.replace('fn ledger_with<T>', 'pub(super) fn ledger_with<T>')
        peer += '\npub use owner_attempt::{Attempt, attempt, finish};\n'
        peer += 'pub(crate) use owner_attempt::cancel_unstarted;\n'
        program = template.replace('// PRODUCTION_BODIES', '\n'.join(pieces)).replace(
            '// WARM_PLATFORM_FIXTURES', platform).replace('// EVIDENCE_MODULES', modules).replace(
            '// PEER_FIXTURE', 'mod peer_replay {\n' + peer + '\n}')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original_capture = ROOT / 'kernel/src/domain_tasks/capture_credit.rs'
            capture_path = directory / 'capture_credit.rs'
            capture_path.write_text(original_capture.read_text() + '\n' +
                (ROOT / 'tests/host/unstarted_capture_test_support.rs').read_text())
            program = program.replace(str(original_capture), str(capture_path))
            (directory / 'harness.rs').write_text(program)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="unstarted-custody"\nversion="0.1.0"\nedition="2024"\n'
                '[[bin]]\nname="custody"\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\ncyxia-peer-billing={path='
                + json.dumps(str(ROOT / 'crates/peer-billing')) + '}\nsha2="=0.10.9"\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'run', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-unstarted-custody'), '--bin', 'custody']
            result = subprocess.run(command,
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('all cancellation custodians passed', result.stdout)
            for signature, failure in [
                ('pub fn begin_service_segment()', 'service did not retire cancelled custody'),
                ('pub fn begin_builtin(', 'builtin did not retire cancelled custody'),
                ('fn begin_file_credit(', 'file did not retire cancelled custody'),
            ]:
                body = function(program, signature)
                mutant, count = re.subn(r'if !capture_credit::retire\((?:0|slot)\)',
                                        'if false', body)
                self.assertEqual(count, 1)
                (directory / 'harness.rs').write_text(program.replace(body, mutant))
                negative = subprocess.run(command, cwd=ROOT, env=env(),
                    capture_output=True, text=True, timeout=120)
                self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
                self.assertIn(failure, negative.stdout + negative.stderr)

    def test_cancelled_dispatch_has_no_executed_interval_to_lose(self):
        source = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        facade = (ROOT / 'tests/host/paid_owner_admission_harness.rs').read_text().split('// PRODUCTION_BODIES')[0]
        facade = re.sub(r'fn track_credit\([^\n]+\n', '', facade)
        facade = re.sub(r'fn discard_capture\([^\n]+\n', '', facade)
        if 'mod capture_credit {' in facade:
            facade = facade.replace(function(facade, 'mod capture_credit {'), '')
        if 'mod learning_evidence {' in facade:
            facade = facade.replace(function(facade, 'mod learning_evidence {'), '')
        facade = facade.replace('use core::sync::atomic::',
            'extern crate self as cyxia_arch_aarch64;\nuse core::sync::atomic::', 1)
        if 'struct Captures(' in source:
            capture = source[source.index('struct Captures('):source.index('fn throttle(')]
        else:
            capture_start = min(source.index('#[path = "domain_tasks/capture_credit.rs"]'),
                                source.index('#[path = "domain_tasks/cancellation.rs"]'))
            capture = source[capture_start:source.index('fn throttle(')]
            capture = capture.replace('"domain_tasks/', '"' + str(ROOT / 'kernel/src/domain_tasks') + '/')
        pieces_extra = ''
        if 'struct Captures(' not in source:
            pieces_extra = 'mod domain_tasks { pub(crate) use super::Cancellation; }'
        pieces = [re.search(r'^static LOCK:.*;$', source, re.M)[0], capture]
        for signature in ['struct Guard', 'impl Guard', 'impl Drop for Guard', 'fn acquire_guard()',
                          'fn locked<R>', 'fn locked_with_guard<R>', 'pub struct Credit',
                          'fn admit_service(', 'pub fn begin_service_segment()',
                          'fn revalidate_unstarted(', 'pub fn revalidate_service_segment()']:
            pieces.append(function(source, signature))
        pieces.insert(0, '#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs'))
                      + '] mod owner_gate;')
        template = (ROOT / 'tests/host/unstarted_capture_harness.rs').read_text()
        program = facade + '\n' + pieces_extra + '\n' + '\n'.join(pieces) + '\n' + template.replace(
            '// EVIDENCE_MODULE', '#[path=' + json.dumps(str(ROOT / 'kernel/src/learning_evidence.rs'))
            + '] mod learning_evidence;')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'harness.rs').write_text(program)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="unstarted-capture"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            result = subprocess.run([str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-unstarted-capture'), '--lib', '--', '--test-threads=1'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('1 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
