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
                          'pub fn authorize_service_turn()', 'pub fn complete_builtin(']:
            body = function(source, signature)
            if signature == 'pub struct Credit':
                body = '#[derive(Clone, Copy)]\n' + body
            pieces.append(body)
        for signature in ['pub fn close_cpu(', 'pub fn quiescent(']:
            if signature in source:
                pieces.append(function(source, signature))
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
        runtime = (ROOT / 'kernel/src/prototype_runtime.rs').read_text()
        tail = function(runtime, 'fn stop_action_tail(')
        tail = tail[:tail.index('    worker.context = None;')] + '''
    // Hardware timer/GIC/TLB tail is outside this host fixture. Retain the
    // actual task/retirement prefix and stop_turn that decides entry to it.
    worker.context = None;
    STOP_TASK_ACK.store(operation, Ordering::Release);
    STOP_ACK.store(operation, Ordering::Release);
}
'''
        disabled = function((ROOT / 'kernel/src/smp.rs').read_text(), 'if !view.enabled {')
        program = program.replace('// STOP_BODIES', function(runtime, 'pub(super) fn stop_turn(') + '\n' + tail)
        program = program.replace('// DISABLED_BRANCH', disabled)
        program = program.replace('// LOCAL_RETIRE_EXPORT',
            'pub(crate) use super::retire_cpu_capture;' if 'fn retire_cpu_capture(' in source else '')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            evidence_path = directory / 'learning_evidence.rs'
            evidence_path.write_text((ROOT / 'kernel/src/learning_evidence.rs').read_text().replace(
                '"learning_evidence/', '"' + str(ROOT / 'kernel/src/learning_evidence') + '/') + '''
pub fn host_with_collector(f: impl FnOnce()) { let _guard = lock().unwrap(); f(); }
pub fn host_completion(attempt: &OwnerAttempt) -> Option<(u64,u64)> { attempt.measured }
pub fn host_handoff() -> [u64;32] { handoff::host_snapshot() }
pub fn host_drain() { for _ in 0..16 { handoff::drain(1); } }
''')
            handoff_path = directory / 'handoff.rs'
            handoff_path.write_text((ROOT / 'kernel/src/learning_evidence/handoff.rs').read_text() + '''
pub(super) fn host_snapshot() -> [u64;32] {
    core::array::from_fn(|i| REPLAY_CAPTURE_EVIDENCE.0[i].load(Ordering::Acquire))
}
''')
            evidence_path.write_text(evidence_path.read_text().replace(
                str(ROOT / 'kernel/src/learning_evidence/handoff.rs'), str(handoff_path)))
            warm_path = directory / 'learning_prewarm.rs'
            warm_path.write_text((ROOT / 'kernel/src/learning_prewarm.rs').read_text() + '''
pub fn host_counts() -> (usize,usize,bool) {
    (OPEN.load(Ordering::Acquire), HEAD[3].load(Ordering::Acquire), LOST.load(Ordering::Acquire))
}
''')
            program = program.replace(str(ROOT / 'kernel/src/learning_evidence.rs'), str(evidence_path))
            program = program.replace(str(ROOT / 'kernel/src/learning_prewarm.rs'), str(warm_path))
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
                + json.dumps(str(ROOT / 'crates/peer-billing')) + '}\ncyxia-kernel-core={path='
                + json.dumps(str(ROOT / 'crates/kernel-core')) + '}\nsha2="=0.10.9"\n'
                '[features]\ndefault=["unified-runtime","prototype-runtime"]\nunified-runtime=[]\nprototype-runtime=[]\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'run', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-unstarted-custody'), '--bin', 'custody']
            result = subprocess.run(command,
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('all cancellation custodians passed', result.stdout)
            completed_env = env()
            completed_env['CYXIA_COMPLETED_TEST'] = '1'
            completed = subprocess.run(command, cwd=ROOT, env=completed_env,
                capture_output=True, text=True, timeout=120)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn('completed dispatch custody passed', completed.stdout)
            stop_env = env()
            stop_env['CYXIA_COMPLETED_TEST'] = 'stop'
            stopped = subprocess.run(command, cwd=ROOT, env=stop_env,
                capture_output=True, text=True, timeout=120)
            self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
            self.assertIn('disabled CPU2 completion custody passed', stopped.stdout)
            stop_guard = '''        if !crate::domain_tasks::retire_cpu_capture(2) {
            return;
        }
'''
            self.assertEqual(program.count(stop_guard), 1)
            (directory / 'harness.rs').write_text(program.replace(stop_guard, ''))
            negative = subprocess.run(command, cwd=ROOT, env=stop_env,
                capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('disabled CPU2 acknowledged stop', negative.stdout + negative.stderr)
            (directory / 'harness.rs').write_text(program)
            capture_text = capture_path.read_text()
            retirement = function(capture_text, 'pub(super) fn retire(')
            guard = 'if !finish_completed(capture, true)'
            self.assertEqual(retirement.count(guard), 1)
            capture_path.write_text(capture_text.replace(retirement, retirement.replace(guard, 'if false')))
            negative = subprocess.run(command, cwd=ROOT, env=completed_env,
                capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('completed token allowed a new grant', negative.stdout + negative.stderr)
            capture_path.write_text(capture_text)
            original_builtin = function(program, 'pub fn begin_builtin(')
            first_settlement = '''    if COMPLETE_READY[slot].load(Ordering::Acquire) {
        let _ = locked(|s| complete_locked(s, slot));
    }
'''
            self.assertEqual(original_builtin.count(first_settlement), 1)
            (directory / 'harness.rs').write_text(program.replace(original_builtin,
                original_builtin.replace(first_settlement, '')))
            negative = subprocess.run(command, cwd=ROOT, env=completed_env,
                capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('capture Busy prevented original Scheduler settlement', negative.stdout + negative.stderr)
            (directory / 'harness.rs').write_text(program)
            capture_path.write_text(capture_text.replace('*binding != capture.binding', 'false'))
            negative = subprocess.run(command, cwd=ROOT, env=completed_env,
                capture_output=True, text=True, timeout=120)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('mismatched retained identity', negative.stdout + negative.stderr)
            capture_path.write_text(capture_text)
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
