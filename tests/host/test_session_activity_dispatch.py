"""Actual OP_TASK dispatch, phase9 Authority and service CPU sample boundaries.

Only hardware clock/socket/wait and service registration are controlled. The
production Scheduler debits the measured cost; host cost is not native WCET.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class SessionActivityDispatch(unittest.TestCase):
    def test_native_activity_guards_fresh_wait_and_paid_dispatch(self):
        native = (ROOT / 'kernel/src/unified.rs').read_text()
        task = (ROOT / 'kernel/src/unified_task.rs').read_text()
        arm = function(native, 'abi::OP_TASK =>')
        phase = function(task, 'if phase == 9')
        template = (ROOT / 'tests/host/session_activity_dispatch_harness.rs').read_text()
        code = template.replace('// PHASE9', phase).replace('// OP_TASK', arm)
        code = code.replace('// SAMPLES', '\n'.join(function(native, name) for name in
            ['fn finish_service(', 'fn service_start(']))
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            rust = d / 'harness.rs'
            (d / 'Cargo.toml').write_text(
                '[package]\nname="session-activity-dispatch"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-kernel-core={path='
                + json.dumps(str(ROOT / 'crates/kernel-core')) + '}\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                       str(d / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-session-activity'),
                       '--', '--test-threads=1']
            def run(source):
                rust.write_text(source)
                result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                        text=True, timeout=120)
                print('$ ' + ' '.join(command))
                print(result.stdout + result.stderr)
                print('EXIT', result.returncode)
                return result
            result = run(code)
            self.assertEqual(result.returncode, 0)
            for old, new, failure in [
                ('Board.now_ms(),', '0,', 'stale activity after broker wait'),
                ('(!connected || offset != epoch)', 'false', 'changed transport admitted activity'),
                ('finish_service(started);', 'finish_service(timer::cpu_ticks());', 'activity escaped original Scheduler debit'),
            ]:
                self.assertIn(old, code)
                result = run(code.replace(old, new))
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Finished `test`', output)
                self.assertIn(failure, output)


if __name__ == '__main__':
    unittest.main()
