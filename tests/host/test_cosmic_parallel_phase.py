"""Run the actual multi-worker completion loop with a deterministic AP clock.

The two live jobs model a polling parent and CPU-bound child. Mailboxes, timers
and CPU wakeups are host fixtures; this does not attest hardware execution.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class CosmicParallelPhase(unittest.TestCase):
    def test_fast_peer_cannot_truncate_the_session_child_quantum(self):
        source = (ROOT / 'kernel/src/desktop/user/parallel.rs').read_text()
        phase = function(source, 'if tickets.iter().any(Option::is_some)')
        template = (ROOT / 'tests/host/cosmic_parallel_phase_harness.rs').read_text()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rust = directory / 'phase.rs'
            rust.write_text(template.replace('// PRODUCTION_PHASE', phase))
            for session in (True, False):
                with self.subTest(session=session):
                    binary = directory / ('session' if session else 'legacy')
                    command = [str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                               '-Dwarnings', str(rust), '-o', str(binary)]
                    if session:
                        command += ['--cfg', 'feature="cosmic-session"']
                    compiled = subprocess.run(command, env=env(), capture_output=True,
                                              text=True, timeout=30)
                    self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                    ran = subprocess.run([str(binary), '--test-threads=1'], env=env(),
                                         capture_output=True, text=True, timeout=10)
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)


if __name__ == '__main__':
    unittest.main()
