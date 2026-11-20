"""Run actual thread preparation; observe context swaps at its memory seam."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


def production_fixture(source=None):
    source = source or (ROOT / 'kernel/src/desktop/user/threads.rs').read_text()
    capacity = [line for line in source.splitlines()
                if line.startswith('pub(super) const MAX_THREADS:')]
    if len(capacity) != 1:
        raise ValueError('ambiguous production thread capacity')
    prepare = function(source, '    pub(super) fn prepare_threads(')
    # Only the memory swap primitive is observed; each call forwards to the
    # real core::mem::swap. The production control flow and policies are intact.
    prepare = prepare.replace('core::mem::swap', 'observed_swap')
    methods = '\n'.join(function(source, signature) for signature in
        ('    pub(super) fn refresh_thread_state(', '    pub(super) fn has_runnable_thread('))
    return ((ROOT / 'tests/host/thread_prepare_harness.rs').read_text()
        .replace('// PRODUCTION_CAPACITY', capacity[0].replace('pub(super)', 'pub'))
        .replace('// PRODUCTION_RUNNABLE', function(source, '    fn runnable('))
        .replace('// PRODUCTION_PREPARE', prepare + '\n' + methods))


class ThreadPreparation(unittest.TestCase):
    def test_in_place_pending_transfer_and_only_needed_context_swaps(self):
        with tempfile.TemporaryDirectory(prefix='cyxia-thread-prepare-') as directory:
            directory = Path(directory)
            source = directory / 'prepare.rs'
            source.write_text(production_fixture())
            for full_os in (False, True):
                with self.subTest(full_os=full_os):
                    binary = directory / ('full-os' if full_os else 'legacy')
                    flags = ['--cfg', 'feature="full-os"'] if full_os else []
                    built = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                        '--cfg', 'feature="ported"', *flags, '-Dwarnings', str(source), '-o', str(binary)],
                        env=env(), capture_output=True, text=True, timeout=30)
                    self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                    ran = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                                         text=True, timeout=10)
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
                    self.assertIn('4 passed; 0 failed', ran.stdout)


if __name__ == '__main__':
    unittest.main()
