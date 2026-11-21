"""Production child collection over explicit usercopy/publication boundaries.

Swap observations forward to the real primitive; capacities and wait delivery
come from production. Hardware, user memory and exit publication are fixtures.
The separate child-exit-custody suite covers publication/signals/accounting.
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


def production_fixture():
    spawn = (ROOT / 'kernel/src/desktop/user/spawn.rs').read_text()
    threads = (ROOT / 'kernel/src/desktop/user/threads.rs').read_text()
    usermem = (ROOT / 'crates/posix/src/usermem.rs').read_text()
    posix = (ROOT / 'crates/posix/src/lib.rs').read_text()
    process_capacity = usermem[usermem.index('#[cfg(feature = "cosmic-session")]'):
                               usermem.index('pub const POOL_PAGES:')]
    receipt_capacity = spawn[spawn.index('#[cfg(feature = "cosmic-session")]'):
                             spawn.index('#[derive(Clone, Copy)]')]
    thread_capacity = [line for line in threads.splitlines()
                       if line.startswith('pub(super) const MAX_THREADS:')]
    if len(thread_capacity) != 1:
        raise ValueError('Ambiguous production thread capacity')
    collect = function(spawn, '    pub(super) fn collect_children(')
    source = (ROOT / 'tests/host/child_collection_harness.rs').read_text()
    return (source.replace('// PROCESS_CAPACITY', process_capacity)
        .replace('// RECEIPT_CAPACITY', receipt_capacity)
        .replace('// THREAD_CAPACITY', thread_capacity[0])
        .replace('// ERRNO', function(posix, 'pub enum Errno'))
        .replace('// USER_STATE', function(posix, 'pub enum UserState') + '\n' + function(posix, 'impl UserState'))
        .replace('// RECEIPT_TYPES', '#[derive(Clone, Copy)]\n' + function(spawn, 'struct Receipt')
                 + '\n' + function(spawn, 'pub(super) struct Children') + '\n' + function(spawn, 'impl Children'))
        .replace('// RUNNABLE', function(threads, '    fn runnable('))
        .replace('// RUNNER_METHODS', '\n'.join([function(spawn, '    pub(super) fn supervisor_result('),
            function(threads, '    pub(super) fn refresh_thread_state('),
            function(threads, '    pub(super) fn has_runnable_thread(')]))
        .replace('// COLLECT', collect.replace('core::mem::swap', 'observed_swap')))


class ChildCollection(unittest.TestCase):
    def test_wait_semantics_and_only_child_wait_contexts_are_exchanged(self):
        with tempfile.TemporaryDirectory(prefix='cyxia-child-collection-') as temporary:
            directory = Path(temporary)
            source = directory / 'collection.rs'
            source.write_text(production_fixture())
            environment = dict(env(), RUST_MIN_STACK='16777216')
            for session in (False, True):
                with self.subTest(cosmic_session=session):
                    binary = directory / ('session' if session else 'legacy')
                    flags = ['--cfg', 'feature="full-os"', '--cfg', 'feature="cosmic-session"'] if session else []
                    compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                        '--cfg', 'feature="ported"', *flags, '-Dwarnings', str(source), '-o', str(binary)],
                        capture_output=True, text=True, env=environment, timeout=30)
                    self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                    ran = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                                         text=True, env=environment, timeout=15)
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
                    self.assertIn('8 passed; 0 failed', ran.stdout)


if __name__ == '__main__':
    unittest.main()
