"""Execute the real OS idle boundary and x86 sleep primitive with IRQ fixtures.

The fixture clocks/interrupts expose unnecessary scheduler sleeps and the
check-to-HLT race. They do not replace guest timing or hardware IRQ validation.
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


class ReadyIdle(unittest.TestCase):
    def test_actual_readiness_checks_selected_and_parked_threads(self):
        threads = (ROOT / 'kernel/src/desktop/user/threads.rs').read_text()
        methods = ('impl Thread {\n' + function(threads, '    fn runnable(') + '\n}\n'
                   + 'impl Runner {\n' + function(threads, '    pub(super) fn has_runnable_thread(')
                   .replace('pub(super)', 'pub') + '\n}\n')
        capacities = [line for line in threads.splitlines()
                      if line.startswith('pub(super) const MAX_THREADS:')]
        self.assertEqual(len(capacities), 1)
        source = '#![allow(dead_code)]\n' + capacities[0].replace('pub(super)', 'pub') + '''
#[derive(Clone, Copy)]
struct Thread { active: bool, waiting: Option<()> }
struct Group { parked: [Thread; MAX_THREADS - 1] }
struct Runner { thread: Thread, threads: Group }
''' + methods + '''
#[test]
fn readiness_tracks_every_live_thread_without_running_waiters() {
    let inactive = Thread { active: false, waiting: None };
    let mut runner = Runner { thread: inactive, threads: Group { parked: [inactive; MAX_THREADS - 1] } };
    assert!(!runner.has_runnable_thread());
    runner.thread.active = true;
    assert!(runner.has_runnable_thread());
    runner.thread.waiting = Some(());
    assert!(!runner.has_runnable_thread());
    for index in 0..MAX_THREADS - 1 {
        runner.threads.parked[index] = Thread { active: true, waiting: None };
        assert_eq!(runner.has_runnable_thread(), cfg!(feature = "ported"));
        runner.threads.parked[index].waiting = Some(());
        assert!(!runner.has_runnable_thread());
        runner.threads.parked[index] = inactive;
    }
}
'''
        with tempfile.TemporaryDirectory(prefix='cyxia-thread-readiness-') as directory:
            directory = Path(directory)
            rust = directory / 'ready.rs'
            rust.write_text(source)
            for ported, full_os in ((False, False), (True, False), (True, True)):
                binary = directory / f'ready-{ported}-{full_os}'
                command = [str(RUST_BIN / 'rustc'), '--edition=2024', '--test', '-Dwarnings', str(rust), '-o', str(binary)]
                if ported:
                    command += ['--cfg', 'feature="ported"']
                if full_os:
                    command += ['--cfg', 'feature="full-os"']
                compiled = subprocess.run(command, env=env(), capture_output=True, text=True, timeout=30)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_ready_work_never_pays_an_idle_tick(self):
        runtime = (ROOT / 'kernel/src/arch/x86_64/runtime.rs').read_text()
        os = (ROOT / 'kernel/src/runtime/os.rs').read_text()
        primitive = function(runtime, 'pub fn idle_until(')
        if 'pub fn idle_until_while(' in runtime:
            primitive += '\n' + function(runtime, 'pub fn idle_until_while(')
        template = (ROOT / 'tests/host/os_ready_idle_harness.rs').read_text()
        rust = template.replace('// PRODUCTION_IDLE', function(os, 'fn idle(')).replace(
            '// PRODUCTION_PRIMITIVE', primitive)
        with tempfile.TemporaryDirectory(prefix='cyxia-ready-idle-') as directory:
            directory = Path(directory)
            source = directory / 'idle.rs'
            binary = directory / 'idle'
            source.write_text(rust)
            compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                '-Dwarnings', str(source), '-o', str(binary)], env=env(),
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                                 text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('4 passed; 0 failed', ran.stdout)


if __name__ == '__main__':
    unittest.main()
