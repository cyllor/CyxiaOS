"""Exercise owned subprocess cleanup and real PTY verification boundaries."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from tools import build_cosmic
import verify_pty


class BoundsTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "fixture requires Linux subreaper/procfs")
    def test_timeout_kills_child_after_leader_exits_on_term(self):
        # Adopt/reap the fixture's orphan instead of relying on container PID 1.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        child = None
        reaped = False
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / 'child.pid'
            program = '''import os, signal, sys, time
from pathlib import Path
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.alarm(10)
    Path(sys.argv[1]).write_text(str(os.getpid()))
    while True: time.sleep(.01)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(.01)
'''
            try:
                with self.assertRaisesRegex(build_cosmic.CosmicBuildError, 'deadline'):
                    build_cosmic.run_bounded([sys.executable, '-c', program, str(pidfile)],
                        root, dict(os.environ), root / 'log', .5, 0, 10**8)
                child = int(pidfile.read_text())
                # Inspect immediately at the return boundary, before waiting or
                # reaping. A zombie is stopped and cannot touch build outputs.
                state = Path(f'/proc/{child}/stat').read_text().rpartition(') ')[2].split()[0]
                self.assertIn(state, ('Z', 'X'), 'owned child still live when cleanup returned')
            finally:
                if child is None and not reaped and pidfile.exists():
                    child = int(pidfile.read_text())
                if child is not None and not reaped:
                    try:
                        # First reap an already terminated child. Once reaped,
                        # its numeric PID no longer authorizes any signal.
                        waited, _ = os.waitpid(child, os.WNOHANG)
                        if waited == child:
                            reaped = True
                        else:
                            os.kill(child, signal.SIGKILL)
                            os.waitpid(child, 0)
                            reaped = True
                    except ChildProcessError:
                        reaped = True
                libc.prctl(36, previous.value, 0, 0, 0)

    def run_term_ignoring_leader(self, observer_failure=False, probe_failure=False):
        owned = []
        original_popen = subprocess.Popen
        original_killpg = os.killpg
        probe_denials = 0
        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            owned.append(process)
            return process
        def killpg(pgid, signum):
            nonlocal probe_denials
            if probe_failure and signum == 0 and probe_denials < 2:
                probe_denials += 1
                raise PermissionError('injected group probe denial')
            return original_killpg(pgid, signum)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = ('import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                       'signal.alarm(10); time.sleep(9)')
            try:
                with patch.object(build_cosmic.subprocess, 'Popen', side_effect=spawn), \
                     patch.object(build_cosmic.os, 'killpg', side_effect=killpg):
                    if observer_failure:
                        with patch.object(build_cosmic, 'process_group_live',
                                          side_effect=PermissionError('injected observer denial')):
                            with self.assertRaises(build_cosmic.CosmicBuildError) as caught:
                                build_cosmic.run_bounded([sys.executable, '-c', program],
                                    root, dict(os.environ), root / 'log', .5, 0, 10**8)
                        self.assertIn('injected observer denial', str(caught.exception))
                    elif probe_failure:
                        with self.assertRaisesRegex(build_cosmic.CosmicBuildError, 'deadline') as caught:
                            build_cosmic.run_bounded([sys.executable, '-c', program],
                                root, dict(os.environ), root / 'log', .5, 0, 10**8)
                        self.assertIn('injected group probe denial', str(caught.exception))
                        self.assertEqual(probe_denials, 2)
                    else:
                        # Force the portable existence observer without procfs.
                        with patch.object(build_cosmic.sys, 'platform', 'portable-test'):
                            with self.assertRaisesRegex(build_cosmic.CosmicBuildError, 'deadline'):
                                build_cosmic.run_bounded([sys.executable, '-c', program],
                                    root, dict(os.environ), root / 'log', .5, 0, 10**8)
                self.assertEqual(owned[0].returncode, -signal.SIGKILL,
                                 'leader must be stopped and reaped before return')
            finally:
                for process in owned:
                    # Popen retains ownership until poll/wait reaps; do not
                    # signal a numeric PID after that ownership has ended.
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)

    def test_observer_failure_still_kills_and_reaps_owned_leader(self):
        self.run_term_ignoring_leader(observer_failure=True)

    def test_group_probe_denial_still_kills_and_reaps_owned_leader(self):
        self.run_term_ignoring_leader(probe_failure=True)

    def test_portable_observer_reaps_term_ignoring_leader_before_group_check(self):
        self.run_term_ignoring_leader()

    def test_callable_rejects_nonpositive_before_reading_image(self):
        for runs in (0, -1):
            with self.subTest(runs=runs), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    verify_pty.verify(Path(directory) / 'missing.elf', Path(directory) / 'out', runs)
                self.assertFalse((Path(directory) / 'out/summary.json').exists())

    def test_cli_rejects_nonpositive_without_pass_or_guest(self):
        for runs in (0, -1):
            with self.subTest(runs=runs), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([sys.executable, 'tools/verify_pty.py', '--elf',
                    str(Path(directory) / 'missing.elf'), '--output', directory, '--runs', str(runs)],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('positive', result.stderr)
                self.assertNotIn('PASS', result.stdout)
                self.assertFalse((Path(directory) / 'summary.json').exists())

    def test_positive_runs_report_each_completed_probe(self):
        class Guest:
            entered = 0
            def __init__(self, *args, **kwargs): self.text = bytearray()
            def __enter__(self): Guest.entered += 1; return self
            def __exit__(self, *args): pass
            def until(self, *args): pass
            def command(self, command):
                if command == 'posix exec pty-probe':
                    self.text.extend(b'EL0 pid=1 Exited code=0\n' + b'\n'.join(
                        f'PTY_PROBE {stage} PASS'.encode() for stage in
                        ('RAW_BOUNDS', 'CANONICAL_CHILD', 'SIGNALS_EOF', 'LIFETIME', 'SHELL')) + b'\nPTY_PROBE PASS\n')
                return b''
        row = dict(state='Exited', free_pages=64, heap_pages=0, image_pages=0,
                   thread_count=0, heap_free=8, image_free=4096, rank_model=12289, ai_selections=1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / 'artifacts/sysroot/aarch64-musl/pty-probe.elf'
            program.parent.mkdir(parents=True)
            program.write_bytes(b'probe')
            elf = root / 'kernel'; elf.write_bytes(b'kernel probe')
            with patch.object(verify_pty, 'ROOT', root), patch.object(verify_pty, 'Guest', Guest), \
                 patch.object(verify_pty, 'boot_profile', return_value={'heap_pages': 8}), \
                 patch.object(verify_pty, 'wait'), \
                 patch.object(verify_pty, 'parse_processes', return_value={1: row, 2: row}):
                report = verify_pty.verify(elf, root / 'out', 2)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(len(report['runs']), 2)
            self.assertEqual(Guest.entered, 2)
            self.assertEqual(len(json.loads((root / 'out/summary.json').read_text())['runs']), 2)
