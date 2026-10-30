"""An interrupted validation lane owns and cleans up its entire process group."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ProcessCleanup(unittest.TestCase):
    def run_interrupted(self, source, expected_children):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / 'checks'
            ready = root / 'ready'
            child = root / 'child.py'
            child.write_text(source)
            steps = [('owned', [sys.executable, str(child), str(ready)]),
                     ('must-not-run', [sys.executable, '-c', 'pass'])]
            script = ('import sys; from pathlib import Path; '
                      f'sys.path.insert(0, {str(ROOT / "tools")!r}); '
                      'from prototype import run_steps; '
                      f'raise SystemExit(run_steps({steps!r}, Path({str(output)!r})))')
            parent = subprocess.Popen([sys.executable, '-c', script],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children = []
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and parent.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists(), 'owned child never became ready')
                children = json.loads(ready.read_text())
                self.assertEqual(len(children), expected_children)
                parent.send_signal(signal.SIGINT)
                out, err = parent.communicate(timeout=8)
                self.assertEqual(parent.returncode, 130, out + err)
                summary = json.loads((output / 'summary.json').read_text())
                self.assertEqual(summary['status'], 'FAIL')
                self.assertEqual([r['name'] for r in summary['steps']], ['owned'])
                self.assertEqual(summary['steps'][0]['returncode'], 130)
                for pid in children:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.communicate(timeout=5)
                for pid in children:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_term_ignoring_child_is_killed_and_reaped(self):
        self.run_interrupted('''import json, os, signal, sys, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(sys.argv[1]).write_text(json.dumps([os.getpid()]))
time.sleep(60)
''', 1)

    def test_nested_child_receives_the_owned_group_signal(self):
        self.run_interrupted('''import json, os, signal, subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
def stop(*_):
    child.wait(timeout=2)
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
Path(sys.argv[1]).write_text(json.dumps([os.getpid(), child.pid]))
time.sleep(60)
''', 2)


if __name__ == '__main__':
    unittest.main()
