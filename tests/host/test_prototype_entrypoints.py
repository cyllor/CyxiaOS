"""Delivery commands preserve actual results; no fixture is native evidence."""
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
sys.path.insert(0, str(ROOT / 'tools'))


class PrototypeEntrypoints(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'tools/prototype.py'), *args],
                              cwd=ROOT, capture_output=True, text=True, timeout=30)

    def test_report_reconstructs_current_catalogue_and_exits_nonzero_when_incomplete(self):
        result = self.cli('report')
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['states'], {'PASS': 0, 'FAIL': 0, 'NOT_RUN': 69})
        self.assertFalse(report['functional_acceptance_complete'])
        self.assertFalse(report['filesystem_fault_matrix_complete'])

    def test_native_entrypoints_forward_to_the_real_backend_help(self):
        for entry, option in [('build', '--identity-a'),
                              ('run-single', '--replay-pairs'),
                              ('run-pair', '--qemu-source')]:
            with self.subTest(entry=entry):
                result = self.cli(entry, '--help')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(option, result.stdout)

    def test_unknown_native_argument_preserves_backend_failure(self):
        result = self.cli('build', '--definitely-unknown')
        self.assertEqual(result.returncode, 2)
        self.assertIn('usage: build_unified.py', result.stderr)

    def test_failed_step_keeps_output_and_runs_the_following_independent_check(self):
        from prototype import run_steps
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'checks'
            commands = [('fail', [sys.executable, '-c',
                         'import sys; print("failure reason", file=sys.stderr); sys.exit(7)']),
                        ('next', [sys.executable, '-c', 'print("second check ran")'])]
            status = run_steps(commands, output)
            self.assertEqual(status, 1)
            report = json.loads((output / 'summary.json').read_text())
            self.assertEqual(report['status'], 'FAIL')
            self.assertEqual([r['returncode'] for r in report['steps']], [7, 0])
            self.assertIn('failure reason', (output / '01-fail.log').read_text())
            self.assertIn('second check ran', (output / '02-next.log').read_text())
            self.assertFalse(report['release_acceptance_verified'])

    def test_missing_executable_is_recorded_and_does_not_hide_later_results(self):
        from prototype import run_steps
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'checks'
            status = run_steps([('missing', [str(Path(temp) / 'absent')]),
                                ('next', [sys.executable, '-c', 'pass'])], output)
            self.assertEqual(status, 1)
            report = json.loads((output / 'summary.json').read_text())
            self.assertEqual([r['returncode'] for r in report['steps']], [127, 0])
            self.assertIn('No such file', (output / '01-missing.log').read_text())

    def test_existing_evidence_directory_is_never_reused(self):
        from prototype import run_steps
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'checks'
            output.mkdir()
            original = output / 'summary.json'
            original.write_text('original evidence')
            with self.assertRaises(FileExistsError):
                run_steps([('check', [sys.executable, '-c', 'pass'])], output)
            self.assertEqual(original.read_text(), 'original evidence')

    def test_successful_host_checks_cannot_claim_release_acceptance(self):
        from prototype import run_steps
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'checks'
            self.assertEqual(run_steps([('check', [sys.executable, '-c', 'pass'])], output), 0)
            report = json.loads((output / 'summary.json').read_text())
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['scope'], 'host-validation')
            self.assertFalse(report['release_acceptance_verified'])

    def test_governance_check_keeps_cargo_outputs_in_the_ignored_root_target(self):
        from prototype import test_steps
        commands = dict(test_steps(False))
        command = commands['governance-clippy']
        self.assertIn('--target-dir', command)
        self.assertEqual(command[command.index('--target-dir') + 1],
                         str(ROOT / 'target/prototype-governance'))

    def test_empty_checks_cannot_create_a_success_receipt(self):
        from prototype import run_steps
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'checks'
            with self.assertRaisesRegex(ValueError, 'at least one'):
                run_steps([], output)
            self.assertFalse(output.exists())

    def test_report_does_not_overwrite_an_existing_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'report.json'
            output.write_text('original receipt')
            result = self.cli('report', '--output', str(output))
            self.assertEqual(result.returncode, 1)
            self.assertEqual(output.read_text(), 'original receipt')

    def test_bad_catalogue_returns_a_reason_and_no_report(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / 'invalid.json'
            manifest.write_text('{}')
            result = self.cli('report', '--manifest', str(manifest))
            self.assertEqual(result.returncode, 1)
            self.assertIn('prototype:', result.stderr)
            self.assertEqual(result.stdout, '')

    def test_interrupt_retains_failure_and_stops_the_running_child(self):
        with tempfile.TemporaryDirectory() as temp:
            output, ready = Path(temp) / 'checks', Path(temp) / 'ready'
            child = (f'from pathlib import Path; import os,time; '
                     f'Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(60)')
            commands = [('wait', [sys.executable, '-c', child]),
                        ('next', [sys.executable, '-c', 'pass'])]
            parent = ('import sys; from pathlib import Path; '
                      f'sys.path.insert(0, {str(ROOT / "tools")!r}); '
                      f'from prototype import run_steps; '
                      f'raise SystemExit(run_steps({commands!r}, Path({str(output)!r})))')
            process = subprocess.Popen([sys.executable, '-c', parent],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists(), 'validation child never started')
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 130, stdout + stderr)
                report = json.loads((output / 'summary.json').read_text())
                self.assertEqual(report['status'], 'FAIL')
                self.assertEqual(len(report['steps']), 1)
                self.assertEqual(report['steps'][0]['returncode'], 130)
                self.assertIn('Interrupted by user', (output / '01-wait.log').read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(ready.read_text()), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
