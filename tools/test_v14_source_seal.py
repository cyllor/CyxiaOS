"""Exact-source component reports must seal source after execution as well."""
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import v14_workstreams as runner


class SourceSeal(unittest.TestCase):
    def fake_run(self, steps, output):
        output.mkdir()
        rows = [{'name': name, 'argv': argv, 'status': 'PASS', 'returncode': 0}
                for name, argv in steps]
        (output / 'summary.json').write_text(json.dumps({'steps': rows}))
        (output / '01-components.log').write_text('sealed source fixture\n')
        return 0

    def test_changed_or_dirty_source_after_checks_cannot_be_pass(self):
        source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'tracked_dirty': False}
        for after in ({**source, 'commit': 'c' * 40},
                      {**source, 'tree': 'd' * 40},
                      ValueError('tracked source changed during checks')):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as directory, \
                    patch.object(runner, 'source_identity', side_effect=[source, after]), \
                    patch.object(runner, 'run_steps', side_effect=self.fake_run):
                output = Path(directory) / 'W1'
                with self.assertRaises(ValueError):
                    runner.run_lane('W1', output)
                report = json.loads((output / 'workstream.json').read_text())
                self.assertEqual(report['status'], 'FAIL')
                self.assertFalse(report['source_verified_after_checks'])
                self.assertEqual(report['native_acceptance_status'], 'NOT_RUN')
                self.assertTrue((output / 'checks/01-components.log').is_file())

    def test_real_git_identity_rejects_tracked_edits_and_untracked_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                subprocess.run(['git', *args], cwd=root, check=True,
                               capture_output=True, text=True)
            git('init', '-q')
            source = root / 'module.py'
            source.write_text('value = 1\n')
            git('add', 'module.py')
            git('-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                'commit', '-qm', 'fixture')
            clean = runner.source_identity(root)
            source.write_text('value = 2\n')
            with self.assertRaises(ValueError):
                runner.source_identity(root)
            git('checkout', '--', 'module.py')
            untracked = root / 'injected.py'
            untracked.write_text('value = 3\n')
            with self.assertRaises(ValueError):
                runner.source_identity(root)
            untracked.unlink()
            self.assertEqual(runner.source_identity(root), clean)

    def test_unchanged_source_is_sealed_without_promoting_native_acceptance(self):
        source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'tracked_dirty': False}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runner, 'source_identity', return_value=source) as identity, \
                patch.object(runner, 'run_steps', side_effect=self.fake_run):
            output = Path(directory) / 'W1'
            self.assertEqual(runner.run_lane('W1', output), 0)
            report = json.loads((output / 'workstream.json').read_text())
            self.assertEqual(identity.call_count, 2)
            self.assertTrue(report['source_verified_after_checks'])
            self.assertEqual(report['source_after_checks'], source)
            self.assertFalse(report['release_acceptance_verified'])


if __name__ == '__main__':
    unittest.main()
