"""Engineering lane attribution must never promote native acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import v14_workstreams as runner


class Workstreams(unittest.TestCase):
    def test_exact_nonoverlapping_A_coverage_and_real_targets(self):
        runner.validate_lanes()
        self.assertEqual(len(runner.LANES), 6)
        for lane in runner.LANES:
            steps = runner.steps_for(lane)
            self.assertTrue(steps)
            self.assertEqual(steps[0][0], 'rust-components')
            self.assertIn('--locked', steps[0][1])
            self.assertIn('--offline', steps[0][1])
            self.assertNotIn('--', steps[0][1])  # no name filter that runs zero tests

    def test_missing_or_duplicate_requirement_is_rejected(self):
        for ids in (('A01',), ('A01', 'A01', 'A03', 'A04')):
            lanes = copy.deepcopy(runner.LANES)
            lanes['W1']['ids'] = ids
            with self.assertRaisesRegex(ValueError, 'exactly once'):
                runner.validate_lanes(lanes)

    def test_empty_missing_or_multiply_owned_rust_target_is_rejected(self):
        for targets, error in (((), 'empty'), (('not-a-real-test',), 'missing'),
                                (('journal',), 'multiple')):
            lanes = copy.deepcopy(runner.LANES)
            lanes['W1']['rust'] = targets
            with self.assertRaisesRegex(ValueError, error):
                runner.validate_lanes(lanes)

    def test_missing_python_target_is_rejected(self):
        lanes = copy.deepcopy(runner.LANES)
        lanes['W1']['python'] = (('tools', 'not-a-real-test.py'),)
        with self.assertRaisesRegex(ValueError, 'missing Python'):
            runner.validate_lanes(lanes)

    def fake_run(self, steps, output, *, fail=False, truncate=False):
        output.mkdir()
        rows = []
        for name, argv in steps[:1] if truncate else steps:
            rows.append({'name': name, 'argv': argv,
                         'status': 'FAIL' if fail else 'PASS',
                         'returncode': 1 if fail else 0})
        (output / 'summary.json').write_text(json.dumps({'steps': rows}))
        (output / '01-component.log').write_text('component-only fixture\n')
        return int(fail)

    def test_success_retains_hashes_but_never_promotes_native_status(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runner, 'source_identity', return_value={'commit': 'a'*40}), \
                patch.object(runner, 'run_steps', side_effect=self.fake_run):
            output = Path(directory) / 'W1'
            self.assertEqual(runner.run_lane('W1', output), 0)
            report = json.loads((output / 'workstream.json').read_text())
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['native_acceptance_status'], 'NOT_RUN')
            self.assertFalse(report['native_execution_attempted'])
            self.assertFalse(report['release_acceptance_verified'])
            self.assertEqual(len(report['log_sha256']['01-component.log']), 64)
            with self.assertRaises(FileExistsError):
                runner.run_lane('W1', output)

    def test_failed_or_incomplete_execution_is_never_green(self):
        for fail, truncate in ((True, False), (False, True)):
            with self.subTest(fail=fail, truncate=truncate), \
                    tempfile.TemporaryDirectory() as directory, \
                    patch.object(runner, 'source_identity', return_value={'commit': 'a'*40}), \
                    patch.object(runner, 'run_steps', side_effect=lambda s, o:
                                 self.fake_run(s, o, fail=fail, truncate=truncate)):
                output = Path(directory) / 'W1'
                self.assertNotEqual(runner.run_lane('W1', output), 0)
                report = json.loads((output / 'workstream.json').read_text())
                self.assertEqual(report['status'], 'FAIL')
                self.assertEqual(report['native_acceptance_status'], 'NOT_RUN')

    def test_launch_exception_preserves_failure_reason(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runner, 'source_identity', return_value={'commit': 'a'*40}), \
                patch.object(runner, 'run_steps', side_effect=OSError('missing tool')):
            output = Path(directory) / 'W1'
            with self.assertRaises(OSError):
                runner.run_lane('W1', output)
            report = json.loads((output / 'workstream.json').read_text())
            self.assertEqual(report['status'], 'FAIL')
            self.assertIn('missing tool', report['error'])

    def test_workflow_isolates_lanes_and_pins_the_tested_source(self):
        text = (runner.ROOT / '.github/workflows/v14-a-workstreams.yml').read_text()
        self.assertIn('fail-fast: false', text)
        self.assertIn('lane: [W1, W2, W3, W4, W5, W6]', text)
        self.assertIn('github.event.pull_request.head.sha || github.sha', text)
        self.assertIn('if: always()', text)
        self.assertIn('persist-credentials: false', text)
        self.assertNotIn('continue-on-error', text)


if __name__ == '__main__':
    unittest.main()
