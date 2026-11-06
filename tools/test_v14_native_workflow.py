"""W1/A02 native lane must execute and independently verify its own capture."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / '.github/workflows/v14-native-a02.yml').read_text()

    def test_native_lane_pins_head_emulator_and_selftest_image(self):
        for required in ('github.event.pull_request.head.sha || github.sha',
                         'persist-credentials: false',
                         'f8ed81651e61d9c2166df6121ce2af0f44f06b3e',
                         'cyxia-per-vcpu-pmu.patch', '--selftest',
                         'python3 tools/run_v13_a02.py', '--qemu-source'):
            self.assertIn(required, self.text)
        self.assertLess(self.text.index('git archive --format=tar HEAD'),
                        self.text.index('tools/provision.py'))

    def test_independent_replay_precedes_run_specific_enrolment(self):
        replay = self.text.index('from verify_v13_a02 import verify_native_receipt')
        enrol = self.text.index('python3 tools/enroll_v13_a02.py')
        self.assertLess(replay, enrol)
        self.assertIn("result.get('native_execution_verified') is not True", self.text)
        self.assertIn('run-catalogue.json', self.text)
        self.assertNotIn('--output docs/implementation/v13-requirements.json', self.text)
        self.assertNotIn('continue-on-error', self.text)

    def test_failed_native_attempts_keep_raw_evidence_not_private_pair_directory(self):
        collection = self.text[self.text.index('      - name: Collect raw capture'):]
        self.assertIn('if: always()', collection)
        self.assertIn('cp -a "$GITHUB_WORKSPACE/artifacts/v14-a02-current/run"', collection)
        self.assertIn('path: ${{ runner.temp }}/a02-evidence/', collection)
        self.assertNotIn('path: ${{ runner.temp }}/a02-private-pair', collection)
        self.assertIn('git status --porcelain --untracked-files=no', collection)

    def test_full_engineering_lane_also_tests_exact_head_and_seals_source(self):
        text = (ROOT / '.github/workflows/validate-prototype.yml').read_text()
        self.assertIn('ref: ${{ github.event.pull_request.head.sha || github.sha }}', text)
        self.assertIn('Verify exact head before testing', text)
        self.assertIn('source-tree.txt', text)
        self.assertEqual(text.count('git status --porcelain --untracked-files=all'), 2)
        self.assertIn('${{ github.run_attempt }}', text)


if __name__ == '__main__':
    unittest.main()
