"""Engineering sharding must preserve every original gate and native boundaries."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from prototype import TEST_LANES, test_steps


class ValidationLanes(unittest.TestCase):
    def test_disjoint_lanes_cover_all_nine_original_engineering_gates(self):
        all_steps = test_steps(False)
        combined = [step for lane in TEST_LANES for step in test_steps(False, lane)]
        self.assertEqual(len(combined), 9)
        self.assertEqual(len({name for name, _ in combined}), len(combined))
        self.assertEqual(sorted(combined), sorted(all_steps))

    def test_lane_selection_does_not_rewrite_commands_or_promote_host_to_native(self):
        full = dict(test_steps(True))
        for lane, expected in TEST_LANES.items():
            steps = test_steps(True, lane)
            self.assertEqual(set(dict(steps)), set(expected))
            for name, command in steps:
                self.assertEqual(command, full[name])
                self.assertNotIn('verify_domains.py', ' '.join(command))
                self.assertNotIn('verify_unified.py', ' '.join(command))

    def test_pinned_fixture_preparation_precedes_host_checks_only(self):
        host = test_steps(True, 'host')
        self.assertEqual([name for name, _ in host], ['fixtures', 'host'])
        self.assertIn('--fetch', host[0][1])
        self.assertNotIn('--fetch', test_steps(False, 'host')[0][1])
        for lane in ('static', 'rust', 'tools'):
            self.assertNotIn('fixtures', dict(test_steps(True, lane)))

    def test_typo_cannot_silently_produce_an_empty_successful_lane(self):
        with self.assertRaisesRegex(ValueError, 'unknown validation lane'):
            test_steps(False, 'ruts')

    def test_workflow_preserves_failure_collection_link_gate_and_aggregate_gate(self):
        source = (ROOT / '.github/workflows/validate-prototype.yml').read_text()
        self.assertIn('lane: [static, rust, host, tools]', source)
        self.assertIn('fail-fast: false', source)
        self.assertIn('prototype.py test --lane "$LANE"', source)
        self.assertIn('cargo rustc --release --locked --offline', source)
        self.assertIn('rustup override set 1.95.0', source)
        self.assertIn('needs: validate', source)
        self.assertIn('run: test "$VALIDATION_RESULT" = success', source)
        self.assertIn('prototype-validation-${{ matrix.lane }}-${{ github.sha }}', source)
        self.assertNotIn('continue-on-error:', source)


if __name__ == '__main__':
    unittest.main()
