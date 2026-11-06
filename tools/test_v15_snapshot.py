"""V0.15 source consolidation must preserve provenance and acceptance boundaries."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SourceSnapshot(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (ROOT / 'docs/implementation/v15-source-baseline.json').read_text())

    def test_frozen_software_baseline_does_not_rename_the_specification(self):
        self.assertEqual(self.manifest['software_version'], '0.15.0-dev')
        self.assertEqual(self.manifest['specification_version'], '1.3')
        self.assertEqual(self.manifest['package_kind'], 'development-source-only')
        self.assertEqual(self.manifest['branch'], 'CyxiaOS-V0.15')
        source = self.manifest['source']
        for key in ('parent_commit', 'parent_tree', 'previous_version_commit'):
            self.assertRegex(source[key], r'^[0-9a-f]{40}$')
        self.assertEqual(source['integration_pull_request'], 17)
        self.assertEqual(source['integrated_commit_count_since_v014'], 14)

    def test_historical_native_proof_is_bound_only_to_its_original_commit(self):
        history = self.manifest['historical_verification']
        self.assertEqual(history['source_commit'], self.manifest['source']['parent_commit'])
        self.assertEqual(history['native_a02_status'], 'PASS')
        self.assertIs(history['applies_to_new_commits'], False)
        self.assertRegex(history['native_a02_artifact_sha256'], r'^[0-9a-f]{64}$')
        policy = self.manifest['acceptance_policy']
        self.assertIs(policy['inherit_native_verdicts'], False)
        self.assertIs(policy['source_snapshot_implies_acceptance'], False)
        self.assertIs(policy['new_commit_requires_independent_runtime_verification'], True)
        self.assertIs(policy['release_gate_opened_by_branch_creation'], False)

    def test_frozen_catalogue_summary_and_workstream_attribution_are_complete(self):
        catalogue = self.manifest['acceptance_catalogue']
        self.assertEqual(catalogue['path'], 'docs/implementation/v13-requirements.json')
        self.assertRegex(catalogue['sha256'], r'^[0-9a-f]{64}$')
        for prefix, count in (('A', 16), ('T', 20), ('E', 15)):
            self.assertEqual(catalogue['tracked_' + prefix],
                             {'PASS': 0, 'FAIL': 0, 'NOT_RUN': count})
        ids = [case for lane in self.manifest['workstreams'].values() for case in lane]
        self.assertEqual(sorted(ids), [f'A{i:02}' for i in range(1, 17)])

    def test_engineering_component_and_native_gates_follow_v015(self):
        for filename in ('validate-prototype.yml', 'v14-a-workstreams.yml',
                         'v14-native-a02.yml'):
            with self.subTest(filename=filename):
                text = (ROOT / '.github/workflows' / filename).read_text()
                push = re.search(r'(?ms)^  push:\n(.*?)(?=^  \w|\Z)', text)
                pull = re.search(r'(?ms)^  pull_request:\n(.*?)(?=^  \w|\Z)', text)
                self.assertIsNotNone(push)
                self.assertIsNotNone(pull)
                self.assertIn('CyxiaOS-V0.15', push[1])
                self.assertIn('CyxiaOS-V0.15', pull[1])
                self.assertIn('github.event.pull_request.head.sha || github.sha', text)
                self.assertIn('persist-credentials: false', text)
                self.assertNotIn('continue-on-error:', text)

    def test_snapshot_uses_git_archive_and_keeps_identity_and_failure_logs(self):
        text = (ROOT / '.github/workflows/v15-source.yml').read_text()
        for required in ('branches: [CyxiaOS-V0.15]', 'ref: ${{ github.sha }}',
                         'git archive --format=zip', 'git rev-parse HEAD^{tree}',
                         'git status --porcelain --untracked-files=all',
                         'test_v15_snapshot.py', 'source_zip_sha256',
                         "'native_execution_attempted_by_this_workflow': False",
                         "'release_acceptance_verified': False", 'if: always()',
                         '${{ github.run_attempt }}'):
            self.assertIn(required, text)
        self.assertNotIn('--output docs/implementation/v13-requirements.json', text)
        self.assertNotIn('continue-on-error:', text)


if __name__ == '__main__':
    unittest.main()
