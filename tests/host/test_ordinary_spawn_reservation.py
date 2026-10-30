"""Actual Creator admission control over production queue and scheduler.

PTE/page/capability construction is a counted facade. Its reservation checks
and final scheduler-admission branch come from the actual build body.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class OrdinarySpawnReservation(unittest.TestCase):
    def test_actual_creator_defers_before_effects_and_keeps_original_receipt(self):
        source = (ROOT / 'kernel/src/domain_tasks/execution.rs').read_text()
        build = function(source, 'fn build(')
        checks = build[build.index('        trace.step(11)'):build.index('        trace.step(12)')]
        signature = 'if reservation.is_none() {' if 'if reservation.is_none() {' in build else 'if !local {'
        late_admission = function(build, signature)
        template = (ROOT / 'tests/host/ordinary_spawn_reservation_harness.rs').read_text()
        template = template.replace('mod learning_evidence {', 'mod learning_evidence {' +
                                    (ROOT / 'tests/host/capture_identity_facade.rs').read_text())
        template = template.replace('// BUILD_CHECKS', checks).replace('// LATE_ADMISSION', late_admission)
        template = template.replace('// THREAD_SPEC', function(source, 'fn thread_spec('))
        template = template.replace('// ACTUAL_CREATOR', '\n'.join([
            function(source, 'fn authorize(&mut self, r: &SpawnRequest)'),
            function(source, 'fn create(&mut self, r: &SpawnRequest)')]))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'harness.rs').write_text(template)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="ordinary-spawn-reservation"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-ordinary-spawn-reservation'),
                '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('4 passed; 0 failed', result.stdout)
            for old, new, expected in [
                ('let reservation = if !r.recovery {', 'let reservation = if r.caller == CLUSTER_CALLER {',
                 'ordinary creator converted temporary committed capacity into permanent failure'),
                ('if reservation.is_none() {', 'if true {', 'original spawn did not create after release'),
            ]:
                self.assertEqual(template.count(old), 1)
                (directory / 'harness.rs').write_text(template.replace(old, new))
                negative = subprocess.run(command + ['--exact',
                    'ordinary_child_waits_without_effects_then_creates_once_after_real_capacity_release'],
                    cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
                self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
                self.assertIn(expected, negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
