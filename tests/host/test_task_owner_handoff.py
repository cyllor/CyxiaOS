"""Exercise the actual native task gate under reproducible CPU contention."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class TaskOwnerHandoff(unittest.TestCase):
    def test_waiting_cpu_gets_bounded_owner_opportunity_without_spinning(self):
        source = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        template = (ROOT / 'tests/host/task_owner_handoff_harness.rs').read_text()
        gate = ROOT / 'kernel/src/domain_tasks/owner_gate.rs'
        module = '#[path=' + json.dumps(str(gate)) + '] mod owner_gate;' if gate.exists() else ''
        pieces = [re.search(r'^static LOCK:.*;$', source, re.M)[0],
                          re.search(r'struct Guard(?:\s*;|\s*\{[^}]*\})', source)[0],
                          function(source, 'impl Drop for Guard')]
        if 'fn acquire_guard()' in source:
            pieces.append(function(source, 'fn acquire_guard()'))
        pieces.append(function(source, 'fn locked<R>'))
        pieces.append(function(source, 'pub fn service_segment<R>'))
        body = '\n'.join(pieces)
        template = template.replace('// OWNER_GATE_MODULE', module).replace('// OWNER_GATE_BODY', body)
        publication = (ROOT / 'kernel/src/domain_tasks/publication.rs').read_text()
        template = template.replace('// PUBLICATION_BODIES', '\n'.join(function(publication, signature)
            for signature in ['pub(crate) struct BaselinePublication', 'fn owns(',
                              'pub(crate) fn reserve_baseline_publication(']))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="task-owner-handoff"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-task-owner-handoff'), '--', '--test-threads=1']
            if gate.exists():
                original = gate.read_text()
                burst = '} else if now < end {\n            self.cpu\n        } else {'
                self.assertEqual(original.count(burst), 1)
                mutant = directory / 'immediate-handoff.rs'
                mutant.write_text(original.replace(burst, '} else {'))
                changed = '#[path=' + json.dumps(str(mutant)) + '] mod owner_gate;'
                (directory / 'harness.rs').write_text(template.replace(module, changed))
                red = subprocess.run(command + ['--exact',
                    'paid_owner_must_reach_its_real_body_after_admission_and_revalidation'],
                    cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
                self.assertNotEqual(red.returncode, 0, red.stdout + red.stderr)
                self.assertIn('paid owner could not reach its body after admission: Some(Err(Busy))',
                              red.stdout + red.stderr)
            (directory / 'harness.rs').write_text(template)
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                    text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('7 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
