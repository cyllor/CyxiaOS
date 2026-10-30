"""Compile the actual coordinator dispatcher; never treat this as native proof."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    for at in range(opening + 1, len(source)):
        depth += (source[at] == '{') - (source[at] == '}')
        if depth == 0:
            return source[start:at + 1]
    raise ValueError('unterminated production function')


class GovernanceTurn(unittest.TestCase):
    def test_actual_bounded_dispatch_preserves_deadlines_ownership_and_physical_credit(self):
        source = (ROOT / 'kernel/src/prototype_runtime/governance.rs').read_text()
        body = function(source, 'fn perform_runtime_turn(')
        template = (ROOT / 'tests/host/governance_turn_harness.rs').read_text()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'Cargo.toml').write_text(
                '[package]\nname="governance-turn-regression"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(root / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-governance-turn'), '--', '--test-threads=1']
            mutations = [
                ('prepare_runtime_snapshot(runtime, resources, credit)?,',
                 'return prepare_runtime_snapshot(runtime, resources, credit),'),
                ('        run_runtime_context(runtime, resources)?;',
                 '        return run_runtime_context(runtime, resources);'),
                ('credit.cpu != 1 || credit.core_generation != current.0', 'false'),
                ('validate_runtime_command(runtime, resources)?;',
                 'let _ = validate_runtime_command(runtime, resources);'),
                ('PHASE_RUN | PHASE_VALIDATE => {}',
                 'PHASE_RUN | PHASE_VALIDATE => { prepare_runtime_snapshot(runtime, resources, credit)?; }'),
            ]
            for old, replacement in mutations:
                with self.subTest(mutation=old):
                    self.assertEqual(body.count(old), 1, 'mutation must match exactly once')
                    mutant = body.replace(old, replacement)
                    (root / 'harness.rs').write_text(template.replace('// PRODUCTION_TURN', mutant))
                    # A nonzero compiler exit is not an executed negative control.
                    compiled = subprocess.run(command[:-2] + ['--no-run'], cwd=ROOT,
                        env=env(), capture_output=True, text=True, timeout=180)
                    self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                    result = subprocess.run(command, cwd=ROOT, env=env(),
                        capture_output=True, text=True, timeout=180)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('test result: FAILED', result.stdout)
            (root / 'harness.rs').write_text(template.replace('// PRODUCTION_TURN', body))
            result = subprocess.run(command, cwd=ROOT, env=env(),
                capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('9 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
