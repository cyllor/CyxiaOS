"""Source-bound host regression for the V0.14 pre-hash budget gate.

This compiles the real production preparation.rs module with narrow host type
facades, and checks the call ordering in the real native control path.
It is NOT proof of four-vCPU execution, WCET or the prototype A/T/E catalogue.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativePrehashBudget(unittest.TestCase):
    def test_production_gate_precedes_fixed_input_hash(self):
        text = (ROOT / 'kernel/src/domain_control.rs').read_text()
        marker = '    preparation_phase(3);\n'
        self.assertEqual(text.count(marker), 1)
        start = text.index(marker)
        end = text.index('    let input_hash =', start)
        section = text[start:end]
        self.assertIn('let cpu_elapsed = timer::cpu_elapsed_ns(cpu_started);', section)
        self.assertIn('pending.total(preparation_identity, now(), cpu_elapsed)?;', section)
        self.assertIn('preparation::check_decision_cpu(cpu_elapsed)?;', section)
        self.assertLess(section.index('pending.total('), section.index('let input_bytes'))
        self.assertLess(section.index('check_decision_cpu('), section.index('let input_bytes'))
        self.assertIn('cyxia_arch_aarch64::sha256::digest_page(input_bytes)', text[end:])

    def test_real_preparation_module_compiles_and_exercises_cpu_boundaries(self):
        rustc = shutil.which('rustc')
        self.assertIsNotNone(rustc, 'rustc is required; do not silently skip')
        harness = ROOT / 'tests/host/prehash_decision_budget_harness.rs'
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'prehash-harness'
            compile_result = subprocess.run(
                [rustc, '--edition=2024', '--test', str(harness), '-o', str(binary)],
                cwd=ROOT, capture_output=True, text=True, timeout=90,
            )
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stdout + compile_result.stderr)
            run = subprocess.run([str(binary), '--test-threads=1'],
                                 cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('2 passed; 0 failed', run.stdout)


if __name__ == '__main__':
    unittest.main()
