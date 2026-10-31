"""Compile the real boot worker; mocks test ordering, never native execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    'exact-final-cpu', 'valid-rejection', 'pending-settlement', 'cancelled-return',
    'late-settlement', 'unexpected-trap', 'wrong-magic', 'wrong-cases',
    'invalid-boolean', 'settlement-error', 'cpu-overrun', 'preempt-resume',
    'aggregate-overrun', 'no-credit-deadline',
)


class BootWorkerOrdering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='cyxia-a01-worker-')
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        template = (ROOT / 'tests/host/boot_model_harness.rs').read_text()
        marker = '"../../kernel/src/prototype_runtime/boot_model.rs"'
        if template.count(marker) != 1:
            raise AssertionError('worker harness must include exactly the actual kernel source')

        def compile_worker(subject, name):
            source = root / (name + '.rs')
            source.write_text(template.replace(marker, json.dumps(str(subject)), 1))
            binary = root / name
            result = subprocess.run(['rustc', '--edition=2024', '-C', 'opt-level=1',
                                     str(source), '-o', str(binary)],
                                    capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            return binary

        cls.current = compile_worker(ROOT / 'kernel/src/prototype_runtime/boot_model.rs', 'current')
        original = (ROOT / 'tests/fixtures/a01-boot-worker-before-settlement.rs.txt').read_bytes()
        # Exact reviewed Git blob from 9336226; a historical implementation,
        # not a second hand-written model of the behavior under test.
        identity = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
        if identity != 'c26d59b15fb84ed9317eaa57e083a9019c8efec1':
            raise AssertionError('historical red comparator changed')
        historical = root / 'historical-worker.rs'
        historical.write_bytes(original)
        cls.historical = compile_worker(historical, 'historical')

    def run_case(self, binary, scenario):
        return subprocess.run([str(binary), scenario], capture_output=True, text=True, timeout=10)

    def test_current_worker_preserves_all_fourteen_ordering_contracts(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                result = self.run_case(self.current, scenario)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('HOST_ONLY ' + scenario + ' PASS', result.stdout)
                self.assertIn('native_acceptance_status=NOT_RUN', result.stdout)

    def test_historical_source_reproduces_the_fixed_failures(self):
        healthy = self.run_case(self.historical, 'no-credit-deadline')
        self.assertEqual(healthy.returncode, 0, healthy.stdout + healthy.stderr)
        for scenario in ('exact-final-cpu', 'pending-settlement', 'cancelled-return',
                         'late-settlement', 'unexpected-trap', 'settlement-error'):
            with self.subTest(scenario=scenario):
                result = self.run_case(self.historical, scenario)
                self.assertNotEqual(result.returncode, 0, 'historical source unexpectedly passed ' + scenario)
                self.assertIn('panicked', result.stderr)


if __name__ == '__main__':
    unittest.main()
