"""Execute native admission/throttling bodies against real Scheduler budgets."""
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


class DynamicEntryCredit(unittest.TestCase):
    def test_short_returns_resume_within_the_existing_thread_budget(self):
        source = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        template = (ROOT / 'tests/host/dynamic_entry_credit_harness.rs').read_text()
        definitions = [re.search(rf'^const {name}: u64 = .*;$', source, re.M)[0] for name in
            ['BUILTIN_WINDOW_HEADROOM_NS', 'BUILTIN_MIN_GRANT_NS', 'DYNAMIC_EL0_MIN_GRANT_NS']]
        definitions += [function(source, signature) for signature in
                        ['fn throttle(', 'fn refresh_throttled(', 'pub fn begin_builtin(']]
        template = template.replace('// NATIVE_ADMISSION', '\n'.join(definitions))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="dynamic-entry-credit"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            (directory / 'harness.rs').write_text(template)
            result = subprocess.run([str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-dynamic-entry-credit'), '--', '--test-threads=1'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('5 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
