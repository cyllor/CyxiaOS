"""Single-CPU dispatch must restart the winner's age after a granted slice.

Injects the real process selector and the real `dispatch_parallel`; only the AP
publication machinery, accounting and the clock are fixtures. The AP branch is
compiled but never runs because the fixture reports CPU0 alone.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from test_governance_billing_priority import function


def production_fixture():
    user = (ROOT / 'kernel/src/desktop/user.rs').read_text()
    parallel = (ROOT / 'kernel/src/desktop/user/parallel.rs').read_text()
    policy = function(user, 'fn process_dispatch_policy(')
    dispatch = function(parallel, '    pub(super) fn dispatch_parallel(')
    return ((ROOT / 'tests/host/single_cpu_age_harness.rs').read_text()
            .replace('// PRODUCTION_POLICY', policy)
            .replace('// PRODUCTION_DISPATCH',
                     'impl crate::Supervisor {\n' + dispatch + '\n}'))


class SingleCpuAge(unittest.TestCase):
    def test_runnable_processes_share_cpu0_and_winner_age_restarts(self):
        with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyxia-single-cpu-age-') as tmp:
            idle_native_host()
            directory = Path(tmp)
            (directory / 'fixture.rs').write_text(production_fixture())
            manifest = directory / 'Cargo.toml'
            manifest.write_text(
                '[package]\nname="single-cpu-age-regression"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="fixture.rs"\n[workspace]\n'
                '[features]\ncosmic-session=[]\nabi-trace=[]\n[dependencies]\n'
                'cyxia-ai-runtime={path=' + json.dumps(str(ROOT / 'crates/ai-runtime')) + '}\n'
                'cyxia-contracts={path=' + json.dumps(str(ROOT / 'crates/contracts')) + '}\n')
            environment = dict(os.environ, CARGO_INCREMENTAL='0', RUST_MIN_STACK='16777216',
                               CARGO_TARGET_DIR=str(ROOT / 'target/host-single-cpu-age'))
            result = subprocess.run(['cargo', 'test', '--offline', '--manifest-path', str(manifest),
                                     '--', '--test-threads=1'], capture_output=True, text=True,
                                    cwd=directory, env=environment, timeout=120)
            print(result.stdout, end='')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('2 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
