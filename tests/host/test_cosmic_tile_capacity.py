"""Exercise the actual phase-version native cursor; only the syscall is injected.

CYXIA_PRESENTATION_BASELINE=1 selects the pinned unmodified cursor, which must
fail the deterministic submission-work budget. Existing cursor tests also run.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

PORT = ROOT / 'ports/cosmic/native-presentation-v1'
PATCH = PORT / 'tile-capacity.patch'


class NativeTileCapacity(unittest.TestCase):
    def test_actual_native_cursor_capacity_and_existing_completion_guards(self):
        policy = json.loads((PORT / 'source-policy.json').read_text())
        source = PORT / 'base/presentation.rs'
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), policy['base_phase_source_sha256'])
        with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-tiles-') as tmp:
            idle_native_host()
            tmp = Path(tmp)
            folder = tmp / 'src/backend/cyxia'
            (folder / 'native').mkdir(parents=True)
            for name in ['native.rs', 'linux_syscall.rs']:
                shutil.copyfile(ROOT / 'ports/cosmic/native-comp/backend' / name, folder / name)
            destination = folder / 'native/presentation.rs'
            shutil.copyfile(source, destination)
            if os.environ.get('CYXIA_PRESENTATION_BASELINE') != '1':
                self.assertEqual(hashlib.sha256(PATCH.read_bytes()).hexdigest(), policy['patch_sha256'])
                subprocess.run(['git', 'apply', '--check', str(PATCH)], cwd=tmp, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(['git', 'apply', str(PATCH)], cwd=tmp, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), policy['patched_source_sha256'])
            destination.write_text(destination.read_text() + '\n' +
                                   (ROOT / 'tests/host/cosmic_tile_capacity.rs').read_text())
            harness = tmp / 'harness.rs'
            locking = ROOT / 'ports/cosmic/native-comp/backend/locking.rs'
            harness.write_text('#[path = "src/backend/cyxia/native.rs"]\nmod native;\n'
                               + '#[path = ' + json.dumps(str(locking)) + ']\nmod locking;\n')
            compiler = shutil.which('rustc')
            self.assertIsNotNone(compiler)
            compiled = subprocess.run([compiler, '--edition=2024', '--test', '-O', str(harness),
                                       '-o', str(tmp / 'tests')], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(tmp / 'tests'), '--nocapture',
                                     '--test-threads=1'], capture_output=True, text=True, timeout=20)
            print(result.stdout, end='')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
