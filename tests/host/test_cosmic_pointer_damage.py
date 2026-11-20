"""Exercise the real native presentation cursor, injecting only tile submission.

CYXIA_DAMAGE_BASELINE=1 uses the unmodified full-frame constructor selected by
the old render_output call site. It must fail the small cursor work budget.
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

PORT = ROOT / 'ports/cosmic/native-pointer-damage-v1'


class NativePointerDamage(unittest.TestCase):
    def test_real_presentation_damage_and_completion_guards(self):
        baseline = os.environ.get('CYXIA_DAMAGE_BASELINE') == '1'
        policy = json.loads((PORT / 'source-policy.json').read_text())
        with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-damage-') as tmp:
            idle_native_host()
            tmp = Path(tmp)
            folder = tmp / 'src/backend/cyxia'
            (folder / 'native').mkdir(parents=True)
            for name in ['native.rs', 'linux_syscall.rs']:
                shutil.copyfile(ROOT / 'ports/cosmic/native-comp/backend' / name, folder / name)
            for name, digest in policy['base_sources'].items():
                source = PORT / 'base' / Path(name).name
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
                shutil.copyfile(source, folder / name)
            if not baseline:
                patch = PORT / 'damage.patch'
                self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), policy['patch_sha256'])
                subprocess.run(['git', 'apply', '--check', str(patch)], cwd=tmp, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(['git', 'apply', str(patch)], cwd=tmp, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for name, digest in policy['patched_sources'].items():
                    self.assertEqual(hashlib.sha256((folder / name).read_bytes()).hexdigest(), digest)
            presentation = folder / 'native/presentation.rs'
            presentation.write_text(presentation.read_text() + '\n' +
                                    (ROOT / 'tests/host/cosmic_tile_capacity.rs').read_text() + '\n' +
                                    (ROOT / 'tests/host/cosmic_pointer_damage.rs').read_text())
            locking = ROOT / 'ports/cosmic/native-comp/backend/locking.rs'
            harness = tmp / 'harness.rs'
            harness.write_text('#[path = "src/backend/cyxia/native.rs"]\nmod native;\n'
                               + '#[path = ' + json.dumps(str(locking)) + ']\nmod locking;\n')
            command = [shutil.which('rustc'), '--edition=2024', '--test', '-O', str(harness),
                       '-o', str(tmp / 'tests')]
            if baseline:
                command.extend(['--cfg', 'cyxia_damage_baseline'])
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            command = [str(tmp / 'tests'), '--nocapture', '--test-threads=1']
            if baseline:
                command.append('small_cursor_motion_submits_one_damage_tile')
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            print(result.stdout, end='')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
