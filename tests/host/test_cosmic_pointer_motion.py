"""Exercise actual dispatch_actions, native decoding and delivered-key ledger.

Only the surrounding COSMIC shell and clock/syscall boundaries are substituted.
The baseline must fail by dispatching 24 redundant background motion events.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from test_governance_billing_priority import function

PORT = ROOT / 'ports/cosmic/native-pointer-motion-v1'
DISPATCH_PORT = ROOT / 'ports/cosmic/native-pointer-dispatch-v1'


class PointerMotion(unittest.TestCase):
    def test_actual_dispatch_coalescing_and_input_guards(self):
        self.check_dispatch(baseline=os.environ.get('CYXIA_MOTION_BASELINE') == '1')

    def test_turning_motion_shares_clock_sampling(self):
        self.check_dispatch(batch=True)

    def test_relative_motion_routes_first_click_to_destination(self):
        patch = DISPATCH_PORT / 'dispatch.patch'
        policy = json.loads((DISPATCH_PORT / 'source-policy.json').read_text())
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), policy['patch_sha256'])
        hunks = [hunk for hunk in re.split(r'^@@[^\n]*\n', patch.read_text(), flags=re.M)
                 if 'ptr.motion(' in hunk]
        self.assertEqual(len(hunks), 1)
        # Compile the call from the port's exact postimage hunk. The fixture
        # substitutes Smithay's receiver and supplies the two hit-test results.
        postimage = '\n'.join(line[1:] for line in hunks[0].splitlines() if line.startswith((' ', '+')))
        start = postimage.index('ptr.motion(')
        call = postimage[start:postimage.index(');', start) + 2]
        template = (ROOT / 'tests/host/cosmic_pointer_focus.rs').read_text()
        with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-focus-') as tmp:
            idle_native_host()
            source, binary = Path(tmp) / 'focus.rs', Path(tmp) / 'focus'
            source.write_text(template.replace('// PRODUCTION_MOTION', call))
            subprocess.run([shutil.which('rustc'), '--edition=2024', '--test', str(source), '-o', str(binary)],
                           check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=30)

    def check_dispatch(self, *, baseline=False, batch=False):
        policy = json.loads((PORT / 'source-policy.json').read_text())
        with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-motion-') as tmp:
            idle_native_host()
            tmp = Path(tmp)
            folder = tmp / 'src/backend/cyxia'
            folder.mkdir(parents=True)
            for name, digest in policy['base_sources'].items():
                source = PORT / 'base' / name
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
                shutil.copyfile(source, folder / name)
            if not baseline:
                patch = PORT / 'motion.patch'
                self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), policy['patch_sha256'])
                subprocess.run(['git', 'apply', '--check', str(patch)], cwd=tmp, check=True, capture_output=True)
                subprocess.run(['git', 'apply', str(patch)], cwd=tmp, check=True, capture_output=True)
                for name, digest in policy['patched_sources'].items():
                    self.assertEqual(hashlib.sha256((folder / name).read_bytes()).hexdigest(), digest)
            if batch and os.environ.get('CYXIA_POINTER_DISPATCH_BASELINE') != '1':
                batch_policy = json.loads((DISPATCH_PORT / 'source-policy.json').read_text())
                patch = DISPATCH_PORT / 'dispatch.patch'
                self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), batch_policy['patch_sha256'])
                relative = 'src/backend/cyxia/mod.rs'
                self.assertEqual(hashlib.sha256((tmp / relative).read_bytes()).hexdigest(),
                                 batch_policy['base_sources'][relative])
                subprocess.run(['git', 'apply', f'--include={relative}', str(patch)],
                               cwd=tmp, check=True, capture_output=True)
                self.assertEqual(hashlib.sha256((tmp / relative).read_bytes()).hexdigest(),
                                 batch_policy['patched_sources'][relative])
            (folder / 'native').mkdir()
            shutil.copyfile(ROOT / 'ports/cosmic/native-comp/backend/native/presentation.rs',
                            folder / 'native/presentation.rs')
            shutil.copyfile(ROOT / 'ports/cosmic/native-comp/backend/linux_syscall.rs', folder / 'linux_syscall.rs')
            body = function((folder / 'mod.rs').read_text(), 'fn dispatch_actions(')
            template = (ROOT / 'tests/host/cosmic_pointer_motion.rs').read_text()
            harness = tmp / 'harness.rs'
            harness.write_text(template.replace('// PRODUCTION_DISPATCH', body))
            command = [shutil.which('rustc'), '--edition=2024', '--test', '-O', str(harness),
                       '-o', str(tmp / 'tests')]
            if batch:
                command.extend(['--cfg', 'cyxia_pointer_dispatch'])
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(tmp / 'tests'), '--nocapture', '--test-threads=1'],
                                    capture_output=True, text=True, timeout=30)
            print(result.stdout, end='')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
