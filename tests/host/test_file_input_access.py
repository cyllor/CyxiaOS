"""Execute native user-memory access bodies with the real Memory owner model."""
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


class FileInputAccess(unittest.TestCase):
    def test_preflight_holds_one_owner_borrow_and_retains_memory_authority(self):
        memory = (ROOT / 'kernel/src/domain_tasks/memory.rs').read_text()
        files = (ROOT / 'kernel/src/domain_file_abi.rs').read_text()
        template = (ROOT / 'tests/host/file_input_access_harness.rs').read_text()
        signatures = ['pub(crate) struct UserMemoryAccess', "impl UserMemoryAccess<'_>",
                      'pub(crate) fn with_user_memory', 'pub(super) fn frame_ptr(',
                      'pub(super) fn fault_page(', 'fn code_frame(', 'pub(super) fn prepare(',
                      'pub(super) fn copy_from(', 'pub(super) fn copy_to(',
                      'pub fn copyin(', 'pub fn copyout(']
        template = template.replace('// MEMORY_BODIES', '\n'.join(
            function(memory, signature) for signature in signatures))
        template = template.replace('// FILE_BODIES', '\n'.join(
            function(files, signature) for signature in ['fn validate_shape(', 'fn prepare_input(', 'fn deliver(']))
        template = template.replace('ABI_PATH', json.dumps(str(ROOT / 'user/prototype-task/files_abi.rs')))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="file-input-access"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline',
                '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-file-input-access'), '--', '--test-threads=1']
            # Reintroduce either former sequence of independent acquisitions.
            # Each mutation must fail its named behavior before actual source
            # is accepted; a merely absent new API is not the only RED signal.
            for signature, before, after, failure in [
                ('fn prepare_input(', 'domain_tasks::with_user_memory', 'split_user_memory',
                 'preflight reacquired the contended owner gate'),
                ('fn deliver(', 'domain_tasks::with_user_memory', 'split_user_memory',
                 'retained delivery reacquired the owner gate'),
                ('fn prepare_input(', '*copied = true;', '// lost copied stage',
                 'copied frame lost its error-delivery stage'),
                (None, None, None, None),
            ]:
                mutated = template
                if signature:
                    body = function(files, signature)
                    mutated = mutated.replace(body, body.replace(before, after))
                (directory / 'harness.rs').write_text(mutated)
                result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                        text=True, timeout=120)
                output = result.stdout + result.stderr
                if failure:
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertIn(failure, output)
                else:
                    self.assertEqual(result.returncode, 0, output)
                    self.assertIn('9 passed; 0 failed', output)


if __name__ == '__main__':
    unittest.main()
