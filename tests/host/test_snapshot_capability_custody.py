"""Execute the production restore/capability publication boundaries."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from host_prototype_library import build_host_prototype_library
from test_a01_formal_recorder import function


class SnapshotCapabilityCustody(unittest.TestCase):
    def test_revocation_is_inside_the_file_owner_and_new_notifications_survive_grants(self):
        source = (ROOT / 'tests/host/snapshot_capability_custody_harness.rs').read_text()
        storage = (ROOT / 'kernel/src/runtime/files/domain_storage.rs').read_text()
        source = source.replace('// STORAGE_BODIES', '\n'.join(function(storage, name) for name in [
            'pub fn validate_file_object(', 'pub fn stat_file_object(',
            'pub fn read_cache_page(', 'pub fn snapshot_execute(',
        ]))
        abi = (ROOT / 'kernel/src/runtime/tasks/domain_tasks/abi.rs').read_text()
        source = source.replace('// CAPABILITY_BODIES', '\n'.join(function(abi, name) for name in [
            'pub fn invalidate_file_capabilities(', 'pub fn file_capabilities_invalidated(',
            'pub fn grant_file_cap(',
        ]))
        deps, library = build_host_prototype_library()
        with tempfile.TemporaryDirectory(prefix='snapshot-capability-custody-') as temporary:
            path = Path(temporary) / 'harness.rs'
            binary = Path(temporary) / 'harness'
            path.write_text(source)
            result = subprocess.run([
                str(RUST_BIN / 'rustc'), '--edition=2024', '-C', 'panic=abort', str(path),
                '-L', 'dependency=' + str(deps), '--extern', 'cyxia_prototype=' + str(library),
                '-o', str(binary),
            ], env=env(), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('OWNER_PUBLICATION_AND_CAPABILITY_REVOKE PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
