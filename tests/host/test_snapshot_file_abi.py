"""Execute the production snapshot wire parser and native broker on a real journal.

These are host regression proofs. They do not attest native boot or QEMU cuts.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from host_prototype_library import build_host_prototype_library


class SnapshotFileAbi(unittest.TestCase):
    def test_shared_schema_golden_vectors_and_malformed_shapes(self):
        with tempfile.TemporaryDirectory(prefix='snapshot-schema-') as temporary:
            binary = Path(temporary) / 'schema'
            result = subprocess.run([
                str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                str(ROOT / 'tests/host/snapshot_schema_harness.rs'), '-o', str(binary),
            ], env=env(), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('4 passed', result.stdout)

    def test_real_broker_authority_history_and_retained_completion(self):
        deps, library = build_host_prototype_library()
        source = (ROOT / 'tests/host/snapshot_file_broker_harness.rs').read_text()
        source = source.replace('__BROKER__', str(ROOT / 'kernel/src/runtime/files/domain_file_abi.rs'))
        source = source.replace('__SNAPSHOT_ADAPTER__', str(ROOT / 'tests/host/snapshot_storage_adapter.rs'))
        with tempfile.TemporaryDirectory(prefix='snapshot-broker-') as temporary:
            source_path = Path(temporary) / 'harness.rs'
            binary = Path(temporary) / 'harness'
            source_path.write_text(source)
            result = subprocess.run([
                str(RUST_BIN / 'rustc'), '--edition=2024', '-C', 'opt-level=1', '-C', 'panic=abort',
                str(source_path), '-L', 'dependency=' + str(deps),
                '--extern', 'cyxia_prototype=' + str(library), '-o', str(binary),
            ], env=env(), capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for signal in ['HANDLE_BUDGET', 'SNAPSHOT_BUDGET', 'AUTHORITY_BOUNDARIES', 'RETAINED_COMPLETION', 'PREFIX_DIGEST_SCOPE',
                           'IMMUTABLE_HISTORY', 'SHARED_COMPLETION_CUSTODY', 'RESTORE_EPOCH']:
                self.assertIn(signal + ' PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
