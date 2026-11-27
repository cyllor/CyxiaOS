"""Exercise inventory discovery and keep diagnostic claims out of verdicts."""

import json
from pathlib import Path
import tempfile
import unittest
import zipfile

if __package__:
    from . import inventory_v0199_archives as inventory
else:
    import inventory_v0199_archives as inventory


class InventoryTests(unittest.TestCase):
    def test_exact_required_proof_classes_and_source_coverage(self):
        result = inventory.requirements()
        self.assertEqual(result["stable_ids"], 127)
        self.assertEqual(result["g4_required_pairs"], 262)
        self.assertEqual(result["g5_required_pairs"], 288)
        self.assertEqual(result["g4_required"], {"RUNTIME_QEMU": 127, "STATIC_EL1": 51,
                                                 "MODEL_CHECK": 84})
        self.assertEqual(result["g5_additional"], {"ARCH_A53": 26})

    def test_reads_zip_members_and_sees_malformed_candidates_without_promoting_status(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "test.zip"
            with zipfile.ZipFile(archive, "w") as files:
                files.writestr("diag/summary.json", json.dumps({"status": "PASS"}))
                files.writestr("diag/source-manifest.json", json.dumps({"rust-source.rs": "hash"}))
                files.writestr("run/frozen", json.dumps({"schema": inventory.MANIFEST_SCHEMA}))
                files.writestr("run/verdicts/00010001-1.bin", b"malformed test input")
                files.writestr("run/evidence/00010001-1.json", json.dumps({"files": []}))
                files.writestr("run/nested.zip", b"outside inventory scope")

            scan = inventory.ArchiveScan("expected")
            scan.inspect_path(archive)
            result = scan.result(archive)
            self.assertEqual(result["inspection_errors"], [])
            self.assertEqual(result["counts"]["nested_or_unsupported_containers_skipped"], 1)
            self.assertEqual(len(result["run_manifest_candidates"]), 1)
            self.assertFalse(result["run_manifest_candidates"][0]["inventory_hash_matches"])
            self.assertEqual(len(result["verdict_record_candidates"]), 1)
            self.assertIn("parse_error", result["verdict_record_candidates"][0])
            self.assertEqual(len(result["evidence_manifest_paths"]), 1)
            self.assertNotIn("PASS", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
