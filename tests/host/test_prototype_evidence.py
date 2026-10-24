"""Synthetic receipts test validator mechanics; none is guest execution evidence."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import check_prototype_evidence as check


class PrototypeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "code.rs").write_text("// Synthetic test-only code path\n")
        self.tree = "a" * 40
        self.doc = {"schema_version": 1, "baseline_commit": "b" * 40, "baseline_tree": self.tree,
                    "specs": dict(check.SPECS), "requirements": [
                        {"id": i, "requirement": "Synthetic fixture", "clause": "test fixture", "status": "NOT_RUN",
                         "gap": "No actual guest execution", "code": ["code.rs"], "evidence": None}
                        for i in sorted(check.REQUIRED)]}

    def artifact(self, name, data=b"test-only, not a guest artifact\n"):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}

    def row(self, ident="A01"):
        return next(r for r in self.doc["requirements"] if r["id"] == ident)

    def receipt(self, ident="A01"):
        r = {"schema_version": 1, "test_id": ident, "verdict": "PASS", "source_tree": self.tree,
             "execution": "native-cyxia-guest", "nodes": [], "build_id": "TEST_FIXTURE_ONLY",
             "qemu_version": "TEST_FIXTURE_ONLY", "seed": 0, "fault_injection_point": "synthetic",
             "expected_invariant": "synthetic", "observed_result": "synthetic"}
        for i in range(2 if ident in check.CLUSTER else 1):
            r["nodes"].append({"node_id": str(i+1) * 64, "boot_epoch": 1, "os": "CyxiaOS", "vcpus": 4,
                               "image": self.artifact(f"images/{i}.elf")})
        for f in ("model", "action_schema", "machine_config", "events", "reproducer", "verifier"):
            r[f] = self.artifact(f"fixture/{f}.bin")
        return r

    def bind(self, receipt):
        row = self.row(receipt["test_id"])
        row["status"] = "PASS"
        row["evidence"] = self.artifact(f'receipts/{row["id"]}.json', json.dumps(receipt).encode())

    def validate(self):
        return check.validate(self.doc, self.root, self.tree)

    def test_repository_catalogue_is_complete_but_not_runtime_pass(self):
        result = check.validate(check.read_json(check.DEFAULT), ROOT, self.tree)
        self.assertEqual(result["requirements"], 81)
        self.assertFalse(result["release_evidence_complete"])
        self.assertFalse(result["runtime_truth_attested"])
        self.assertEqual(result["states"]["PASS"], 0)

    def test_missing_or_duplicate_gate_cannot_reduce_denominator(self):
        self.doc["requirements"].pop()
        with self.assertRaises(check.EvidenceError): self.validate()
        self.setUp()
        self.doc["requirements"][-1] = copy.deepcopy(self.doc["requirements"][0])
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_seven_states_are_explicit_and_unrecognized_states_rejected(self):
        self.assertEqual(len(check.STATUSES), 7)
        self.row()["status"] = "DONE"
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_pass_without_bound_artifacts_is_rejected(self):
        self.row()["status"] = "PASS"
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_synthetic_consistent_receipt_only_validates_integrity(self):
        self.bind(self.receipt())
        r = self.validate()
        self.assertEqual(r["states"]["PASS"], 1)
        self.assertFalse(r["release_evidence_complete"])
        self.assertFalse(r["runtime_truth_attested"])

    def test_host_tests_do_not_close_a_native_requirement(self):
        r = self.receipt(); r["execution"] = "host-unit-test"; self.bind(r)
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_other_source_tree_does_not_close_current_requirement(self):
        r = self.receipt(); r["source_tree"] = "f" * 40; self.bind(r)
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_false_verdict_cannot_be_changed_by_outer_pass_status(self):
        r = self.receipt(); r["verdict"] = "FAIL"; self.bind(r)
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_missing_context_or_hash_mismatch_is_rejected(self):
        for f in ("model", "action_schema", "machine_config", "events", "reproducer", "verifier"):
            with self.subTest(field=f):
                r = self.receipt(); r[f]["sha256"] = "f" * 64; self.bind(r)
                with self.assertRaises(check.EvidenceError): self.validate()

    def test_node_count_and_distinct_incarnations_are_required(self):
        r = self.receipt("T01"); r["nodes"].pop(); self.bind(r)
        with self.assertRaises(check.EvidenceError): self.validate()
        r = self.receipt("T01"); r["nodes"][1]["node_id"] = r["nodes"][0]["node_id"]; self.bind(r)
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_proxy_os_or_single_cpu_cannot_satisfy_native_target(self):
        for field, value in [("os", "Linux proxy"), ("vcpus", 1), ("vcpus", True), ("boot_epoch", 0)]:
            with self.subTest(field=field):
                r = self.receipt(); r["nodes"][0][field] = value; self.bind(r)
                with self.assertRaises(check.EvidenceError): self.validate()

    def test_symlinks_in_any_path_component_are_rejected(self):
        target = self.root / "real"; target.mkdir(); (target / "data").write_bytes(b"payload")
        (self.root / "alias").symlink_to(target, target_is_directory=True)
        with self.assertRaises(check.EvidenceError): check.safe_path(self.root, "alias/data")
        (self.root / "link").symlink_to(target / "data")
        with self.assertRaises(check.EvidenceError): check.safe_path(self.root, "link")

    def test_escape_absolute_backslash_and_noncanonical_paths_rejected(self):
        for name in ["../code.rs", "/code.rs", "a/../code.rs", "./code.rs", "a\\b", "", "a//b"]:
            with self.subTest(name=name):
                with self.assertRaises(check.EvidenceError): check.safe_path(self.root, name)

    def test_specification_hash_cannot_silently_change(self):
        self.doc["specs"]["system"] = "0" * 64
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_duplicate_json_keys_and_nonfinite_numbers_rejected(self):
        for payload in ['{"status":"FAIL","status":"PASS"}', '{"seed":NaN}']:
            p = self.root / "bad.json"; p.write_text(payload)
            with self.assertRaises(check.EvidenceError): check.read_json(p)

    def test_nonpass_cannot_smuggle_a_success_receipt(self):
        self.bind(self.receipt()); self.row()["status"] = "IMPLEMENTED"
        with self.assertRaises(check.EvidenceError): self.validate()

    def test_release_mode_refuses_well_formed_but_incomplete_manifest(self):
        p = self.root / "catalogue.json"; p.write_text(json.dumps(self.doc))
        self.assertEqual(check.main(["--manifest", str(p), "--root", str(self.root),
                                     "--source-tree", self.tree, "--release"]), 2)

    def test_failed_native_receipt_is_retained_but_blocks_release(self):
        r = self.receipt(); r["verdict"] = "FAIL"; self.bind(r); self.row()["status"] = "FAIL"
        out = self.validate()
        self.assertEqual(out["states"]["FAIL"], 1)
        self.assertFalse(out["release_evidence_complete"])

    def test_unknown_schema_fields_are_not_ignored(self):
        self.row()["override_pass"] = True
        with self.assertRaises(check.EvidenceError): self.validate()


if __name__ == "__main__":
    unittest.main()
