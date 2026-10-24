import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from verify_domains import ALL_FAMILIES, CONTROL_MAGIC, CONTROL_WORDS, CONTROL_CREDIT_MAGIC, IPI_MAGIC, RUNTIME_MAGIC, UNIFIED_MAGIC, code_source_map, diagnostics, parse_control, parse_control_credit, parse_ipi, parse_runtime, parse_tasks, parse_unified, sha, verify_source_build


def encode(values):
    return struct.pack(f"<{len(values)}Q", *values)


def control():
    values = [0] * CONTROL_WORDS
    values[:4] = [CONTROL_MAGIC, 1, 7, ALL_FAMILIES]
    values[12:14] = [64, 640]
    return values


class EvidenceParserTests(unittest.TestCase):
    def source_build(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        for name in ("kernel/src/smp.rs", "crates/arch-aarch64/src/user.rs", "Cargo.lock", "tools/build_unified.py"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("source fixture\n")
        sources = code_source_map(root)
        digest = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        data = {
            "schema_version": 1, "status": "BUILT_NOT_RUN", "profiles": {"selftest": True},
            "own_private_key_only_verified": True, "code_source_map": sources,
            "code_source_sha256": digest, "builder_sha256": sha(root / "tools/build_unified.py"),
            "artifacts": {"node-a.elf": {"sha256": "a" * 64}, "node-b.elf": {"sha256": "b" * 64}},
            "nodes": {"a": {"node_id": "a" * 64, "peer_node_id": "b" * 64},
                      "b": {"node_id": "b" * 64, "peer_node_id": "a" * 64}},
        }
        path = root / "build-manifest.json"
        path.write_text(json.dumps(data))
        return path, root, data

    def test_truncated_capture_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "size"):
            parse_control(encode(control())[:-8])

    def test_boot_identity_must_match(self):
        with self.assertRaisesRegex(ValueError, "BootEpoch"):
            parse_control(encode(control()), boot_epoch=8)

    def test_registered_families_are_not_execution(self):
        result = parse_control(encode(control()), boot_epoch=7)
        self.assertEqual(result["registered_families"], ALL_FAMILIES)
        self.assertEqual(result["applied_objects"], [])

    def test_applied_cannot_be_configuration_only(self):
        values = control()
        at = 512
        for index, value in {0: 1, 1: 1, 2: 4, 3: 1, 4: 22, 5: 7,
                             7: 7, 8: 1, 9: 2, 14: 2, 28: 3, 30: 1}.items():
            values[at + index] = value
        with self.assertRaisesRegex(ValueError, "published EL0 reply"):
            parse_control(encode(values))
        values[at + 639] = 1
        self.assertEqual(parse_control(encode(values))["applied_objects"], [])

    def test_fatal_and_nonzero_file_exit_never_pass(self):
        values = [0] * 512
        values[15] = 25
        with self.assertRaisesRegex(ValueError, "fatal code 25"):
            parse_unified(encode(values))
        values[0:2] = [UNIFIED_MAGIC, 7]
        values[15:21] = [0, 1, 4096, 4, 1, 16]
        with self.assertRaisesRegex(ValueError, "exit code 16"):
            parse_unified(encode(values))

    def test_disabled_file_probe_is_not_success(self):
        values = [0] * 512
        values[0:2] = [UNIFIED_MAGIC, 7]
        with self.assertRaisesRegex(ValueError, "enabled ordinary EL0 file probe"):
            parse_unified(encode(values))

    def test_completed_probe_does_not_hide_cluster_service_fatal(self):
        values = [0] * 512
        values[0:2] = [UNIFIED_MAGIC, 7]
        values[6] = 2
        values[16:21] = [1, 4096, 4, 1, 0]
        values[32:36] = [1, 1, 0x107, 2]
        with self.assertRaisesRegex(ValueError, "fatal event"):
            parse_unified(encode(values))
        values[34] = (1 << 63) | 0x500
        with self.assertRaisesRegex(ValueError, "fatal event"):
            parse_unified(encode(values))

    def test_business_core_quarantine_cannot_hide_behind_control_progress(self):
        values = [0] * 32
        values[0] = 0x43595441534B0001
        values[2] = 12
        values[3] = 2
        with self.assertRaisesRegex(ValueError, "overrun/quarantine"):
            parse_tasks(encode(values))

    def test_published_overrun_remains_a_real_receipt_but_fails_acceptance(self):
        values = control()
        at = 512
        for index, value in {0: 1, 1: 1, 7: 7, 12: 500_001,
                             13: 1, 14: 1, 18: 1, 30: 1}.items():
            values[at + index] = value
        with self.assertRaisesRegex(ValueError, "0.5 ms publication"):
            parse_control(encode(values))
        values[at + 12] = 500_000
        values[at + 18] = 0
        values[at + 10] = 1_900_000
        values[at + 11] = 100_000
        values[at + 29] = 1
        with self.assertRaisesRegex(ValueError, "encoding/inference/decoding"):
            parse_control(encode(values))

    def test_sticky_credit_failure_cannot_be_hidden_by_old_task_snapshot(self):
        task = [0] * 32
        task[0] = 0x43595441534B0001
        sticky = [0] * 32
        sticky[:2] = [0x43594F5652520001, 1]
        with self.assertRaisesRegex(ValueError, "sticky CPU credit overrun"):
            diagnostics({}, {
                "UNIFIED_EVIDENCE": encode([0] * 512),
                "DOMAIN_TASK_EVIDENCE": encode(task),
                "TASK_OVERRUN_EVIDENCE": encode(sticky),
            })

    def test_ipi_notification_is_not_a_completed_wake(self):
        values = [0] * 512
        values[:5] = [IPI_MAGIC, 1, 15, 1, 3]
        values[8] = 3
        self.assertFalse(parse_ipi(encode(values))["wake_verified"])
        values[5:7] = [1, 1]
        values[10] = 1
        self.assertFalse(parse_ipi(encode(values))["wake_verified"])
        values[5:7] = [2, 2]
        values[9] = 1
        self.assertTrue(parse_ipi(encode(values))["wake_verified"])

    def test_c_credit_receipt_rejects_even_when_periodic_task_record_is_clean(self):
        receipt = [0] * 64
        receipt[:2] = [CONTROL_CREDIT_MAGIC, 1]
        receipt[2:24] = [2, 1, 7, 1, 9, 900_000_000, 900_010_000,
                          902_600_000, 2_500_000, 2_590_000, 5_000_000,
                          5_090_000, 5_000_000, 5_090_000, 6, 120,
                          700_000, 900_011_000, 2, 1, 1, 7]
        parsed = parse_control_credit(encode(receipt))
        self.assertEqual(parsed[0]["actual_ns"], 2_590_000)
        self.assertEqual(parsed[0]["last_phase"], 6)
        guest = {}
        with self.assertRaisesRegex(ValueError, "native C credit failure"):
            diagnostics(guest, {"UNIFIED_EVIDENCE": encode([0] * 512),
                                "CONTROL_CREDIT_EVIDENCE": encode(receipt),
                                "DOMAIN_TASK_EVIDENCE": encode([0] * 32)})
        self.assertEqual(guest["control_credit"], parsed)

    def test_incomplete_c_credit_failure_is_not_a_successful_capture(self):
        receipt = [0] * 64
        receipt[24] = 1
        with self.assertRaisesRegex(ValueError, "native C credit failure"):
            diagnostics({}, {"UNIFIED_EVIDENCE": encode([0] * 512),
                             "CONTROL_CREDIT_EVIDENCE": encode(receipt)})

    def test_runtime_sticky_control_fault_survives_partial_snapshot(self):
        runtime = [0] * 1024
        runtime[:3] = [RUNTIME_MAGIC, 3, 5]
        runtime[38] = 1
        with self.assertRaisesRegex(ValueError, "control worker fault count 1"):
            parse_runtime(encode(runtime))
        runtime[38] = 0
        self.assertIsNone(parse_runtime(encode(runtime)))

    def test_ipi_receipt_must_have_real_handler_and_consume(self):
        values = [0] * 512
        values[:5] = [IPI_MAGIC, 1, 15, 1, 3]
        values[8:10] = [3, 1]
        with self.assertRaisesRegex(ValueError, "real handler receipt"):
            parse_ipi(encode(values))
        values[5:7] = [1, 1]
        values[13] = 2
        with self.assertRaisesRegex(ValueError, "IPI receipt error 2"):
            parse_ipi(encode(values))

    def test_build_binding_checks_actual_source_and_image_not_only_manifest(self):
        path, root, data = self.source_build()
        proof = verify_source_build(path, root, ["a" * 64, "b" * 64])
        self.assertEqual(proof["code_source_sha256"], data["code_source_sha256"])
        with self.assertRaisesRegex(ValueError, "image differs"):
            verify_source_build(path, root, ["a" * 64, "c" * 64])
        (root / "kernel/src/smp.rs").write_text("changed after build\n")
        with self.assertRaisesRegex(ValueError, "source changed"):
            verify_source_build(path, root, ["a" * 64, "b" * 64])

    def test_build_binding_rejects_unbound_source_and_same_node_identity(self):
        path, root, data = self.source_build()
        data["nodes"]["b"] = data["nodes"]["a"]
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "distinct reciprocal identities"):
            verify_source_build(path, root, ["a" * 64, "b" * 64])
        (root / "kernel/src/new.rs").write_text("new compiled source\n")
        with self.assertRaisesRegex(ValueError, "source changed"):
            verify_source_build(path, root, ["a" * 64, "b" * 64])


if __name__ == "__main__":
    unittest.main()
