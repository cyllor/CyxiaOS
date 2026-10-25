import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from verify_domains import ALL_FAMILIES, CONTROL_MAGIC, CONTROL_WORDS, CONTROL_CREDIT_MAGIC, CONTROL_POOL_MAGIC, LEARNING_MAGIC, IPI_MAGIC, RUNTIME_MAGIC, UNIFIED_MAGIC, code_source_map, diagnostics, parse_control, parse_control_credit, parse_control_pool, parse_learning, parse_ipi, parse_runtime, parse_tasks, parse_unified, sha, verify_source_build
from verify_domains import RECONNECT_OUTAGE_NS, ReconnectProbe, run


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
        for name in ("kernel/src/smp.rs", "crates/arch-aarch64/src/user.rs", "Cargo.lock", "tools/build_unified.py",
                     "ports/control-service/core-head.bin", "ports/control-service/model-sha256.rs"):
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

    def test_embedded_model_outside_crates_is_bound_to_actual_build(self):
        path, root, data = self.source_build()
        name = "ports/control-service/core-head.bin"
        self.assertIn(name, data["code_source_map"])
        self.assertIn("ports/control-service/model-sha256.rs", data["code_source_map"])
        (root / name).write_bytes(b"\x00\xffchanged model parameters\x00")
        with self.assertRaisesRegex(ValueError, "source changed"):
            verify_source_build(path, root, ["a" * 64, "b" * 64])

    def learning(self):
        values = [0] * 128
        for index, value in {0: LEARNING_MAGIC, 1: 1, 2: 7, 3: 1, 13: 5, 14: 1,
                             15: 1, 22: 1024 * 1024, 25: 1, 26: 1, 127: 2}.items():
            values[index] = value
        return values

    def test_actual_control_pool_must_fit_its_fixed_backing(self):
        values = [0] * 16
        values[:6] = [CONTROL_POOL_MAGIC, 8 * 1024 * 1024, 0x44000000, 64, 4, 2]
        self.assertEqual(parse_control_pool(encode(values))["allocated_pages"], 64)
        values[3] = 2049
        with self.assertRaisesRegex(ValueError, "allocation/pin bounds"):
            parse_control_pool(encode(values))

    def test_independent_operator_selftest_is_never_training(self):
        values = self.learning()
        result = parse_learning(encode(values))
        self.assertTrue(result["mechanism_ready"])
        self.assertTrue(result["data_incomplete"])
        self.assertFalse(result["trained_model_verified"])
        self.assertEqual((result["jobs"], result["completed"]), (0, 0))
        values[13] = 4
        self.assertFalse(parse_learning(encode(values))["mechanism_ready"])
        values[17] = 1
        with self.assertRaisesRegex(ValueError, "without a real submitted job"):
            parse_learning(encode(values))

    def test_learning_failure_survives_an_interrupted_evidence_write(self):
        values = self.learning()
        values[127] = 3
        self.assertIsNone(parse_learning(encode(values)))
        values[10] = 17
        with self.assertRaisesRegex(ValueError, "worker fault 17"):
            parse_learning(encode(values))

    def test_learning_charges_only_sum_the_same_physical_cpu_window(self):
        values = self.learning()
        values[4:6] = [9_000_000, 65_000_000]
        values[27:29] = [41, 42]
        self.assertIsNotNone(parse_learning(encode(values)))
        values[27] = 42
        with self.assertRaisesRegex(ValueError, "actual budget"):
            parse_learning(encode(values))
        values[27] = 41
        values[4] = 9_000_001
        with self.assertRaisesRegex(ValueError, "actual budget"):
            parse_learning(encode(values))


class ReconnectProbeTests(unittest.TestCase):
    class Qmp:
        def __init__(self):
            self.calls = []

        def execute(self, command, arguments):
            self.calls.append((command, arguments))

    def guests(self):
        guests = []
        for frequency in (1000, 2000):
            runtime = [0] * 1024
            runtime[:5] = [RUNTIME_MAGIC, 3, 2, frequency, frequency]
            runtime[14], runtime[20], runtime[32] = 10, 20, 7
            unified = [0] * 512
            unified[:2] = [UNIFIED_MAGIC, 7]
            unified[4:7] = [100, 100, 5]
            unified[16:21] = [1, 4096, 4, 1, 0]
            unified[32:42:2] = [1, 2, 3, 0x211, 0x212]
            guests.append({"qmp": self.Qmp(), "runtime": parse_runtime(encode(runtime)),
                           "unified": parse_unified(encode(unified))})
        return guests

    def update(self, guest, ms, *, inferences=None, business=None, events=None, traffic=None):
        runtime, unified = guest["runtime"], guest["unified"]
        runtime["clock_ticks"] = ms * runtime["timer_frequency"] // 1000
        if inferences is not None:
            runtime["inferences"] = inferences
        if business is not None:
            runtime["business_cpu3"] = business
        if events is not None:
            unified["events"].extend(events)
        if traffic is not None:
            unified["sent_bytes"] += traffic
            unified["received_bytes"] += traffic

    def down(self):
        guests, probe = self.guests(), ReconnectProbe()
        self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "isolating")
        for guest in guests:
            # Work between the cut command and this captured baseline must
            # not be credited to the independently measured outage interval.
            self.update(guest, 1100, inferences=15, business=25)
        self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "down")
        return guests, probe

    def up(self):
        guests, probe = self.down()
        for guest in guests:
            self.update(guest, 3100, inferences=16, business=26, events=[4])
        self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "up")
        return guests, probe

    def test_initial_connection_and_all_existing_functional_gates_precede_cut(self):
        guests, probe = self.guests(), ReconnectProbe()
        guests[1]["unified"]["events"].pop()
        self.assertFalse(probe.step(guests, True))
        self.assertTrue(all(not guest["qmp"].calls for guest in guests))
        guests[1]["unified"]["events"].append(0x212)
        self.assertFalse(probe.step(guests, False))
        self.assertTrue(all(not guest["qmp"].calls for guest in guests))
        self.assertFalse(probe.step(guests, True))
        for guest in guests:
            self.assertEqual(guest["qmp"].calls, [("set_link", {"name": "eth0", "up": False})])

    def test_each_guest_clock_not_host_sleep_controls_outage(self):
        guests, probe = self.down()
        for guest, milliseconds in zip(guests, (3100, 3099)):
            self.update(guest, milliseconds, inferences=16, business=26, events=[4])
        with patch("verify_domains.time.monotonic", return_value=1_000_000):
            self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "down")
        self.assertTrue(all(len(guest["qmp"].calls) == 1 for guest in guests))
        self.update(guests[1], 3100)
        self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "up")
        self.assertEqual([p["guest_elapsed_ns"] for p in probe.progress],
                         [RECONNECT_OUTAGE_NS, RECONNECT_OUTAGE_NS])

    def test_long_outage_without_actual_service_disconnect_cannot_restore(self):
        guests, probe = self.down()
        for guest in guests:
            self.update(guest, 3100, inferences=16, business=26)
        self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "down")
        self.update(guests[0], 3100, events=[4])
        self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "down")
        self.update(guests[1], 3100, events=[4])
        self.assertFalse(probe.step(guests, True))
        self.assertEqual(probe.phase, "up")

    def test_pre_cut_work_or_one_sided_progress_cannot_hide_local_stall(self):
        for missing in ("inferences", "business"):
            with self.subTest(missing=missing):
                guests, probe = self.down()
                for guest in guests:
                    self.update(guest, 3100, inferences=16, business=26, events=[4])
                self.update(guests[1], 3100, **{missing: 15 if missing == "inferences" else 25})
                with self.assertRaisesRegex(ValueError, "AI/business stopped"):
                    probe.step(guests, True)
                self.assertTrue(all(len(guest["qmp"].calls) == 1 for guest in guests))

    def test_old_authentication_or_one_new_peer_is_not_reauthentication(self):
        guests, probe = self.up()
        self.assertFalse(probe.step(guests, True))
        self.update(guests[0], 3200, events=[3, 0x212], traffic=10)
        self.assertFalse(probe.step(guests, True))
        self.assertFalse(probe.evidence()["verified"])
        self.update(guests[1], 3200, events=[3, 0x212], traffic=10)
        self.assertTrue(probe.step(guests, True))
        self.assertTrue(probe.evidence()["verified"])
        self.assertEqual(len(probe.evidence()["commands"]), 4)
        for guest in guests:
            self.assertEqual(guest["qmp"].calls, [
                ("set_link", {"name": "eth0", "up": False}),
                ("set_link", {"name": "eth0", "up": True})])

    def test_ready_must_follow_new_authentication_and_new_bidirectional_bytes(self):
        guests, probe = self.up()
        for guest in guests:
            self.update(guest, 3200, events=[0x212, 3])
        self.assertFalse(probe.step(guests, True))
        for guest in guests:
            self.update(guest, 3200, events=[0x212])
        self.assertFalse(probe.step(guests, True))
        for guest in guests:
            self.update(guest, 3200, traffic=1)
        self.assertTrue(probe.step(guests, True))

    def test_reboot_timer_change_and_counter_rollback_are_not_outage_progress(self):
        for field in ("boot_epoch", "timer_frequency", "clock_ticks", "inferences"):
            with self.subTest(field=field):
                guests, probe = self.down()
                if field == "boot_epoch":
                    guests[0]["runtime"][field] += 1
                    guests[0]["unified"][field] += 1
                elif field == "timer_frequency":
                    guests[0]["runtime"][field] += 1
                else:
                    guests[0]["runtime"][field] -= 1
                with self.assertRaisesRegex(ValueError, "changed|regressed"):
                    probe.step(guests, True)
        guests, probe = self.down()
        guests[0]["unified"]["events"][2] = 4
        with self.assertRaisesRegex(ValueError, "history regressed"):
            probe.step(guests, True)

    def test_single_guest_reconnect_is_rejected_before_any_process_or_file_work(self):
        with self.assertRaisesRegex(ValueError, "requires --peer-elf"):
            run(SimpleNamespace(timeout=60, hold=0, sample_ms=250,
                                single=True, peer_elf=None, reconnect=True))
        with self.assertRaisesRegex(ValueError, "two native guests"):
            ReconnectProbe().step(self.guests()[:1], True)


if __name__ == "__main__":
    unittest.main()
