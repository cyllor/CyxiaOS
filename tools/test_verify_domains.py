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
from verify_domains import REPLAY_MAGIC, capture, parse_replay, refresh_snapshot, replay_ready


class PreparationRejectionTests(unittest.TestCase):
    def journal(self, total=1):
        values = [0x4359505245503133, total, max(0, total - 16), total * 2,
                  1, 40, 16, 0] + [0] * 640
        for ordinal in range(max(1, total - 15), total + 1):
            row = [0] * 40
            row[:18] = [ordinal + 10, 7, 2, 14, 1, 4, 5, 6, 9, 10,
                        100, 2_100_000, 0, 6, 3_000_000, 14, 0, 0]
            row[22:30] = [1] * 8
            row[30:34] = [row[0], 9, 10, ordinal]
            base = 8 + ((ordinal - 1) % 16) * 40
            values[base:base + 40] = row
        return values

    def parse(self, values):
        from verify_domains import parse_preparation_rejections
        return parse_preparation_rejections(encode(values))

    def test_wrapped_journal_keeps_original_cost_identity_and_order(self):
        parsed = self.parse(self.journal(18))
        self.assertEqual(parsed['total'], 18)
        self.assertEqual(parsed['overwritten'], 2)
        rows = parsed['retained']
        self.assertEqual([r['ordinal'] for r in rows], list(range(3, 19)))
        self.assertEqual(rows[0]['sequence'], 13)
        self.assertEqual(rows[0]['cpu_ns'], 2_100_000)
        self.assertEqual(rows[0]['snapshot_ns'], 100)
        self.assertEqual(rows[0]['error'], 'Budget')
        self.assertEqual(rows[0]['target'], [4, 5])
        self.assertIsNone(rows[0]['work'])

    def test_empty_and_in_progress_are_not_completed_rejections(self):
        self.assertIsNone(self.parse([0] * 648))
        words = self.journal()
        words[3] |= 1
        self.assertIsNone(self.parse(words))

    def test_readonly_identity_keeps_zero_slot_and_false_flags(self):
        words = self.journal()
        words[8 + 17:8 + 22] = [1, 42, 0, 0, 0]
        self.assertEqual(self.parse(words)['retained'][0]['work'], [42, 0, 0, 0])

    def test_warm_work_uses_u16_serial_instead_of_request_array_slot(self):
        words = self.journal()
        words[8 + 17:8 + 22] = [1, 42, 200, 1, 0]
        self.assertEqual(self.parse(words)['retained'][0]['work'], [42, 200, 1, 0])

    def test_malformed_retirement_cannot_be_reported_as_evidence(self):
        for offset, value in [(2, 1), (4, 2), (8 + 13, 10), (8 + 15, 13),
                              (8 + 30, 999), (8 + 33, 2), (8 + 34, 1),
                              (8 + 18, 1), (8 + 14, 99)]:
            with self.subTest(offset=offset, value=value):
                words = self.journal()
                words[offset] = value
                with self.assertRaises(ValueError):
                    self.parse(words)


def encode(values):
    return struct.pack(f"<{len(values)}Q", *values)


def control():
    values = [0] * CONTROL_WORDS
    values[:4] = [CONTROL_MAGIC, 1, 7, ALL_FAMILIES]
    values[12:14] = [64, 640]
    return values


class EvidenceParserTests(unittest.TestCase):
    def test_secondary_fault_retains_original_exception_before_cpu0_panic(self):
        guest = {}
        snapshot = self.snapshot()
        bank = [0x4359534d50464131, 1, 8, 8, 0, 0, 0, 0] + [0] * 64
        bank[16:24] = [44, 123, 4, 0x96000047, 0xffffffc042cf4000,
                       0xffffffc040425000, 0x345, 0xffffffc042cf3d50]
        snapshot['SMP_FAULT_EVIDENCE'] = encode(bank)
        with self.assertRaisesRegex(ValueError, 'secondary fatal evidence'):
            refresh_snapshot(guest, snapshot)
        self.assertEqual(guest.get('smp_fault_evidence'), bank)
        refresh_snapshot(guest, self.snapshot())
        self.assertIsNone(guest['smp_fault_evidence'])

    def test_multithread_tcg_rejects_instruction_count_clock_before_launch(self):
        args = SimpleNamespace(timeout=30, hold=0, sample_ms=250, single=True,
                               peer_elf=None, replay_pairs=0, reconnect=False,
                               clock_profile='icount', tcg_threads='multi')
        with self.assertRaisesRegex(ValueError, 'icount requires single-thread TCG'):
            run(args)

    def test_preparation_timing_survives_credit_failure_and_clears_when_absent(self):
        guest = {}
        snapshot = self.snapshot(overrun=True)
        timings = [100, 200, 220, 250, 400, 500, 550, 560] + [0] * 8
        snapshot['DOMAIN_PREPARATION_EVIDENCE'] = encode(timings)
        with self.assertRaisesRegex(ValueError, 'overrun/quarantine'):
            refresh_snapshot(guest, snapshot)
        self.assertEqual(guest.get('preparation_evidence'), timings)
        refresh_snapshot(guest, self.snapshot())
        self.assertIsNone(guest['preparation_evidence'])

    def test_preparation_stages_survive_fault_and_reject_truncated_capture(self):
        guest = {}
        snapshot = self.snapshot(overrun=True)
        stages = [100, 120, 140, 160, 180, 200, 220, 240, 260, 280, 300, 320] + [0] * 20
        snapshot['DOMAIN_PREPARATION_DETAIL'] = encode(stages)
        with self.assertRaisesRegex(ValueError, 'overrun/quarantine'):
            refresh_snapshot(guest, snapshot)
        self.assertEqual(guest.get('preparation_detail'), stages)
        snapshot = self.snapshot()
        snapshot['DOMAIN_PREPARATION_DETAIL'] = encode(stages[:-1])
        with self.assertRaises(ValueError):
            refresh_snapshot(guest, snapshot)
        self.assertIsNone(guest['preparation_detail'])
        refresh_snapshot(guest, self.snapshot())
        self.assertIsNone(guest['preparation_detail'])

    def test_rejected_preparation_keeps_original_cost_after_credit_failure(self):
        guest = {}
        snapshot = self.snapshot(overrun=True)
        journal = PreparationRejectionTests().journal()
        snapshot['DOMAIN_PREPARATION_REJECTIONS'] = encode(journal)
        with self.assertRaisesRegex(ValueError, 'overrun/quarantine'):
            refresh_snapshot(guest, snapshot)
        self.assertEqual(guest.get('preparation_rejections'), journal)
        self.assertEqual(guest['rejected_preparations']['retained'][0]['cpu_ns'], 2_100_000)
        snapshot = self.snapshot()
        snapshot['DOMAIN_PREPARATION_REJECTIONS'] = encode(journal[:-1])
        with self.assertRaisesRegex(ValueError, 'incorrect evidence size'):
            refresh_snapshot(guest, snapshot)
        self.assertIsNone(guest['preparation_rejections'])
        self.assertIsNone(guest['rejected_preparations'])
        refresh_snapshot(guest, self.snapshot())
        self.assertIsNone(guest['preparation_rejections'])

    def snapshot(self, *, returns=100, jobs=1, phase=3, generation=0, overrun=False):
        unified = [0] * 512
        unified[:3] = [UNIFIED_MAGIC, 7, returns]
        unified[6] = 3
        unified[16:21] = [1, 4096, 4, 0, 0]
        unified[32:38:2] = [1, 2, 3]
        ctl = control()
        ctl[4] = jobs
        task = [0] * 32
        task[:4] = [0x43595441534B0001, 3_809_301_008, int(overrun), int(overrun)]
        replay = [0] * 64
        replay[:10] = [2, REPLAY_MAGIC, phase, 1, 1, 0, 2, 1, 7, generation]
        if generation:
            replay[14:16] = [3_805_891_984, 9_805_891_984]
        return {"UNIFIED_EVIDENCE": encode(unified), "DOMAIN_CONTROL_EVIDENCE": encode(ctl),
                "DOMAIN_TASK_EVIDENCE": encode(task), "REPLAY_V13_EVIDENCE": encode(replay)}

    def test_final_fault_snapshot_keeps_new_replay_and_raw_without_old_healthy_fields(self):
        guest = {}
        refresh_snapshot(guest, self.snapshot())
        self.assertEqual(guest["tasks"]["overruns"], 0)
        self.assertEqual(guest["replay"]["phase"], 3)
        latest = self.snapshot(returns=2036, jobs=2, phase=4, generation=1, overrun=True)
        sticky = [0] * 32
        sticky[:12] = [0x43594F5645520001, 1, 76159, 257, 1, 2_500_000,
                       3_411_680, 3_805_887_472, 3_809_301_008, 38, 1, 0]
        latest["TASK_OVERRUN_EVIDENCE"] = encode(sticky)

        class Qmp:
            def __init__(self, memory):
                self.memory, self.calls = memory, []

            def execute(self, command, arguments=None):
                self.calls.append(command)
                if command == "pmemsave":
                    data = self.memory[arguments["val"]]
                    self.assert_size(arguments["size"], len(data))
                    Path(arguments["filename"]).write_bytes(data)

            @staticmethod
            def assert_size(expected, actual):
                if expected != actual:
                    raise AssertionError("fixture memory size mismatch")

        with tempfile.TemporaryDirectory() as temporary:
            guest["folder"] = Path(temporary)
            guest["locations"] = {name: {"pa": i * 0x100000, "size": len(data)}
                                  for i, (name, data) in enumerate(latest.items(), 1)}
            guest["qmp"] = Qmp({guest["locations"][name]["pa"]: data for name, data in latest.items()})
            bundle, = capture([guest], resume=False)
            with self.assertRaisesRegex(ValueError, "overrun/quarantine: mask=1 overruns=1"):
                refresh_snapshot(guest, bundle)
            self.assertEqual(guest["qmp"].calls[0], "stop")
            self.assertNotIn("cont", guest["qmp"].calls)
            for name, data in latest.items():
                self.assertEqual((guest["folder"] / (name + ".bin")).read_bytes(), data)
        self.assertIsNone(guest["tasks"], "failed task parse must not leave the older zero-overrun result")
        self.assertEqual(guest["task_evidence"][2:4], [1, 1])
        self.assertEqual(guest["overrun_evidence"], sticky)
        self.assertEqual(guest["unified"]["el0_returns"], 2036)
        self.assertEqual(guest["control"]["jobs"], 2)
        self.assertEqual(guest["replay"]["phase"], 4)
        self.assertEqual(guest["replay"]["capture_generation"], 1)
        self.assertEqual(guest["replay"]["first_ns"], 3_805_891_984)
        self.assertEqual([e["field"] for e in guest["diagnostic_errors"]], ["tasks", "overrun_evidence"])

    def test_invalid_unified_does_not_hide_new_control_or_supply_an_old_boot_identity(self):
        guest = {}
        refresh_snapshot(guest, self.snapshot())
        latest = self.snapshot(returns=200, jobs=3, phase=4, generation=1)
        bad_unified = list(struct.unpack("<512Q", latest["UNIFIED_EVIDENCE"]))
        bad_unified[15] = 37
        latest["UNIFIED_EVIDENCE"] = encode(bad_unified)
        new_control = control()
        new_control[2], new_control[4] = 8, 3
        latest["DOMAIN_CONTROL_EVIDENCE"] = encode(new_control)
        with self.assertRaisesRegex(ValueError, "native fatal code 37"):
            refresh_snapshot(guest, latest)
        self.assertIsNone(guest["unified"])
        self.assertEqual(guest["unified_words"][15], 37)
        self.assertEqual((guest["control"]["boot_epoch"], guest["control"]["jobs"]), (8, 3))
        self.assertEqual(guest["replay"]["phase"], 4)
        self.assertEqual([e["field"] for e in guest["diagnostic_errors"]], ["unified"])

    def test_root_failure_diagnostic_survives_other_fault_and_is_never_an_acceptance_gate(self):
        guest = {"replay_root_evidence": [999] * 32, "replay_owner_evidence": [999] * 32,
                 "replay_config_evidence": [999] * 32, "replay_capture_evidence": [999] * 32,
                 "local_placement_evidence": [999] * 32}
        latest = self.snapshot(overrun=True)
        root = list(range(32))
        owner = list(reversed(range(32)))
        placement = [2 * n for n in range(32)]
        configuration = [3 * n for n in range(32)]
        capture_loss = [4 * n for n in range(32)]
        latest["REPLAY_ROOT_EVIDENCE"] = encode(root)
        latest["REPLAY_OWNER_EVIDENCE"] = encode(owner)
        latest["LOCAL_PLACEMENT_EVIDENCE"] = encode(placement)
        latest["REPLAY_CONFIG_EVIDENCE"] = encode(configuration)
        latest["REPLAY_CAPTURE_EVIDENCE"] = encode(capture_loss)
        with self.assertRaisesRegex(ValueError, "overrun/quarantine"):
            refresh_snapshot(guest, latest)
        self.assertEqual(guest["replay_root_evidence"], root)
        self.assertEqual(guest["replay_owner_evidence"], owner)
        self.assertEqual(guest["local_placement_evidence"], placement)
        self.assertEqual(guest["replay_config_evidence"], configuration)
        self.assertEqual(guest["replay_capture_evidence"], capture_loss)
        self.assertFalse(replay_ready(guest["replay"], 1))
        refresh_snapshot(guest, self.snapshot())
        self.assertIsNone(guest["replay_root_evidence"])
        self.assertIsNone(guest["replay_owner_evidence"])
        self.assertIsNone(guest["local_placement_evidence"])
        self.assertIsNone(guest["replay_config_evidence"])
        self.assertIsNone(guest["replay_capture_evidence"])

    def test_independent_parser_faults_all_refresh_and_incomplete_optional_fields_clear(self):
        guest = {"runtime": {"old": True}, "learning": {"old": True}, "panic_evidence": [99]}
        refresh_snapshot(guest, self.snapshot())
        self.assertIsNone(guest["runtime"])
        self.assertIsNone(guest["learning"])
        self.assertIsNone(guest["panic_evidence"])
        latest = self.snapshot(returns=300, jobs=4, overrun=True)
        partial = list(struct.unpack("<64Q", latest["REPLAY_V13_EVIDENCE"]))
        partial[0] = 3
        latest["REPLAY_V13_EVIDENCE"] = encode(partial)
        bad_control = control()
        bad_control[25] = 9
        latest["DOMAIN_CONTROL_EVIDENCE"] = encode(bad_control)
        latest["PANIC_EVIDENCE"] = encode([1] + [0] * 7)
        with self.assertRaisesRegex(ValueError, "overrun/quarantine"):
            refresh_snapshot(guest, latest)
        self.assertIsNone(guest["tasks"])
        self.assertIsNone(guest["control"])
        self.assertIsNone(guest["replay"], "odd seqlock cannot retain a prior accepted replay snapshot")
        self.assertEqual(guest["unified"]["el0_returns"], 300)
        self.assertEqual([e["field"] for e in guest["diagnostic_errors"]], ["tasks", "panic_evidence", "control"])

    def test_preparation_cleanup_has_no_capture_or_accepted_pair(self):
        values = [0] * 64
        values[0:8] = [2, REPLAY_MAGIC, 23, 1, 2, 0, 1, 2]
        values[8] = 7
        parsed = parse_replay(encode(values))
        self.assertEqual(parsed["phase"], 23)
        self.assertEqual(parsed["boot_epoch"], 7)
        self.assertEqual(parsed["capture_generation"], 0)
        self.assertFalse(replay_ready(parsed, 1))
        values[2] = 24
        with self.assertRaisesRegex(ValueError, "invalid native replay state"):
            parse_replay(encode(values))

    def test_native_pair_gate_needs_both_actual_sides_and_durable_archives(self):
        values = [0] * 64
        values[0:8] = [2, REPLAY_MAGIC, 5, 1, 1, 0, 1, 2]
        values[10] = 1
        values[17] = 1
        values[19] = 1
        values[24] = 1
        result = parse_replay(encode(values))
        self.assertFalse(replay_ready(result, 1))
        values[10] = values[17] = 2
        self.assertTrue(replay_ready(parse_replay(encode(values)), 1))
        self.assertFalse(replay_ready(parse_replay(encode(values)), 2))
        values[17] = 1
        with self.assertRaisesRegex(ValueError, "before durable archive"):
            parse_replay(encode(values))

    def test_partial_replay_snapshot_and_unmatched_label_count_are_not_evidence(self):
        values = [0] * 64
        values[0:8] = [3, REPLAY_MAGIC, 5, 1, 1, 0, 1, 2]
        self.assertIsNone(parse_replay(encode(values)))
        values[0] = 4
        values[19] = 1
        with self.assertRaisesRegex(ValueError, "label count mismatch"):
            parse_replay(encode(values))

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
        preparation = list(range(16))
        detail = list(range(32))
        prefix_detail = list(range(16))
        entry_detail = list(range(16))
        context = [4, 3, 1, 0x1234, 7, 1024, 32, 900_010_000] + [0] * 8
        with self.assertRaisesRegex(ValueError, r'"preparation_evidence":\[0,1,2'):
            diagnostics(guest, {"UNIFIED_EVIDENCE": encode([0] * 512),
                                "CONTROL_CREDIT_EVIDENCE": encode(receipt),
                                "DOMAIN_TASK_EVIDENCE": encode([0] * 32),
                                "DOMAIN_PREPARATION_EVIDENCE": encode(preparation),
                                "DOMAIN_PREPARATION_DETAIL": encode(detail),
                                "DOMAIN_PREPARATION_PREFIX_DETAIL": encode(prefix_detail),
                                "DOMAIN_PREPARATION_ENTRY_DETAIL": encode(entry_detail),
                                "DOMAIN_PREPARATION_CONTEXT": encode(context)})
        self.assertEqual(guest["control_credit"], parsed)
        self.assertEqual(guest["preparation_evidence"], preparation)
        self.assertEqual(guest["preparation_detail"], detail)
        self.assertEqual(guest["preparation_prefix_detail"], prefix_detail)
        self.assertEqual(guest["preparation_entry_detail"], entry_detail)
        self.assertEqual(guest["preparation_context"], context)

    def test_standalone_service_stage_overrides_legacy_unified_word(self):
        unified = [0] * 512
        unified[30] = 41
        sticky = [0] * 32
        sticky[0] = 1
        guest = {}
        with self.assertRaisesRegex(ValueError, r'"service_stage":47'):
            diagnostics(guest, {
                "UNIFIED_EVIDENCE": encode(unified),
                "UNIFIED_SERVICE_STAGE": encode([47]),
                "TASK_OVERRUN_EVIDENCE": encode(sticky),
            })
        self.assertEqual(guest["service_stage_word"], 47)

    def test_service_detail_is_retained_in_credit_failure(self):
        unified = [0] * 512
        sticky = [0] * 32
        sticky[0] = 1
        detail = list(range(16))
        with self.assertRaisesRegex(ValueError, r'"service_detail":\[0,1,2'):
            diagnostics({}, {
                "UNIFIED_EVIDENCE": encode(unified),
                "TASK_OVERRUN_EVIDENCE": encode(sticky),
                "DOMAIN_SERVICE_DETAIL": encode(detail),
            })

    def test_builtin_detail_is_retained_in_credit_failure(self):
        unified = [0] * 512
        sticky = [0] * 32
        sticky[0] = 1
        detail = list(range(32))
        with self.assertRaisesRegex(ValueError, r'"builtin_detail":\[0,1,2'):
            diagnostics({}, {
                "UNIFIED_EVIDENCE": encode(unified),
                "TASK_OVERRUN_EVIDENCE": encode(sticky),
                "BUILTIN_TASK_DETAIL": encode(detail),
            })

    def test_legacy_service_stage_remains_available(self):
        unified = [0] * 512
        unified[30] = 43
        sticky = [0] * 32
        sticky[0] = 1
        with self.assertRaisesRegex(ValueError, r'"service_stage":43'):
            diagnostics({}, {
                "UNIFIED_EVIDENCE": encode(unified),
                "TASK_OVERRUN_EVIDENCE": encode(sticky),
            })

    def test_incomplete_c_credit_failure_is_not_a_successful_capture(self):
        receipt = [0] * 64
        receipt[24] = 1
        with self.assertRaisesRegex(ValueError, "native C credit failure"):
            diagnostics({}, {"UNIFIED_EVIDENCE": encode([0] * 512),
                             "CONTROL_CREDIT_EVIDENCE": encode(receipt)})

    def test_incomplete_concurrent_c_row_does_not_hide_complete_task_failure(self):
        receipt = [0] * 64
        receipt[24] = 1
        task = [0] * 32
        task[:4] = [0x43595441534B0001, 1, 4, 1]
        with self.assertRaisesRegex(ValueError, "native task credit overrun/quarantine"):
            diagnostics({}, {
                "UNIFIED_EVIDENCE": encode([0] * 512),
                "CONTROL_CREDIT_EVIDENCE": encode(receipt),
                "DOMAIN_TASK_EVIDENCE": encode(task),
            })

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
