"""Synthetic unit tests for the V0.20 wave-11 production verifier.

Every page and serial stream here is SYNTHETIC (built in-test); these tests
check the verifier's acceptance logic only and are not runtime evidence.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import v020_production_media as media  # noqa: E402
import verify_v020_production as v  # noqa: E402

SVC64 = 0x5600_0000
GA_MARKER = ("V020_W11_PRODUCTION frame_meta=1 recovery=1 metered=1 net=1 "
             "tcp_echo=1 tls_echo=0 media_staging_enabled=0 staging_ok=0")
STAGING_MARKER = GA_MARKER.replace("media_staging_enabled=0 staging_ok=0",
                                   "media_staging_enabled=1 staging_ok=1")


def wave10_words() -> list:
    words = [0] * 512
    words[:16] = [v.MAGIC, 1, 1, 15, 1, 14, 1, 1, 4, 1, 1, 0, 2, 1, 1, 5]
    words[16:24] = [6, SVC64, 0x50, 1, 1, 1, 7, 0]
    words[24:32] = [2, SVC64, 0x50, 1, 1, 4, 7, 0]
    words[32:40] = [8, SVC64, 0x41, 1, 1, 1, 7, 0]
    words[40:48] = [1, 1, 1, 2, 0, 180, 7, 0]
    words[48:56] = [0, 0, 0, 1, 0, 2, 2, 1]
    for slot in range(1, 4):
        words[64 + (slot - 1) * 4:68 + (slot - 1) * 4] = [slot, 3, 0, 5]
    for i in range(8):
        calls = int(i < v.SNAPSHOT_ROLE_COUNT or i == 7)
        words[80 + i * 6:86 + i * 6] = [
            0x1000 * (i + 1), 1, calls, 1 - calls, 9, v.EAGAIN_RESULT if calls else 0
        ]
    return words


def w11_words(staging: bool = False) -> list:
    words = wave10_words()
    words[128:144] = [v.W11_MAGIC, 1, 3673, 4, 15, 1, 1, 1, 0, 4, 1, 1, 1, 512, 0, 1]
    if staging:
        words[144:152] = [1] * 8
    words[152:156] = [3, 3184, 1, 68_000]
    return words


def wave10_lines() -> list:
    lines = ["SMP_BOOT_OK a=4 b=15 c=0"]
    lines += [f"SMP_CPU_ON a={c} b={c} c=0" for c in (1, 2, 3)]
    lines += ["V020_PROD_PIE_LOAD a=8 b=0 c=0"]
    lines += [f"V020_PROD_PIE_ROLE a={role} b=1 c={int(i < v.SNAPSHOT_ROLE_COUNT or i == 7)}"
              for i, role in enumerate(v.PIE_ROLE_IDS)]
    lines += [
        f"V020_PROD_SUBMIT a=6 b={SVC64} c=1",
        "V020_PROD_REVIEW a=4 b=1 c=0",
        f"V020_PROD_REGISTER a=2 b={SVC64} c=1",
        "V020_PROD_REGISTER_RETRY a=2 b=2 c=0",
        f"V020_PROD_PUBLISH a=8 b={SVC64} c=1",
        "V020_PROD_PUBLISH_REPLAY a=8 b=2 c=1",
        f"V020_PROD_RECOVERY_REJECT a=8 b={v.E_AUTH_RESULT} c=1",
        "V020_PROD_APPLY a=1 b=180 c=4",
        "V020_PROD_SETTLE a=1 b=1 c=2",
        "V020_PROD_CHAIN a=1 b=1 c=1",
        "V020_PROD_NEG a=0 b=0 c=0",
        "V020_PROD_WRONG_CPU a=1 b=0 c=0",
        "V020_PROD_BAD_PUBLISH a=6 b=0 c=0",
    ]
    lines += [f"V020_PROD_BUSINESS a={s} b=3 c=5" for s in (1, 2, 3)]
    return lines


def w11_lines(staging: bool = False) -> list:
    lines = wave10_lines()
    lines += ["V020_W11_FRAME_META_ROWS a=3673 b=3868 c=195",
              "V020_W11_FRAME_META_ARENA a=3184 b=489 c=0",
              "V020_W11_RECOVERY_GATE_REJECTS a=0 b=1 c=2",
              "V020_W11_RECOVERY_HANDOFF a=14 b=15 c=15",
              "V020_W11_POLICY_LOCK_METER a=0 b=1 c=3",
              "V020_W11_NET_LISTEN a=7 b=0 c=0",
              "V020_W11_NET_GUEST_END a=0 b=0 c=0",
              f"V020_W11_NET_ADMISSION a=1 b={v.QEMU_GATEWAY_IPV4} c=1",
              "V020_W11_NET_RELAY a=71 b=1 c=512"]
    if staging:
        lines += [f"V020_W11_MEDIA_STEP a={index} b=1 c={detail}"
                  for index, detail in enumerate((1, 5, 151, 1, 1), start=1)]
        lines += [f"V020_W11_MEDIA_SNAPSHOT_0X40 a=3 b={v.EAGAIN_RESULT} c=0",
                  "V020_W12_MEDIA_EPOCH a=0 b=1 c=0",
                  "V020_W11_MEDIA_IO a=135359 b=4138 c=6",
                  "V020_W11_MEDIA_SCOPE persistence=false format_golden=false signed_config=false",
                  "V020_W11_MEDIA_STAGING golden_vector_pending=1"]
    lines += [STAGING_MARKER if staging else GA_MARKER, v.SCOPE,
              "V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt"]
    return lines


def encode(words: list, lines: list):
    return ("\n".join(lines) + "\n").encode("ascii"), struct.pack("<512Q", *words)


def volatile_write_fixture(epoch: int) -> tuple[list, list]:
    words = [0] * 512
    words[148] = words[240] = epoch
    words[288:296] = [epoch, 768, 2, 2, 2, 1, 15, 9]
    lines = [f"V020_W21_WRITE a={epoch} b=768 c=2",
             "V020_W21_WRITE_READBACK a=2 b=2 c=1",
             "V020_W21_WRITE_CHECKS a=9 b=15 c=0"]
    return words, lines


class W11Validation(unittest.TestCase):
    def check(self, words=None, lines=None, staging=False, modes=v.Modes()):
        words = w11_words(staging) if words is None else words
        lines = w11_lines(staging) if lines is None else lines
        serial, page = encode(words, lines)
        return v.Production(staging=staging, modes=modes).validate(serial, page, 4)

    def rejects(self, pattern, **kw):
        with self.assertRaisesRegex(ValueError, pattern):
            self.check(**kw)

    def test_accepts_complete_w11_page(self):
        obs = self.check()
        self.assertTrue(obs["real_net_device"])
        self.assertTrue(obs["tcp_to_local_echo"])
        self.assertFalse(obs["tls_echo_turn_verified"])
        self.assertEqual(obs["echo_bytes_relayed"], 512)
        self.assertEqual(obs["policy_lock_settled_in_budget"]
                         + obs["policy_lock_overrun_or_unmeasured"], 4)
        self.assertFalse(obs["media_staging_enabled"])
        self.assertEqual(obs["frame_meta_registered_static_pages"], 3673)
        self.assertEqual(obs["frame_meta_service_arena_pages"], 3184)
        self.assertEqual(obs["frame_meta_permanent_rows"], 3868)
        self.assertEqual(obs["frame_meta_permanent_gap_rows"], 195)
        self.assertEqual(obs["recovery_required_publish_rejected"], 1)
        self.assertEqual(obs["recovery_writer_takeovers"], 3)
        self.assertEqual(obs["policy_lock_measured_overruns"], 1)
        self.assertEqual(obs["policy_lock_unmeasured"], 3)
        self.assertEqual(obs["admission_leases"], 1)
        self.assertTrue(obs["w11_completion_marker"].endswith("staging_ok=0"))

    def test_rejects_missing_net_device(self):
        words = w11_words()
        words[138] = 0
        self.rejects("real_net_device", words=words)

    def test_requires_frame_meta_arena_registration(self):
        words = w11_words()
        words[153] = 0
        self.rejects("FrameMeta Arena", words=words)

    def test_measured_overrun_must_exceed_the_work_budget(self):
        words = w11_words()
        words[154:156] = [1, 45_000]
        self.rejects("policy_lock measured overrun", words=words)

    def test_meter_rejects_a_run_with_no_settled_measurement(self):
        words = w11_words()
        words[154:156] = [0, 0]
        lines = ["V020_W11_POLICY_LOCK_METER a=0 b=0 c=4"
                 if line.startswith("V020_W11_POLICY_LOCK_METER") else line
                 for line in w11_lines()]
        self.rejects("policy_lock requires a settled measurement", words=words, lines=lines)

    def test_requires_direct_admission_receipt(self):
        lines = [line for line in w11_lines() if not line.startswith("V020_W11_NET_ADMISSION")]
        self.rejects("Admission receipt", lines=lines)

    def test_requires_policy_lock_accounting_consistent(self):
        for at, value in ((135, 0), (137, 3), (136, 1)):
            words = w11_words()
            words[at] = value
            with self.subTest(word=at, value=value):
                self.rejects("policy_lock", words=words)
        words = w11_words()
        words[136:138] = [2, 2]
        lines = ["V020_W11_POLICY_LOCK_METER a=2 b=1 c=1"
                 if line.startswith("V020_W11_POLICY_LOCK_METER") else line
                 for line in w11_lines()]
        self.assertEqual(self.check(words=words, lines=lines)["policy_lock_settled_in_budget"], 2)

    def test_rejects_tls_claim(self):
        words = w11_words()
        words[142] = 1
        self.rejects("tls_echo_turn_verified", words=words)

    def test_rejects_staging_words_in_ga_lane(self):
        for at in (144, 145, 151):
            words = w11_words()
            words[at] = 1
            with self.subTest(word=at):
                self.rejects("staging", words=words)

    def test_rejects_staging_marker_in_ga_lane(self):
        lines = w11_lines()
        lines.insert(-3, "V020_W11_MEDIA_STAGING golden_vector_pending=1")
        self.rejects("staging", lines=lines)

    def test_net_absent_must_agree_with_missing_network_evidence(self):
        lines = w11_lines()
        lines.insert(-3, "V020_W11_NET_ABSENT device=0 tcp_echo=0")
        self.rejects("network absence evidence", lines=lines)

    def test_net_absent_page_is_fail_closed(self):
        # What a -nic none boot really leaves: 138..141 zero, NET_ABSENT on serial.
        words = w11_words()
        words[138:142] = [0, 0, 0, 0]
        lines = [x for x in w11_lines() if not x.startswith("V020_W11_NET_")]
        lines.insert(-3, "V020_W11_NET_ABSENT device=0 tcp_echo=0")
        self.rejects("NIC|NET_ABSENT|real_net_device", words=words, lines=lines)

    def test_bounded_no_peer_has_no_grant(self):
        words = w11_words()
        words[139:143] = [0] * 4
        lines = [line for line in w11_lines() if not line.startswith("V020_W11_NET_")]
        lines.insert(-3, f"V020_W11_NET_NO_PEER a=1 b={v.NET_ACCEPT_TURNS} c=0")
        self.rejects("V020_W11_NET_NO_PEER", words=words, lines=lines)
        words[140] = 1
        self.rejects("valid bounded no-peer outcome", words=words, lines=lines)

    def test_peer_silent_exhausts_handshake_budget(self):
        words = w11_words()
        words[141] = 0
        self.rejects("peer silent", words=words)

    def test_requires_admission_lease(self):
        words = w11_words()
        words[140] = 0
        self.rejects("lease", words=words)

    def test_relay_row_must_match_memory(self):
        lines = [x.replace("c=512", "c=511") if x.startswith("V020_W11_NET_RELAY") else x
                 for x in w11_lines()]
        self.rejects("relay", lines=lines)

    def test_rejects_bad_w11_magic_and_baseline_rows(self):
        # Each word must fail for ITS OWN reason, not an unrelated check.
        for at, value, pattern in ((128, 0, "magic"),
                                   (129, 0, "frame_meta_production_statics"),
                                   (130, 0, "registered static pages"),
                                   (131, 3, "recovery_accumulators"),
                                   (132, 0, "DegradedEvent"),
                                   (133, 0, "word 133"),
                                   (133, 2, "word 133"),
                                   (134, 0, "recovery_pair_facts_staged"),
                                   (143, 0, "staged_boot_epoch")):
            words = w11_words()
            words[at] = value
            with self.subTest(word=at, value=value):
                self.rejects(pattern, words=words)

    def test_frame_meta_rows_row_must_match_word_130(self):
        for row in ("V020_W11_FRAME_META_ROWS a=3672 b=3868 c=196",
                    "V020_W11_FRAME_META_ROWS a=3673 b=3868 c=194",
                    "V020_W11_FRAME_META_ROWS a=3673 b=3600 c=0"):
            lines = [row if x.startswith("V020_W11_FRAME_META_ROWS") else x
                     for x in w11_lines()]
            with self.subTest(row=row):
                self.rejects("FrameMeta rows", lines=lines)
        lines = [x for x in w11_lines() if not x.startswith("V020_W11_FRAME_META_ROWS")]
        self.rejects("FrameMeta rows", lines=lines)

    def test_gate_refusal_counter_is_a_second_signal(self):
        for row in ("V020_W11_RECOVERY_GATE_REJECTS a=0 b=0 c=2",
                    "V020_W11_RECOVERY_GATE_REJECTS a=1 b=1 c=2",
                    "V020_W11_RECOVERY_GATE_REJECTS a=0 b=1 c=1"):
            lines = [row if x.startswith("V020_W11_RECOVERY_GATE_REJECTS") else x
                     for x in w11_lines()]
            with self.subTest(row=row):
                self.rejects("refusal counter", lines=lines)
        lines = [x for x in w11_lines()
                 if not x.startswith("V020_W11_RECOVERY_GATE_REJECTS")]
        self.rejects("refusal counter", lines=lines)

    def test_rejects_nonzero_reserved_tail(self):
        for at in (156, 159, 161, 177, 183, 195, 199, 211, 223, 231, 236, 252,
                   261, 263, 268, 271, 281, 287, 296, 303, 304, 511):
            words = w11_words()
            words[at] = 1
            self.rejects("reserved", words=words)

    def test_recovery_handoff_matches_the_parked_cpus(self):
        words = w11_words()
        words[152] = 1
        self.rejects("writer takeover", words=words)
        for row in ("V020_W11_RECOVERY_HANDOFF a=6 b=15 c=15",
                    "V020_W11_RECOVERY_HANDOFF a=14 b=14 c=15"):
            lines = [row if line.startswith("V020_W11_RECOVERY_HANDOFF") else line
                     for line in w11_lines()]
            self.rejects("writer handoff", lines=lines)

    def test_completion_marker_exactly_once_and_matches_memory(self):
        lines = [x for x in w11_lines() if not x.startswith("V020_W11_PRODUCTION")]
        self.rejects("completion marker", lines=lines)
        lines = w11_lines()
        lines.insert(-3, GA_MARKER)
        self.rejects("completion marker", lines=lines)
        lines = [x.replace("tls_echo=0", "tls_echo=1") for x in w11_lines()]
        self.rejects("completion marker", lines=lines)

    def test_wave10_rows_unchanged(self):
        words = w11_words()
        words[14] = 0
        self.rejects("advice-chain", words=words)

    def test_staging_requires_golden_vector_pending(self):
        self.assertTrue(self.check(staging=True)["media_staging_enabled"])
        words = w11_words(staging=True)
        words[151] = 0
        self.rejects("golden_vector_pending", words=words, staging=True)
        lines = [x for x in w11_lines(staging=True)
                 if not x.startswith("V020_W11_MEDIA_STAGING")]
        self.rejects("golden_vector_pending", lines=lines, staging=True)

    def test_staging_requires_every_step(self):
        for at in range(144, 151):
            words = w11_words(staging=True)
            words[at] = 0
            with self.subTest(word=at):
                self.rejects("staging", words=words, staging=True)

    def test_staging_requires_snapshot_refusal_on_serial(self):
        lines = [line for line in w11_lines(staging=True)
                 if not line.startswith("V020_W11_MEDIA_SNAPSHOT_0X40")]
        self.rejects("snapshot refusal", lines=lines, staging=True)
        words = w11_words(staging=True)
        words[85] = 0
        self.rejects("return in-vector EAGAIN", words=words, staging=True)

    def test_staging_binds_serial_steps_and_boot_epoch(self):
        lines = [line for line in w11_lines(staging=True)
                 if not line.startswith("V020_W11_MEDIA_STEP")]
        self.rejects("media staging serial steps", lines=lines, staging=True)
        lines[0:0] = [f"V020_W11_MEDIA_STEP a={step} b=1 c={detail}"
                      for step, detail in enumerate((1, 5, 151, 2, 1), start=1)]
        self.rejects("BootEpoch", lines=lines, staging=True)

    def test_staging_rejects_incomplete_line(self):
        lines = w11_lines(staging=True)
        lines.insert(-3, "V020_W11_MEDIA_STAGING_INCOMPLETE step=1")
        self.rejects("INCOMPLETE", lines=lines, staging=True)

    def test_staging_marker_carries_staging_ok(self):
        obs = self.check(staging=True)
        self.assertTrue(obs["w11_completion_marker"].endswith(
            "media_staging_enabled=1 staging_ok=1"))
        # A guest claiming staging_ok=1 in the G-A lane disagrees with memory.
        lines = [x.replace("staging_ok=0", "staging_ok=1") for x in w11_lines()]
        self.rejects("completion marker", lines=lines)

    def test_staging_rejects_media_absent(self):
        lines = w11_lines(staging=True)
        lines.insert(-3, "V020_W11_MEDIA_ABSENT golden_vector_pending=1")
        self.rejects("MEDIA_ABSENT", lines=lines, staging=True)

    def test_authenticated_mode_requires_actual_rng_delivery(self):
        modes = v.Modes(authenticated_net=True)
        self.rejects("VirtIO RNG evidence", modes=modes)
        words = w11_words()
        words[160] = 96
        words[176] = 1
        lines = w11_lines() + [
            "V020_W12_NET_ENTROPY a=8 b=96 c=0",
            f"V020_W13_NET_RETIRE a=1 b={v.QEMU_GATEWAY_IPV4} c=1",
        ]
        obs = self.check(words=words, lines=lines, modes=modes)
        self.assertEqual(obs["virtio_rng_guest_bytes"], 96)
        self.assertEqual(obs["native_admission_retirements"], 1)
        self.assertFalse(obs["tls_echo_turn_verified"], "page evidence alone cannot prove TLS")
        self.rejects("unexpected authenticated RNG", words=words, lines=lines)

    def test_authenticated_eof_keeps_the_admission_credit(self):
        words = w11_words()
        words[160] = 96
        lines = [
            "V020_W11_NET_GUEST_END a=0 b=1 c=0"
            if line.startswith("V020_W11_NET_GUEST_END") else line
            for line in w11_lines()
        ] + ["V020_W12_NET_ENTROPY a=8 b=96 c=0"]
        modes = v.Modes(authenticated_net=True, orderly_close=False)
        self.assertEqual(self.check(words=words, lines=lines, modes=modes)["native_admission_retirements"], 0)
        self.rejects("retirement proof", words=words, lines=lines, modes=v.Modes(authenticated_net=True))
        words[176] = 1
        lines.append(f"V020_W13_NET_RETIRE a=1 b={v.QEMU_GATEWAY_IPV4} c=1")
        self.rejects("retirement proof", words=words, lines=lines, modes=modes)

    def test_rng_missing_cannot_fall_back_to_listening(self):
        modes = v.Modes(authenticated_net=True)
        words = w11_words()
        words[139:143] = [0] * 4
        lines = [line for line in w11_lines() if not line.startswith("V020_W11_NET_")]
        lines += ["V020_W12_NET_ENTROPY_UNAVAILABLE a=1 b=0 c=0"]
        self.rejects("V020_W12_NET_ENTROPY_UNAVAILABLE", words=words, lines=lines, modes=modes)
        lines += ["V020_W11_NET_LISTEN a=7 b=0 c=0"]
        self.rejects("inconsistent refusal", words=words, lines=lines, modes=modes)

    def test_live_observations_require_protected_role_readback(self):
        modes = v.Modes(live_control=True)
        words = w11_words()
        words[164:168] = [5, 4, 1, 3]
        words[178:181] = [3, 3, 1]
        lines = w11_lines() + [
            "V020_W12_LIVE_SNAPSHOT a=5 b=4 c=17",
            "V020_W12_VOLATILE_AUDIT a=11 b=1 c=1",
            "V020_W12_CONTROL_UNREADY a=3 b=0 c=0",
            "V020_W13_AUDIT_SESSION a=3 b=3 c=1",
        ]
        obs = self.check(words=words, lines=lines, modes=modes)
        self.assertEqual(obs["volatile_audit_sequence"], 1)
        self.assertEqual(obs["volatile_audit_released"], 3)
        self.rejects("consume and acknowledge", words=words, lines=lines[:-1], modes=modes)
        words[179] = 2
        self.rejects("consume and acknowledge", words=words, lines=lines, modes=modes)
        words[179] = 3
        words[164] = 7
        self.rejects("authorized D01", words=words, lines=lines, modes=modes)

    def test_signed_scratch_needs_the_selected_epoch_and_scope(self):
        words = w11_words(staging=True)
        words[181:188] = [1, 1, 1, 2, 3, 4, 5]
        lines = w11_lines(staging=True) + [
            "V020_W23_RECEIPT_VIEW a=1 b=7 c=2",
            "V020_W13_SIGNED_SCRATCH a=1 b=1 c=0",
            "V020_W13_MEDIA_SCOPE test_key=true format_golden=false signed_config=true",
        ]
        modes = v.Modes(signed_media=True)
        obs = self.check(words=words, lines=lines, staging=True, modes=modes)
        self.assertTrue(obs["signed_test_config_verified"])
        self.assertEqual(obs["signed_config_bound_boot_epoch"], 1)
        self.assertEqual(obs["signed_receipt_view_sha256"],
                         b"".join(word.to_bytes(8, "little") for word in (2, 3, 4, 5)).hex())
        self.rejects("signed receipt view", words=words,
                     lines=[line for line in lines if not line.startswith("V020_W23_RECEIPT_VIEW")],
                     staging=True, modes=modes)
        words[183] = 2
        self.rejects("signed receipt view", words=words, lines=lines, staging=True, modes=modes)
        words[183] = 1
        self.rejects("unexpected signed scratch", words=words, lines=lines, staging=True)
        self.rejects("signed scratch test scope", words=words, lines=lines[:-1], staging=True, modes=modes)
        words[182] = 2
        self.rejects("signed scratch verdict and BootEpoch", words=words, lines=lines, staging=True, modes=modes)

    def test_frame_pool_requires_conservation_and_matching_uart(self):
        modes = v.Modes(frame_pool=True)
        self.rejects("native FrameMeta pool", modes=modes)
        words = w11_words()
        words[192:195] = [1, 4, 4]
        lines = w11_lines() + ["V020_W14_FRAME_POOL a=1 b=4 c=4"]
        obs = self.check(words=words, lines=lines, modes=modes)
        self.assertEqual(obs["frame_pool_free_after_revoke"], 4)
        self.rejects("native FrameMeta pool", words=words, lines=lines[:-1], modes=modes)
        self.rejects("unexpected FrameMeta pool", words=words, lines=lines)
        words[194] = 3
        self.rejects("native FrameMeta pool", words=words, lines=lines, modes=modes)

    def test_snapshot_envelopes_require_all_four_bound_to_generation_one(self):
        modes = v.Modes(media_envelopes=True)
        staging_lines = [line.replace("b=4138 c=6", "b=4142 c=6")
                         if line.startswith("V020_W11_MEDIA_IO ") else line
                         for line in w11_lines(staging=True)]
        self.rejects("snapshot envelope evidence", lines=staging_lines, staging=True, modes=modes)
        words = w11_words(staging=True)
        words[196:199] = [4, 1, 1]
        marker = "V020_W14_SNAPSHOT_ENVELOPES a=4 b=1 c=1"
        lines = staging_lines + [marker]
        obs = self.check(words=words, lines=lines, staging=True, modes=modes)
        self.assertEqual(obs["snapshot_envelopes_verified"], 4)
        self.rejects("unexpected snapshot envelope", words=words,
                     lines=w11_lines(staging=True) + [marker], staging=True)
        words[197] = 2
        self.rejects("snapshot envelope evidence", words=words, lines=lines, staging=True, modes=modes)

    def test_unified_mount_requires_eight_disk_objects_and_conservation(self):
        modes = v.Modes(media_unified=True)
        words = w11_words(staging=True)
        words[196:199] = [4, 1, 1]
        lines = [
            line.replace("b=4138 c=6", "b=4276 c=6").replace(
                "V020_W11_MEDIA_STEP a=2 b=1 c=5", "V020_W11_MEDIA_STEP a=2 b=1 c=9")
            for line in w11_lines(staging=True)
        ] + ["V020_W14_SNAPSHOT_ENVELOPES a=4 b=1 c=1"]
        self.rejects("unified mount requires eight", words=words, lines=lines, staging=True, modes=modes)
        words[208:211] = [8, 151, 152]
        lines.append("V020_W15_UNIFIED_MOUNT a=8 b=151 c=152")
        obs = self.check(words=words, lines=lines, staging=True, modes=modes)
        self.assertEqual(obs["unified_mount_system_blocks"], 151)
        self.assertEqual(obs["unified_mount_data_blocks"], 152)
        words[210] = 151
        self.rejects("unified mount requires eight", words=words, lines=lines, staging=True, modes=modes)

    def test_snapshot_catalog_evidence_requires_mounted_epoch_and_real_denials(self):
        modes = v.Modes(snapshot_catalog=True)
        self.rejects("snapshot catalog", staging=True, modes=modes)
        words = w11_words(staging=True)
        words[224:231] = [1, 1, 2, 1, 7, 1, 3]
        digest = bytes(range(32))
        words[232:236] = struct.unpack("<4Q", digest)
        lines = w11_lines(staging=True) + [
            "V020_W16_CATALOG a=1 b=1 c=2",
            "V020_W16_CATALOG_CHECKS a=1 b=7 c=1",
            "V020_W16_CATALOG_BINDING a=3 b=1 c=1",
        ]
        obs = self.check(words=words, lines=lines, staging=True, modes=modes)
        self.assertEqual(obs["snapshot_catalog_sha256"], digest.hex())
        self.assertEqual(obs["snapshot_catalog_lists"], 2)
        self.assertEqual(obs["snapshot_catalog_service_generation"], 3)
        self.rejects("unexpected snapshot catalog", words=words, lines=lines, staging=True)
        words[224] = 2
        self.rejects("snapshot catalog", words=words, lines=lines, staging=True, modes=modes)
        words[224] = 1
        words[228] = 6
        self.rejects("snapshot catalog", words=words, lines=lines, staging=True, modes=modes)
        words[228] = 7
        words[230] = 1
        self.rejects("snapshot catalog", words=words, lines=lines, staging=True, modes=modes)

    def test_staged_file_evidence_binds_epoch_owner_and_result_custody(self):
        import hashlib

        digest = hashlib.sha256(b"CyxiaOS V0.20 signed scratch\n").digest()
        words = [0] * 512
        words[148] = 2
        words[240:248] = [2, 1, 1, 3, 49484, 1, 255, 3]
        words[248:252] = struct.unpack("<4Q", digest)
        lines = ["V020_W18_FILE_READ a=2 b=3 c=49484",
                 "V020_W18_FILE_CHECKS a=255 b=1 c=3",
                 "V020_W18_FILE_OWNER a=1 b=1 c=11"]
        evidence = v.file_read_evidence(words, lines, True)
        self.assertEqual(evidence["file_read_sha256"], digest.hex())
        self.assertEqual(evidence["file_read_acks"], 3)
        with self.assertRaisesRegex(ValueError, "unexpected staged file"):
            v.file_read_evidence(words, lines, False)
        for word, message in ((240, "operation"), (241, "owner"), (243, "operation"),
                              (244, "operation"), (245, "replay"), (246, "refusal"),
                              (247, "ACK"), (248, "digest")):
            with self.subTest(word=word):
                tampered = words.copy()
                tampered[word] ^= 1
                with self.assertRaisesRegex(ValueError, message):
                    v.file_read_evidence(tampered, lines, True)

    def test_snapshot_read_evidence_binds_epochs_denials_and_slot_digest(self):
        words = [0] * 512
        words[148] = words[224] = words[240] = 2
        words[256:261] = [2, 1, 1, 31, 1]
        digest = bytes(range(32))
        words[264:268] = struct.unpack("<4Q", digest)
        lines = ["V020_W19_SNAPSHOT_READ a=2 b=1 c=1", "V020_W19_SNAPSHOT_CHECKS a=31 b=1 c=0"]
        self.assertEqual(v.snapshot_read_evidence(words, lines, True), {
            "snapshot_read_boot_epoch": 2,
            "snapshot_read_query_missing": 1,
            "snapshot_read_history_missing": 1,
            "snapshot_read_denials_mask": 31,
            "snapshot_read_stale_checks": 1,
            "snapshot_read_slot_sha256": digest.hex(),
        })
        for offset, message in (
            (148, "BootEpochs"), (224, "BootEpochs"), (240, "BootEpochs"), (256, "BootEpochs"),
            (257, "missing QUERY"), (258, "missing HISTORY_OPEN"),
            (259, "denial checks"), (260, "stale HISTORY_OPEN"),
        ):
            with self.subTest(offset=offset):
                modified = words.copy()
                modified[offset] ^= 1
                with self.assertRaisesRegex(ValueError, message):
                    v.snapshot_read_evidence(modified, lines, True)
        with self.assertRaisesRegex(ValueError, "missing QUERY"):
            v.snapshot_read_evidence(words, lines + lines[:1], True)
        with self.assertRaisesRegex(ValueError, "denial checks"):
            v.snapshot_read_evidence(words, lines[:1] + [lines[1].replace("c=0", "c=1")], True)
        words[264:268] = [0] * 4
        with self.assertRaisesRegex(ValueError, "SlotStore digest"):
            v.snapshot_read_evidence(words, lines, True)

    def test_inactive_snapshot_read_rejects_sealed_and_serial_evidence(self):
        for offset in (256, 264):
            with self.subTest(offset=offset):
                words = w11_words()
                words[offset] = 1
                self.rejects("unexpected snapshot read evidence", words=words)
        for line in ("V020_W19_SNAPSHOT_READ a=1 b=1 c=1", "V020_W19_SNAPSHOT_CHECKS"):
            with self.subTest(line=line):
                self.rejects("unexpected snapshot read evidence", lines=w11_lines() + [line])

    def test_inactive_file_sessions_reject_sealed_and_serial_evidence(self):
        words = w11_words()
        words[272] = 1
        self.rejects("unexpected file session evidence", words=words)
        for line in ("V020_W20_FILE_HANDLES a=1 b=4 c=5", "V020_W20_FILE_CHECKS"):
            with self.subTest(line=line):
                self.rejects("unexpected file session evidence", lines=w11_lines() + [line])

    def test_inactive_file_volatile_write_rejects_sealed_and_serial_evidence(self):
        words = w11_words()
        words[288] = 1
        self.rejects("unexpected file volatile write evidence", words=words)
        for line in ("V020_W21_WRITE a=1 b=768 c=2", "V020_W21_WRITE_CHECKS"):
            with self.subTest(line=line):
                self.rejects("unexpected file volatile write evidence", lines=w11_lines() + [line])

    def test_reopen_needs_prior_epoch_and_cannot_claim_format(self):
        modes = v.Modes(media_reopen=True)
        words = w11_words(staging=True)
        words[145] = 0
        words[148] = 2
        words[162:164] = [1, 1]
        lines = [
            line.replace("b=1 c=1", "b=1 c=2")
            if line.startswith("V020_W11_MEDIA_STEP a=4 ") else line
            for line in w11_lines(staging=True)
        ]
        replacements = {
            "V020_W12_MEDIA_EPOCH a=0 b=1 c=0": "V020_W12_MEDIA_EPOCH a=1 b=2 c=1",
            "V020_W11_MEDIA_IO a=135359 b=4138 c=6": "V020_W11_MEDIA_IO a=8261 b=15 c=5",
        }
        lines = [replacements.get(line, line) for line in lines]
        obs = self.check(words=words, lines=lines, staging=True, modes=modes)
        self.assertEqual((obs["staging_previous_epoch"], obs["staging_confirmed_epoch"]), (1, 2))
        words[145] = 1
        self.rejects("staging steps", words=words, lines=lines, staging=True, modes=modes)
        words[145] = 0
        lines = [line.replace("b=15 c=5", "b=15 c=0") for line in lines]
        self.rejects("writes and flushes", words=words, lines=lines, staging=True, modes=modes)


class FileSessionsEvidence(unittest.TestCase):
    def setUp(self):
        self.words = [0] * 512
        self.words[148] = self.words[240] = 2
        self.words[272:281] = [2, 4, 5, 3, 1, 2, 12, 127, 15]
        self.lines = ["V020_W20_FILE_HANDLES a=2 b=4 c=5",
                      "V020_W20_FILE_IO a=3 b=1 c=2",
                      "V020_W20_FILE_CHECKS a=12 b=127 c=15"]

    def test_reports_exact_file_session_counts_and_masks(self):
        self.assertEqual(v.file_sessions_evidence(self.words, self.lines, True), {
            "file_session_boot_epoch": 2,
            "file_session_peak_handles": 4,
            "file_session_opens": 5,
            "file_session_reads": 3,
            "file_session_closes": 1,
            "file_session_replays": 2,
            "file_session_acks": 12,
            "file_session_denials_mask": 127,
            "file_session_revoked_mask": 15,
        })

    def test_volatile_write_consumes_three_prior_acks(self):
        with self.assertRaisesRegex(ValueError, "counts, denials or revocations"):
            v.file_sessions_evidence(self.words, self.lines, True, file_volatile_write=True)
        self.words[278] = 9
        self.lines[2] = self.lines[2].replace("a=12", "a=9")
        self.assertEqual(v.file_sessions_evidence(
            self.words, self.lines, True, file_volatile_write=True,
        )["file_session_acks"], 9)
        with self.assertRaisesRegex(ValueError, "counts, denials or revocations"):
            v.file_sessions_evidence(self.words, self.lines, True)

    def test_every_sealed_word_is_checked(self):
        for indexes, message in (
            ((148, 240, 272), "BootEpochs"),
            (range(273, 281), "counts, denials or revocations"),
            (range(281, 288), "reserved"),
        ):
            for offset in indexes:
                with self.subTest(offset=offset):
                    changed = self.words.copy()
                    changed[offset] ^= 1
                    with self.assertRaisesRegex(ValueError, message):
                        v.file_sessions_evidence(changed, self.lines, True)

    def test_rejects_missing_duplicate_and_conflicting_serial_rows(self):
        for lines in (self.lines[:-1], self.lines + self.lines[:1],
                      self.lines[:2] + [self.lines[2].replace("c=15", "c=14")],
                      self.lines + ["V020_W20_FILE_UNKNOWN"]):
            with self.subTest(lines=lines):
                with self.assertRaisesRegex(ValueError, "serial rows"):
                    v.file_sessions_evidence(self.words, lines, True)

    def test_rejected_media_requires_no_file_session_evidence(self):
        report = {
            "status": "FAIL",
            "error": "ValueError: guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed",
            "scratch_before_sha256": "unchanged",
            "scratch_disk": {"scratch_after_sha256": "unchanged"},
        }
        lines = ["V020_W11_MEDIA_STAGING_INCOMPLETE step=2", "V020_W11_MEDIA_IO a=1 b=0 c=0"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            page = output / "native-page.bin"
            page.write_bytes(bytes(4096))
            media.require_read_only_refusal(report, lines, output, 2)
            with self.assertRaisesRegex(ValueError, "unexpected file session evidence"):
                media.require_read_only_refusal(report, lines + self.lines[:1], output, 2)
            page.write_bytes(struct.pack("<512Q", *self.words))
            with self.assertRaisesRegex(ValueError, "unexpected file session evidence"):
                media.require_read_only_refusal(report, lines, output, 2)

    def test_reopen_summarizes_file_sessions_from_both_boots(self):
        def boot(_elf, output, _timeout, *, modes, **_):
            if output.name == "unsigned-fixture":
                self.assertEqual(modes, v.Modes(media_unified=True, live_control=True))
                return {"status": "PASS", "scratch_disk": {"scratch_after_sha256": "unsigned"}}
            if output.name in ("reopen-blank", "reopen-unsigned"):
                step = 1 if output.name == "reopen-blank" else 2
                output.mkdir()
                (output / "serial.txt").write_text(
                    f"V020_W11_MEDIA_STAGING_INCOMPLETE step={step}\n"
                    "V020_W11_MEDIA_IO a=1 b=0 c=0\n"
                    "V020_W13_SIGNED_SCRATCH a=0 b=0 c=0\n"
                    "V020_W14_SNAPSHOT_ENVELOPES a=0 b=0 c=0\n"
                    "V020_W15_UNIFIED_MOUNT a=0 b=0 c=0\n"
                )
                (output / "native-page.bin").write_bytes(bytes(4096))
                return {
                    "status": "FAIL",
                    "error": "ValueError: guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed",
                    "scratch_before_sha256": "unsigned",
                    "scratch_disk": {"scratch_after_sha256": "unsigned"},
                }
            epoch = 2 if modes.media_reopen else 1
            words = self.words.copy()
            words[148] = words[240] = words[272] = epoch
            lines = [self.lines[0].replace("a=2", f"a={epoch}"), *self.lines[1:]]
            if modes.file_volatile_write:
                words[278] = 9
                lines[2] = lines[2].replace("a=12", "a=9")
                write_words, write_lines = volatile_write_fixture(epoch)
                words[288:304] = write_words[288:304]
                lines.extend(write_lines)
            return {
                "status": "PASS",
                "scratch_before_sha256": str(epoch - 1),
                "scratch_disk": {"scratch_after_sha256": str(epoch)},
                "snapshot_envelope_disk": {"objects": {}, "system_inodes": 8, "snapshot_blocks": 4,
                                           "file_read_sha256": "file", "file_read_dirent_sha256": "dirent"},
                "observations": {"staging_confirmed_epoch": epoch, "file_read_calls": 3,
                                 **v.file_sessions_evidence(words, lines, True,
                                                            file_volatile_write=modes.file_volatile_write),
                                 **v.file_volatile_write_evidence(words, lines, modes.file_volatile_write)},
            }

        for volatile_write, session_acks in ((False, 12), (True, 9)):
            modes = v.Modes(media_reopen=True, signed_media=True, media_unified=True, live_control=True,
                            file_read=True, file_sessions=True, file_volatile_write=volatile_write)
            with (self.subTest(volatile_write=volatile_write), tempfile.TemporaryDirectory() as directory,
                  patch.object(media, "create_scratch"), patch.object(media, "verify_envelope_rejections"),
                  patch.object(media, "verify_unified_rejections"), patch.object(media, "verify_file_rejection"),
                  patch.object(media, "verify_file_acl_rejection") as reject_acl):
                report = media.run_media_reopen(boot, Path("fresh.elf"), Path("reopen.elf"),
                                                Path(directory) / "out", 120, modes, Path("unsigned.elf"))
                self.assertEqual(report["status"], "PASS", report.get("error"))
                self.assertEqual(report["file_session_boot_epoch_per_boot"], [1, 2])
                self.assertEqual(report["file_session_peak_handles_per_boot"], [4, 4])
                self.assertEqual(report["file_session_revoked_mask_per_boot"], [15, 15])
                self.assertEqual(report["file_session_acks_per_boot"], [session_acks] * 2)
                self.assertEqual(report["file_session_acks_total"], session_acks * 2)
                self.assertIs(report["file_volatile_write_mode"], volatile_write)
                if volatile_write:
                    reject_acl.assert_called_once()
                    self.assertTrue(report["file_volatile_write_acl_mismatch_refused_without_write"])
                    self.assertEqual(report["file_volatile_write_boot_epoch_per_boot"], [1, 2])
                    self.assertEqual(report["file_volatile_write_owner_rights_per_boot"], [768, 768])
                    self.assertEqual(report["file_volatile_write_last_write_seq_per_boot"], [2, 2])
                    self.assertEqual(report["file_volatile_write_acks_per_boot"], [9, 9])
                    self.assertEqual(report["file_volatile_write_acks_total"], 18)
                    self.assertEqual(report["file_read_sha256"], "file")
                else:
                    reject_acl.assert_not_called()
                    self.assertNotIn("file_volatile_write_acks_total", report)


class FileVolatileWriteEvidence(unittest.TestCase):
    def setUp(self):
        self.words, self.lines = volatile_write_fixture(2)

    def test_reports_exact_volatile_write_counters(self):
        self.assertEqual(v.file_volatile_write_evidence(self.words, self.lines, True), {
            "file_volatile_write_boot_epoch": 2,
            "file_volatile_write_owner_rights": 768,
            "file_volatile_write_writes": 2,
            "file_volatile_write_last_write_seq": 2,
            "file_volatile_write_reads": 2,
            "file_volatile_write_replays": 1,
            "file_volatile_write_denials_mask": 15,
            "file_volatile_write_acks": 9,
        })

    def test_every_sealed_word_is_checked(self):
        for indexes, message in (
            ((148, 240, 288), "BootEpochs"),
            ((289,), "owner rights"),
            (range(290, 296), "counts, sequence or denials"),
            (range(296, 304), "reserved"),
        ):
            for offset in indexes:
                with self.subTest(offset=offset):
                    changed = self.words.copy()
                    changed[offset] ^= 1
                    with self.assertRaisesRegex(ValueError, message):
                        v.file_volatile_write_evidence(changed, self.lines, True)

    def test_rejects_missing_duplicate_conflicting_and_unknown_serial_rows(self):
        for lines in (self.lines[:-1], self.lines + self.lines[:1],
                      self.lines[:2] + [self.lines[2].replace("c=0", "c=1")],
                      self.lines + ["V020_W21_UNKNOWN"]):
            with self.subTest(lines=lines):
                with self.assertRaisesRegex(ValueError, "serial rows"):
                    v.file_volatile_write_evidence(self.words, lines, True)

    def test_rejected_media_requires_no_volatile_write_proof(self):
        report = {
            "status": "FAIL",
            "error": "ValueError: guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed",
            "scratch_before_sha256": "unchanged",
            "scratch_disk": {"scratch_after_sha256": "unchanged"},
        }
        lines = ["V020_W11_MEDIA_STAGING_INCOMPLETE step=2", "V020_W11_MEDIA_IO a=1 b=0 c=0"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            page = output / "native-page.bin"
            page.write_bytes(bytes(4096))
            media.require_read_only_refusal(report, lines, output, 2)
            with self.assertRaisesRegex(ValueError, "unexpected file volatile write evidence"):
                media.require_read_only_refusal(report, lines + self.lines[:1], output, 2)
            page.write_bytes(struct.pack("<512Q", *self.words))
            with self.assertRaisesRegex(ValueError, "unexpected file volatile write evidence"):
                media.require_read_only_refusal(report, lines, output, 2)

    def test_acl_mode_mismatch_rejects_and_restores_the_original_record(self):
        offset = 4126 * 4096 + 64
        original = bytearray(struct.pack("<IIQQQIIQIIII", 1, 1, 1, 1, 1, 768, 0, 1, 0, 0, 0, 0))
        struct.pack_into("<I", original, 60, media.crc32c_zeroed(original, 60))
        modes = v.Modes(media_reopen=True, file_volatile_write=True)

        def boot(_elf, output, _timeout, *, staging, modes, boot_disk):
            self.assertTrue(staging and modes.file_volatile_write)
            self.assertEqual(output.name, "reopen-file-acl-mode")
            with boot_disk.open("rb") as disk:
                disk.seek(offset)
                acl = disk.read(64)
            self.assertEqual(acl[:32], original[:32])
            self.assertEqual(struct.unpack_from("<I", acl, 32), (256,))
            self.assertEqual(acl[36:60], original[36:60])
            self.assertEqual(struct.unpack_from("<I", acl, 60), (media.crc32c_zeroed(acl, 60),))
            output.mkdir()
            (output / "serial.txt").write_text(
                "V020_W11_MEDIA_STAGING_INCOMPLETE step=2\n"
                "V020_W11_MEDIA_IO a=1 b=0 c=0\n"
                f"V020_W11_MEDIA_STEP a=2 b=0 c={mount_error}\n"
                "V020_W14_SNAPSHOT_ENVELOPES a=0 b=0 c=0\n"
                "V020_W15_UNIFIED_MOUNT a=0 b=0 c=0\n"
            )
            (output / "native-page.bin").write_bytes(bytes(4096))
            digest = v.sha(boot_disk)
            return {
                "status": "FAIL",
                "error": "ValueError: guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed",
                "scratch_before_sha256": digest,
                "scratch_disk": {"scratch_after_sha256": digest},
            }

        for mount_error in (media.MOUNT_UNAUTHORIZED, media.MOUNT_CONFLICT):
            with self.subTest(mount_error=mount_error), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                scratch = output / "scratch.raw"
                with scratch.open("wb") as disk:
                    disk.seek(offset)
                    disk.write(original)
                digest = v.sha(scratch)
                params = (boot, Path("reopen.elf"), output, 120, modes, scratch)
                if mount_error == media.MOUNT_UNAUTHORIZED:
                    media.verify_file_acl_rejection(*params)
                else:
                    with self.assertRaisesRegex(ValueError, "expected mount error"):
                        media.verify_file_acl_rejection(*params)
                self.assertEqual(v.sha(scratch), digest)


class Labels(unittest.TestCase):
    def test_ga_metadata_is_honest(self):
        meta = v.Production().metadata()
        for key in ("tls_echo_turn_verified", "policy_lock_budget_verified",
                    "entropy_production", "admission_leases_inferred",
                    "full_authority", "real_models", "media_staging_enabled"):
            self.assertIs(meta[key], False, key)
        for key in ("recovery_pair_facts_staged", "policy_lock_timing_emulated",
                    "production_skeleton", "staged_boot_epoch"):
            self.assertIs(meta[key], True, key)
        self.assertNotIn("golden_vector_pending", meta)
        self.assertIs(meta["recovery_trigger_synthetic"], True)
        self.assertIs(meta["degraded_events_drive_gate"], False)
        self.assertIs(meta["durable_audit_consumer_takeover"], False)
        text = repr(meta) + repr(v.Production().success())
        self.assertNotIn("G4", text)

    def test_measured_flags_only_in_success(self):
        meta = v.Production().metadata()
        for key in ("real_net_device", "tcp_to_local_echo", "frame_meta_production_statics",
                    "recovery_accumulators", "policy_lock_metered", "recovery_writer_takeovers",
                    "sec_n_pools_frame_meta_registered", "admission_receipt_verified"):
            self.assertNotIn(key, meta)
            self.assertIn(key, v.Production().success())

    def test_staging_metadata(self):
        meta = v.Production(staging=True).metadata()
        self.assertIs(meta["golden_vector_pending"], True)
        self.assertIs(meta["signed_config"], False)
        self.assertIs(meta["boot_epoch_verify_staged"], True)
        self.assertIs(meta["admission_flow_fixed_inputs"], True)
        self.assertIs(meta["persistent_audit_slot"], False)
        self.assertIs(meta["media_staging_enabled"], True)
        self.assertIs(meta["file_sessions_mode"], False)
        self.assertIs(meta["file_volatile_write_mode"], False)
        selected = v.Production(staging=True, modes=v.Modes(file_sessions=True)).metadata()
        self.assertIs(selected["file_sessions_mode"], True)
        selected = v.Production(staging=True, modes=v.Modes(file_volatile_write=True)).metadata()
        self.assertIs(selected["file_volatile_write_mode"], True)


class Argv(unittest.TestCase):
    def args(self, **kw):
        return v.qemu_args("qemu", "/q.sock", Path("/k.elf"), 4242, **kw)

    def test_ga_argv_has_real_virtio_net(self):
        a = self.args()
        self.assertNotIn("-nic", a)
        self.assertEqual(a[a.index("-m") + 1], "256M")
        self.assertIn("user,id=n0,hostfwd=tcp:127.0.0.1:4242-:7", a)
        self.assertIn("virtio-net-device,netdev=n0", a)
        self.assertIn("virtio-mmio.force-legacy=false", a)
        self.assertFalse(any("virtio-blk" in x for x in a))
        self.assertIn("virt-10.2,gic-version=2,secure=off,virtualization=off", a)
        self.assertEqual(a[a.index("-smp") + 1], "4")
        self.assertEqual(a[a.index("-cpu") + 1], "cortex-a53")

    def test_rng_is_attached_only_to_selected_runs(self):
        self.assertNotIn("virtio-rng-device,rng=rng0", self.args())
        self.assertIn("virtio-rng-device,rng=rng0", self.args(rng=True))

    def test_staging_argv_adds_scratch_and_1g(self):
        a = self.args(scratch=Path("/s.raw"))
        self.assertEqual(a[a.index("-m") + 1], "1024M")
        self.assertIn("virtio-blk-device,drive=scratch", a)
        self.assertIn("virtio-net-device,netdev=n0", a)

    def test_no_nic_negative_argv(self):
        a = self.args(nic=False)
        self.assertEqual(a[a.index("-nic") + 1], "none")
        self.assertFalse(any("netdev" in x for x in a))

    def test_peer_sample_is_fixed_512_bytes(self):
        self.assertEqual(len(v.PEER_SAMPLE), 512)
        self.assertEqual(v.PEER_SAMPLE, bytes((i * 7 + 3) & 0xFF for i in range(512)))

    def test_snapshot_read_requires_a_staging_or_reopen_run(self):
        argv = ["verify_v020_production.py", "--output", "/out", "--snapshot-read"]
        with patch.object(sys, "argv", argv), redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as result:
                v.main()
        self.assertEqual(result.exception.code, 2)
        self.assertIn("--snapshot-read requires a staging or reopen run", errors.getvalue())

    def test_file_sessions_requires_a_staging_or_reopen_run(self):
        argv = ["verify_v020_production.py", "--output", "/out", "--file-sessions"]
        with patch.object(sys, "argv", argv), redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as result:
                v.main()
        self.assertEqual(result.exception.code, 2)
        self.assertIn("--file-sessions requires a staging or reopen run", errors.getvalue())

    def test_file_sessions_enables_file_read_without_snapshot_read(self):
        elf = Path("/kernel.elf")
        argv = ["verify_v020_production.py", "--output", "/out", "--media-staging", "--file-sessions"]
        with (patch.object(sys, "argv", argv), patch.object(v, "build", return_value=elf) as build,
              patch.object(v, "run", return_value={"status": "PASS"}) as run, redirect_stdout(io.StringIO())):
            self.assertEqual(v.main(), 0)
        modes = build.call_args.args[1]
        self.assertEqual(run.call_args.kwargs["modes"], modes)
        self.assertEqual(set(modes.features(staging=True).split(",")), {
            "v020-production-media-staging", "v020-production-file-sessions", "v020-production-file-read",
            "v020-production-media-signed", "v020-production-media-unified", "v020-production-live-control",
        })

    def test_file_volatile_write_requires_a_staging_or_reopen_run(self):
        argv = ["verify_v020_production.py", "--output", "/out", "--file-volatile-write"]
        with patch.object(sys, "argv", argv), redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as result:
                v.main()
        self.assertEqual(result.exception.code, 2)
        self.assertIn("--file-volatile-write requires a staging or reopen run", errors.getvalue())
        modes = v.Modes(file_volatile_write=True)
        with self.assertRaisesRegex(ValueError, "requires a staging or reopen run"):
            modes.features(staging=False)

    def test_file_volatile_write_implies_signed_unified_file_read_and_live_control(self):
        elf = Path("/kernel.elf")
        argv = ["verify_v020_production.py", "--output", "/out", "--media-staging", "--file-volatile-write"]
        with (patch.object(sys, "argv", argv), patch.object(v, "build", return_value=elf) as build,
              patch.object(v, "run", return_value={"status": "PASS"}) as run, redirect_stdout(io.StringIO())):
            self.assertEqual(v.main(), 0)
        modes = build.call_args.args[1]
        self.assertEqual(run.call_args.kwargs["modes"], modes)
        self.assertEqual(modes, v.Modes(file_volatile_write=True))
        self.assertEqual(set(modes.features(staging=True).split(",")), {
            "v020-production-media-staging", "v020-production-file-volatile-write", "v020-production-file-read",
            "v020-production-media-signed", "v020-production-media-unified", "v020-production-live-control",
        })

    def test_snapshot_read_reopen_keeps_file_modes_opt_in_and_uses_unsigned_fixture(self):
        for file_args in ([], ["--file-sessions"], ["--file-volatile-write"],
                          ["--file-sessions", "--file-volatile-write"]):
            with self.subTest(file_args=file_args), tempfile.TemporaryDirectory() as directory:
                elf = Path(directory) / "kernel.elf"
                elf.write_bytes(b"mock ELF")
                argv = ["verify_v020_production.py", "--output", str(Path(directory) / "evidence"),
                        "--media-reopen", "--snapshot-read", *file_args]
                with (patch.object(sys, "argv", argv), patch.object(v, "build", return_value=elf) as build,
                      patch.object(v, "run_media_reopen", return_value={"status": "PASS"}),
                      redirect_stdout(io.StringIO())):
                    self.assertEqual(v.main(), 0)
                fresh, unsigned, reopen = [call.args[1] for call in build.call_args_list]
                for modes in (fresh, reopen):
                    features = modes.features(staging=True).split(",")
                    for feature in ("snapshot-read", "snapshot-catalog", "file-read", "media-signed",
                                    "media-unified", "live-control"):
                        self.assertIn("v020-production-" + feature, features)
                    for feature in ("file-sessions", "file-volatile-write"):
                        self.assertEqual("v020-production-" + feature in features, "--" + feature in file_args)
                self.assertFalse(fresh.media_reopen)
                self.assertTrue(reopen.media_reopen)
                self.assertEqual(unsigned, v.Modes(media_unified=True, live_control=True))


if __name__ == "__main__":
    unittest.main()
