"""Synthetic unit tests for the V0.20 wave-11 production verifier.

Every page and serial stream here is SYNTHETIC (built in-test); these tests
check the verifier's acceptance logic only and are not runtime evidence.
"""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_v020_production as v  # noqa: E402

SVC64 = 0x5600_0000
GA_MARKER = ("V020_W11_PRODUCTION frame_meta=1 recovery=1 metered=1 net=1 "
             "tcp_echo=1 tls_echo=0 media_staging=0")
STAGING_MARKER = GA_MARKER[:-1] + "1"


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
        words[80 + i * 6:86 + i * 6] = [0x1000 * (i + 1), 1, 1, 0, 9, 0]
    return words


def w11_words(staging: bool = False) -> list:
    words = wave10_words()
    words[128:144] = [v.W11_MAGIC, 1, 337, 4, 15, 1, 1, 1, 0, 4, 1, 1, 1, 512, 0, 1]
    if staging:
        words[144:152] = [1] * 8
    return words


def wave10_lines() -> list:
    lines = ["SMP_BOOT_OK a=4 b=15 c=0"]
    lines += [f"SMP_CPU_ON a={c} b={c} c=0" for c in (1, 2, 3)]
    lines += ["V020_PROD_PIE_LOAD a=8 b=0 c=0"]
    lines += [f"V020_PROD_PIE_ROLE a={i} b=1 c=0" for i in range(8)]
    lines += [
        f"V020_PROD_SUBMIT a=6 b={SVC64} c=1",
        "V020_PROD_REVIEW a=4 b=1 c=0",
        f"V020_PROD_REGISTER a=2 b={SVC64} c=1",
        "V020_PROD_REGISTER_RETRY a=2 b=2 c=0",
        f"V020_PROD_PUBLISH a=8 b={SVC64} c=1",
        "V020_PROD_PUBLISH_REPLAY a=8 b=2 c=1",
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
    lines += ["V020_W11_NET_LISTEN a=7 b=0 c=0",
              "V020_W11_NET_GUEST_END a=0 b=0 c=0",
              "V020_W11_NET_RELAY a=71 b=1 c=512"]
    if staging:
        lines += ["V020_W11_MEDIA_SCOPE persistence=false format_golden=false signed_config=false",
                  "V020_W11_MEDIA_STAGING golden_vector_pending=1"]
    lines += [STAGING_MARKER if staging else GA_MARKER, v.SCOPE,
              "V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt"]
    return lines


def encode(words: list, lines: list):
    return ("\n".join(lines) + "\n").encode("ascii"), struct.pack("<512Q", *words)


class W11Validation(unittest.TestCase):
    def check(self, words=None, lines=None, staging=False):
        words = w11_words(staging) if words is None else words
        lines = w11_lines(staging) if lines is None else lines
        serial, page = encode(words, lines)
        return v.Production(staging=staging).validate(serial, page, 4)

    def rejects(self, pattern, **kw):
        with self.assertRaisesRegex(ValueError, pattern):
            self.check(**kw)

    def test_accepts_complete_w11_page(self):
        obs = self.check()
        self.assertTrue(obs["real_net_device"])
        self.assertTrue(obs["tcp_to_local_echo"])
        self.assertFalse(obs["tls_echo_turn_verified"])
        self.assertEqual(obs["echo_bytes_relayed"], 512)
        self.assertEqual(obs["policy_lock_settled"] + obs["policy_lock_overruns"], 4)
        self.assertFalse(obs["media_staging_enabled"])

    def test_rejects_missing_net_device(self):
        words = w11_words()
        words[138] = 0
        self.rejects("real_net_device", words=words)

    def test_requires_policy_lock_accounting_consistent(self):
        for at, value in ((135, 0), (137, 3), (136, 1)):
            words = w11_words()
            words[at] = value
            with self.subTest(word=at, value=value):
                self.rejects("policy_lock", words=words)
        words = w11_words()
        words[136:138] = [2, 2]
        self.assertEqual(self.check(words=words)["policy_lock_settled"], 2)

    def test_rejects_tls_claim(self):
        words = w11_words()
        words[142] = 1
        self.rejects("tls_echo_turn_verified", words=words)

    def test_rejects_staging_words_in_ga_lane(self):
        for at in (144, 145, 151, 159):
            words = w11_words()
            words[at] = 1
            with self.subTest(word=at):
                self.rejects("staging", words=words)

    def test_rejects_staging_marker_in_ga_lane(self):
        lines = w11_lines()
        lines.insert(-3, "V020_W11_MEDIA_STAGING golden_vector_pending=1")
        self.rejects("staging", lines=lines)

    def test_net_absent_is_fail_closed(self):
        lines = w11_lines()
        lines.insert(-3, "V020_W11_NET_ABSENT device=0 tcp_echo=0")
        self.rejects("V020_W11_NET_ABSENT", lines=lines)

    def test_net_absent_page_is_fail_closed(self):
        # What a -nic none boot really leaves: 138..141 zero, NET_ABSENT on serial.
        words = w11_words()
        words[138:142] = [0, 0, 0, 0]
        lines = [x for x in w11_lines() if not x.startswith("V020_W11_NET_")]
        lines.insert(-3, "V020_W11_NET_ABSENT device=0 tcp_echo=0")
        self.rejects("NIC|NET_ABSENT|real_net_device", words=words, lines=lines)

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
        for at, value in ((128, 0), (129, 0), (130, 0), (131, 3), (132, 0),
                          (133, 0), (134, 0), (143, 0)):
            words = w11_words()
            words[at] = value
            with self.subTest(word=at):
                with self.assertRaises(ValueError):
                    self.check(words=words)

    def test_rejects_nonzero_reserved_tail(self):
        words = w11_words()
        words[160] = 1
        self.rejects("reserved", words=words)

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
        words = w11_words(staging=True)
        words[152] = 1
        self.rejects("staging", words=words, staging=True)

    def test_staging_rejects_media_absent(self):
        lines = w11_lines(staging=True)
        lines.insert(-3, "V020_W11_MEDIA_ABSENT golden_vector_pending=1")
        self.rejects("MEDIA_ABSENT", lines=lines, staging=True)


class Labels(unittest.TestCase):
    def test_ga_metadata_is_honest(self):
        meta = v.Production().metadata()
        for key in ("tls_echo_turn_verified", "policy_lock_budget_verified",
                    "entropy_production", "sec_n_pools_frame_meta_registered",
                    "full_authority", "real_models", "media_staging_enabled"):
            self.assertIs(meta[key], False, key)
        for key in ("recovery_pair_facts_staged", "policy_lock_timing_emulated",
                    "admission_leases_inferred", "production_skeleton", "staged_boot_epoch"):
            self.assertIs(meta[key], True, key)
        self.assertNotIn("golden_vector_pending", meta)
        text = repr(meta) + repr(v.Production().success())
        self.assertNotIn("G4", text)

    def test_measured_flags_only_in_success(self):
        meta = v.Production().metadata()
        for key in ("real_net_device", "tcp_to_local_echo", "frame_meta_production_statics",
                    "recovery_accumulators", "policy_lock_metered"):
            self.assertNotIn(key, meta)
            self.assertIn(key, v.Production().success())

    def test_staging_metadata(self):
        meta = v.Production(staging=True).metadata()
        self.assertIs(meta["golden_vector_pending"], True)
        self.assertIs(meta["signed_config"], False)
        self.assertIs(meta["boot_epoch_verify_staged"], True)
        self.assertIs(meta["admission_flow_fixed_inputs"], True)
        self.assertIs(meta["media_staging_enabled"], True)


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


if __name__ == "__main__":
    unittest.main()
