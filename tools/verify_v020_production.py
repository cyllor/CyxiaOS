#!/usr/bin/env python3
"""Independent pinned-QEMU check of the V0.20 production boot + in-vector SVC
dispatch SKELETON (wave 10 T1, feature v020-production).

This verifies that, in the production profile, the eight ABI3 PIE role packages
load through the build catalog and execute, and that the advice causal chain
(AdviceEnvelope v1 -> 0x50 intake -> RuleProfile review -> 0x50 register ->
0x41 publish -> ApplyReport -> supervisor terminal) is serviced by REAL EL0
SVC64 traps dispatched IN THE EXCEPTION VECTOR (ESR=0x56000000), not a fixture
turn loop. It also checks the fail-closed negatives and that CPU1-3 keep
business-only progress.

HONEST SCOPE: this is a production SKELETON, not full production authority. The
boot epoch is staged (volatile), the executor is a bounded fixture target, no
real model is active, and the snapshot/audit backend stays fail-closed (EAGAIN).
The verifier requires the guest to advertise exactly that scope and refuses any
claim of full_authority / real_models.

WAVE 11 (words 128..160): the G-A lane boots with a REAL VirtIO-net device
(QEMU user-net, hostfwd 127.0.0.1:<free port> -> guest :7) and a host peer that
sends one fixed 512-byte sample. It requires FrameMeta production statics,
four RecoveryProof v2 accumulators, policy_lock metering whose accounting is
consistent, and real TCP bytes relayed to the EL0 local-echo guest via 0x43.
HONEST SCOPE: no TLS echo turn is verified (word 142 must be 0); admission
leases are inferred from guest POLL->ENTROPY; entropy is the fixture PRNG; under
QEMU TCG every metered section overruns 45 us, so policy_lock timing is
emulated and the budget is NOT verified. `--media-staging` boots the opt-in
staging feature with a fresh all-zero scratch disk at -m 1024M; it proves the
boot and fail-closed paths only (golden_vector_pending, no signed config).
`--no-nic` is a negative control: the G-A lane must FAIL without a NIC.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

import verify_smp
from run_qemu import Qmp
from transport import FrameDecoder


ROOT = Path(__file__).resolve().parents[1]
# Profile-scoped source binding (a concurrent remediation wave can transiently
# break a whole-tree binding by editing another agent's scope). Bind the
# production skeleton's own stable sources plus the ELF.
PRODUCTION_SOURCES = [
    "kernel/src/arch/aarch64/production.rs",
    "kernel/src/arch/aarch64/v0199_advice_user.S",
    "kernel/src/arch/aarch64/smp.rs",
    "kernel/src/arch/aarch64/boot.rs",
    "kernel/src/arch/aarch64/exceptions.rs",
    "kernel/src/arch/aarch64/console.rs",
    "kernel/Cargo.toml",
    "kernel/build/aarch64.rs",
    "kernel/build/v0199_roles.rs",
    "kernel/src/arch/aarch64/sec_n_broker.rs",
    "kernel/src/arch/aarch64/scratch_blk.rs",
    "kernel/src/arch/aarch64/production/evidence.rs",
    "kernel/src/arch/aarch64/production/frames.rs",
    "kernel/src/arch/aarch64/production/recovery.rs",
    "kernel/src/arch/aarch64/production/meter.rs",
    "kernel/src/arch/aarch64/production/net.rs",
    "kernel/src/arch/aarch64/production/media_staging.rs",
    "kernel/src/arch/aarch64/production/media_staging/authority.rs",
    "kernel/src/arch/aarch64/production/media_staging/volume.rs",
    "user/local-echo/src/runtime.rs",
    "tools/verify_v020_production.py",
]
GUEST_ELF = "target/aarch64-unknown-none/release/cyxia-local-echo"
MAGIC = 0x4359_5052_4431_3030
COMPLETION = b"V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt\n"
SCOPE = "V020_PROD_SCOPE production_skeleton=true full_authority=false real_models=false"
SVC64 = 0x5600_0000

# Wave-11 evidence segment (kernel/src/arch/aarch64/production/evidence.rs).
W11_MAGIC = 0x4359_5052_4431_3131
W11_END = 160
# Metered production calls per boot (task-4 ruling): settled + overrun == 4.
POLICY_LOCK_METERED_CALLS = 4
RECOVERY_ACCUMULATORS = 4
W11_MARKER = "V020_W11_PRODUCTION"
STAGING_MARKER = "V020_W11_MEDIA_STAGING golden_vector_pending=1"
STAGING_INCOMPLETE = b"V020_W11_MEDIA_STAGING_INCOMPLETE"
# Words 145..150 must all be nonzero for the marker's `staging_ok=1`.
STAGING_STEP_WORDS = range(145, 151)
NET_ABSENT = b"V020_W11_NET_ABSENT"
# Fixed 512-byte host-peer sample (same bytes Task 5 measured). It is NOT a TLS
# ClientHello: the guest's rustls rejects it and parks, so no echo is expected.
PEER_SAMPLE = bytes((i * 7 + 3) & 0xFF for i in range(512))
PEER_WAIT_SECONDS = 5.0
GA_RAM = "256M"
# The staging feature enables prototype-memory (RAM_MIB = 1024; task-6 ruling).
STAGING_RAM = "1024M"
SCRATCH_BYTES = 512 * 1024 * 1024


class Production:
    completion = COMPLETION

    def __init__(self, staging: bool = False) -> None:
        self.staging = staging

    def profile(self, elf: bytes) -> dict:
        return verify_smp.profile(elf)

    def metadata(self) -> dict:
        meta = {
            "scope": ("native-v020-production-media-staging" if self.staging
                      else "native-v020-production-skeleton"),
            "production_skeleton": True,
            "full_authority": False,
            "real_models": False,
            "in_vector_dispatch": True,
            "staged_boot_epoch": True,
            "fixture_executor": True,
            "real_control_services": False,
            "real_executor_device": False,
            # Wave-11 scope labels (true regardless of the run's outcome).
            "tls_echo_turn_verified": False,
            "recovery_pair_facts_staged": True,
            "policy_lock_timing_emulated": True,
            "policy_lock_budget_verified": False,
            "policy_lock_note": ("QEMU TCG: every metered section overruns the 45 us budget; "
                                 "after the sticky latch trips only the first section is "
                                 "actually measured. Overruns are NOT budget compliance."),
            "admission_leases_inferred": True,
            "entropy_production": False,
            "sec_n_pools_frame_meta_registered": False,
            "host_peer_sample": "fixed 512-byte non-TLS pattern (not a ClientHello)",
            "media_staging_enabled": self.staging,
            # Word 133 (task-3 / final-review I3): the 0x41 refusal follows a
            # SYNTHETIC mark_unknown(); accumulators do not drive the gate and
            # no consumer takeover exists. The count itself is measured.
            "recovery_trigger_synthetic": True,
            "degraded_events_drive_gate": False,
            "accumulator_takeover_instantiated": False,
        }
        if self.staging:
            meta.update({
                "golden_vector_pending": True,
                "signed_config": False,
                "boot_epoch_verify_staged": True,
                "admission_flow_fixed_inputs": True,
                "prototype_memory_ram": STAGING_RAM,
            })
        return meta

    def success(self) -> dict:
        # Measured flags: merged into the summary only after validate() passed.
        return {
            "native_v020_production_skeleton_verified": True,
            "production_skeleton": True,
            "full_authority": False,
            "real_models": False,
            "in_vector_dispatch": True,
            "frame_meta_production_statics": True,
            "recovery_accumulators": RECOVERY_ACCUMULATORS,
            "policy_lock_metered": True,
            "real_net_device": True,
            "tcp_to_local_echo": True,
            "native_v020_media_staging_boot_verified": self.staging,
        }

    def validate(self, serial: bytes, page: bytes, cpu_count: int) -> dict:
        require = verify_smp.require
        require(cpu_count == 4, "QMP did not prove four real guest CPUs")
        require(len(page) == 4096, "short native-owned evidence page")
        words = struct.unpack("<512Q", page)
        # [MAGIC, version, completion, online, control, business, advice_seq,
        #  plan_seq, decision_seq, disp_state, selected, fallback, causal_label,
        #  accept_count, action_count, rejected_negatives]
        require(list(words[:16]) == [
            MAGIC, 1, 1, 15, 1, 14, 1, 1, 4, 1, 1, 0, 2, 1, 1, 5
        ], "incomplete production advice-chain completion evidence")
        require(all(v == 0 for v in words[56:64]), "nonzero reserved evidence")
        require(all(v == 0 for v in words[76:80]), "nonzero reserved evidence")
        require(all(v == 0 for v in words[W11_END:]), "nonzero reserved evidence tail")
        require(b"SMP_ERROR" not in serial and b"FAIL" not in serial, "guest reported fault")
        lines = serial.decode("ascii").splitlines()
        require(lines.count(
            "V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt"
        ) == 1, "missing/duplicate production completion marker")
        require(lines.count(SCOPE) == 1, "production skeleton scope must be advertised exactly")
        require(sum(line.startswith("V020_PROD_SCOPE") for line in lines) == 1,
                "exactly one scope line")
        # The skeleton must NOT claim full authority or real models.
        require(b"full_authority=true" not in serial, "must not claim full authority")
        require(b"real_models=true" not in serial, "must not claim real models")

        def rows(name: str):
            pattern = re.compile(re.escape(name) + r" a=(\d+) b=(\d+) c=(\d+)")
            matched = []
            for line in lines:
                if line.startswith(name + " "):
                    found = pattern.fullmatch(line)
                    require(found is not None, "malformed " + name)
                    matched.append(tuple(map(int, found.groups())))
            return matched

        require(rows("SMP_BOOT_OK") == [(4, 15, 0)], "invalid four-core boot marker")
        require(rows("SMP_CPU_ON") == [(1, 1, 0), (2, 2, 0), (3, 3, 0)], "CPU_ON proof missing")
        # PIE role bootstrap: eight packages loaded, each clocked.
        pie_load = rows("V020_PROD_PIE_LOAD")
        require(len(pie_load) == 1 and pie_load[0][0] == 8, "eight PIE packages must load")
        pie_roles = rows("V020_PROD_PIE_ROLE")
        require(len(pie_roles) == 8, "eight PIE role evidence rows required")
        require(all(c >= 1 for (_, c, _) in pie_roles), "every PIE role must clock")
        # Positive in-vector causal chain (ESR must be a real SVC64 trap).
        require(rows("V020_PROD_SUBMIT") == [(6, SVC64, 1)], "in-vector advice submit not recorded")
        require(rows("V020_PROD_REVIEW") == [(4, 1, 0)], "rule review did not adopt candidate 4")
        require(rows("V020_PROD_REGISTER") == [(2, SVC64, 1)], "register not frozen via in-vector 0x50")
        require(rows("V020_PROD_REGISTER_RETRY") == [(2, 2, 0)], "register retry not idempotent")
        require(rows("V020_PROD_PUBLISH") == [(8, SVC64, 1)], "publish not accepted via in-vector 0x41")
        require(rows("V020_PROD_PUBLISH_REPLAY") == [(8, 2, 1)], "publish replay re-accepted")
        require(rows("V020_PROD_APPLY") == [(1, 180, 4)], "executor apply evidence wrong")
        require(rows("V020_PROD_SETTLE") == [(1, 1, 2)], "terminal/causal label wrong")
        require(rows("V020_PROD_CHAIN") == [(1, 1, 1)], "causal chain ids disagree")
        # Negatives.
        require(rows("V020_PROD_NEG") == [(0, 0, 0)], "identity/domain/cap negatives not rejected")
        require(rows("V020_PROD_WRONG_CPU") == [(1, 0, 0)], "wrong-CPU negative missing")
        require(rows("V020_PROD_BAD_PUBLISH") == [(6, 0, 0)], "non-publisher not rejected")
        # Independent memory rows.
        submit = words[16:24]
        register = words[24:32]
        publish = words[32:40]
        settle = words[40:48]
        negatives = words[48:56]
        require(tuple(submit[:6]) == (6, SVC64, 0x50, 1, 1, 1), "submit memory row wrong")
        require(tuple(register[:6]) == (2, SVC64, 0x50, 1, 1, 4), "register memory row wrong")
        require(tuple(publish[:6]) == (8, SVC64, 0x41, 1, 1, 1), "publish memory row wrong")
        require(tuple(settle[:6]) == (1, 1, 1, 2, 0, 180), "settle memory row wrong")
        require(tuple(negatives) == (0, 0, 0, 1, 0, 2, 2, 1), "negative memory row wrong")
        require(submit[6] != 0 and register[6] != 0 and publish[6] != 0 and settle[6] != 0,
                "causal digests must be nonzero")
        # PIE evidence: eight distinct TTBR roots, each clocked; snapshot/audit
        # roles serviced an in-vector role call (EAGAIN), sleep roles yielded.
        roots = []
        for i in range(8):
            at = 80 + i * 6
            root, clocks, role_calls, yields, hash_lo, svc_out = words[at:at + 6]
            require(root != 0 and root % 4096 == 0, "PIE TTBR root must be a real page")
            require(clocks >= 1, "PIE role did not clock")
            require(role_calls >= 1 or yields >= 1, "PIE role made no progress")
            require(hash_lo != 0, "PIE image hash must be nonzero")
            roots.append(root)
        require(len(set(roots)) == 8, "eight PIE TTBR roots must be distinct")
        # Business CPUs kept running, control never promoted.
        business = rows("V020_PROD_BUSINESS")
        require(len(business) == 3, "missing business progress")
        progress_total = 0
        for slot in range(1, 4):
            affinity, progress, control_turns, irqs = words[64 + (slot - 1) * 4:68 + (slot - 1) * 4]
            require(affinity == slot and progress >= 2 and control_turns == 0 and irqs > 0,
                    "CPU1-3 did not keep business-only native progress")
            require(business[slot - 1] == (slot, progress, irqs), "business serial/memory mismatch")
            progress_total += progress
        wave11 = validate_w11(words, lines, serial, self.staging)
        return {
            **wave11,
            "guest_cpus": 4,
            "fixed_control_cpu": 0,
            "business_cpu_mask": 14,
            "pie_roles_loaded": 8,
            "pie_distinct_ttbr_roots": len(set(roots)),
            "advice_seq": words[6],
            "plan_seq": words[7],
            "decision_seq": words[8],
            "disposition_state": words[9],
            "selected_index": words[10],
            "fallback_index": words[11],
            "causal_label": words[12],
            "unique_native_accept_count": words[13],
            "rejected_negatives": words[15],
            "business_progress_turns": progress_total,
            "in_vector_dispatch": True,
            "production_skeleton": True,
            "full_authority": False,
            "real_models": False,
            "evidence_kind": "guest-EL0-in-vector-production-skeleton",
        }


def w11_rows(lines: list, name: str) -> list:
    pattern = re.compile(re.escape(name) + r" a=(\d+) b=(\d+) c=(\d+)")
    matched = []
    for line in lines:
        if line.startswith(name + " "):
            found = pattern.fullmatch(line)
            verify_smp.require(found is not None, "malformed " + name)
            matched.append(tuple(map(int, found.groups())))
    return matched


def completion_marker(flags: dict) -> str:
    return W11_MARKER + " " + " ".join(f"{k}={int(v)}" for k, v in flags.items())


def check_w11_baseline(words: tuple) -> None:
    require = verify_smp.require
    require(words[128] == W11_MAGIC, "missing wave-11 evidence magic (word 128)")
    require(words[129] == 1, "frame_meta_production_statics not set (word 129)")
    require(words[130] > 0, "FrameMeta registered static pages must be > 0 (word 130)")
    require(words[131] == RECOVERY_ACCUMULATORS, "recovery_accumulators must be 4 (word 131)")
    require(words[132] >= 1, "no DegradedEvent recorded (word 132)")
    require(words[133] == 1,
            "recovery gate must refuse exactly one 0x41 publish after the synthetic "
            f"mark_unknown() probe (word 133), got {words[133]}")
    require(words[134] == 1, "recovery_pair_facts_staged label missing (word 134)")
    require(words[135] == 1, "policy_lock_metered not set (word 135)")
    require(words[136] + words[137] == POLICY_LOCK_METERED_CALLS,
            "policy_lock accounting inconsistent: settled (136) + overrun (137) must equal "
            f"{POLICY_LOCK_METERED_CALLS} metered calls, got {words[136]}+{words[137]}")
    require(words[142] == 0, "must not claim tls_echo_turn_verified (word 142)")
    require(words[143] == 1, "staged_boot_epoch not set (word 143)")


def check_w11_rows(words: tuple, lines: list) -> dict:
    """Serial rows that carry measured counts beside the memory words."""
    require = verify_smp.require
    frame_rows = w11_rows(lines, "V020_W11_FRAME_META_ROWS")
    require(len(frame_rows) == 1, "FrameMeta rows serial row (V020_W11_FRAME_META_ROWS) missing")
    registered, permanent, gaps = frame_rows[0]
    require(registered == words[130] and permanent >= registered
            and gaps == permanent - registered,
            "FrameMeta rows serial row disagrees with word 130 (registered static pages)")
    gate = w11_rows(lines, "V020_W11_RECOVERY_GATE_REJECTS")
    require(gate == [(0, words[133], 1)],
            "recovery gate refusal counter must go 0 -> 1 with the gate Unknown "
            "(V020_W11_RECOVERY_GATE_REJECTS) and match word 133")
    return {"frame_meta_permanent_rows": permanent, "frame_meta_permanent_gap_rows": gaps}


def check_w11_net(words: tuple, lines: list, serial: bytes) -> None:
    require = verify_smp.require
    require(NET_ABSENT not in serial,
            "guest reported V020_W11_NET_ABSENT: no real VirtIO-net device (NIC missing); "
            "the G-A lane fails closed")
    require(words[138] == 1, "real_net_device not set (word 138): no NIC was brought up")
    require(words[139] == 1, "tcp_to_local_echo not set (word 139): no TCP bytes reached the guest")
    require(words[140] >= 1, "no Admission lease issued (word 140)")
    require(words[141] > 0,
            "peer silent: tcp_to_local_echo claimed but 0 bytes relayed via 0x43 (word 141); "
            "the handshake budget was exhausted without peer data")
    relay = w11_rows(lines, "V020_W11_NET_RELAY")
    require(len(relay) == 1 and relay[0][1:] == (words[140], words[141]),
            "net relay serial row (V020_W11_NET_RELAY) disagrees with memory words 140/141")


def check_w11_staging(words: tuple, lines: list, serial: bytes, staging: bool) -> None:
    require = verify_smp.require
    if not staging:
        require(words[144] == 0 and all(v == 0 for v in words[145:W11_END]),
                "media staging words 144..159 must be zero in the G-A lane")
        require(b"V020_W11_MEDIA_" not in serial, "media staging markers in the G-A lane")
        return
    require(b"V020_W11_MEDIA_ABSENT" not in serial, "V020_W11_MEDIA_ABSENT: no scratch disk")
    require(STAGING_INCOMPLETE not in serial,
            "guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed")
    require(words[144] == 1, "media_staging_enabled not set (word 144)")
    require(all(words[w] == 1 for w in range(145, 151)),
            "media staging steps incomplete (words 145..150 must all be 1)")
    require(words[151] == 1, "golden_vector_pending not set (word 151)")
    require(lines.count(STAGING_MARKER) == 1,
            "staging marker with golden_vector_pending=1 must appear exactly once")
    require(all(v == 0 for v in words[152:W11_END]), "nonzero media staging reserved words")


def validate_w11(words: tuple, lines: list, serial: bytes, staging: bool) -> dict:
    """Words 128..160 and the wave-11 serial contract (words 0..127 are checked by the caller)."""
    require = verify_smp.require
    check_w11_baseline(words)
    measured_rows = check_w11_rows(words, lines)
    check_w11_net(words, lines, serial)
    check_w11_staging(words, lines, serial, staging)
    flags = {
        "frame_meta": words[129] == 1,
        "recovery": words[131] == RECOVERY_ACCUMULATORS and words[133] == 1,
        "metered": words[135] == 1,
        "net": words[138] == 1,
        "tcp_echo": words[139] == 1,
        "tls_echo": words[142] == 1,
        "media_staging_enabled": words[144] == 1,
        "staging_ok": all(words[w] != 0 for w in STAGING_STEP_WORDS),
    }
    expected = completion_marker(flags)
    require(sum(line.startswith(W11_MARKER + " ") for line in lines) == 1
            and lines.count(expected) == 1,
            "W11 completion marker missing, duplicated or disagreeing with memory; expected "
            + repr(expected))
    return {
        "frame_meta_production_statics": True,
        "frame_meta_registered_static_pages": words[130],
        **measured_rows,
        "recovery_accumulators": words[131],
        "degraded_events": words[132],
        "recovery_publish_rejected_after_synthetic_unknown": words[133],
        "policy_lock_metered": True,
        "policy_lock_settled_in_budget": words[136],
        "policy_lock_overrun_or_unmeasured": words[137],
        "real_net_device": True,
        "tcp_to_local_echo": True,
        "admission_leases_inferred_count": words[140],
        "echo_bytes_relayed": words[141],
        "tls_echo_turn_verified": False,
        "media_staging_enabled": staging,
        "w11_completion_marker": expected,
    }


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def source_manifest() -> dict:
    names = {}
    for name in PRODUCTION_SOURCES:
        p = ROOT / name
        verify_smp.require(p.is_file() and not p.is_symlink(), "missing production source " + name)
        names[name] = sha(p)
    return names


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def qemu_args(binary: str, qmp_path: str, elf: Path, port: int,
              scratch: Path | None = None, nic: bool = True) -> list:
    """Pinned G-A argv; `scratch` selects the media-staging lane (-m 1024M + blk)."""
    ram = STAGING_RAM if scratch is not None else GA_RAM
    args = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
            "-cpu", "cortex-a53", "-smp", "4", "-m", ram, "-accel", "tcg,thread=multi",
            "-display", "none", "-monitor", "none"]
    if nic:
        # `-nic user,model=virtio-net-device` is not created on virt, and the
        # driver accepts modern (version 2) virtio-mmio only (task-5 ruling).
        args += ["-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:7",
                 "-device", "virtio-net-device,netdev=n0"]
    else:
        args += ["-nic", "none"]
    if nic or scratch is not None:
        args += ["-global", "virtio-mmio.force-legacy=false"]
    if scratch is not None:
        args += ["-drive", f"file={scratch},if=none,id=scratch,format=raw,cache=none",
                 "-device", "virtio-blk-device,drive=scratch"]
    return args + ["-chardev", "ringbuf,id=cyxlog,size=1048576", "-serial", "chardev:cyxlog",
                   "-qmp", f"unix:{qmp_path},server=on,wait=off", "-kernel", str(elf),
                   "-no-reboot"]


class HostPeer(threading.Thread):
    """Connect through hostfwd once the guest listens, send PEER_SAMPLE, read <= 5 s.

    QEMU slirp connects to the guest from its own ephemeral port; no fixed
    source port is bound here.
    """

    def __init__(self, port: int) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.listening = threading.Event()
        self.stopping = threading.Event()
        self.result: dict = {"sent": 0, "received": 0}

    def run(self) -> None:
        while not self.listening.wait(0.05):
            if self.stopping.is_set():
                self.result["error"] = "guest never listened"
                return
        try:
            with socket.create_connection(("127.0.0.1", self.port),
                                          timeout=PEER_WAIT_SECONDS) as conn:
                conn.sendall(PEER_SAMPLE)
                self.result["sent"] = len(PEER_SAMPLE)
                self.result["closed_by_guest"] = self.drain(conn)
        except OSError as error:
            self.result["error"] = type(error).__name__ + ": " + str(error)

    def drain(self, conn: socket.socket) -> bool:
        deadline = time.monotonic() + PEER_WAIT_SECONDS
        while not self.stopping.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            conn.settimeout(min(left, 0.25))
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return True
            self.result["received"] += len(chunk)
        return False


def create_scratch(path: Path) -> None:
    with path.open("xb") as handle:
        handle.truncate(SCRATCH_BYTES)


def scratch_summary(path: Path) -> dict:
    nonzero = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4096), b""):
            nonzero += any(block)
    return {"scratch_bytes": SCRATCH_BYTES, "scratch_after_sha256": sha(path),
            "scratch_after_nonzero_blocks": nonzero}


def shutdown(proc, qmp) -> None:
    if proc.poll() is None:
        try:
            if qmp:
                qmp.execute("quit")
        except (OSError, ValueError, RuntimeError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=2)


def connect_qmp(proc, path: str, end: float):
    require = verify_smp.require
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        require(proc.poll() is None, "QEMU exited before handshake")
        if time.monotonic() >= end:
            raise TimeoutError("QMP handshake deadline")
        try:
            sock.connect(path)
            return sock
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.01)


def run(elf: Path, output: Path, timeout: float = 120, staging: bool = False,
        nic: bool = True) -> dict:
    require = verify_smp.require
    require(1 <= timeout <= 300, "invalid execution budget")
    require(nic or not staging, "--no-nic is a G-A negative control only")
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), "refuse to reuse evidence output")
    output.mkdir(parents=True)
    before = source_manifest()
    (output / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    acceptance = Production(staging=staging)
    report = {
        "status": "FAIL", "scope": "native-v020-production-skeleton",
        "model_driven": False, "production_skeleton": True, "full_authority": False,
        "elf_sha256": sha(elf),
        "source_manifest_sha256": sha(output / "source-manifest.json"),
        "source_binding": "production-scoped (concurrent-wave whole-tree binding skipped)",
    }
    report.update(acceptance.metadata())
    if not nic:
        report["negative_control"] = "no-nic: the G-A lane must FAIL closed"
    decoder = FrameDecoder(); raw = bytearray(); decoded = bytearray()
    proc = None; sock = None; qmp = None; peer = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cyx-prod-") as td, (output / "qemu-stderr.log").open("wb") as err:
        scratch = Path(td) / "scratch.raw" if staging else None
        try:
            location = acceptance.profile(elf.read_bytes())
            binary = shutil.which("qemu-system-aarch64")
            require(binary is not None, "qemu-system-aarch64 is missing")
            version = subprocess.check_output([binary, "--version"], timeout=10, text=True)
            # Prefix match accepts both stock 10.2.2 and the repo's pinned
            # per-vCPU-PMU-patched 10.2.2 build (mirrors verify_v0199_eight_packages).
            require(version.splitlines()[0].startswith("QEMU emulator version 10.2.2"),
                    "unverified QEMU version")
            report["qemu_version"] = version
            report["qemu_sha256"] = sha(Path(binary))
            if scratch is not None:
                create_scratch(scratch)
            port = free_port()
            path = str(Path(td) / "q.sock")
            args = qemu_args(binary, path, elf, port, scratch=scratch, nic=nic)
            report["argv"] = args
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
            if nic:
                peer = HostPeer(port)
                peer.start()
            end = started + timeout
            sock = connect_qmp(proc, path, end)
            qmp = Qmp(sock)
            require("QMP" in qmp.receive(end), "invalid QMP greeting")
            qmp.execute("qmp_capabilities")
            actual_cpus = qmp.execute("query-cpus-fast")
            report["qmp_cpus"] = actual_cpus
            while time.monotonic() < end:
                require(proc.poll() is None, "QEMU exited before acceptance")
                value = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 1048576, "format": "base64"})
                data = base64.b64decode(value, validate=True)
                raw.extend(data)
                require(len(raw) <= 2 * 1024 * 1024, "serial budget exceeded")
                for frame in decoder.feed(data):
                    decoded.extend(frame)
                if peer is not None and b"V020_W11_NET_LISTEN" in decoded:
                    peer.listening.set()
                if b"FAIL" in decoded or b"SMP_ERROR" in decoded:
                    raise ValueError("guest failure")
                if acceptance.completion in decoded:
                    qmp.execute("stop")
                    qmp.execute("pmemsave", {"val": location["pa"], "size": 4096,
                                            "filename": str(output / "native-page.bin")})
                    require(decoder.loss == 0 and decoder.corrupt == 0 and not decoder.buffer,
                            "incomplete/corrupt framed UART transport")
                    page = (output / "native-page.bin").read_bytes()
                    report["observations"] = acceptance.validate(bytes(decoded), page, len(actual_cpus))
                    require(peer is None or report["observations"]["echo_bytes_relayed"]
                            == peer.result["sent"],
                            "relayed bytes (word 141) differ from the bytes the host peer sent")
                    require(sha(elf) == report["elf_sha256"], "ELF changed during guest run")
                    require(before == source_manifest(), "production source changed during guest run")
                    report["status"] = "PASS"
                    report.update(acceptance.success())
                    break
                time.sleep(0.01)
            else:
                raise TimeoutError("native execution deadline")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if proc is not None:
                shutdown(proc, qmp)
                report["qemu_exit"] = proc.returncode
            if peer is not None:
                peer.stopping.set()
                peer.join(timeout=PEER_WAIT_SECONDS + 1)
                report["host_peer"] = dict(peer.result)
            if sock:
                sock.close()
            if qmp:
                (output / "qmp.jsonl").write_text("".join(json.dumps(m) + "\n" for m in qmp.transcript))
            if scratch is not None and scratch.exists():
                report["scratch_disk"] = scratch_summary(scratch)
    (output / "serial.bin").write_bytes(raw)
    (output / "serial.txt").write_bytes(decoded)
    report["transport"] = dict(frames=decoder.frames, lost=decoder.loss, corrupt=decoder.corrupt)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["evidence_sha256"] = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def build(staging: bool) -> Path:
    """Build the fixture-identity local-echo guest first (the kernel embeds it),
    then the production kernel feature, exactly as verify_v0199_sec_n.build()."""
    import os
    import verify_v0199_sec_n
    verify_v0199_sec_n.build_guest()
    verify_smp.require((ROOT / GUEST_ELF).is_file(), "local-echo guest ELF missing after build")
    feature = "v020-production-media-staging" if staging else "v020-production"
    kernel_env = dict(os.environ)
    kernel_env.pop("RUSTFLAGS", None)
    subprocess.run(
        verify_v0199_sec_n.cargo_prefix()
        + "cargo build --locked --offline -p cyxia-kernel --target aarch64-unknown-none-softfloat "
        f"--features smp-selftest,{feature}",
        shell=True, cwd=ROOT, env=kernel_env, check=True, executable="/bin/bash")
    return ROOT / "target/aarch64-unknown-none-softfloat/debug/cyxia-kernel"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--elf", type=Path, help="kernel ELF; omitted -> build guest + kernel first")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--media-staging", action="store_true",
                        help="opt-in staging lane: -m 1024M + fresh all-zero scratch disk")
    parser.add_argument("--no-nic", action="store_true",
                        help="negative control: boot with -nic none; the G-A lane must FAIL")
    args = parser.parse_args()
    try:
        elf = args.elf if args.elf is not None else build(args.media_staging)
        result = run(elf, args.output, args.timeout, staging=args.media_staging,
                     nic=not args.no_nic)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=__import__("sys").stderr)
        return 1
    print(json.dumps(result, indent=2))
    if result["status"] != "PASS":
        print("FAIL: " + result.get("error", "unknown"), file=__import__("sys").stderr)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
