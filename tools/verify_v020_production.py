#!/usr/bin/env python3
"""Independent pinned-QEMU check of the V0.20 production boot + in-vector SVC
dispatch SKELETON (feature v020-production-diagnostic).

This verifies that, in the diagnostic profile, the eight ABI3 PIE role packages
load through the build catalog and execute, and that the advice causal chain
(AdviceEnvelope v1 -> 0x50 intake -> RuleProfile review -> 0x50 register ->
0x41 publish -> ApplyReport -> supervisor terminal) is serviced by REAL EL0
SVC64 traps dispatched IN THE EXCEPTION VECTOR (ESR=0x56000000), not a fixture
turn loop. It also checks the fail-closed negatives and that CPU1-3 keep
business-only progress.

HONEST SCOPE: this is a production SKELETON, not full production authority. The
boot epoch is staged (volatile), the executor is a bounded fixture target and no
real model is active. Snapshot/audit require a ready, authorized data source.
The verifier requires the guest to advertise exactly that scope and refuses any
claim of full_authority / real_models.

WAVE 11 (words 128..160): the G-A lane boots with a REAL VirtIO-net device
(QEMU user-net, hostfwd 127.0.0.1:<free port> -> guest :7) and a host peer that
sends one fixed 512-byte sample. It requires FrameMeta production statics,
four RecoveryProof v2 accumulators, a stopped-writer handoff, policy_lock
measurement counts, and a direct Admission receipt and TCP bytes on SVC 0x43.
Opt-in modes exercise pinned fixture TLS with VirtIO RNG, live CPU0
observations, and reopen of the same temporary v1 disk across two VM boots.
Authentication also verifies normal close and native Admission retirement.
Signed media uses a scratch-only test trust root.
Wave 14 adds a bounded native frame lifecycle and independent readback of
four empty D1.5 envelope blocks on the scratch disk.
Wave 15 independently verifies the allocated eight-object scratch layout.
Wave 16 verifies the read-only Supervisor LIST endpoint on that layout.
Wave 19 verifies missing QUERY and HISTORY_OPEN results and reads back the
entire SlotStore independently from the scratch disk.
Wave 20 verifies bounded Supervisor file handles and read-only file sessions.
Wave 21 verifies bounded volatile writes, replay, readback and unchanged staged file bytes on disk.
`--no-nic` and `--no-peer` are negative controls for G-A.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import replace
from functools import partial
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

import verify_smp
from check_elf import symbol
from run_qemu import Qmp
from qmp_stdio import PipeTransport
from transport import FrameDecoder
from v020_production_media import (
    count_fsync_retirement_blocks, run_media_reopen, verify_signed_disk, verify_signed_receipt_view,
)
from v020_production_modes import (
    Modes, QEMU_GATEWAY_IPV4, W21_END, authenticated_echo, file_read_evidence, file_sessions_evidence,
    file_volatile_write_evidence, net_reset_proofs, rows as w11_rows, signed_media_authority, snapshot_catalog_evidence,
    snapshot_envelope_evidence, snapshot_read_evidence, unified_mount_evidence, validate_extensions,
)
from v020_production_host_samples import HostMediaSamples
from v020_production_qemu import (
    GA_RAM, PEER_SAMPLE, PEER_WAIT_SECONDS, SCRATCH_BYTES, STAGING_RAM, HostPeer,
    connect_qmp, create_scratch, free_port, qemu_args, scratch_summary, sha, shutdown,
)
from v020_snapshot_envelopes import verify_envelopes


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
    "kernel/src/arch/aarch64/mod.rs",
    "kernel/src/arch/aarch64/panic_stop.rs",
    "kernel/Cargo.toml",
    "kernel/linker/aarch64.ld",
    "kernel/build/aarch64.rs",
    "kernel/build/v0199_roles.rs",
    "kernel/build/startup_catalog.rs",
    "kernel/src/arch/aarch64/sec_n_broker.rs",
    "kernel/src/arch/aarch64/sec_n_broker/ingress.rs",
    "kernel/src/arch/aarch64/sec_n_broker/receipt.rs",
    "kernel/src/arch/aarch64/sec_n_broker/signer.rs",
    "kernel/src/arch/aarch64/scratch_blk.rs",
    "kernel/src/arch/aarch64/production/authorized.rs",
    "kernel/src/arch/aarch64/production/evidence.rs",
    "kernel/src/arch/aarch64/production/frames.rs",
    "kernel/src/arch/aarch64/production/frames/dense.rs",
    "kernel/src/arch/aarch64/production/frames/pool.rs",
    "kernel/src/arch/aarch64/production/file_read.rs",
    "kernel/src/arch/aarch64/production/file_read/sessions.rs",
    "kernel/src/arch/aarch64/production/file_read/volatile_write.rs",
    "kernel/src/arch/aarch64/production/file_durable.rs",
    "kernel/src/arch/aarch64/production/file_receipt.rs",
    "kernel/src/arch/aarch64/production/recovery.rs",
    "kernel/src/arch/aarch64/production/role_loader.rs",
    "kernel/src/arch/aarch64/production/signed_budget_trace.rs",
    "kernel/src/arch/aarch64/production/signed_resident.rs",
    "kernel/src/arch/aarch64/production/startup_catalog.rs",
    "kernel/src/arch/aarch64/production/meter.rs",
    "kernel/src/arch/aarch64/production/net.rs",
    "kernel/src/arch/aarch64/production/net_entropy.rs",
    "kernel/src/arch/aarch64/production/startup_catalog.rs",
    "kernel/src/arch/aarch64/production/media_staging.rs",
    "kernel/src/arch/aarch64/production/media_staging/authority.rs",
    "kernel/src/arch/aarch64/production/media_staging/fsync.rs",
    "kernel/src/arch/aarch64/production/media_staging/fsync_retire.rs",
    "kernel/src/arch/aarch64/production/media_staging/reopen.rs",
    "kernel/src/arch/aarch64/production/media_staging/signed.rs",
    "kernel/src/arch/aarch64/production/media_staging/volume.rs",
    "kernel/src/arch/aarch64/production/observations.rs",
    "kernel/src/arch/aarch64/production/observations/audit_record.rs",
    "kernel/src/arch/aarch64/production/observations/audit_rpc.rs",
    "kernel/src/arch/aarch64/production/snapshot_catalog.rs",
    "kernel/src/arch/aarch64/production/copy_window.rs",
    "kernel/src/platform/virt/net_device.rs",
    "crates/arch-aarch64/src/entry.S",
    "crates/arch-aarch64/src/secondary.S",
    "crates/arch-aarch64/src/vectors.S",
    "crates/arch-aarch64/src/mmu.rs",
    "crates/arch-aarch64/src/timer.rs",
    "crates/platform-virt/src/lib.rs",
    "crates/driver-virtio/src/lib.rs",
    "crates/driver-virtio/src/block.rs",
    "crates/driver-virtio/src/block/batched.rs",
    "crates/driver-virtio/src/net.rs",
    "crates/driver-virtio/src/net/batched.rs",
    "crates/driver-virtio/src/queue.rs",
    "crates/driver-virtio/src/reset.rs",
    "crates/driver-virtio/src/transport.rs",
    "crates/contracts/src/net_ingress.rs",
    "crates/contracts/src/tls_signer.rs",
    "crates/kernel-core/src/control_plane/pie_image_v0199.rs",
    "crates/kernel-core/src/security/recovery_proof_v2.rs",
    "crates/kernel-core/src/security/boot_epoch_v1.rs",
    "crates/kernel-core/src/security/network/entropy.rs",
    "crates/kernel-core/src/security/network/tls_deadline.rs",
    "crates/kernel-core/src/security/network/tls_packages.rs",
    "crates/kernel-core/src/security/startup_catalog_v0199.rs",
    "crates/kernel-core/src/security/startup_catalog_v0199/lifecycle_packages.rs",
    "crates/kernel-core/src/security/startup_catalog_v0199/profile.rs",
    "crates/kernel-core/src/security/durable_role_epoch_v0199.rs",
    "crates/kernel-core/src/security/epoch_redo_v0199.rs",
    "crates/kernel-core/src/security/offline_config_v1.rs",
    "crates/kernel-core/src/security/file_format_v1.rs",
    "crates/kernel-core/src/security/file_media_unified_v1.rs",
    "crates/kernel-core/src/security/file_mount_v1.rs",
    "crates/kernel-core/src/security/file_fsync_v1.rs",
    "crates/kernel-core/src/security/recovery_v1.rs",
    "crates/kernel-core/src/security/file_receipt_query_v4.rs",
    "crates/kernel-core/src/security/file_receipt_store_v0199.rs",
    "crates/kernel-core/src/security/file_index_v0199.rs",
    "crates/kernel-core/src/security/file_media_v0199.rs",
    "crates/kernel-core/src/security/file_structure_v1.rs",
    "crates/kernel-core/src/security/file_service_v4.rs",
    "crates/kernel-core/src/security/file_read_v4.rs",
    "crates/kernel-core/src/security/snapshot_list_v4.rs",
    "crates/kernel-core/src/security/snapshot_read_v4.rs",
    "crates/kernel-core/src/security/memory.rs",
    "crates/kernel-core/src/security/syscall_v3.rs",
    "crates/kernel-core/src/frame_meta_v0199.rs",
    "crates/kernel-core/src/frames.rs",
    "crates/kernel-core/src/control_plane/policy_lock_v0199.rs",
    "crates/kernel-core/src/control_plane/control_rpc_v1.rs",
    "crates/kernel-core/src/control_plane/action_schema_v2.rs",
    "crates/kernel-core/src/control_plane/registered_gate_v3.rs",
    "crates/kernel-core/src/control_plane/svc_bridge_v3.rs",
    "crates/kernel-core/src/control_plane/snapshot_store_v3.rs",
    "crates/net-transport/src/admission.rs",
    "crates/net-transport/src/device.rs",
    "crates/net-transport/src/ingress.rs",
    "crates/net-transport/src/native_tcp.rs",
    "crates/net-transport/src/tcp.rs",
    "crates/net-transport/src/tcp/observe.rs",
    "crates/net-transport/src/tls.rs",
    "user/v0199-control/main.rs",
    "user/v0199-control/audit.rs",
    "user/v0199-control/audit_hash.rs",
    "user/v0199-control/catalog.rs",
    "user/v0199-control/file_read.rs",
    "user/v0199-control/file_receipt.rs",
    "user/v0199-control/file_fsync.rs",
    "user/local-echo/src/broker.rs",
    "user/local-echo/src/ingress.rs",
    "user/local-echo/src/lib.rs",
    "user/local-echo/src/runtime.rs",
    "user/local-echo/src/signer.rs",
    "user/local-echo/build.rs",
    "user/local-echo/linker.ld",
    "tools/verify_v020_production.py",
    "tools/verify_v0199_sec_n.py",
    "tools/test_v020_signed_scratch_vector.py",
    "tools/verify_v020_fsync_scratch.py",
    "tools/qmp_stdio.py",
    "tools/v020_production_media.py",
    "tools/v020_production_modes.py",
    "tools/v020_production_qemu.py",
    "tools/v020_production_host_samples.py",
    "tools/v020_snapshot_envelopes.py",
    "tools/v020_tls_peer.py",
    "tests/fixtures/v020-signed-scratch/config.bin",
    "tests/fixtures/v020-signed-scratch/fsync-config.bin",
    "tests/fixtures/v020-signed-scratch/fsync-receipt-query.bin",
    "tests/fixtures/v020-signed-scratch/fsync-client.bin",
]
GUEST_ELF = "target/aarch64-unknown-none/release/cyxia-local-echo"
MAGIC = 0x4359_5052_4431_3030
COMPLETION = b"V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt\n"
SCOPE = "V020_PROD_SCOPE production_skeleton=true full_authority=false real_models=false"
SVC64 = 0x5600_0000
E_AUTH_RESULT = (1 << 64) - 1
EAGAIN_RESULT = (1 << 64) - 13
PIE_ROLE_IDS = (6, 7, 2, 8, 9, 3, 10, 11)
SNAPSHOT_ROLE_COUNT = 3

# Wave-11 evidence segment (kernel/src/arch/aarch64/production/evidence.rs).
W11_MAGIC = 0x4359_5052_4431_3131
W11_END = 160
# Two registrations and two publish attempts enter the meter.
POLICY_LOCK_METERED_CALLS = 4
POLICY_LOCK_WORK_BUDGET_NS = 45_000
# Cortex-A53 in the pinned virt-10.2 machine uses GTIMER_BACKCOMPAT_HZ.
TARGET_LOCK_COUNTER_HZ = 62_500_000
RECOVERY_ACCUMULATORS = 4
RECOVERY_REQUIRED_STATE = 2
SECONDARY_CPU_MASK = 0b1110
W11_MARKER = "V020_W11_PRODUCTION"
STAGING_MARKER = "V020_W11_MEDIA_STAGING golden_vector_pending=1"
STAGING_INCOMPLETE = b"V020_W11_MEDIA_STAGING_INCOMPLETE"
NET_ABSENT = b"V020_W11_NET_ABSENT"
NET_ACCEPT_TURNS = 20_000


class Production:
    completion = COMPLETION

    def __init__(self, staging: bool = False, modes: Modes = Modes()) -> None:
        self.staging = staging
        self.modes = modes

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
            "tls_credit_retirement_verified": False,
            "recovery_pair_facts_staged": True,
            "policy_lock_timing_emulated": True,
            "policy_lock_budget_verified": False,
            "policy_lock_note": ("TCG diagnostic timing separates measured overruns from "
                                 "attempts with invalid clock samples; all completed bridge calls are observed."),
            "admission_leases_inferred": False,
            "entropy_production": False,
            "host_peer_sample": "fixed 512-byte non-TLS pattern (not a ClientHello)",
            "media_staging_enabled": self.staging,
            "recovery_trigger_synthetic": True,
            "recovery_trigger": "staged single checkpoint witness withdrawn",
            "degraded_events_drive_gate": False,
            "durable_audit_consumer_takeover": False,
            "authenticated_net_mode": self.modes.authenticated_net,
            "live_control_mode": self.modes.live_control,
            "frame_pool_mode": self.modes.frame_pool,
            "fixture_identity": self.modes.authenticated_net,
        }
        if self.staging:
            meta.update({
                "golden_vector_pending": True,
                "signed_config": False,
                "boot_epoch_verify_staged": True,
                "admission_flow_fixed_inputs": True,
                "persistent_audit_slot": False,
                "media_reopen_mode": self.modes.media_reopen,
                "signed_media_mode": self.modes.signed_media,
                "media_envelopes_mode": self.modes.snapshot_envelopes,
                "media_unified_mode": self.modes.media_unified,
                "snapshot_catalog_mode": self.modes.snapshot_catalog,
                "file_read_mode": self.modes.file_read,
                "snapshot_read_mode": self.modes.snapshot_read,
                "file_sessions_mode": self.modes.file_sessions,
                "file_volatile_write_mode": self.modes.file_volatile_write,
                "prototype_memory_ram": STAGING_RAM,
            })
        if self.modes.authenticated_net:
            meta["host_peer_sample"] = "pinned TLS 1.3 and a fresh read-only Echo challenge"
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
            "sec_n_pools_frame_meta_registered": True,
            "recovery_accumulators": RECOVERY_ACCUMULATORS,
            "recovery_writer_takeovers": SECONDARY_CPU_MASK.bit_count(),
            "policy_lock_metered": True,
            "real_net_device": True,
            "tcp_to_local_echo": True,
            "admission_receipt_verified": True,
            "native_v020_media_staging_boot_verified": self.staging,
        }

    def validate(self, serial: bytes, page: bytes, cpu_count: int, *,
                 pending_fsync_blocks: int | None = None,
                 expected_fsync_epoch: int | None = None) -> dict:
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
        require(all(v == 0 for v in words[W21_END:]), "nonzero reserved evidence tail")
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
            return w11_rows(lines, name)

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
        lock = rows("V020_SEC_S_TARGET_LOCK")
        require(len(lock) == 1, "missing or duplicate D01 target-lock interval")
        work_ns, overhead_ns, irq_off_ns = lock[0]
        lock_ticks = words[156:W11_END]
        before, start, end, restored = lock_ticks
        require(0 < before <= start <= end <= restored and before < restored,
                "missing or invalid raw D01 target-lock counters")

        def elapsed_ns(ticks: int) -> int:
            return (ticks * 1_000_000_000 + TARGET_LOCK_COUNTER_HZ - 1) // TARGET_LOCK_COUNTER_HZ

        # The outer samples include IRQ masking and restoration. Compute the
        # combined overhead before rounding so splitting it leaves its bound intact.
        acquire_ticks = start - before
        release_ticks = restored - end
        measured = (
            elapsed_ns(end - start),
            elapsed_ns(acquire_ticks + release_ticks),
            elapsed_ns(restored - before),
        )
        require((work_ns, overhead_ns, irq_off_ns) == measured,
                "D01 target-lock durations differ from raw counters")
        # Safety budgets are checked independently from the bridge observation.
        lock_fault = (int(work_ns > 45_000) | (int(overhead_ns > 5_000) << 1)
                      | (int(irq_off_ns > 50_000) << 2))
        require(rows("V020_SEC_S_TARGET_INSTALL") == [(7, 4, lock_fault)],
                "D01 target install did not enforce measured budgets")
        labels = [line.split(" ", 1)[0] for line in lines]
        require(labels.index("V020_SEC_S_TARGET_LOCK")
                < labels.index("V020_SEC_S_TARGET_INSTALL") < labels.index("V020_PROD_APPLY"),
                "D01 target-lock measurement must precede its application report")
        require(rows("V020_PROD_SETTLE") == [(1, 1, 2)], "terminal/causal label wrong")
        require(rows("V020_PROD_CHAIN") == [(1, 1, 1)], "causal chain ids disagree")
        # Negatives.
        require(rows("V020_PROD_NEG") == [(0, 0, 0)], "identity/domain/cap negatives not rejected")
        require(rows("V020_PROD_WRONG_CPU") == [(1, 0, 0)], "wrong-CPU negative missing")
        require(rows("V020_PROD_BAD_PUBLISH") == [(6, 0, 0)], "non-publisher not rejected")
        require(rows("V020_PROD_RECOVERY_REJECT") == [(8, E_AUTH_RESULT, words[13])],
                "in-vector recovery refusal must return E_AUTH without another acceptance")
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
        snapshot_calls = 0
        for i, role_id in enumerate(PIE_ROLE_IDS):
            at = 80 + i * 6
            root, clocks, role_calls, yields, hash_lo, svc_out = words[at:at + 6]
            require(root != 0 and root % 4096 == 0, "PIE TTBR root must be a real page")
            require(clocks >= 1, "PIE role did not clock")
            require(role_calls >= 1 or yields >= 1, "PIE role made no progress")
            require(hash_lo != 0, "PIE image hash must be nonzero")
            require(pie_roles[i] == (role_id, clocks, role_calls), "PIE serial/memory mismatch")
            if i < SNAPSHOT_ROLE_COUNT or role_id == PIE_ROLE_IDS[-1]:
                require(role_calls > 0 and svc_out == EAGAIN_RESULT,
                        "PIE snapshot/audit call must return in-vector EAGAIN")
            if i < SNAPSHOT_ROLE_COUNT:
                snapshot_calls += role_calls
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
        if self.modes.signed_media and STAGING_INCOMPLETE in serial:
            require(not any(words[138:143]) and words[160] == words[176] == 0
                    and not any(line.startswith(("V020_W11_NET_", "V020_SEC_N_", "V020_SEC_D_NET_RESET_"))
                                for line in lines), "network started without signed media custody")
            raise ValueError("guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed")
        rejected_packages = rows("V020_SEC_N_PACKAGE_REJECTED")
        if rejected_packages:
            require(self.modes.authenticated_net and len(rejected_packages) == 1
                    and rejected_packages[0][0] > 0 and rejected_packages[0][1] > 0
                    and rejected_packages[0][2] == 0 and not any(words[138:143])
                    and words[160] == words[176] == 0
                    and not any(line.startswith(("V020_W11_NET_", "V020_SEC_D_NET_RESET_"))
                                for line in lines)
                    and not rows("V020_SEC_N_SIGNER_SPACE"),
                    "TLS package rejection did not fence the network before device ownership")
            raise ValueError("V020_SEC_N_PACKAGE_REJECTED: both packaged credentials required")
        extensions = validate_extensions(words, lines, self.modes)
        wave11 = validate_w11(words, lines, serial, self.staging, snapshot_calls, self.modes,
                              pending_fsync_blocks=pending_fsync_blocks,
                              expected_fsync_epoch=expected_fsync_epoch)
        signed = signed_media_authority(words, lines, self.modes)
        return {
            **wave11,
            **extensions,
            **signed,
            **snapshot_envelope_evidence(words, lines, self.modes.snapshot_envelopes),
            **unified_mount_evidence(words, lines, self.modes.media_unified, file_read=self.modes.file_read),
            **snapshot_catalog_evidence(words, lines, self.modes.snapshot_catalog),
            **file_read_evidence(words, lines, self.modes.file_read),
            **snapshot_read_evidence(words, lines, self.modes.snapshot_read),
            **file_sessions_evidence(words, lines, self.modes.file_sessions,
                                     file_volatile_write=self.modes.file_volatile_write),
            **file_volatile_write_evidence(words, lines, self.modes.file_volatile_write),
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
            "target_lock_work_ns": work_ns,
            "target_lock_mask_and_acquire_ns": elapsed_ns(acquire_ticks),
            "target_lock_release_and_restore_ns": elapsed_ns(release_ticks),
            "target_lock_overhead_ns": overhead_ns,
            "target_lock_irq_off_ns": irq_off_ns,
            "target_lock_raw_ticks": lock_ticks,
            "target_lock_counter_frequency_hz": TARGET_LOCK_COUNTER_HZ,
            "target_lock_closed_new_work": lock_fault != 0,
            "rejected_negatives": words[15],
            "business_progress_turns": progress_total,
            "in_vector_dispatch": True,
            "production_skeleton": True,
            "full_authority": False,
            "real_models": False,
            "evidence_kind": "guest-EL0-in-vector-production-skeleton",
        }


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
            f"recovery gate must refuse exactly one 0x41 in RECOVERY_REQUIRED (word 133), got {words[133]}")
    require(words[134] == 1, "recovery_pair_facts_staged label missing (word 134)")
    require(words[135] == 1, "policy_lock_metered not set (word 135)")
    require(words[136] + words[137] == POLICY_LOCK_METERED_CALLS,
            "policy_lock accounting inconsistent: settled (136) + overrun (137) must equal "
            f"{POLICY_LOCK_METERED_CALLS} metered calls, got {words[136]}+{words[137]}")
    require(words[142] == 0, "must not claim tls_echo_turn_verified (word 142)")
    require(words[143] == 1, "staged_boot_epoch not set (word 143)")
    require(words[152] == SECONDARY_CPU_MASK.bit_count(),
            "RecoveryProof writer takeover must cover the three stopped CPUs (word 152)")
    require(0 < words[153] < words[130], "FrameMeta Arena pages missing or inconsistent (word 153)")
    require(words[154] <= words[137]
            and (words[155] > POLICY_LOCK_WORK_BUDGET_NS) == (words[154] > 0),
            "policy_lock measured overrun disagrees with the maximum elapsed time")
    require(words[136] + words[154] > 0, "policy_lock requires a settled measurement")


def check_w11_rows(words: tuple, lines: list) -> dict:
    """Serial rows that carry measured counts beside the memory words."""
    require = verify_smp.require
    frame_rows = w11_rows(lines, "V020_W11_FRAME_META_ROWS")
    require(len(frame_rows) == 1, "FrameMeta rows serial row (V020_W11_FRAME_META_ROWS) missing")
    registered, permanent, gaps = frame_rows[0]
    require(registered == words[130] and permanent >= registered
            and gaps == permanent - registered,
            "FrameMeta rows serial row disagrees with word 130 (registered static pages)")
    require(w11_rows(lines, "V020_W11_FRAME_META_ARENA")
            == [(words[153], registered - words[153], 0)],
            "FrameMeta Arena serial counts disagree with words 130/153")
    gate = w11_rows(lines, "V020_W11_RECOVERY_GATE_REJECTS")
    require(gate == [(0, words[133], RECOVERY_REQUIRED_STATE)],
            "recovery gate refusal counter must go 0 -> 1 in RECOVERY_REQUIRED "
            "(V020_W11_RECOVERY_GATE_REJECTS) and match word 133")
    handoff = w11_rows(lines, "V020_W11_RECOVERY_HANDOFF")
    require(len(handoff) == 1, "expected one RecoveryProof writer handoff row")
    mask, retained, fixture_faults = handoff[0]
    require(mask == SECONDARY_CPU_MASK and 0 < fixture_faults <= retained <= words[132],
            "RecoveryProof writer handoff counts or CPU mask disagree with the sealed page")
    unmeasured = words[137] - words[154]
    require(w11_rows(lines, "V020_W11_POLICY_LOCK_METER") == [(words[136], words[154], unmeasured)],
            "policy_lock serial accounting disagrees with the sealed page")
    return {
        "frame_meta_permanent_rows": permanent,
        "frame_meta_permanent_gap_rows": gaps,
        "frame_meta_service_arena_pages": words[153],
        "recovery_handoff_events_retained": retained,
        "recovery_validated_fixture_faults": fixture_faults,
        "policy_lock_unmeasured": unmeasured,
    }


def check_w11_net(words: tuple, lines: list, serial: bytes) -> None:
    require = verify_smp.require
    if NET_ABSENT in serial:
        require(lines.count("V020_W11_NET_ABSENT device=0 tcp_echo=0") == 1
                and not any(words[138:143])
                and not w11_rows(lines, "V020_W11_NET_ADMISSION")
                and not w11_rows(lines, "V020_W11_NET_RELAY"),
                "network absence evidence disagrees with the sealed network fields")
        raise ValueError("guest reported V020_W11_NET_ABSENT: no real VirtIO-net device "
                         "(NIC missing); the G-A lane fails closed")
    require(words[138] == 1, "real_net_device not set (word 138): no NIC was brought up")
    no_peer = w11_rows(lines, "V020_W11_NET_NO_PEER")
    if no_peer:
        require(no_peer == [(1, NET_ACCEPT_TURNS, 0)] and not any(words[139:143])
                and not w11_rows(lines, "V020_W11_NET_ADMISSION"),
                "network accept failed without a valid bounded no-peer outcome")
        raise ValueError("V020_W11_NET_NO_PEER: bounded TCP accept ended without a connection")
    require(words[139] == 1, "tcp_to_local_echo not set (word 139): no TCP bytes reached the guest")
    require(words[140] == 1, "expected one Admission lease (word 140)")
    require(words[141] > 0,
            "peer silent: tcp_to_local_echo claimed but 0 bytes relayed via 0x43 (word 141); "
            "the handshake budget was exhausted without peer data")
    relay = w11_rows(lines, "V020_W11_NET_RELAY")
    require(len(relay) == 1 and relay[0][1:] == (words[140], words[141]),
            "net relay serial row (V020_W11_NET_RELAY) disagrees with memory words 140/141")
    admission = w11_rows(lines, "V020_W11_NET_ADMISSION")
    require(admission == [(1, QEMU_GATEWAY_IPV4, words[140])],
            "direct Admission receipt missing or disagrees with the pinned connection")


def fsync_checkpoint_retirement_io(row: tuple, commit_lsn: int,
                                  pending_fsync_blocks: int | None) -> tuple:
    epoch, lsn, retired = row
    verify_smp.require(epoch == 1 and lsn == commit_lsn and 0 <= retired <= 32
                       and retired == pending_fsync_blocks,
                       "initial FSYNC checkpoint retirement differs from observed log")
    return 6 + retired, 3 + int(retired != 0)


def check_w11_staging(words: tuple, lines: list, serial: bytes, staging: bool,
                      snapshot_calls: int, modes: Modes, *,
                      pending_fsync_blocks: int | None = None,
                      expected_fsync_epoch: int | None = None) -> dict:
    require = verify_smp.require
    if not staging:
        require(all(v == 0 for v in words[144:152]),
                "media staging words 144..151 must be zero in the G-A lane")
        require(b"V020_W11_MEDIA_" not in serial, "media staging markers in the G-A lane")
        return {}
    require(b"V020_W11_MEDIA_ABSENT" not in serial, "V020_W11_MEDIA_ABSENT: no scratch disk")
    require(STAGING_INCOMPLETE not in serial,
            "guest reported V020_W11_MEDIA_STAGING_INCOMPLETE: a staging step failed")
    reopen = modes.media_reopen
    require(words[144] == 1, "media_staging_enabled not set (word 144)")
    epoch = 2 if reopen else 1
    if expected_fsync_epoch is not None:
        require(reopen and modes.fsync_scratch and expected_fsync_epoch >= 2,
                "expected FSYNC epoch requires a scratch reopen")
        epoch = expected_fsync_epoch
    require(words[145:151] == (int(not reopen), 1, 1, epoch, 1, 1),
            "media staging steps or confirmed epoch disagree with the selected mode")
    require(words[162:164] == (int(reopen), epoch - 1)
            and w11_rows(lines, "V020_W12_MEDIA_EPOCH") == [(epoch - 1, epoch, int(reopen))],
            "media staging prior epoch and reopen flags must match serial")
    require(words[151] == 1, "golden_vector_pending not set (word 151)")
    require(lines.count(STAGING_MARKER) == 1,
            "staging marker with golden_vector_pending=1 must appear exactly once")
    steps = w11_rows(lines, "V020_W11_MEDIA_STEP")
    retirement = w11_rows(lines, "V020_FSYNC_CHECKPOINT_RETIRE")
    require(not retirement or (modes.fsync_scratch and reopen and epoch == 2
                               and len(retirement) == 1),
            "unexpected FSYNC checkpoint retirement")
    selected_generation = 2 if retirement else epoch - int(reopen)
    live_inodes = (9 if modes.media_unified else 5) + int(modes.file_read or modes.fsync_scratch)
    require([step[:2] for step in steps] == [(index, 1) for index in range(1, 6)]
            and steps[0][2] == selected_generation and steps[1][2] == live_inodes
            and steps[2][2] == 151 and steps[4][2] == 1,
            "media staging serial steps must show format, mount, map, epoch and admission success")
    require(steps[3][2] == words[148], "media staging BootEpoch disagrees with word 148")
    io = w11_rows(lines, "V020_W11_MEDIA_IO")
    fresh_writes = 4138 + (4 if modes.media_envelopes else 0)
    if modes.media_unified:
        fresh_writes = 4276 + int(modes.file_read)
    expected_io = (15, 5) if reopen else (fresh_writes, 6)
    if modes.fsync_bound:
        event = "V020_FSYNC_UNKNOWN_RECOVERED" if reopen else "V020_FSYNC_BOUND"
        terminal = w11_rows(lines, event)
        require(len(terminal) == 1 and (
                    (terminal[0][:2] == (epoch, 14) and terminal[0][2] > 0) if reopen else
                    (terminal[0][0] == 14 and terminal[0][1] > 0 and terminal[0][2] == 0)
                ) and not any(w11_rows(lines, marker) for marker in (
                    "V020_FSYNC_COMMITTED", "V020_FSYNC_RECOVERED",
                )), "BOUND receipt must preserve uncertainty")
        if not reopen:
            expected_io = (4155, 10)
        elif retirement:
            expected_io = fsync_checkpoint_retirement_io(retirement[0], 14, pending_fsync_blocks)
        elif epoch == 2:
            require(pending_fsync_blocks in (None, 18), "pre-replay BOUND log block count differs")
            expected_io = (30, 5)  # Five homes, a checkpoint, 18 retirements, six boot records.
        else:
            require(pending_fsync_blocks in (None, 4), "pre-replay BootEpoch pair block count differs")
    elif modes.fsync_scratch:
        event = "V020_FSYNC_RECOVERED" if reopen else "V020_FSYNC_COMMITTED"
        terminal = w11_rows(lines, event)
        legacy = [(epoch, 19, 7)] if reopen else [(19, 7, 29)]
        commit = terminal[0][1 if reopen else 0] if len(terminal) == 1 else 0
        growth = commit == 23
        low, high = (4097, 8192) if growth else (29, 4096)
        current = len(terminal) == 1 and (
            terminal[0][0] == epoch and commit in (21, 23) and terminal[0][2] > 0 if reopen else
            commit in (21, 23) and terminal[0][1] > 0 and low <= terminal[0][2] <= high
        )
        require(terminal == legacy or current, "media staging FSYNC terminal differs")
        if retirement:
            expected_io = fsync_checkpoint_retirement_io(retirement[0], commit, pending_fsync_blocks)
        elif reopen and epoch > 2:
            # Only the earlier BootEpoch pair remains. The two data tails
            # are zero, and the boot-only recovery clears all six log blocks.
            require(pending_fsync_blocks in (None, 4),
                    "pre-replay BootEpoch pair block count differs")
        elif reopen:
            # The data REDO's continuation only needs clearing if the final
            # 64 bytes are nonzero. Archived 29-byte runs have no such block.
            allowed = (30, 31, 32) if growth else ((28, 29) if current else (24,))
            retired = allowed[0] if pending_fsync_blocks is None else pending_fsync_blocks
            require(retired in allowed, "pre-replay FSYNC journal block count differs")
            # Growth adds a data home and its bitmap to the legacy closure.
            expected_io = (14 + retired + 2 * growth, 5)
        else:
            expected_io = (4171 if growth else (4167 if current else 4163), 12)
    require(len(io) == 1 and io[0][0] > 0 and io[0][1:] == expected_io,
            "media staging device writes and flushes disagree with the selected protocol")
    evidence = {}
    synced = w11_rows(lines, "V020_FSYNC_WRITE_ABI")
    if synced:
        require(modes.fsync_scratch and not modes.fsync_bound and not reopen and synced == [(1, 11, 1)],
                "unexpected native file FSYNC client identity")
        evidence["native_file_fsync"] = {
            "boot_epoch": synced[0][0],
            "actor": synced[0][1],
            "service_generation": synced[0][2],
        }
    receipt = w11_rows(lines, "V020_FSYNC_RECEIPT_ABI")
    if receipt:
        require(modes.fsync_scratch and reopen and receipt == [(epoch, 11, 1)],
                "unexpected native file receipt-query identity")
        evidence["native_file_receipt_query"] = {
            "boot_epoch": receipt[0][0],
            "actor": receipt[0][1],
            "service_generation": receipt[0][2],
        }
    snapshot = w11_rows(lines, "V020_W11_MEDIA_SNAPSHOT_0X40")
    require(snapshot == [(snapshot_calls, EAGAIN_RESULT, 0)],
            "media staging snapshot refusal must match in-vector EAGAIN role calls")
    queue = w11_rows(lines, "V020_W11_MEDIA_QUEUE")
    if not queue:
        return evidence  # Historical staging ELFs report only logical block operations.
    reads, writes, flushes = io[0]
    expected = 2 * (reads + writes) + flushes
    require(len(queue) == 1 and queue[0][:2] == (expected, expected)
            and 0 <= queue[0][2] <= expected,
            "scratch queue requests disagree with logical blocks and isolated flushes")
    evidence.update({"scratch_virtio_requests_completed": expected,
                     "scratch_virtio_doorbells": queue[0][2]})
    return evidence


def validate_w11(words: tuple, lines: list, serial: bytes, staging: bool,
                 snapshot_calls: int, modes: Modes, *,
                 pending_fsync_blocks: int | None = None,
                 expected_fsync_epoch: int | None = None) -> dict:
    """Words 128..160 and the wave-11 serial contract (words 0..127 are checked by the caller)."""
    require = verify_smp.require
    check_w11_baseline(words)
    measured_rows = check_w11_rows(words, lines)
    check_w11_net(words, lines, serial)
    media_rows = check_w11_staging(words, lines, serial, staging, snapshot_calls, modes,
                                   pending_fsync_blocks=pending_fsync_blocks,
                                   expected_fsync_epoch=expected_fsync_epoch)
    net_boot_epoch = words[148] if modes.signed_media else 1
    confirmed = w11_rows(lines, "V020_SEC_N_CONFIRMED_BOOT")
    if modes.signed_media:
        require(confirmed == [(net_boot_epoch, 1, 1)],
                "missing confirmed TLS boot binding for signed scratch media")
        listen = "V020_W11_NET_LISTEN a=7 b=0 c=0"
        confirmation = f"V020_W11_MEDIA_STEP a=4 b=1 c={net_boot_epoch}"
        network = f"V020_SEC_N_CONFIRMED_BOOT a={net_boot_epoch} b=1 c=1"
        require(lines.count(listen) == 1
                and lines.index(confirmation) < lines.index(network) < lines.index(listen),
                "signed-media network listened before durable BootEpoch binding")
    else:
        require(not confirmed, "unexpected signed scratch network binding")
    flags = {
        "frame_meta": words[129] == 1,
        "recovery": (words[131] == RECOVERY_ACCUMULATORS and words[133] == 1
                     and words[152] == SECONDARY_CPU_MASK.bit_count()),
        "metered": words[135] == 1,
        "net": words[138] == 1,
        "tcp_echo": words[139] == 1,
        "tls_echo": words[142] == 1,
        "media_staging_enabled": words[144] == 1,
        "staging_ok": staging,
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
        **net_reset_proofs(lines, boot_epoch=net_boot_epoch),
        **media_rows,
        "recovery_accumulators": words[131],
        "degraded_events": words[132],
        "recovery_required_publish_rejected": words[133],
        "recovery_writer_takeovers": words[152],
        "policy_lock_metered": True,
        "policy_lock_settled_in_budget": words[136],
        "policy_lock_overrun_or_unmeasured": words[137],
        "policy_lock_measured_overruns": words[154],
        "policy_lock_max_elapsed_ns": words[155],
        "real_net_device": True,
        "tcp_to_local_echo": True,
        "admission_leases": words[140],
        "echo_bytes_relayed": words[141],
        "tls_echo_turn_verified": False,
        "media_staging_enabled": staging,
        "staging_confirmed_epoch": words[148] if staging else None,
        "staging_previous_epoch": words[163] if staging else None,
        "staging_reopened": modes.media_reopen,
        "native_tls_confirmed_boot_epoch": confirmed[0][0] if confirmed else None,
        "w11_completion_marker": expected,
    }


def supervisor_copy_windows(elf, qmp, output, lines, *, snapshot_lists=None, file_copy=False,
                            audit_copy=False):
    window = symbol(elf, "__copy_window_l3")
    require = verify_smp.require
    counts = {}
    if snapshot_lists is not None:
        witnessed = w11_rows(lines, "V020_SEC_M_COPY_WINDOW")
        require(len(witnessed) == 1, "missing one Supervisor snapshot copy-window witness")
        reads, writes, closed = witnessed[0]
        require(snapshot_lists > 0 and writes == 2 * snapshot_lists and reads >= writes and closed == 1,
                "cross-page snapshot copy-window close counts differ")
        counts["snapshot_copy_window"] = (reads, writes)
    if file_copy:
        witnessed = w11_rows(lines, "V020_SEC_M_FILE_COPY_WINDOW")
        require(len(witnessed) == 1, "missing one Supervisor file copy-window witness")
        reads, writes, closed = witnessed[0]
        require(reads > 0 and writes > 0 and closed == 1, "invalid file copy-window close counts")
        counts["file_copy_window"] = (reads, writes)
    if audit_copy:
        witnessed = w11_rows(lines, "V020_SEC_S_AUDIT_COPY_WINDOW")
        require(len(witnessed) == 1, "missing one Supervisor audit copy-window witness")
        reads, writes, closed = witnessed[0]
        require(reads >= writes > 0 and closed == 1, "invalid audit copy-window close counts")
        counts["audit_copy_window"] = (reads, writes)
    page = 4096
    root_index = 258

    def read_table(label, address):
        require(address % page == 0, "unaligned copy table")
        path = output / ("copy-" + label + ".bin")
        qmp.execute("pmemsave", {"val": address, "size": page, "filename": str(path)})
        raw = path.read_bytes()
        require(len(raw) == page, "incomplete copy table readback")
        return struct.unpack("<512Q", raw)

    cpu0 = symbol(elf, "high_l1")["pa"]
    secondary = symbol(elf, "__copy_secondary_l1")["pa"]
    mid = symbol(elf, "__copy_window_l2")["pa"]
    leaf = window["pa"]
    require(len({cpu0, secondary, mid, leaf}) == 4, "copy table pages alias")
    primary = read_table("primary-l1", cpu0)
    common = read_table("secondary-l1", secondary)
    require(primary[root_index] == (mid | 3) and common[root_index] == 0,
            "copy L2 is not exclusive to the CPU0 root")
    require(primary[:root_index] == common[:root_index]
            and primary[root_index + 1:] == common[root_index + 1:],
            "secondary root differs outside the copy slot")
    branch = read_table("l2", mid)
    require(branch[0] == (leaf | 3) and not any(branch[1:]), "copy window has multiple branches")
    require(not any(read_table("l3", leaf)), "temporary copy translation remained valid")
    readback = {
        "cpu0_root_pa": hex(cpu0), "secondary_root_pa": hex(secondary),
        "copy_l2_pa": hex(mid), "copy_l3_pa": hex(leaf),
        "copy_leaf_invalid": True, "secondary_copy_branch_absent": True,
    }
    return {
        scope: dict(readback, read_only_fragments_closed=reads, writable_fragments_closed=writes)
        for scope, (reads, writes) in counts.items()
    }


def signer_retirement(elf, qmp, output, image_pages, retired_pages):
    """Independently verify that the stopped Signer's root and writable pages are zero."""
    require = verify_smp.require
    page = 4096
    frames, leaves, tables, shared, stack = 64, 9, 2, 4, 16
    space = symbol(elf, "V020_SEC_N_SIGNER_SPACE_PAGES")
    base = space["pa"]
    require(base % page == 0 and space["size"] == (frames + leaves + tables + shared + stack) * page,
            "unexpected private Signer address space geometry")
    root = base + (frames + leaves + 1) * page
    bss = retired_pages - shared - stack
    require(0 <= bss < image_pages <= frames, "invalid retired Signer data range")

    def erased(name, address, pages):
        if pages:
            path = output / f"signer-{name}.bin"
            qmp.execute("pmemsave", {"val": address, "size": pages * page, "filename": str(path)})
            require(path.read_bytes() == bytes(pages * page), f"Signer {name} was not erased")

    erased("root-and-mailbox-stack", root, 1 + shared + stack)
    erased("bss", base + (image_pages - bss) * page, bss)
    return {"root_pa": hex(root), "root_invalid": True, "writable_pages_scrubbed": retired_pages}


def ingress_mappings(elf, qmp, output, image_pages):
    """Read the stopped parser's actual tree and every resulting leaf."""
    require = verify_smp.require
    page = 4096
    image_slots, mid_first, mid_count, shared_slots, stack_pages = 16, 8, 9, 4, 4
    space = symbol(elf, "V020_SEC_N_INGRESS_SPACE")
    base = space["pa"]
    require(base % page == 0 and space["size"] ==
            (image_slots + mid_count + 2 + shared_slots + stack_pages) * page,
            "unexpected private parser address space geometry")
    leaves = base + image_slots * page
    mid = leaves + mid_count * page
    root = mid + page
    mailbox = root + page
    stack = mailbox + shared_slots * page

    def read(name, address):
        path = output / f"ingress-{name}.bin"
        qmp.execute("pmemsave", {"val": address, "size": page, "filename": str(path)})
        data = path.read_bytes()
        require(len(data) == page, "incomplete parser page readback")
        return data

    def table(name, address):
        return struct.unpack("<512Q", read(name, address))

    root_entries = table("root", root)
    require(root_entries[0] == mid | 3 and not any(root_entries[1:]),
            "unexpected parser root branch")
    mid_entries = table("mid", mid)
    expected_mid = {
        mid_first + index: (leaves + index * page) | 3 for index in range(mid_count)
    }
    require(all(entry == expected_mid.get(index, 0)
                for index, entry in enumerate(mid_entries)), "unexpected parser mid branch")

    xn = 1 << 54
    readonly = 1 << 7
    user_base = (1 << 53) | 0xf43
    valid_va = {0x01000000 + index * page: base + index * page for index in range(image_pages)}
    mailbox_va = 0x02000000
    stack_va = 0x01f00000
    extra = {mailbox_va: mailbox | user_base | xn | readonly}
    extra.update({stack_va + index * page: (stack + index * page) | user_base | xn
                  for index in range(stack_pages)})
    for index in range(mid_count):
        leaf = table(f"leaf-{index}", leaves + index * page)
        for slot, entry in enumerate(leaf):
            va = ((mid_first + index) << 21) | (slot << 12)
            pa = valid_va.get(va)
            if pa is None:
                require(entry == extra.get(va, 0), "parser mapped a foreign or unneeded page")
            else:
                require(entry in (pa | user_base | readonly, pa | user_base | readonly | xn),
                        "parser image moved or mapped writable")
    require(read("mailbox", mailbox) == bytes(page), "stopped parser mailbox retained bytes")
    return {"root_pa": hex(root), "mailbox_pa": hex(mailbox), "mailbox_read_only": True,
            "mailbox_scrubbed": True, "stack_pages": stack_pages, "private_leaves_verified": True}


def dense_frame_meta(qmp, output, lines, permanent_observed):
    require = verify_smp.require

    def observed(name):
        records = w11_rows(lines, "V020_SEC_M_DENSE_FRAME_" + name)
        require(len(records) == 1, "missing one dense FrameMeta " + name + " witness")
        return records[0]

    page = 4096
    ram_base, arena_end, ram_end = 0x40000000, 0x44000000, 0x80000000
    table, count, table_bytes = observed("TABLE")
    control, progress, pool_bytes = observed("POOLS")
    permanent, free, reserved = observed("ROWS")
    slot, actor, actor_generation = observed("OWNER")
    frame, previous_generation, generation = observed("REVOKE")
    row = struct.Struct("<IIQQIIII")
    require(count == (ram_end - ram_base) // page and table_bytes == count * row.size
            and pool_bytes == 8 * 1024 * 1024, "dense FrameMeta geometry differs")
    ranges = sorted((start, start + size) for start, size in (
        (table, table_bytes), (control, pool_bytes), (progress, pool_bytes), (frame, page),
    ))
    require(all(arena_end <= start < end <= ram_end and start % page == 0 for start, end in ranges)
            and all(before[1] <= after[0] for before, after in zip(ranges, ranges[1:])),
            "dense FrameMeta reservations or ordinary frame overlap")
    require(slot == len(PIE_ROLE_IDS) - 1 and actor == PIE_ROLE_IDS[slot]
            and any(record[:2] == (actor, actor_generation)
                    for record in w11_rows(lines, "V020_PROD_PIE_ROLE")),
            "dense FrameMeta allocation owner differs from the native Supervisor")
    require(previous_generation > 0 and generation == previous_generation + 1,
            "dense FrameMeta did not advance the reclaimed frame generation")

    path = output / "dense-frame-meta.bin"
    qmp.execute("pmemsave", {"val": table, "size": table_bytes, "filename": str(path)})
    raw = path.read_bytes()
    require(len(raw) == table_bytes, "incomplete dense FrameMeta readback")
    permanent_rows = 0
    for owner, flags, owner_generation, _, refs, pins, dma, shares in row.iter_unpack(raw):
        require(owner == 0xFFFFFFFF and not any((owner_generation, refs, pins, dma, shares))
                and flags in (0, 4, 8), "dense FrameMeta leaked a frame or reference")
        permanent_rows += flags == 4
    require((permanent, free, reserved) == (permanent_rows, count - permanent_rows, 0)
            and permanent == permanent_observed, "dense FrameMeta inventory differs from the table")
    for start, end in [(ram_base, arena_end), (table, table + table_bytes),
                       (control, control + pool_bytes), (progress, progress + pool_bytes)]:
        begin, finish = ((pa - ram_base) // page * row.size for pa in (start, end))
        require(all(record == (0xFFFFFFFF, 4, 0, 0, 0, 0, 0, 0)
                    for record in row.iter_unpack(raw[begin:finish])),
                "a fixed dense FrameMeta reservation was not permanent")
    require(row.unpack_from(raw, (frame - ram_base) // page * row.size)
            == (0xFFFFFFFF, 0, 0, generation, 0, 0, 0, 0), "reclaimed frame row differs")
    sample = output / "dense-scrubbed-frame.bin"
    qmp.execute("pmemsave", {"val": frame, "size": page, "filename": str(sample)})
    require(sample.read_bytes() == bytes(page), "reclaimed frame was not scrubbed")
    return {"table_pa": hex(table), "row_count": count, "table_bytes": table_bytes,
            "control_pool_pa": hex(control), "progress_pool_pa": hex(progress),
            "permanent_rows": permanent, "free_rows": free, "probe_pa": hex(frame),
            "owner_slot": slot, "actor": actor, "actor_generation": actor_generation,
            "frame_generation": generation, "scrubbed": True}


def source_manifest() -> dict:
    names = {}
    for name in PRODUCTION_SOURCES:
        p = ROOT / name
        verify_smp.require(p.is_file() and not p.is_symlink(), "missing production source " + name)
        names[name] = sha(p)
    return names


def run(elf: Path, output: Path, timeout: float = 120, staging: bool = False,
        nic: bool = True, connect_peer: bool = True, *, modes: Modes = Modes(),
        rng_present: bool = True, boot_disk: Path | None = None,
        qmp_stdio: bool = False, expected_fsync_epoch: int | None = None) -> dict:
    require = verify_smp.require
    require(1 <= timeout <= 300, "invalid execution budget")
    require(not staging or (nic and connect_peer), "network negative controls are G-A only")
    require(staging or not modes.media_reopen, "media reopen requires the staging lane")
    require(staging or not modes.file_volatile_write, "file volatile write requires the staging lane")
    require(staging or not modes.signed_media, "signed media requires the staging lane")
    require(staging or not modes.snapshot_envelopes, "snapshot envelopes require the staging lane")
    require(not modes.fsync_scratch or not modes.snapshot_envelopes,
            "baseline FSYNC scratch requires an envelope-free volume")
    require(not modes.snapshot_read or (staging and modes.snapshot_catalog and modes.file_read),
            "snapshot read requires the staging lane, snapshot catalog and file read")
    require(not modes.file_sessions or (staging and modes.file_read),
            "file sessions require the staging lane and file read")
    require(not modes.snapshot_catalog or (staging and modes.signed_media
                                            and modes.media_unified and modes.live_control),
            "snapshot catalog requires signed unified media and the live Supervisor role")
    require(not modes.file_read or (staging and modes.signed_media
                                    and modes.media_unified and modes.live_control),
            "file read requires signed unified media and the live Supervisor role")
    require(rng_present or modes.authenticated_net, "missing RNG control requires authenticated mode")
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), "refuse to reuse evidence output")
    output.mkdir(parents=True)
    before = source_manifest()
    (output / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    acceptance = Production(staging=staging, modes=modes)
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
    elif not connect_peer:
        report["negative_control"] = "no-peer: bounded accept with the NIC present"
    elif not rng_present:
        report["negative_control"] = "no-rng: authenticated relay must refuse to listen"
    elif modes.authenticated_net and not modes.orderly_close:
        report["negative_control"] = "abrupt-peer: authenticated Echo with no normal credit retirement"
    decoder = FrameDecoder(); raw = bytearray(); decoded = bytearray()
    proc = None; sock = None; qmp = None; peer = None
    host_samples = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cyx-prod-") as td, (output / "qemu-stderr.log").open("wb") as err:
        scratch = (boot_disk or Path(td) / "scratch.raw") if staging else None
        pending_fsync_blocks = None
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
                if boot_disk is None:
                    create_scratch(scratch)
                require(scratch.is_file() and not scratch.is_symlink()
                        and scratch.stat().st_size == SCRATCH_BYTES, "invalid staging scratch disk")
                report["scratch_before_sha256"] = sha(scratch)
                if modes.media_reopen and modes.fsync_scratch:
                    pending_fsync_blocks = count_fsync_retirement_blocks(scratch)
            port = free_port()
            path = str(Path(td) / "q.sock")
            args = qemu_args(binary, path, elf, port, scratch=scratch, nic=nic,
                            rng=modes.authenticated_net and rng_present, qmp_stdio=qmp_stdio)
            report["argv"] = args
            report["qmp_transport"] = "stdio" if qmp_stdio else "unix"
            proc = subprocess.Popen(args, stdin=subprocess.PIPE if qmp_stdio else None,
                                    stdout=subprocess.PIPE if qmp_stdio else subprocess.DEVNULL,
                                    stderr=err, bufsize=0)
            if nic and connect_peer:
                peer = HostPeer(port, modes.authenticated_net, modes.orderly_close)
                peer.start()
            end = started + timeout
            sock = PipeTransport(proc) if qmp_stdio else connect_qmp(proc, path, end)
            qmp = Qmp(sock)
            require("QMP" in qmp.receive(end), "invalid QMP greeting")
            qmp.execute("qmp_capabilities")
            actual_cpus = qmp.execute("query-cpus-fast")
            report["qmp_cpus"] = actual_cpus
            if scratch is not None:
                host_samples = HostMediaSamples(proc.pid, actual_cpus)
                host_samples.observe(len(decoded), phase="start")
            while time.monotonic() < end:
                require(proc.poll() is None, "QEMU exited before acceptance")
                poll_started = time.monotonic_ns() if host_samples is not None else None
                value = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 1048576, "format": "base64"})
                poll_elapsed = time.monotonic_ns() - poll_started if poll_started is not None else None
                data = base64.b64decode(value, validate=True)
                raw.extend(data)
                require(len(raw) <= 2 * 1024 * 1024, "serial budget exceeded")
                for frame in decoder.feed(data):
                    decoded.extend(frame)
                if host_samples is not None:
                    host_samples.observe(len(decoded), poll_elapsed)
                if peer is not None and b"V020_W11_NET_LISTEN" in decoded:
                    peer.listening.set()
                if b"FAIL" in decoded or b"SMP_ERROR" in decoded:
                    raise ValueError("guest failure")
                if acceptance.completion in decoded:
                    if host_samples is not None:
                        host_samples.observe(len(decoded), phase="completion")
                    qmp.execute("stop")
                    qmp.execute("pmemsave", {"val": location["pa"], "size": 4096,
                                            "filename": str(output / "native-page.bin")})
                    require(decoder.loss == 0 and decoder.corrupt == 0 and not decoder.buffer,
                            "incomplete/corrupt framed UART transport")
                    page = (output / "native-page.bin").read_bytes()
                    report["observations"] = acceptance.validate(
                        bytes(decoded), page, len(actual_cpus), pending_fsync_blocks=pending_fsync_blocks,
                        expected_fsync_epoch=expected_fsync_epoch)
                    lines = decoded.decode("ascii").splitlines()
                    if modes.frame_pool and staging:
                        report["dense_frame_meta"] = dense_frame_meta(
                            qmp, output, lines, report["observations"]["frame_meta_permanent_rows"],
                        )
                    if modes.live_control or modes.snapshot_catalog or modes.file_read or modes.fsync_scratch:
                        report.update(supervisor_copy_windows(
                            elf.read_bytes(), qmp, output, lines,
                            snapshot_lists=(report["observations"]["snapshot_catalog_lists"]
                                            if modes.snapshot_catalog else None),
                            file_copy=modes.file_read or modes.fsync_scratch,
                            audit_copy=modes.live_control,
                        ))
                    relay_bytes = report["observations"]["echo_bytes_relayed"]
                    if modes.authenticated_net:
                        report["ingress_mappings"] = ingress_mappings(
                            elf.read_bytes(), qmp, output,
                            report["observations"]["native_parser_image_pages"],
                        )
                        report["signer_retirement"] = signer_retirement(
                            elf.read_bytes(), qmp, output,
                            report["observations"]["native_signer_image_pages"],
                            report["observations"]["native_signer_discarded_pages"],
                        )
                        require(peer is not None, "missing authenticated host peer")
                        peer.join(timeout=min(max(end - time.monotonic(), 0), PEER_WAIT_SECONDS))
                        authenticated_echo(peer.result, relay_bytes, modes.orderly_close)
                    else:
                        require(peer is None or relay_bytes == peer.result["sent"],
                                "relayed bytes (word 141) differ from the bytes the host peer sent")
                    require(sha(elf) == report["elf_sha256"], "ELF changed during guest run")
                    require(before == source_manifest(), "production source changed during guest run")
                    if modes.signed_media:
                        epoch = report["observations"]["signed_config_bound_boot_epoch"]
                        report["signed_scratch_policy_sha256"] = verify_signed_disk(
                            scratch, epoch, fsync_scratch=modes.fsync_scratch)
                        report["signed_receipt_view_disk_sha256"] = verify_signed_receipt_view(
                            scratch, report["observations"]["signed_receipt_view_sha256"])
                        report["signed_config"] = True
                    if modes.snapshot_envelopes:
                        disk_evidence = verify_envelopes(
                            scratch, unified=modes.media_unified, file_read=modes.file_read,
                            snapshot_read=modes.snapshot_read, file_volatile_write=modes.file_volatile_write,
                        )
                        require(disk_evidence["superblock_generation"] ==
                                report["observations"]["staging_confirmed_epoch"],
                                "scratch checkpoint generation disagrees with the confirmed BootEpoch")
                        if modes.media_unified:
                            require(all(disk_evidence[key] == report["observations"]["unified_mount_" + key]
                                        for key in ("system_inodes", "system_blocks", "data_blocks")),
                                    "host and guest unified mount evidence disagree")
                        if modes.snapshot_catalog:
                            require(disk_evidence["objects"]["catalog"]["envelope_sha256"] ==
                                    report["observations"]["snapshot_catalog_sha256"],
                                    "Supervisor catalog witness differs from the scratch disk bytes")
                        if modes.file_read:
                            require(disk_evidence["file_read_sha256"] == report["observations"]["file_read_sha256"],
                                    "Supervisor staged file witness differs from the scratch disk bytes")
                        if modes.file_volatile_write:
                            require(disk_evidence["file_owner_rights"] ==
                                    report["observations"]["file_volatile_write_owner_rights"],
                                    "Supervisor volatile write owner rights differ from the scratch disk ACL")
                        if modes.snapshot_read:
                            require(disk_evidence["objects"]["slot"]["extent_sha256"] ==
                                    report["observations"]["snapshot_read_slot_sha256"],
                                    "Supervisor SlotStore witness differs from the scratch disk bytes")
                        report["snapshot_envelope_disk"] = disk_evidence
                    if modes.authenticated_net:
                        report["tls_echo_turn_verified"] = True
                        report["observations"]["tls_echo_turn_verified"] = True
                        report["tls_credit_retirement_verified"] = modes.orderly_close
                    report["status"] = "PASS"
                    report.update(acceptance.success())
                    break
                time.sleep(0.01)
            else:
                raise TimeoutError("native execution deadline")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if host_samples is not None:
                host_samples.observe(len(decoded), phase="shutdown")
            if proc is not None:
                shutdown(proc, qmp)
                report["qemu_exit"] = proc.returncode
            if host_samples is not None:
                try:
                    (output / "host-media-samples.json").write_text(
                        json.dumps(host_samples.evidence(), indent=2) + "\n")
                    report["host_media_samples"] = {
                        "file": "host-media-samples.json", "count": len(host_samples.samples),
                        "limit_reached": host_samples.limit_reached,
                    }
                except OSError as error:
                    report["host_media_samples"] = {"unavailable": type(error).__name__}
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


def build(staging: bool, modes: Modes = Modes()) -> Path:
    """Build the fixture-identity local-echo guest first (the kernel embeds it),
    then the production kernel feature, exactly as verify_v0199_sec_n.build()."""
    import os
    import verify_v0199_sec_n
    verify_v0199_sec_n.build_guest(isolated_signer=modes.authenticated_net)
    verify_smp.require((ROOT / GUEST_ELF).is_file(), "local-echo guest ELF missing after build")
    feature = modes.features(staging)
    kernel_env = dict(os.environ)
    kernel_env.pop("RUSTFLAGS", None)
    if modes.fsync_bound and not modes.media_reopen:
        kernel_env["CYXIA_FSYNC_TEST_BOUND"] = "1"
    else:
        kernel_env.pop("CYXIA_FSYNC_TEST_BOUND", None)
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
    parser.add_argument("--qmp-stdio", action="store_true", help="use owned pipes instead of a Unix socket")
    media = parser.add_mutually_exclusive_group()
    media.add_argument("--media-staging", action="store_true",
                       help="staging boot with an all-zero scratch disk")
    media.add_argument("--media-reopen", action="store_true",
                       help="format and reopen the same temporary staging disk across QEMU boots")
    parser.add_argument("--fresh-elf", type=Path, help="first boot ELF for --media-reopen")
    parser.add_argument("--unsigned-fresh-elf", type=Path,
                        help="prebuilt unsigned comparison ELF for signed reopen")
    parser.add_argument("--signed-media", action="store_true",
                        help="authenticate the temporary disk with the pinned test policy")
    parser.add_argument("--media-envelopes", action="store_true",
                        help="verify empty D1.5 snapshot envelopes on the temporary disk")
    parser.add_argument("--media-unified", action="store_true",
                        help="format or reopen the allocated eight-object scratch layout")
    parser.add_argument("--snapshot-catalog", action="store_true",
                        help="verify the empty LIST endpoint with signed unified media and the Supervisor")
    parser.add_argument("--file-read", action="store_true",
                        help="verify the Supervisor's read-only file service on signed unified media")
    parser.add_argument("--snapshot-read", action="store_true",
                        help="verify Supervisor QUERY and HISTORY_OPEN refusals and the SlotStore digest")
    parser.add_argument("--file-sessions", action="store_true",
                        help="verify bounded Supervisor file handles, replay and revocation on signed media")
    parser.add_argument("--file-volatile-write", action="store_true",
                        help="verify bounded Supervisor RAM writes, replay and disk readback on signed media")
    parser.add_argument("--frame-pool", action="store_true",
                        help="verify the bounded native allocator and FrameMeta lifecycle")
    parser.add_argument("--authenticated-net", action="store_true", help="pinned fixture TLS and VirtIO RNG")
    parser.add_argument("--live-control", action="store_true", help="live D01 and volatile audit readbacks")
    network = parser.add_mutually_exclusive_group()
    network.add_argument("--no-nic", action="store_true",
                         help="negative control: boot with -nic none")
    network.add_argument("--no-peer", action="store_true",
                         help="negative control: attach VirtIO-net and omit the TCP peer")
    network.add_argument("--no-rng", action="store_true",
                         help="negative control: authenticated boot without VirtIO RNG")
    network.add_argument("--abrupt-peer", action="store_true",
                         help="authenticated Echo with abrupt EOF and retained credit")
    args = parser.parse_args()
    snapshot_catalog = args.snapshot_catalog or args.snapshot_read
    file_read = args.file_read or args.snapshot_read or args.file_sessions
    modes = Modes(authenticated_net=args.authenticated_net,
                  live_control=args.live_control or snapshot_catalog or file_read,
                  media_reopen=args.media_reopen, signed_media=args.signed_media or snapshot_catalog or file_read,
                  orderly_close=not args.abrupt_peer, frame_pool=args.frame_pool,
                  media_envelopes=args.media_envelopes, media_unified=args.media_unified or snapshot_catalog or file_read,
                  snapshot_catalog=snapshot_catalog, file_read=file_read, snapshot_read=args.snapshot_read,
                  file_sessions=args.file_sessions, file_volatile_write=args.file_volatile_write)
    if args.fresh_elf is not None and not args.media_reopen:
        parser.error("--fresh-elf requires --media-reopen")
    if args.media_reopen and ((args.elf is None) != (args.fresh_elf is None)):
        parser.error("--media-reopen requires both ELFs or neither")
    if args.media_reopen and (args.no_nic or args.no_peer or args.no_rng):
        parser.error("--media-reopen uses an independent blank disk negative control")
    if args.snapshot_read and not (args.media_staging or args.media_reopen):
        parser.error("--snapshot-read requires a staging or reopen run")
    if args.file_sessions and not (args.media_staging or args.media_reopen):
        parser.error("--file-sessions requires a staging or reopen run")
    if args.file_volatile_write and not (args.media_staging or args.media_reopen):
        parser.error("--file-volatile-write requires a staging or reopen run")
    if args.snapshot_catalog and not (args.media_staging or args.media_reopen):
        parser.error("--snapshot-catalog requires a staging or reopen run")
    if modes.signed_media and not (args.media_staging or args.media_reopen):
        parser.error("--signed-media requires a staging or reopen run")
    if modes.snapshot_envelopes and not (args.media_staging or args.media_reopen):
        parser.error("--media-envelopes and --media-unified require a staging or reopen run")
    if args.unsigned_fresh_elf and not (modes.signed_media and args.media_reopen and args.elf):
        parser.error("--unsigned-fresh-elf requires a prebuilt signed reopen run")
    if modes.signed_media and args.media_reopen and args.elf and args.unsigned_fresh_elf is None:
        parser.error("prebuilt signed reopen also requires --unsigned-fresh-elf")
    if (args.abrupt_peer or args.no_rng) and not args.authenticated_net:
        parser.error("--abrupt-peer and --no-rng require --authenticated-net")
    runner = partial(run, qmp_stdio=True) if args.qmp_stdio else run
    try:
        if args.media_reopen:
            with tempfile.TemporaryDirectory(prefix="cyx-v020-images-") as temp:
                fresh = args.fresh_elf
                unsigned = args.unsigned_fresh_elf
                if fresh is None:
                    fresh = Path(temp) / "fresh.elf"
                    shutil.copyfile(build(True, replace(modes, media_reopen=False)), fresh)
                    if modes.signed_media:
                        unsigned = Path(temp) / "unsigned.elf"
                        shutil.copyfile(build(True, modes.unsigned_fixture()), unsigned)
                elf = args.elf if args.elf is not None else build(True, modes)
                result = run_media_reopen(runner, fresh, elf, args.output, args.timeout, modes, unsigned)
        else:
            elf = args.elf if args.elf is not None else build(args.media_staging, modes)
            result = runner(elf, args.output, args.timeout, staging=args.media_staging,
                         nic=not args.no_nic, connect_peer=not args.no_peer, modes=modes,
                         rng_present=not args.no_rng)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=__import__("sys").stderr)
        return 1
    print(json.dumps(result, indent=2))
    if result["status"] != "PASS":
        print("FAIL: " + result.get("error", "unknown"), file=__import__("sys").stderr)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
