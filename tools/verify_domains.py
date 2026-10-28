#!/usr/bin/env python3
"""Native domain functional probe and exact host replay of captured EL0 inputs.

This runner does not replace verify_unified.py or certify physical real-time
deadlines, a trained model, or two effective policies for all eighteen families.
Every PASS requires the real EL0 file probe and a captured publication whose
executor later reported APPLIED; the host verifier checks the original input,
hashes, candidate set, model evaluation and Plan reply.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import time

try:
    from .build_unified import code_source_map
    from .check_elf import boot_profile, inspect_elf, symbol
    from .doctor import ROOT
    from .run_qemu import Qmp
    from .transport import FrameDecoder
except ImportError:
    from build_unified import code_source_map
    from check_elf import boot_profile, inspect_elf, symbol
    from doctor import ROOT
    from run_qemu import Qmp
    from transport import FrameDecoder

CONTROL_MAGIC = 0x435958444F4D3031
UNIFIED_MAGIC = 0x435958554E493031
IPI_MAGIC = 0x4359495049000001
CONTROL_CREDIT_MAGIC = 0x4359434352454401
CONTROL_POOL_MAGIC = 0x435943504F4F4C01
LEARNING_MAGIC = 0x43594C4541524E01
GOVERNANCE_MAGIC = 0x4359474F56455201
GOVERNANCE_RUNTIME_MAGIC = 0x43594752554E0001
REPLAY_MAGIC = 0x435952504C593133
RUNTIME_MAGIC = 0x43595852554E3133
# The actual cluster Driver closes after 1.5 guest seconds without an RPC.
# Keep the NIC down for at least two guest seconds AND observe that close;
# elapsed host time alone cannot satisfy either condition under icount.
RECONNECT_OUTAGE_NS = 2_000_000_000
CONTROL_WORDS = 512 + 64 * 640
ALL_FAMILIES = (1 << 18) - 1
# Older service images reported these startup errors through OP_TRACE and then
# yielded forever. Never accept that as a healthy service just because another
# domain's ordinary probe and control loop made progress.
LEGACY_FATAL_EVENTS = {0xFE, 0xFF, 0x101, 0x102, 0x104, 0x105, 0x106,
                       0x107, 0x108, 0x109, 0x110, 0x111}
REQUIRED = {
    "UNIFIED_EVIDENCE": 4096,
    "DOMAIN_CONTROL_EVIDENCE": CONTROL_WORDS * 8,
    "RUNTIME_V13_EVIDENCE": 8192,
    "STORAGE_V13_EVIDENCE": 4096,
    "DOMAIN_TASK_EVIDENCE": 256,
    "TASK_OVERRUN_EVIDENCE": 256,
    "CONTROL_CREDIT_EVIDENCE": 512,
    "IPI_EVIDENCE": 4096,
}
OPTIONAL = {"DYNAMIC_V13_EVIDENCE": 4096, "PANIC_EVIDENCE": 64, "SMP_FAULT_EVIDENCE": 576,
            "FILE_SERVICE_EVIDENCE": 512,
            "TASK_VECTOR_EVIDENCE": 512,
            "TASK_SPAWN_EVIDENCE": 256,
            "TASK_SLICE_EVIDENCE": 1024, "CONTROL_POOL_EVIDENCE": 128,
            "LEARNING_V13_EVIDENCE": 1024, "GOVERNANCE_V13_EVIDENCE": 128,
            "GOVERNANCE_RUNTIME_V13_EVIDENCE": 512,
            "REPLAY_V13_EVIDENCE": 512,
            "REPLAY_ROOT_EVIDENCE": 256, "REPLAY_OWNER_EVIDENCE": 256,
            "REPLAY_CONFIG_EVIDENCE": 256, "REPLAY_CAPTURE_EVIDENCE": 256,
            "LOCAL_PLACEMENT_EVIDENCE": 256, "DOMAIN_PREPARATION_EVIDENCE": 128,
            "DOMAIN_PREPARATION_DETAIL": 256, "DOMAIN_PREPARATION_CONTEXT": 128,
            "DOMAIN_PREPARATION_REJECTIONS": 5184, "UNIFIED_SERVICE_STAGE": 8,
            "DOMAIN_SERVICE_DETAIL": 128, "BUILTIN_TASK_DETAIL": 256,
            "DOMAIN_PREPARATION_PREFIX_DETAIL": 128,
            "DOMAIN_PREPARATION_ENTRY_DETAIL": 128}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def words(data, count):
    require(len(data) == count * 8, "incorrect evidence size")
    return struct.unpack(f"<{count}Q", data)


def parse_unified(data):
    u = words(data, 512)
    require(u[15] == 0, f"native fatal code {u[15]}")
    if u[0] == 0:
        return None
    require(u[0] == UNIFIED_MAGIC and u[1] > 0, "invalid unified header")
    require(u[6] <= 200, "unified event trace overflow")
    events = list(u[32:32 + 2 * u[6]:2])
    require(not any(event in LEGACY_FATAL_EVENTS or event & (1 << 63) for event in events),
            "EL0 service reported a fatal event")
    require(u[16] == 1 and u[17] > 0 and u[18] > 0,
            "image does not contain an enabled ordinary EL0 file probe")
    require(u[19] in (0, 1), "invalid probe completion flag")
    if u[19]:
        require(u[20] == 0, f"ordinary EL0 file probe exit code {u[20]}")
    return {
        "boot_epoch": u[1], "el0_returns": u[2],
        "sent_bytes": u[4], "received_bytes": u[5],
        "events": events,
        "probe_object": [u[17], u[18]], "probe_completed": bool(u[19]),
        "probe_exit_code": u[20],
    }


def parse_control(data, boot_epoch=None):
    w = words(data, CONTROL_WORDS)
    if w[0] == 0:
        return None
    require(w[0] == CONTROL_MAGIC and w[1] == 1 and w[2] > 0,
            "invalid domain control header")
    require(w[12:14] == (64, 640), "unsupported domain evidence layout")
    require(w[25] == 0, f"native resource confirmation error {w[25]} in domain {w[26]}")
    require(w[28] == 0, f"native stability receipt error {w[28]} in domain {w[29]}")
    if boot_epoch is not None:
        require(w[2] == boot_epoch, "domain/unified BootEpoch mismatch")
    require(w[3] & ~ALL_FAMILIES == 0, "unknown registered family")
    complete = []
    for slot in range(64):
        r = w[512 + slot * 640:512 + (slot + 1) * 640]
        # A stopped vCPU may be inside a record update. Such a record is never
        # evidence of completion; the host verifier also skips odd seqlocks.
        if r[639] & 1 or r[0] == 0 or r[30] == 0:
            continue
        require(r[0] == r[1] and r[7] == w[2], "record identity mismatch")
        require(1 <= r[14] <= 4, "invalid executor state")
        if r[13] > 0:
            require(r[9] >= r[8] and r[9] - r[8] <= 50_000_000,
                    "published control job exceeded 50 ms wall deadline")
            require(r[12] <= 500_000 and r[18] == 0,
                    "published policy exceeded 0.5 ms publication budget")
            require(r[10] + r[11] + r[29] <= 2_000_000,
                    "published inference exceeded encoding/inference/decoding budget")
        if r[14] == 2:
            require(r[13] > 0 and r[19] == 1 and r[15] == 0,
                    "APPLIED without a published EL0 reply")
            require(r[28] >= r[9] >= r[8], "executor completion time ordering")
            complete.append((r[2], r[3], r[4], r[5]))
    return {
        "boot_epoch": w[2], "registered_families": w[3],
        "jobs": w[4], "published": w[5], "rejected": w[6],
        "applied": w[7], "failed": w[8], "unknown": w[9],
        "aborted": w[10], "applied_objects": complete,
        "family_jobs": list(w[32:50]), "family_applied": list(w[64:82]),
    }


def active_control_records(data):
    if len(data) != CONTROL_WORDS * 8:
        return []
    w = words(data, CONTROL_WORDS)
    if w[0] != CONTROL_MAGIC or w[1] != 1:
        return []
    active = []
    for slot in range(64):
        r = w[512 + slot * 640:512 + (slot + 1) * 640]
        if r[639] & 1 or r[0] == 0:
            continue
        active.append({
            "slot": slot, "sequence": r[0], "domain": r[2], "kind": r[3],
            "target_id": r[4], "target_generation": r[5],
            "candidate_count": r[16], "approved_version": r[13],
            "executor_state": r[14], "complete": bool(r[30]),
        })
    return active


def parse_tasks(data):
    w = words(data, 32)
    if w[0] == 0:
        return None
    require(w[0] == 0x43595441534B0001, "invalid task evidence header")
    require(w[2] == 0 and w[3] == 0,
            f"native task credit overrun/quarantine: mask={w[2]} overruns={w[3]}")
    return {
        "now_ns": w[1], "quarantine_mask": w[2], "overruns": w[3],
        "cpu_spent_ns": [w[4], w[5], w[6]], "threads": w[7],
        "service_admitted": bool(w[8]), "probe_object": [w[9], w[10]],
        "probe_life": w[11], "probe_entered": bool(w[12]),
        "probe_exit_code": w[13], "probe_cpu_ns": w[14],
        "stopped_pc": w[15], "stopped_kind": w[16],
        "stopped_esr": w[17], "stopped_far": w[18],
        "file_pending": w[21], "file_busy": w[22], "file_done": w[23],
        "cpu3_active_task": w[26], "cpu3_reserved_ns": w[27],
        "stopped_x0": w[29], "stopped_x8": w[30], "runnable": w[31],
    }


def parse_ipi(data):
    w = words(data, 512)
    require(w[13] == 0, f"native IPI receipt error {w[13]}")
    if w[0] == 0:
        return None
    require(w[0] == IPI_MAGIC and w[1] == 1, "invalid IPI evidence header")
    require(w[9] + w[10] <= w[6] <= w[5] and w[9] + w[10] <= w[8],
            "IPI completion without a consumed real handler receipt")
    return {
        "registered_cpus": w[2], "core_generation": w[3],
        "hardware_notifications": w[4], "handler_entries": w[5],
        "consumed_receipts": w[6], "probe_requests": w[8],
        "observed_receipts": w[9], "stale_receipts": w[10],
        "wake_verified": bool(w[2] & (1 << 3) and w[4] > 0 and w[9] > 0),
    }


def parse_control_credit(data):
    w = words(data, 64)
    require(w[0] in (0, CONTROL_CREDIT_MAGIC), "invalid control credit evidence header")
    if w[0]:
        require(w[1] == 1, "unsupported control credit evidence version")
    failures = []
    names = ("cpu", "sequence", "core_generation", "window", "grant_start_ns",
             "body_start_ns", "finish_ns", "reserved_ns", "actual_ns",
             "control_prepaid_ns", "control_actual_ns", "physical_prepaid_ns",
             "physical_actual_ns", "last_phase", "phase_bits", "evaluation_cpu_ns",
             "job_start_ns", "request_state", "preemptions", "flags", "error")
    for cpu, offset in ((1, 2), (2, 24)):
        row = w[offset:offset + 22]
        require(row[0] in (0, 1, 2), "invalid control credit receipt state")
        if not row[0]:
            continue
        if row[0] == 1:
            failures.append({"cpu": cpu, "complete": False})
            continue
        require(row[1] == cpu and row[2] > 0 and row[8] > 0 and row[21] > 0,
                "invalid completed control credit receipt")
        failures.append(dict(zip(names, row[1:]), complete=True))
    return failures


def parse_runtime(data):
    w = words(data, 1024)
    # This counter is sticky even when the periodic record's seqlock is odd.
    require(w[38] == 0, f"native control worker fault count {w[38]}")
    if w[0] == 0 or w[2] & 1:
        return None
    require(w[0] == RUNTIME_MAGIC and w[1] == 3, "invalid native runtime header")
    return {"control_mask": w[6], "business_mask": w[7],
            "quarantined_mask": w[9], "core_generation": w[10],
            "control_max_debit": w[35], "control_ticks": w[36],
            "control_faults": w[38], "failed_cpus": w[56],
            "publication": w[2], "clock_ticks": w[3], "timer_frequency": w[4],
            "boot_epoch": w[32], "inferences": w[14], "business_cpu3": w[20]}


class ReconnectProbe:
    """A real link transition with independently observed guest progress.

    Every sample is parsed by the usual budget/fault gates before entering this
    state machine. The post-command baseline deliberately comes from the next
    capture, so pre-disconnection execution cannot count as outage progress.
    """
    def __init__(self):
        self.phase = "waiting"
        self.before_down = None
        self.during_down = None
        self.before_up = None
        self.after_up = None
        self.previous = None
        self.progress = []
        self.commands = []

    @staticmethod
    def snapshot(guest):
        unified, runtime = guest.get("unified"), guest.get("runtime")
        if unified is None or runtime is None:
            return None
        require(runtime["publication"] > 0 and runtime["timer_frequency"] > 0,
                "reconnect needs a published guest clock")
        require(runtime["boot_epoch"] == unified["boot_epoch"],
                "reconnect runtime/unified BootEpoch mismatch")
        return {"boot_epoch": unified["boot_epoch"],
                "ticks": runtime["clock_ticks"], "frequency": runtime["timer_frequency"],
                "inferences": runtime["inferences"], "business_cpu3": runtime["business_cpu3"],
                "sent_bytes": unified["sent_bytes"], "received_bytes": unified["received_bytes"],
                "events": list(unified["events"])}

    def set_links(self, guests, up):
        for node, guest in enumerate(guests, 1):
            guest["qmp"].execute("set_link", {"name": "eth0", "up": up})
            self.commands.append({"node": node, "up": up})

    def step(self, guests, functional_ready):
        require(len(guests) == 2, "reconnect requires two native guests")
        samples = [self.snapshot(guest) for guest in guests]
        if any(sample is None for sample in samples):
            return False
        if self.previous is not None:
            for old, new in zip(self.previous, samples):
                require((old["boot_epoch"], old["frequency"]) ==
                        (new["boot_epoch"], new["frequency"]),
                        "guest identity or timer changed during reconnect")
                require(all(new[key] >= old[key] for key in
                            ("ticks", "inferences", "business_cpu3", "sent_bytes", "received_bytes"))
                        and new["events"][:len(old["events"])] == old["events"],
                        "guest clock, progress or event history regressed during reconnect")
        self.previous = samples
        if self.phase == "waiting":
            if not functional_ready or not all(3 in s["events"] and 0x212 in s["events"]
                                               for s in samples):
                return False
            self.before_down = samples
            self.set_links(guests, False)
            self.phase = "isolating"
            return False
        if self.phase == "isolating":
            self.during_down = samples
            self.phase = "down"
            return False
        if self.phase == "down":
            elapsed = [(new["ticks"] - old["ticks"]) * 1_000_000_000 // old["frequency"]
                       for old, new in zip(self.during_down, samples)]
            if any(duration < RECONNECT_OUTAGE_NS for duration in elapsed):
                return False
            if not all(4 in new["events"][len(old["events"]):]
                       for old, new in zip(self.before_down, samples)):
                return False
            progress = []
            for old, new, duration in zip(self.during_down, samples, elapsed):
                inference = new["inferences"] - old["inferences"]
                business = new["business_cpu3"] - old["business_cpu3"]
                require(inference > 0 and business > 0,
                        "local AI/business stopped during confirmed link loss")
                progress.append({"guest_elapsed_ns": duration, "inferences": inference,
                                 "business_cpu3": business})
            self.progress = progress
            self.before_up = samples
            self.set_links(guests, True)
            self.phase = "up"
            return False
        if self.phase == "up":
            for old, new in zip(self.before_up, samples):
                events = new["events"][len(old["events"]):]
                # READY must follow a newly authenticated session after link
                # restoration; previous or one-sided success cannot pass.
                if 3 not in events or 0x212 not in events[events.index(3) + 1:]:
                    return False
                if (new["sent_bytes"] <= old["sent_bytes"]
                        or new["received_bytes"] <= old["received_bytes"]):
                    return False
            self.after_up = samples
            self.phase = "complete"
        return self.phase == "complete"

    def evidence(self):
        return {"phase": self.phase, "verified": self.phase == "complete",
                "minimum_outage_guest_ns": RECONNECT_OUTAGE_NS,
                "commands": self.commands, "before_link_down": self.before_down,
                "link_down_baseline": self.during_down, "before_link_up": self.before_up,
                "after_reauthentication": self.after_up, "link_loss_progress": self.progress}


def parse_control_pool(data):
    w = words(data, 16)
    if w[0] == 0:
        return None
    require(w[0] == CONTROL_POOL_MAGIC and w[1] == 8 * 1024 * 1024,
            "invalid actual control pool backing")
    require(w[2] > 0 and w[2] % 4096 == 0 and 0 < w[4] <= 64
            and w[4] <= w[3] <= 2048 and w[5] <= 128,
            "control pool allocation/pin bounds")
    return {"bytes": w[1], "physical_address": w[2], "allocated_pages": w[3],
            "allocations": w[4], "live_pins": w[5]}


def parse_governance(data):
    w = words(data, 16)
    if w[0] == 0 or w[15] == 0:
        return None
    require(w[0] == GOVERNANCE_MAGIC and w[1] == 1,
            "invalid governance image identity header")
    require(0x80000 <= w[2] < 0x100000 and w[2] % 4 == 0,
            "invalid governance entry point")
    require(w[3] > 0 and w[3] % 4096 == 0 and 0 < w[4] <= 128,
            "invalid governance mapping root or code pages")
    require(w[5:9] == (1, 1, 4, 3),
            "invalid governance private mapping bounds")
    require(w[9] != 0 and w[10] != 0 and any(w[11:15]),
            "invalid governance role or image hash")
    return {"entry": w[2], "root": w[3], "code_pages": w[4],
            "input_pages": w[5], "output_pages": w[6],
            "stack_pages": w[7], "table_pages": w[8],
            "role_context": [w[9], w[10]],
            "image_hash": b"".join(value.to_bytes(8, "little")
                                   for value in w[11:15]).hex(),
            "mapping_installed": True}


def parse_governance_runtime(data):
    w = words(data, 64)
    require(w[48] == 0, f"native governance runtime fault {w[48]}")
    if w[0] == 0 or w[63] & 1 or w[27] == 0:
        return None
    require(w[0] == GOVERNANCE_RUNTIME_MAGIC and w[1] == 1 and w[2] == 8,
            "invalid governance runtime completion header")
    require(w[6] == 1 and w[7] >= 6 and w[60] >= 4 and w[61] >= 1,
            "governance role did not execute on the registered C owner")
    require(w[3] > 0 and w[4] > 0 and w[5] > 0
            and w[56:59] == (w[3], w[4], w[3]),
            "governance owner/credit generations were not independently revalidated")
    require(w[9] <= 2_500_000 and w[42] == 2_500_000
            and 0 < w[43] <= w[42] and w[47] == 1,
            "governance turn exceeded or failed to settle its physical credit")
    require(w[41] >= w[40] and w[44] >= w[42] and w[45] >= w[42],
            "invalid governance credit accounting evidence")
    probes = ((20, 21, 0x100000, 0x4f),
              (22, 23, 0x80000, 0x4f),
              (24, 25, 0x30000, 0x07))
    for esr, far, address, fsc in probes:
        require(w[esr] >> 26 == 0x24 and w[esr] & 0x7f == fsc
                and w[far] == address,
                "governance EL0 mapping probe did not fault at the protected boundary")
    require(w[26] == 9 and w[10] >= 1,
            "governance EL0 timer preemption was not observed")
    require(w[59] == 8 and w[11] >> 26 == 0x15 and w[11] & 0xffff == 0x562
            and w[12] == 0x101000 and w[13] == 256,
            "governance command did not return through the exact EL0 SVC ABI")
    require(w[14:17] == (1, 1, 1),
            "governance self-test did not return the canonical sequence-one Wait command")
    require(w[18] != 0 and w[19] != 0 and all(w[49:54]),
            "governance runtime identity or address space is missing")
    require(any(w[28:32]) and any(w[32:36]) and any(w[36:40]),
            "governance command, snapshot or image digest is missing")
    require(w[55] < w[17] < w[54],
            "governance command was validated outside its canonical snapshot deadline")
    return {
        "phase": w[2], "cpu": w[6], "turns": w[7],
        "total_actual_ns": w[8], "max_actual_ns": w[9],
        "preemptions": w[10], "core_generation": w[3],
        "ledger_generation": w[4], "credit_sequence": w[5],
        "svc_esr": w[11], "svc_pointer": w[12], "svc_length": w[13],
        "command_kind": w[14], "command_sequence": w[15],
        "snapshot_revision": w[16], "validation_ns": w[17],
        "role_context": [w[18], w[19]],
        "command_digest": b"".join(value.to_bytes(8, "little")
                                    for value in w[28:32]).hex(),
        "snapshot_digest": b"".join(value.to_bytes(8, "little")
                                     for value in w[32:36]).hex(),
        "image_hash": b"".join(value.to_bytes(8, "little")
                                  for value in w[36:40]).hex(),
        "root": w[49], "entry": w[50],
        "mapping_keys": list(w[51:54]), "completed": True,
    }


def parse_learning(data):
    w = words(data, 128)
    # The failure is sticky and cannot be hidden by an interrupted snapshot.
    require(w[10] == 0, f"native learning worker fault {w[10]}")
    if w[0] == 0 or w[127] & 1:
        return None
    require(w[0] == LEARNING_MAGIC and w[1] == 1 and w[3] == 1,
            "invalid independent learning role header")
    require(w[2] <= 7 and w[13] <= 5 and all(w[i] in (0, 1) for i in (14, 15, 25, 26)),
            "invalid learning mechanism state")
    require(w[22] == 1024 * 1024, "learning role workspace differs from frozen 1 MiB")
    require(w[4] <= 9_000_000 and w[5] <= 70_000_000
            and (w[27] != w[28] or w[4] + w[5] <= 70_000_000),
            "learning extra or total C window exceeded its actual budget")
    require(w[17] <= w[16], "learning completion without a real submitted job")
    ready = w[13] == 5 and w[14] == 1 and w[25] == 1 and w[26] == 1
    return {"phase": w[2], "cpu": w[3], "extra_window_ns": w[4],
            "mandatory_window_ns": w[5], "total_extra_cpu_ns": w[6],
            "extra_window": w[27], "mandatory_window": w[28],
            "maximum_slice_ns": w[7], "timer_returns": w[8], "svc_yields": w[9],
            "protection_probes": w[13], "operator_selftest_passed": bool(w[14]),
            "data_incomplete": bool(w[15]), "jobs": w[16], "completed": w[17],
            "workspace_bytes": w[22], "capture_ready": bool(w[25]),
            "capture_loaned": bool(w[26]), "mechanism_ready": ready,
            "trained_model_verified": False}


def parse_replay(data):
    w = words(data, 64)
    if w[1] == 0 or w[0] & 1:
        return None
    require(w[0] > 0 and w[1] == REPLAY_MAGIC, "invalid native replay header")
    require(w[2] <= 23 and 1 <= w[3] <= 16 and w[4] in (1, 2)
            and (w[4] == 1 or w[3] in (1, 16)) and w[5] < 12
            and w[6] in (1, 2) and w[7] > 0, "invalid native replay state")
    training, validation = list(w[24:42]), list(w[42:60])
    require(all(n <= 8 for n in training) and all(n <= 4 for n in validation),
            "native replay exceeds the frozen family split")
    require(w[19] == sum(training) + sum(validation), "native replay label count mismatch")
    require(w[17] >= w[10] + w[11], "native replay retired a side before durable archive")
    require(w[20] in (0, 1) and w[22] in (0, 1) and w[63] in (0, 1),
            "invalid native replay custody flag")
    return {"phase": w[2], "family": [w[3], w[4]], "group": w[5],
            "side": "candidate" if w[6] == 1 else "baseline", "trial": w[7],
            "boot_epoch": w[8], "capture_generation": w[9],
            "verified_sides": w[10], "excluded_sides": w[11], "error": w[12],
            "root_phase": w[13], "first_ns": w[14], "observation_ns": w[15],
            "closing_ns": w[16], "durable_archives": w[17], "data_phase": w[18],
            "labels": w[19], "pending_baseline": bool(w[20]), "data_error": w[21],
            "peer_paused": bool(w[22]), "signed_peer_intervals": w[23],
            "training": training, "validation": validation, "sampled_ns": w[60],
            "history_rows": w[61], "retained_rows": w[62], "archive_complete": bool(w[63])}


def replay_ready(value, minimum):
    # These are the protected native producer's actual accepted pairs and
    # read-back archives. They are a functional ingress gate, not proof of
    # complete model validation, Canary promotion, or all-family acceptance.
    return bool(value and value["labels"] >= minimum
                and value["verified_sides"] >= 2 * minimum
                and value["durable_archives"] >= 2 * minimum)


def parse_preparation_rejections(data):
    """Decode protected failed attempts; these rows never attest a proposal."""
    w = words(data, 648)
    if not any(w) or w[3] & 1:
        return None
    require(w[0] == 0x4359505245503133 and w[4:8] == (1, 40, 16, 0),
            "invalid preparation rejection layout")
    total = w[1]
    require(total > 0 and w[2] == max(0, total - 16) and w[3] == 2 * total,
            "invalid preparation rejection count")
    names = ("Format", "Auth", "Schema", "Stale", "Capacity", "Budget", "Conflict",
             "Expired", "Unsupported", "Busy", "Again", "NotFound", "Exists",
             "NotDirectory", "IsDirectory", "NotEmpty", "Range", "Io", "Overflow", "NotReady")
    retained = []
    occupied = set()
    for ordinal in range(max(1, total - 15), total + 1):
        slot = (ordinal - 1) % 16
        occupied.add(slot)
        r = w[8 + slot * 40:8 + (slot + 1) * 40]
        domain, kind = r[3:5]
        require(1 <= domain <= 16 and kind in (1, 2)
                and (kind == 1 or domain in (1, 16)), "invalid rejected family")
        family = (0 if kind == 1 else 1) if domain == 1 else (17 if kind == 2 else domain)
        require(r[15] == family and r[33] == ordinal and not any(r[34:]),
                "invalid preparation rejection ordinal")
        require(all(r[i] > 0 for i in (0, 1, 2, 5, 6, 7, 8, 9))
                and r[30:33] == (r[0], r[8], r[9]) and r[14] >= r[10]
                and any(r[22:26]) and any(r[26:30]),
                "invalid preparation rejection identity")
        require(r[12] in (0, 1) and r[17] in (0, 1)
                and (r[18] > 0 and r[19] <= 65535 and (r[20] == 1 or r[19] < 100)
                     and r[20] in (0, 1) and r[21] in (0, 1)
                     if r[17] else not any(r[18:22])),
                "invalid preparation rejection custody")
        require(1 <= r[13] <= len(names) and names[r[13] - 1] not in ("Busy", "Again", "NotReady"),
                "transient error is not a retired preparation")
        retained.append({"ordinal": ordinal, "sequence": r[0], "boot_epoch": r[1],
                         "controller_epoch": r[2], "family": [domain, kind],
                         "target": list(r[5:7]), "model_generation": r[7],
                         "core_generation": r[8], "ledger_generation": r[9],
                         "snapshot_ns": r[10], "cpu_ns": r[11], "overflowed": bool(r[12]),
                         "error": names[r[13] - 1], "retired_ns": r[14],
                         "target_ordinal": r[16], "work": list(r[18:22]) if r[17] else None,
                         "model_hash": struct.pack('<4Q', *r[22:26]).hex(),
                         "schema_hash": struct.pack('<4Q', *r[26:30]).hex()})
    require(all(not any(w[8 + slot * 40:8 + (slot + 1) * 40])
                for slot in range(16) if slot not in occupied),
            "unexpected preparation rejection outside retained range")
    return {"total": total, "overwritten": w[2], "retained": retained}


def diagnostics(guest, bundle, *, require_governance_runtime=False):
    # Every field belongs to this stopped snapshot. One failed parser must
    # neither hide another fresh diagnostic nor retain an older healthy value.
    errors = []
    guest["diagnostic_errors"] = []

    def read(key, parser):
        guest[key] = None
        try:
            guest[key] = parser()
        except ValueError as error:
            errors.append(error)
            guest["diagnostic_errors"].append({"field": key, "error": str(error)})

    def check(key, condition, message):
        if not condition:
            error = ValueError(message)
            errors.append(error)
            guest["diagnostic_errors"].append({"field": key, "error": str(error)})

    read("unified_words", lambda: list(words(bundle.get("UNIFIED_EVIDENCE", b""), 512)[:32]))
    if "UNIFIED_SERVICE_STAGE" in bundle:
        read("service_stage_word", lambda: words(bundle["UNIFIED_SERVICE_STAGE"], 1)[0])
    else:
        guest["service_stage_word"] = None
    for symbol_name, key, count in (("DOMAIN_TASK_EVIDENCE", "task_evidence", 32),
                                    ("FILE_SERVICE_EVIDENCE", "file_service_evidence", 64),
                                    ("TASK_VECTOR_EVIDENCE", "task_vector_evidence", 64),
                                    ("TASK_SPAWN_EVIDENCE", "task_spawn_evidence", 32),
                                    ("DOMAIN_PREPARATION_EVIDENCE", "preparation_evidence", 16),
                                    ("DOMAIN_PREPARATION_DETAIL", "preparation_detail", 32),
                                    ("DOMAIN_PREPARATION_PREFIX_DETAIL", "preparation_prefix_detail", 16),
                                    ("DOMAIN_PREPARATION_ENTRY_DETAIL", "preparation_entry_detail", 16),
                                    ("DOMAIN_PREPARATION_CONTEXT", "preparation_context", 16),
                                    ("DOMAIN_SERVICE_DETAIL", "service_detail", 16),
                                    ("BUILTIN_TASK_DETAIL", "builtin_detail", 32),
                                    ("DOMAIN_PREPARATION_REJECTIONS", "preparation_rejections", 648),
                                    ("TASK_OVERRUN_EVIDENCE", "overrun_evidence", 32),
                                    ("SMP_FAULT_EVIDENCE", "smp_fault_evidence", 72),
                                    ("CONTROL_CREDIT_EVIDENCE", "control_credit_evidence", 64),
                                    ("RUNTIME_V13_EVIDENCE", "runtime_evidence", 1024),
                                    ("TASK_SLICE_EVIDENCE", "slice_evidence", 128),
                                    ("IPI_EVIDENCE", "ipi_evidence", 512),
                                    ("CONTROL_POOL_EVIDENCE", "control_pool_evidence", 16),
                                    ("LEARNING_V13_EVIDENCE", "learning_evidence", 128),
                                    ("GOVERNANCE_V13_EVIDENCE", "governance_evidence", 16),
                                    ("GOVERNANCE_RUNTIME_V13_EVIDENCE", "governance_runtime_evidence", 64),
                                    ("REPLAY_V13_EVIDENCE", "replay_evidence", 64),
                                    ("REPLAY_ROOT_EVIDENCE", "replay_root_evidence", 32),
                                    ("REPLAY_OWNER_EVIDENCE", "replay_owner_evidence", 32),
                                    ("REPLAY_CONFIG_EVIDENCE", "replay_config_evidence", 32),
                                    ("REPLAY_CAPTURE_EVIDENCE", "replay_capture_evidence", 32),
                                    ("LOCAL_PLACEMENT_EVIDENCE", "local_placement_evidence", 32),
                                    ("PANIC_EVIDENCE", "panic_evidence", 8)):
        guest[key] = None
        if symbol_name in bundle:
            read(key, lambda: list(words(bundle[symbol_name], count)))
    def credit_detail():
        task_words = guest.get("task_evidence") or []
        sticky_words = guest.get("overrun_evidence") or []
        rows = []
        for cpu, start in ((0, 2), (2, 12), (3, 22)):
            row = sticky_words[start:start + 10]
            if len(row) == 10 and any(row):
                rows.append({
                    "cpu": cpu, "sequence": row[0],
                    "thread": [row[1], row[2]],
                    "reserved_ns": row[3], "actual_ns": row[4],
                    "started_ns": row[5], "finished_ns": row[6],
                    "window": row[7], "core_generation": row[8],
                    "optional": bool(row[9]),
                })
        return {
            "mask": task_words[2] if len(task_words) > 2 else None,
            "overruns": task_words[3] if len(task_words) > 3 else None,
            "cpu_spent_ns": task_words[4:7] if len(task_words) >= 7 else None,
            "service_stage": guest.get("service_stage_word")
            if guest.get("service_stage_word") is not None
            else (guest.get("unified_words") or [None] * 31)[30],
            "service_detail": guest.get("service_detail"),
            "builtin_detail": guest.get("builtin_detail"),
            "sticky_count": sticky_words[1] if len(sticky_words) > 1 else 0,
            "receipts": rows,
        }

    def parse_task_snapshot(data):
        try:
            return parse_tasks(data)
        except ValueError as error:
            detail = credit_detail()
            if detail["mask"] or detail["overruns"]:
                raise ValueError(
                    f"native task credit overrun/quarantine: mask={detail['mask']} "
                    f"overruns={detail['overruns']} detail="
                    + json.dumps(detail, separators=(",", ":"))) from error
            raise

    for symbol_name, key, parser in (("CONTROL_CREDIT_EVIDENCE", "control_credit", parse_control_credit),
                                     ("DOMAIN_PREPARATION_REJECTIONS", "rejected_preparations", parse_preparation_rejections),
                                     ("RUNTIME_V13_EVIDENCE", "runtime", parse_runtime),
                                     ("DOMAIN_TASK_EVIDENCE", "tasks", parse_tasks),
                                     ("IPI_EVIDENCE", "ipi", parse_ipi),
                                     ("CONTROL_POOL_EVIDENCE", "control_pool", parse_control_pool),
                                     ("LEARNING_V13_EVIDENCE", "learning", parse_learning),
                                     ("GOVERNANCE_V13_EVIDENCE", "governance", parse_governance),
                                     ("GOVERNANCE_RUNTIME_V13_EVIDENCE", "governance_runtime", parse_governance_runtime),
                                     ("REPLAY_V13_EVIDENCE", "replay", parse_replay)):
        guest[key] = None
        if symbol_name in bundle:
            if key == "tasks":
                read(key, lambda: parse_task_snapshot(bundle[symbol_name]))
            else:
                read(key, lambda: parser(bundle[symbol_name]))
            if key == "control_credit":
                detail = {
                    "failures": guest[key],
                    "active_records": active_control_records(
                        bundle.get("DOMAIN_CONTROL_EVIDENCE", b"")),
                    "preparation_evidence": guest.get("preparation_evidence"),
                    "preparation_detail": guest.get("preparation_detail"),
                    "preparation_prefix_detail": guest.get("preparation_prefix_detail"),
                    "preparation_context": guest.get("preparation_context"),
                }
                check(key, not guest[key],
                      "native C credit failure: " + json.dumps(detail, separators=(",", ":")))
    mapping = guest.get("governance")
    governance_runtime = guest.get("governance_runtime")
    # The mapping is installed before the independent EL0 role finishes its
    # bounded multi-turn self-test. Live samples may therefore observe an
    # authenticated mapping with a runtime bank that is still deliberately
    # incomplete. Final/stopped acceptance remains strict.
    if require_governance_runtime:
        check("governance_runtime", mapping is None or governance_runtime is not None,
              "governance mapping exists without completed native EL0 execution evidence")
    if mapping is not None and governance_runtime is not None:
        check("governance_runtime",
              mapping["role_context"] == governance_runtime["role_context"]
              and mapping["image_hash"] == governance_runtime["image_hash"]
              and mapping["root"] == governance_runtime["root"]
              and mapping["entry"] == governance_runtime["entry"],
              "governance runtime identity differs from its installed image mapping")

    # A synchronous file operation may retain its caller while waiting for a
    # new credit. Its periodic task snapshot can then be older than the actual
    # completion fault; the independent sticky record must still fail the run.
    check("overrun_evidence", not (guest.get("overrun_evidence") or [0])[0],
          "native sticky CPU credit overrun evidence is present: "
          + json.dumps(credit_detail(), separators=(",", ":")))
    check("panic_evidence", not (guest.get("panic_evidence") or [0])[0], "kernel panic evidence is present")
    check("smp_fault_evidence", not (guest.get("smp_fault_evidence") or [0])[0],
          "native secondary fatal evidence is present")
    if errors:
        # A second CPU can be stopped after claiming its failure row but before
        # sealing it, while the CPU that triggered the stop has already
        # release-published a complete task/sticky receipt. The incomplete C
        # row must still fail acceptance, but it must not hide that complete
        # primary diagnostic.
        incomplete_control = guest.get("control_credit") and all(
            not failure.get("complete", False) for failure in guest["control_credit"])
        if incomplete_control:
            for error in errors:
                if str(error).startswith((
                    "native task credit overrun/quarantine:",
                    "native sticky CPU credit overrun evidence is present:",
                    "kernel panic evidence is present",
                    "native secondary fatal evidence is present",
                )):
                    raise error
        raise errors[0]


def refresh_snapshot(guest, bundle, *, require_governance_runtime=False):
    """Refresh ordinary and final diagnostics before raising the first fault."""
    guest["unified"] = guest["control"] = None
    errors = []
    try:
        diagnostics(guest, bundle, require_governance_runtime=require_governance_runtime)
    except ValueError as error:
        errors.append(error)
    # Both parsers still run after a task/credit/panic fault. A failed unified
    # parser cannot supply an old BootEpoch to the independently parsed control.
    for key, parser in (("unified", lambda: parse_unified(bundle["UNIFIED_EVIDENCE"])),
                        ("control", lambda: parse_control(bundle["DOMAIN_CONTROL_EVIDENCE"],
                            guest["unified"]["boot_epoch"] if guest["unified"] else None))):
        try:
            guest[key] = parser()
        except (ValueError, KeyError) as error:
            error = error if isinstance(error, ValueError) else ValueError("missing snapshot evidence: " + str(error))
            errors.append(error)
            guest["diagnostic_errors"].append({"field": key, "error": str(error)})
    if errors:
        raise errors[0]


def profile(path):
    data = path.read_bytes()
    inspect_elf(data)
    require(boot_profile(data)["ram_mib"] == 1024, "domain image requires 1 GiB")
    locations = {}
    for name, size in REQUIRED.items():
        locations[name] = symbol(data, name)
        require(locations[name]["size"] == size, f"bad {name} size")
    for name, size in OPTIONAL.items():
        try:
            location = symbol(data, name)
        except ValueError as error:
            if str(error) != "missing symbol " + name:
                raise
        else:
            require(location["size"] == size, f"bad {name} size")
            locations[name] = location
    require(("CONTROL_POOL_EVIDENCE" in locations) == ("LEARNING_V13_EVIDENCE" in locations),
            "incomplete native learning/control pool evidence symbols")
    require(("GOVERNANCE_V13_EVIDENCE" in locations)
            == ("GOVERNANCE_RUNTIME_V13_EVIDENCE" in locations),
            "incomplete governance mapping/runtime evidence symbols")
    return data, locations


def drain(guest):
    encoded = guest["qmp"].execute("ringbuf-read", {
        "device": "cyxlog", "size": 1048576, "format": "base64"})
    data = base64.b64decode(encoded, validate=True)
    guest["raw"].extend(data)
    require(len(guest["raw"]) <= 4 * 1024 * 1024, "serial evidence budget exceeded")
    for frame in guest["decoder"].feed(data):
        guest["serial"].extend(frame)
    (guest["folder"] / "serial.txt").write_bytes(guest["serial"])
    require(not any(marker in guest["serial"] for marker in
                    (b"FAIL", b"PANIC", b"SMP_ERROR")), "guest reported failure")


def capture(guests, *, resume):
    """Stop all owned guests before reading evidence; never infer RT from this."""
    stopped = []
    bundles = []
    try:
        for guest in guests:
            guest["qmp"].execute("stop")
            stopped.append(guest)
        for guest in guests:
            bundle = {}
            for name, location in guest["locations"].items():
                path = guest["folder"] / (name + ".bin")
                guest["qmp"].execute("pmemsave", {
                    "val": location["pa"], "size": location["size"],
                    "filename": str(path)})
                bundle[name] = path.read_bytes()
            bundles.append(bundle)
    finally:
        if resume:
            for guest in stopped:
                guest["qmp"].execute("cont")
    return bundles


def archive(guest, data, control, force=False):
    if control is None or control["registered_families"] != ALL_FAMILIES:
        return
    objects = set(control["applied_objects"])
    if not objects or not (force or objects - guest["seen_objects"]):
        return
    require(len(guest["captures"]) < 256, "bounded evidence archive exhausted")
    path = guest["folder"] / f"control-{len(guest['captures']):03d}.bin"
    path.write_bytes(data)
    guest["captures"].append(path)
    guest["seen_objects"].update(objects)


def replay(verifier, capture_path, model):
    command = [str(verifier), str(capture_path)]
    if model is not None:
        command.append(str(model))
    result = subprocess.run(command, capture_output=True, timeout=30)
    capture_path.with_suffix(".verifier.stdout").write_bytes(result.stdout)
    capture_path.with_suffix(".verifier.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "host replay rejected " + capture_path.name +
            ": " + result.stderr.decode(errors="replace")[-2000:])
    proof = json.loads(result.stdout)
    require(proof.get("status") == "PASS" and proof.get("replayed", 0) > 0
            and proof.get("accepted", 0) > 0 and proof.get("applied", 0) > 0,
            "host verifier did not prove a real publication and APPLIED receipt")
    require(proof.get("physical_realtime_verified") is False,
            "functional replay cannot claim physical real-time verification")
    return proof


def verify_source_build(manifest_path, source_root, image_hashes):
    """Check the local builder's frozen source/image record, not just HEAD."""
    require(manifest_path.stat().st_size <= 4 * 1024 * 1024, "build manifest too large")
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get("schema_version") == 1 and manifest.get("status") == "BUILT_NOT_RUN",
            "unsupported native build manifest")
    require(manifest.get("profiles", {}).get("selftest") is True
            and manifest.get("own_private_key_only_verified") is True,
            "build lacks the ordinary probe or separate identity audit")
    actual_sources = code_source_map(source_root)
    require(actual_sources == manifest.get("code_source_map"), "native source changed after build")
    source_hash = hashlib.sha256(json.dumps(actual_sources, sort_keys=True,
                                           separators=(",", ":")).encode()).hexdigest()
    require(source_hash == manifest.get("code_source_sha256"), "native source manifest hash mismatch")
    require(sha(source_root / "tools/build_unified.py") == manifest.get("builder_sha256"),
            "native builder changed after build")
    artifacts = manifest.get("artifacts", {})
    for index, image_hash in enumerate(image_hashes):
        name = f"node-{'ab'[index]}.elf"
        require(artifacts.get(name, {}).get("sha256") == image_hash,
                "native image differs from build manifest: " + name)
    nodes = manifest.get("nodes", {})
    require(nodes.get("a", {}).get("node_id") and nodes.get("b", {}).get("node_id")
            and nodes["a"]["node_id"] != nodes["b"]["node_id"]
            and nodes["a"].get("peer_node_id") == nodes["b"]["node_id"]
            and nodes["b"].get("peer_node_id") == nodes["a"]["node_id"],
            "native build does not bind two distinct reciprocal identities")
    return {"manifest_sha256": sha(manifest_path), "code_source_sha256": source_hash}


def run(args):
    require(1 <= args.timeout <= 600 and 0 <= args.hold <= 60,
            "invalid functional observation deadline")
    require(50 <= args.sample_ms <= 2000, "sample interval must be 50..2000 ms")
    require(args.single != (args.peer_elf is not None),
            "choose --single or provide --peer-elf")
    reconnect_requested = bool(getattr(args, "reconnect", False))
    minimum_pairs = getattr(args, "replay_pairs", 0)
    require(0 <= minimum_pairs <= 216, "--replay-pairs must be 0..216")
    require(not reconnect_requested or not args.single, "--reconnect requires --peer-elf")
    tcg_threads = getattr(args, "tcg_threads", "multi")
    require(tcg_threads in ("single", "multi"), "invalid TCG thread configuration")
    require(args.clock_profile != "icount" or tcg_threads == "single",
            "icount requires single-thread TCG")
    reconnect = ReconnectProbe() if reconnect_requested else None
    images = [args.elf.resolve(strict=True)]
    if not args.single:
        images.append(args.peer_elf.resolve(strict=True))
    require(bool(args.build_manifest) == bool(args.source_root),
            "--build-manifest and --source-root must be provided together")
    manifest_path = args.build_manifest.resolve(strict=True) if args.build_manifest else None
    source_root = args.source_root.resolve(strict=True) if args.source_root else None
    verifier = args.verifier.resolve(strict=True)
    formatter = args.formatter.resolve(strict=True)
    model = args.model.resolve(strict=True) if args.model else None
    binary = Path(args.qemu or shutil.which("qemu-system-aarch64") or "")
    require(binary.is_file(), "qemu-system-aarch64 is missing")
    binary = binary.resolve(strict=True)
    output = args.output.resolve()
    require(not output.exists(), "refuse to reuse a test output directory")
    output.mkdir(parents=True, mode=0o700)
    report = {
        "schema_version": 1, "status": "FAIL", "scope": "native-replay-functional" if minimum_pairs else "native-domain-functional",
        "nodes": len(images), "physical_realtime_verified": False,
        "all_eighteen_families_two_effective_policies_verified": False,
        "release_acceptance_verified": False, "source_build_attested": False,
        "reconnect_requested": reconnect_requested, "reconnect_verified": False,
        "minimum_replay_pairs": minimum_pairs, "native_paired_replay_observed": False,
        "clock_profile": args.clock_profile, "tcg_threads": tcg_threads,
        "sampling": "stopped guest snapshots",
        "elf_sha256": [sha(image) for image in images],
        "verifier_sha256": sha(verifier), "formatter_sha256": sha(formatter),
        "qemu_sha256": sha(binary), "output": str(output),
        "model_sha256": sha(model) if model else None,
    }
    guests = []
    started = time.monotonic()
    end = started + args.timeout
    ready_at = None
    last_progress = 0.0
    previous_umask = os.umask(0o077)
    print(json.dumps({"output": str(output), "nodes": len(images)}), flush=True)
    try:
        if manifest_path:
            report["source_build"] = verify_source_build(manifest_path, source_root, report["elf_sha256"])
        report["qemu_version"] = subprocess.check_output(
            [str(binary), "--version"], text=True, timeout=10).splitlines()[0]
        with tempfile.TemporaryDirectory(prefix="cyx-domains-") as temporary, ExitStack() as files:
            port = None
            if len(images) == 2:
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    port = listener.getsockname()[1]
            try:
                for ordinal, image in enumerate(images, 1):
                    folder = output / f"node-{ordinal}"
                    folder.mkdir(mode=0o700)
                    disk = folder / "disk.raw"
                    formatted = subprocess.run([str(formatter), str(disk), secrets.token_hex(16)],
                                               capture_output=True, check=True, timeout=30)
                    (folder / "format.log").write_bytes(formatted.stdout + formatted.stderr)
                    require(disk.stat().st_size == 512 * 1024 * 1024, "test disk must be 512 MiB")
                    blob, locations = profile(image)
                    qmp_path = str(Path(temporary) / f"q{ordinal}.sock")
                    network = ("hubport,id=net0,hubid=0" if port is None else
                               f"socket,id=net0,{'listen' if ordinal == 1 else 'connect'}=127.0.0.1:{port}")
                    command = [str(binary), "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
                               "-cpu", "cortex-a53", "-smp", "4", "-m", "1024M",
                               "-accel", f"tcg,thread={tcg_threads}", "-S", "-display", "none", "-monitor", "none",
                               "-global", "virtio-mmio.force-legacy=false",
                               "-drive", f"if=none,id=disk0,format=raw,file={disk},cache=writeback",
                               "-device", "virtio-blk-device,drive=disk0", "-netdev", network,
                               "-device", f"virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:0{ordinal}",
                               "-object", f"filter-dump,id=capture,netdev=net0,file={folder / 'ethernet.pcap'}",
                               "-object", "rng-random,id=rng0,filename=/dev/urandom",
                               "-device", "virtio-rng-device,rng=rng0",
                               "-chardev", "ringbuf,id=cyxlog,size=1048576", "-serial", "chardev:cyxlog",
                               "-qmp", f"unix:{qmp_path},server=on,wait=off", "-kernel", str(image), "-no-reboot"]
                    if args.clock_profile == "icount":
                        command += ["-icount", "shift=0,align=on,sleep=on", "-rtc", "clock=vm"]
                    guest = {"folder": folder, "blob": blob, "locations": locations,
                             "argv": command, "raw": bytearray(), "serial": bytearray(),
                             "decoder": FrameDecoder(), "proc": None, "sock": None, "qmp": None,
                             "captures": [], "seen_objects": set()}
                    guests.append(guest)
                    error_log = files.enter_context((folder / "qemu-stderr.log").open("wb"))
                    guest["proc"] = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=error_log)
                    guest["sock"] = socket.socket(socket.AF_UNIX)
                    while True:
                        require(guest["proc"].poll() is None, "QEMU exited before QMP handshake")
                        if time.monotonic() >= end:
                            raise TimeoutError("QMP handshake deadline")
                        try:
                            guest["sock"].connect(qmp_path)
                            break
                        except (FileNotFoundError, ConnectionRefusedError):
                            time.sleep(0.01)
                    guest["qmp"] = Qmp(guest["sock"])
                    require("QMP" in guest["qmp"].receive(end), "invalid QMP greeting")
                    guest["qmp"].execute("qmp_capabilities")
                    require(len(guest["qmp"].execute("query-cpus-fast")) == 4, "four native CPUs required")
                    memory = guest["qmp"].execute("query-memory-size-summary")
                    require(memory["base-memory"] == 1024 ** 3, "wrong QEMU RAM size")
                for guest in guests:
                    guest["qmp"].execute("cont")
                while time.monotonic() < end:
                    if (output / "stop.request").exists():
                        raise RuntimeError("operator stopped this functional run")
                    for guest in guests:
                        require(guest["proc"].poll() is None, "QEMU exited during observation")
                        drain(guest)
                    bundles = capture(guests, resume=True)
                    ready = True
                    progress = []
                    for guest, bundle in zip(guests, bundles):
                        refresh_snapshot(guest, bundle)
                        unified, control = guest["unified"], guest["control"]
                        archive(guest, bundle["DOMAIN_CONTROL_EVIDENCE"], control)
                        observed = (unified is not None and control is not None and
                                    unified["probe_completed"] and unified["el0_returns"] > 0 and
                                    guest.get("ipi") is not None and guest["ipi"]["wake_verified"] and
                                    control["registered_families"] == ALL_FAMILIES and
                                    control["published"] > 0 and bool(guest["captures"]))
                        if len(guests) == 2 and unified:
                            observed = observed and unified["received_bytes"] > 0 and unified["sent_bytes"] > 0 and 3 in unified["events"]
                        if "LEARNING_V13_EVIDENCE" in bundle:
                            observed = (observed and guest.get("control_pool") is not None
                                        and guest.get("learning") is not None
                                        and guest["learning"]["mechanism_ready"]
                                        and guest["unified_words"][28] == 1)
                        if "GOVERNANCE_V13_EVIDENCE" in bundle:
                            observed = (observed and guest.get("governance") is not None
                                        and guest.get("governance_runtime") is not None
                                        and guest["governance_runtime"]["completed"])
                        if minimum_pairs:
                            observed = observed and replay_ready(guest.get("replay"), minimum_pairs)
                        ready = ready and observed
                        progress.append({"probe_done": bool(unified and unified["probe_completed"]),
                                         "jobs": control["jobs"] if control else 0,
                                         "applied": control["applied"] if control else 0,
                                         "replay": guest.get("replay")})
                    now = time.monotonic()
                    if reconnect is not None:
                        ready = reconnect.step(guests, ready) and ready
                    if now - last_progress >= 2:
                        update = {"wall_seconds": round(now - started, 2), "progress": progress}
                        if reconnect is not None:
                            update["reconnect_phase"] = reconnect.phase
                        print(json.dumps(update), flush=True)
                        last_progress = now
                    if ready:
                        ready_at = ready_at or now
                        if now - ready_at >= args.hold:
                            report["functional_conditions_observed"] = True
                            report["native_paired_replay_observed"] = bool(minimum_pairs)
                            break
                    else:
                        ready_at = None
                    time.sleep(args.sample_ms / 1000)
                else:
                    phase = f" (reconnect phase={reconnect.phase})" if reconnect is not None else ""
                    raise TimeoutError("native file/control functional observation deadline" + phase)
            finally:
                if guests and all(g["qmp"] and g["proc"].poll() is None for g in guests):
                    try:
                        final = capture(guests, resume=False)
                        for guest, bundle in zip(guests, final):
                            try:
                                refresh_snapshot(guest, bundle, require_governance_runtime=True)
                                archive(guest, bundle["DOMAIN_CONTROL_EVIDENCE"], guest["control"], force=True)
                            except ValueError as error:
                                guest["final_parse_error"] = str(error)
                            guest["registers"] = guest["qmp"].execute("human-monitor-command", {"command-line": "info registers -a"})
                            try:
                                bottom = symbol(guest["blob"], "__stack_bottom")["pa"]
                                top = symbol(guest["blob"], "__stack_top")["pa"]
                                guest["qmp"].execute("pmemsave", {"val": bottom, "size": top - bottom,
                                                       "filename": str(guest["folder"] / "cpu0-stack.bin")})
                                guest["stack_pa"] = bottom
                            except (ValueError, RuntimeError, OSError):
                                pass
                    except (ValueError, RuntimeError, OSError) as error:
                        report["final_capture_error"] = str(error)
                for guest in guests:
                    process = guest["proc"]
                    if process is not None and process.poll() is None:
                        try:
                            if guest["qmp"]:
                                guest["qmp"].execute("quit")
                        except (ValueError, RuntimeError, OSError):
                            pass
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            try:
                                process.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=2)
                    if guest["sock"]:
                        guest["sock"].close()
                    (guest["folder"] / "serial.raw").write_bytes(guest["raw"])
                    (guest["folder"] / "serial.txt").write_bytes(guest["serial"])
                    if guest["qmp"]:
                        (guest["folder"] / "qmp.json").write_text(json.dumps(guest["qmp"].transcript, indent=2))
        require(not report.get("final_capture_error"), report.get("final_capture_error", ""))
        if reconnect is not None:
            require(reconnect.phase == "complete", "native link restoration did not reauthenticate both peers")
            report["reconnect_verified"] = True
        proofs = []
        for guest in guests:
            require(not guest.get("final_parse_error"), guest.get("final_parse_error", ""))
            require(guest["decoder"].loss == guest["decoder"].corrupt == 0, "corrupt or lost serial frames")
            require(guest["captures"], "no captured APPLIED input for host replay")
            checked = [replay(verifier, path, model) for path in guest["captures"]]
            proofs.append({"captures": len(checked), "replays": checked,
                           "applied_domains": sorted({d for proof in checked for d in proof["applied_domains"]})})
        require([sha(image) for image in images] == report["elf_sha256"], "ELF changed during native run")
        require(sha(verifier) == report["verifier_sha256"], "host verifier changed during native run")
        if manifest_path:
            require(verify_source_build(manifest_path, source_root, report["elf_sha256"])
                    == report["source_build"], "native build record changed during execution")
            report["source_build_attested"] = True
        report.update(status="PASS", host_replay=proofs)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    except KeyboardInterrupt:
        report["error"] = "interrupted by operator"
    finally:
        report["wall_seconds"] = time.monotonic() - started
        if reconnect is not None:
            report["reconnect_evidence"] = reconnect.evidence()
        report["observations"] = [{key: guest.get(key) for key in
                                  ("argv", "unified", "unified_words", "control", "tasks", "ipi", "task_evidence", "file_service_evidence", "task_vector_evidence", "task_spawn_evidence", "overrun_evidence", "panic_evidence",
                                   "ipi_evidence", "slice_evidence", "smp_fault_evidence", "runtime", "runtime_evidence",
                                   "control_credit", "control_credit_evidence", "preparation_evidence", "preparation_detail", "preparation_context", "preparation_rejections", "rejected_preparations",
                                   "control_pool", "control_pool_evidence", "learning", "learning_evidence", "replay", "replay_evidence",
                                   "replay_root_evidence", "replay_owner_evidence",
                                   "replay_config_evidence", "replay_capture_evidence",
                                   "local_placement_evidence",
                                   "registers", "stack_pa", "diagnostic_errors", "final_parse_error")}
                                 for guest in guests]
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        os.umask(previous_umask)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--peer-elf", type=Path)
    mode.add_argument("--single", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--formatter", type=Path, default=ROOT / "target/debug/examples/prototype-disk")
    parser.add_argument("--verifier", type=Path, default=ROOT / "target/debug/examples/verify-domain-evidence")
    parser.add_argument("--model", type=Path, help="raw model package used by the native controller")
    parser.add_argument("--build-manifest", type=Path, help="frozen native build record to verify")
    parser.add_argument("--source-root", type=Path, help="exact source checkout used for that build")
    parser.add_argument("--qemu", help="path to qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=150)
    parser.add_argument("--hold", type=float, default=2, help="wall seconds after all functional conditions hold")
    parser.add_argument("--sample-ms", type=int, default=250)
    parser.add_argument("--clock-profile", choices=("icount", "wallclock"), default="wallclock")
    parser.add_argument(
        "--tcg-threads",
        choices=("single", "multi"),
        default="multi",
        help="TCG execution mode; multi is required by the pinned per-vCPU PMU clock",
    )
    parser.add_argument("--reconnect", action="store_true",
                        help="verify two-node link loss, guest-clock progress and fresh mutual authentication")
    parser.add_argument("--replay-pairs", type=int, default=0,
                        help="also require this many actual accepted native pairs and durable side archives per node")
    args = parser.parse_args()
    try:
        result = run(args)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps({key: result.get(key) for key in ("status", "scope", "output", "error", "wall_seconds")}), flush=True)
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
