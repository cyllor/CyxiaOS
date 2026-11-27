#!/usr/bin/env python3
"""Verify a signed SEC-S load fixture on a disposable provisioned volume."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import tempfile
import time

from transport import FrameDecoder
from v0199_budget_trace import SEC_S_ROLE_LIMITS, SEC_S_ROLE_TURNS, TOTAL_LIMIT, verify_signed_trace
from v020_production_modes import rows
from v020_production_qemu import sha
from verify_smp import require
from verify_v020_signed_resident import (
    PMU_PATCH, ROLES, TRACE_FILE, capture_budget_trace, frame_geometry, verify_disk,
)


PAGE = 4096
PROBE = struct.Struct("<8Q")
STACK_GUARD = 0x2F000
PROBE_CHECKS = 31
PROBE_ROLE_STOP = 32
LOAD_WINDOWS = 8
ACTIVE_CALLS = (0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x30, 0x31, 0x32, 0x50)
UNGRANTED_CALLS = (0x10, 0x13, 0x20, 0x21, 0x22, 0x40, 0x41, 0x42, 0x43, 0x50)


def probe_rows(qmp, output, backing):
    require(backing["size"] == len(ROLES) * 24 * PAGE, "wrong SEC-S fixture backing")
    evidence = []
    digests = []
    for index in (0, 1):
        path = output / f"role-{ROLES[index]}-probe.bin"
        address = backing["pa"] + (24 * index + 15) * PAGE
        qmp.execute("pmemsave", {"val": address, "size": PROBE.size, "filename": str(path)})
        raw = path.read_bytes()
        require(len(raw) == PROBE.size, "incomplete signed fixture readback")
        evidence.append(PROBE.unpack(raw))
        digests.append(hashlib.sha256(raw).hexdigest())
    return {"role_probes": evidence, "role_probe_sha256": digests}


def saturated_windows(replay):
    complete = set(replay["budget_complete_eight_role_windows"])
    lowest = [limit * 7 // 10 for limit in SEC_S_ROLE_LIMITS[:2]]
    sustained = []
    for row in replay["budget_window_replay"]:
        window = row["window"]
        debits = row["role_cpu_ns"][:2]
        if (window in complete and row["upper_ns"] <= TOTAL_LIMIT
                and tuple(row["role_returned_turns"]) == SEC_S_ROLE_TURNS
                and all(lo <= debit <= hi for debit, lo, hi in
                        zip(debits, lowest, SEC_S_ROLE_LIMITS[:2], strict=True))):
            if sustained and window != sustained[-1]["window"] + 1:
                sustained.clear()
            sustained.append(row)
            if len(sustained) == LOAD_WINDOWS:
                return [{"window": w["window"], "ops_ns": w["role_cpu_ns"][0],
                         "sec_ns": w["role_cpu_ns"][1], "upper_ns": w["upper_ns"],
                         "role_returned_turns": w["role_returned_turns"]}
                        for w in sustained]
        else:
            sustained.clear()
    raise ValueError("fewer than eight consecutive loaded Ops and Security windows")


def run(binary, elf, disk, output, epoch, retired, *, timeout):
    output.mkdir()
    deadline = time.monotonic() + timeout
    decoder = FrameDecoder()
    data = bytearray()
    lines = []
    with (tempfile.TemporaryDirectory(prefix="cyx-sec-s-qmp-") as socket_dir,
          (output / "qemu-stderr.log").open("wb") as stderr):
        socket = Path(socket_dir) / "q"
        argv = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
                "-cpu", "cortex-a53", "-smp", "4", "-m", "1024M", "-accel", "tcg,thread=multi",
                "-display", "none", "-monitor", "none", "-nic", "none", "-serial", "stdio",
                "-kernel", str(elf), "-no-reboot", "-qmp", f"unix:{socket},server=on,wait=off",
                "-global", "virtio-mmio.force-legacy=false",
                "-drive", f"file={disk},if=none,id=scratch,format=raw,cache=none",
                "-device", "virtio-blk-device,drive=scratch"]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        try:
            def wait_for(predicate):
                while not predicate():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0 and select.select([proc.stdout], [], [], remaining)[0],
                            "timed out waiting for the SEC-S guest")
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    require(chunk, "SEC-S guest closed the serial channel")
                    data.extend(chunk)
                    require(len(data) <= 1024 * 1024, "SEC-S serial exceeded its evidence limit")
                    lines.extend(frame.decode("ascii").rstrip("\n") for frame in decoder.feed(chunk))

            wait_for(lambda: any(line.startswith("V020_STARTUP ") for line in lines))
            proc.stdin.write(b"status\n")
            proc.stdin.flush()
            wait_for(lambda: bool(rows(lines, "V020_RESIDENT_STATUS")))
            require(decoder.loss == decoder.corrupt == 0, "corrupt SEC-S serial evidence")
            require(rows(lines, "SMP_BOOT_OK") == [(4, 15, 0)]
                    and rows(lines, "V020_SIGNED_RESIDENT_BOOT") == [(epoch, len(ROLES), 0)],
                    "SEC-S guest failed signed admission")
            require("V020_STARTUP state=SECURE_DEGRADED reason=signed_roles_fenced command=status" in lines,
                    "the retired SEC-S fixture did not transfer to read-only recovery")
            require(rows(lines, "V020_RESIDENT_STATUS")[0][:2] == (15, 0),
                    "the response after SEC-S retirement was not from read-only recovery")
            roles = rows(lines, "V020_SIGNED_RESIDENT_ROLE")
            require([(index, actor) for index, actor, _ in roles] == list(enumerate(ROLES))
                    and all(generation > 0 for _, _, generation in roles),
                    "missing SEC-S role identities")
            faults = rows(lines, "V020_SIGNED_RESIDENT_ROLE_FAULT")
            exits = rows(lines, "V020_SIGNED_RESIDENT_EXIT")
            stopped = faults if retired == 0 else exits
            require(len(faults) + len(exits) == len(stopped) == 1
                    and stopped[0][:2] == roles[retired][1:]
                    and (stopped[0][2] >> 26 == 0x24 if retired == 0 else stopped[0][2] == 0),
                    f"unexpected SEC-S role termination: faults {faults}, exits {exits}")
            measured = capture_budget_trace(socket, elf, output, deadline,
                                            frame_table=frame_geometry(lines), retired_index=retired,
                                            inspect_roles=probe_rows)
            expected_abi = dict.fromkeys(ROLES, 3)
            expected_abi[ROLES[retired]] = 0
            require(len(measured.get("role_probes", ())) == 2
                    and measured.get("role_syscall_abi") == expected_abi,
                    "missing SEC-S fixture memory or live and retired ABI bindings")
            for index, probe in enumerate(measured["role_probes"]):
                magic, role, boot, generation, flags, blocks, peer_generation, error = probe
                checks = PROBE_CHECKS | (PROBE_ROLE_STOP if index == retired == 0 else 0)
                require((magic, role, boot, generation, error) ==
                        (0x4359534553435052, ROLES[index], epoch, roles[index][2], 0)
                        and flags == checks
                        and blocks > 0 and (index == 0 or peer_generation == roles[0][2]),
                        f"failed signed SEC-S object or lifecycle probe {probe}")
            recovery = rows(lines, "V020_SIGNED_RESIDENT_RECOVERY")
            media = rows(lines, "V020_SIGNED_MEDIA_BUDGET")
            frame = rows(lines, "V020_SIGNED_FRAME_META_BUDGET")
            runtime = rows(lines, "V020_SEC_S_RECOVERY_BUDGET")
            terminal = rows(lines, "V020_SEC_S_TRACE_FINAL")
            expected_runtime = 1 if retired == 0 else 2
            require([step for step, _, _ in recovery] == list(range(3 + len(ROLES)))
                    and len(media) == len(frame) == len(terminal) == 1
                    and len(runtime) == expected_runtime
                    and (runtime[-1][0] > 1 if retired == 0 else runtime[-1][0] == 1),
                    "missing signed startup, runtime Recovery, or terminal budget evidence")
            replay = verify_signed_trace((output / TRACE_FILE).read_bytes(), epoch, roles,
                                         [used for _, used, _ in recovery],
                                         rows(lines, "V020_SIGNED_RESIDENT_CPU")[-1:],
                                         media_budget=media[0], frame_budget=frame[0],
                                         runtime_recovery=runtime, sec_s_load=True,
                                         trace_final=terminal[0])
            return {"epoch": epoch, "roles": roles, "stopped": stopped[0],
                    "startup_store": rows(lines, "V020_SEC_S_RECOVERY_STORE"),
                    "appended": rows(lines, "V020_SEC_S_RECOVERY_PROOF_DURABLE"),
                    "acknowledged": rows(lines, "V020_SEC_S_RECOVERY_ACK_DURABLE"),
                    "runtime_budget": runtime, "terminal_trace": terminal[0],
                    "loaded_windows": saturated_windows(replay), **measured, **replay}
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            proc.stdin.close()
            proc.stdout.close()
            (output / "serial.bin").write_bytes(data)
            (output / "serial.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def recovery_pages(disk, block):
    with disk.open("rb") as source:
        source.seek(PAGE * block)
        first, second = source.read(PAGE), source.read(PAGE)
    for page in (first, second):
        require(len(page) == PAGE and (not any(page) or (page[:8] == b"CYXRPR01"
                and hashlib.sha256(b"CYX/RECOVERY-PROOF-PAGE/v1" + page[:-32]).digest() == page[-32:])),
                "torn SEC-S recovery page")
    return first, second


def verify_proof_cycle(binary, elf, disk, locator, policy, output, timeout):
    require(len(locator) == 104 and locator[:8] == b"CYXRPF01"
            and locator[24:56] == hashlib.sha256(policy).digest(), "wrong SEC-S recovery locator")
    block = struct.unpack_from("<I", locator, 60)[0]
    require(not any(b for page in recovery_pages(disk, block) for b in page),
            "SEC-S fixture did not start with an empty proof store")
    seed = run(binary, elf, disk, output / "boot-2", 2, 0, timeout=timeout)
    first, second = recovery_pages(disk, block)
    require(struct.unpack_from("<3Q", first, 40) == (1, 2, 0) and not any(second)
            and struct.unpack_from("<H", first, 144)[0] == 1 and seed["appended"] == [(2, 1, 1)]
            and seed["startup_store"] == [(1, 0, 0)] and not seed["acknowledged"],
            "the first boot did not durably publish one role fault")
    proof = first[160:416]
    task_generation = seed["roles"][0][2]
    require(struct.unpack_from("<IHHQI", proof) == (0x43595241, 2, 256, 2, 0)
            and struct.unpack_from("<2Q", proof, 80) == (6, task_generation),
            "durable RecoveryProof is not bound to the actual stopped role")
    verify_disk(disk, 2, seed["roles"], expected_policy_envelope=policy)

    reopen = run(binary, elf, disk, output / "boot-3", 3, 7, timeout=timeout)
    old, retired = recovery_pages(disk, block)
    require(first == old and struct.unpack_from("<5Q", retired, 40) ==
            (2, 3, 1, 3, reopen["roles"][7][2]) and retired[112:144] == first[-32:]
            and struct.unpack_from("<H", retired, 144)[0] == 0
            and reopen["startup_store"] == [(2, 1, 0)] and not reopen["appended"]
            and reopen["acknowledged"] == [(3, 1, 0)],
            "role11 ACK did not durably retire the reopened proof")
    verify_disk(disk, 3, reopen["roles"], expected_policy_envelope=policy)
    return {"status": "PASS", "scope": "signed_sec_s_load_fixture",
            "authorized_syscalls": ACTIVE_CALLS, "ungranted_syscalls_denied": UNGRANTED_CALLS,
            "recovery_blocks": [block, block + 1],
            "proof_page_sha256": hashlib.sha256(first).hexdigest(),
            "ack_page_sha256": hashlib.sha256(retired).hexdigest(), "boots": [seed, reopen]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--patch-sha256", required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--scratch-disk", type=Path, required=True, help="disposable epoch-1 signed volume")
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=35)
    args = parser.parse_args()
    try:
        qemu_digest, patch_digest, elf_digest = sha(args.qemu), sha(PMU_PATCH), sha(args.elf)
        require((qemu_digest, patch_digest) == (args.qemu_sha256, args.patch_sha256),
                "the pinned QEMU/PMU source patch digest differs")
        args.output.mkdir()
        result = verify_proof_cycle(str(args.qemu.resolve()), args.elf.resolve(),
                                    args.scratch_disk.resolve(),
                                    (args.catalog / "recovery-store.bin").read_bytes(),
                                    (args.catalog / "offline-config.bin").read_bytes(),
                                    args.output.resolve(), args.timeout)
        require((sha(args.qemu), sha(args.elf)) == (qemu_digest, elf_digest),
                "an acceptance input changed during the run")
        result.update(qemu_sha256=qemu_digest, pmu_patch_sha256=patch_digest, elf_sha256=elf_digest)
        (args.output / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"SEC-S native verification PASS {args.output}")
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"SEC-S native verification failed: {error}\n")


if __name__ == "__main__":
    main()
