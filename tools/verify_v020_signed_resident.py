#!/usr/bin/env python3
"""Verify signed scratch role lifecycle on the locked per-vCPU PMU QEMU."""

import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from check_elf import symbol
from run_qemu import Qmp
from transport import FrameDecoder
from v0199_budget_trace import SIGNED_EARLY_TRACE_BYTES, SIGNED_TRACE_BYTES, verify_signed_trace
from v020_frame_meta import FRAME_ROW, PERMANENT_ROW, queue_dma_rows
from v020_production_media import (
    BLOCK_BYTES, REDO_HEADER_BYTES, SECURITY_REDO, STAGING_UUID, verify_signed_disk,
)
from v020_production_modes import rows
from v020_production_qemu import create_scratch, sha
from v020_snapshot_envelopes import DATA_START, crc32c_zeroed
from verify_smp import boot_ram_mib, require


ROLES = (6, 7, 2, 8, 9, 3, 10, 11)
COMPLETE_PROGRESS = (0xFFFF, 0x8778)  # Clock/Yield for all, four Sleep and four refusals.
STARTUP = "V020_STARTUP state=SECURE_DEGRADED reason=signed_media_unavailable command=status"
UNQUALIFIED_ROSTER = ("V020_STARTUP state=SECURE_DEGRADED "
                      "reason=lifecycle_packages_unqualified command=status")
RECOVERY_NS = 8_000_000
PMU_PATCH = Path(__file__).resolve().parent / "qemu/cyxia-per-vcpu-pmu.patch"
TRACE_FILE = "cpu0-budget-trace.bin"
FRAME_TABLE_FILE = "dense-frame-meta.bin"
PAGE = 4096


def verify_resident_budget(lines: list, progress: list) -> list:
    samples = rows(lines, "V020_SIGNED_RESIDENT_CPU")
    require(len(progress) - 1 <= len(samples) <= len(progress),
            "missing continuous CPU0 accounting for signed role progress")
    require(all(0 < idle < observed == ledger < 2**64 for observed, ledger, idle in samples),
            "native PMU delta, idle work and continuous CPU0 ledger disagree")
    require(all(right[0] > left[0] and right[2] > left[2]
                for left, right in zip(samples, samples[1:])),
            "continuous CPU0 accounting did not survive aligned windows")
    return samples


def verify_disk(path: Path, epoch: int, roles: list, *, expected_policy_sha256: str | None = None,
                expected_policy_envelope: bytes | None = None) -> str:
    policy = verify_signed_disk(path, epoch, expected_policy_sha256=expected_policy_sha256,
                                expected_policy_envelope=expected_policy_envelope)
    uuid = STAGING_UUID if expected_policy_envelope is None else expected_policy_envelope[16:32]
    with path.open("rb") as disk:
        for offset, expected in (
            (DATA_START * BLOCK_BYTES, epoch - 1),
            ((SECURITY_REDO + 2) * BLOCK_BYTES + REDO_HEADER_BYTES, epoch),
        ):
            disk.seek(offset)
            image = disk.read(BLOCK_BYTES)
            prefix = struct.pack("<IHH16sQ", 0x43594245, 1, 40, uuid, expected)
            require(len(image) == BLOCK_BYTES and image[:32] == prefix
                    and struct.unpack_from("<I", image, 32)[0] == crc32c_zeroed(image, 32),
                    "durable boot home or redo differs from the admitted BootEpoch")
        disk.seek(SECURITY_REDO * BLOCK_BYTES + REDO_HEADER_BYTES + 120)
        generations = struct.unpack("<8Q", disk.read(64))
        require(roles == list(zip(range(len(ROLES)), ROLES, generations)),
                "running role identities differ from the durable security pair")
    return policy


def frame_geometry(lines: list) -> tuple:
    def witness(name):
        found = rows(lines, "V020_SEC_M_DENSE_FRAME_" + name)
        require(len(found) == 1, "missing signed dense FrameMeta " + name)
        return found[0]

    table, count, table_bytes = witness("TABLE")
    control, progress, pool_bytes = witness("POOLS")
    permanent, free, reserved = witness("ROWS")
    require((count, table_bytes, pool_bytes, reserved) == (262_144, 10 << 20, 8 << 20, 0)
            and permanent + free == count, "invalid signed dense FrameMeta inventory")
    starts = [(table, table_bytes), (control, pool_bytes), (progress, pool_bytes)]
    ranges = sorted((base, base + size) for base, size in starts)
    require(all(0x44000000 <= base < end <= 0x80000000 and base % 4096 == 0
                for base, end in ranges)
            and all(before[1] <= after[0] for before, after in zip(ranges, ranges[1:])),
            "signed FrameMeta reservations overlap or exceed RAM")
    return table, table_bytes, permanent, [(0x40000000, 0x44000000), *ranges]


def verify_frame_table(qmp, image: bytes, path: Path, table_bytes: int, permanent: int,
                       ranges: list, dma_queues: set[str]) -> dict:
    raw = path.read_bytes()
    row = FRAME_ROW
    require(len(raw) == table_bytes, "incomplete signed FrameMeta readback")
    dma_rows, queues = queue_dma_rows(qmp, image, raw, dma_queues)
    free = (0xFFFFFFFF, 8, 0, 0, 0, 0, 0, 0)
    observed = 0
    for index, record in enumerate(row.iter_unpack(raw)):
        pinned = dma_rows.get(index, PERMANENT_ROW)
        require(record in (pinned, free), "signed FrameMeta contains unexpected owners or references")
        observed += record == pinned
    require(observed == permanent, "signed FrameMeta inventory differs from stopped RAM")
    for base, end in ranges:
        first, last = ((pa - 0x40000000) // PAGE for pa in (base, end))
        require(all(record == dma_rows.get(index, PERMANENT_ROW)
                    for index, record in enumerate(row.iter_unpack(
                        raw[first * row.size:last * row.size]), start=first)),
                "signed FrameMeta fixed reservation was not permanent")
    return {"frame_meta_table_sha256": sha(path), "frame_meta_permanent_rows": observed,
            "frame_meta_free_rows": len(raw) // row.size - observed, "dma_queues": queues}


def verify_role_mappings(qmp, output: Path, elf: bytes, backing: dict,
                         retired_index: int | None = None) -> dict:
    tables = symbol(elf, "V020_SIGNED_ROLE_TABLES")
    direct = symbol(elf, "ram_l3")["pa"]
    image_pages, stack_pages = 16, 8
    role_pages = image_pages + stack_pages
    table_pages = 3
    require(backing["size"] == len(ROLES) * role_pages * PAGE
            and tables["size"] == len(ROLES) * table_pages * PAGE
            and tables["pa"] % PAGE == backing["pa"] % PAGE == 0,
            "invalid linked signed role extents")

    def capture(name, address, size):
        path = output / name
        qmp.execute("pmemsave", {"val": address, "size": size, "filename": str(path)})
        raw = path.read_bytes()
        require(len(raw) == size, "incomplete signed role translation readback")
        return struct.unpack(f"<{size // 8}Q", raw)

    aliases = capture("signed-role-aliases.bin",
                      direct + ((backing["pa"] - 0x40000000) // PAGE) * 8,
                      len(ROLES) * role_pages * 8)
    entries = capture("signed-role-tables.bin", tables["pa"], tables["size"])
    page_entries = PAGE // 8
    user_leaf = (1 << 53) | 0xf43
    read_only, no_execute = 1 << 7, 1 << 54
    readonly = private = 0
    for role in range(len(ROLES)):
        start = role * table_pages * page_entries
        root, middle, leaf = (entries[start + i * page_entries:start + (i + 1) * page_entries]
                              for i in range(table_pages))
        table = tables["pa"] + role * table_pages * PAGE
        expected_root = 0 if role == retired_index else (table + PAGE) | 3
        require(root[0] == expected_root and middle[0] == ((table + 2 * PAGE) | 3)
                and not any(root[1:]) and not any(middle[1:]),
                "signed role table points outside its dedicated pages")
        image_at, stack_at = 0x10000 // PAGE, 0x30000 // PAGE
        image = leaf[image_at:image_at + image_pages]
        stack = leaf[stack_at:stack_at + stack_pages]
        require(any(entry and not entry & no_execute for entry in image)
                and all(entry and not entry & read_only for entry in stack)
                and not any(leaf[:image_at])
                and not any(leaf[image_at + image_pages:stack_at])
                and not any(leaf[stack_at + stack_pages:]),
                "signed role stack, guard, or image mapping is invalid")
        for index, entry in enumerate(image + stack):
            if not entry:
                continue
            page_index = role * role_pages + index
            pa = backing["pa"] + page_index * PAGE
            expected = pa | user_leaf | (entry & (read_only | no_execute))
            require(entry == expected, "signed role has an unexpected frame or flags")
            if entry & read_only:
                require(aliases[page_index] == (pa | 0x0060_0000_0000_0783),
                        "immutable signed role page has a writable alias")
                readonly += 1
            else:
                require(entry & no_execute and aliases[page_index] == 0,
                        "signed role writable page has an EL1 direct alias")
                private += 1
    return {"role_readonly_pages": readonly, "role_private_writable_pages": private}


def capture_role_syscall_abi(qmp, output: Path, image: bytes,
                             retired_index: int | None = None) -> dict:
    try:
        location = symbol(image, "V020_SIGNED_ROLE_SYSCALL_ABI")
    except ValueError as error:
        if str(error) != "missing symbol V020_SIGNED_ROLE_SYSCALL_ABI":
            raise
        return {}
    width = len(ROLES) * 2
    require(location["size"] == width and location["pa"] % 2 == 0,
            "invalid linked role syscall ABI table")
    path = output / "role-syscall-abi.bin"
    qmp.execute("pmemsave", {"val": location["pa"], "size": width,
                             "filename": str(path.resolve())})
    raw = path.read_bytes()
    require(len(raw) == width, "incomplete role syscall ABI readback")
    tags = struct.unpack(f"<{len(ROLES)}H", raw)
    expected = tuple(0 if index == retired_index else 3 for index in range(len(ROLES)))
    require(tags == expected, "signed ABI3 table disagrees with the live and retired roles")
    return {"role_syscall_abi": dict(zip(ROLES, tags)),
            "role_syscall_abi_sha256": sha(path)}


def capture_budget_trace(socket_path: Path, elf: Path, output: Path, deadline: float, *,
                         frame_table: tuple | None = None, expect_business: bool = False,
                         retired_index: int | None = None, inspect_roles=None) -> dict:
    image = elf.read_bytes()
    location = symbol(image, "V020_SIGNED_CPU_BUDGET_TRACE")
    require(location["size"] in (SIGNED_TRACE_BYTES, SIGNED_EARLY_TRACE_BYTES)
            and location["pa"] % 4096 == 0,
            "invalid linked signed CPU0 trace extent")
    path = output / TRACE_FILE
    try:
        backing = symbol(image, "V020_SIGNED_ROLE_BACKING")
    except ValueError as error:
        if str(error) != "missing symbol V020_SIGNED_ROLE_BACKING":
            raise
        backing = None
    mappings = {}
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(socket_path))
        qmp = Qmp(sock)
        try:
            require("QMP" in qmp.receive(deadline), "invalid signed budget QMP greeting")
            qmp.execute("qmp_capabilities")
            require(qmp.execute("query-status")["running"], "guest was not live before CPU0 capture")
            qmp.execute("stop")
            require(qmp.execute("query-status")["status"] == "paused", "guest did not pause for CPU0 capture")
            qmp.execute("pmemsave", {"val": location["pa"], "size": location["size"],
                                     "filename": str(path.resolve())})
            if frame_table is not None:
                table, table_bytes, permanent, ranges = frame_table
                frames = output / FRAME_TABLE_FILE
                qmp.execute("pmemsave", {"val": table, "size": table_bytes,
                                         "filename": str(frames.resolve())})
                dma_queues = {"block", "rng"} if expect_business else {"block"}
                mappings["frame_meta_table_physical"] = table
                mappings.update(verify_frame_table(qmp, image, frames, table_bytes, permanent,
                                                   ranges, dma_queues))
            mappings.update(capture_role_syscall_abi(qmp, output, image, retired_index))
            if backing is not None:
                mappings.update(verify_role_mappings(qmp, output, image, backing, retired_index))
                if inspect_roles is not None:
                    mappings.update(inspect_roles(qmp, output, backing))
        finally:
            (output / "budget-qmp.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in qmp.transcript), encoding="utf-8",
            )
    return {"budget_trace_sha256": sha(path), "budget_trace_physical": location["pa"], **mappings}


def retain_failed_progress_trace(socket_path, elf, output, deadline) -> dict:
    """Best-effort diagnostic only: never replace the original progress failure."""
    target = output / "failed-progress"
    result = {"status": "CAPTURE_ERROR", "capture_sha256": {}}
    try:
        target.mkdir()
        result["capture"] = capture_budget_trace(socket_path, elf, target, deadline)
        result["status"] = "CAPTURED"
    except (ValueError, OSError, RuntimeError, KeyError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    # A later mapping/ABI readback failure can follow a successful pmemsave.
    # Retain those bytes and the QMP transcript without treating them as proof.
    for name in (TRACE_FILE, "budget-qmp.jsonl"):
        path = target / name
        try:
            if path.is_file():
                result["capture_sha256"][name] = sha(path)
        except OSError as error:
            result["status"] = "CAPTURE_ERROR"
            result["hash_error"] = f"{type(error).__name__}: {error}"
    return result


def boot(binary: str, elf: Path, output: Path, timeout: float, disk: Path | None,
         epoch: int | None, *, expected_policy_sha256: str | None = None,
         expected_policy_envelope: bytes | None = None,
         budget_trace: bool = False, unqualified_roster: bool = False,
         expect_business: bool = False) -> dict:
    output.mkdir()
    elf_digest = sha(elf)
    result = {"elf_sha256": elf_digest, "status": "FAIL"}
    data = bytearray()
    lines = []
    decoder = FrameDecoder()
    image = elf.read_bytes()
    ram = boot_ram_mib(image)
    trace_size = (None if unqualified_roster
                  else symbol(image, "V020_SIGNED_CPU_BUDGET_TRACE")["size"])
    early_boot = trace_size == SIGNED_EARLY_TRACE_BYTES
    dense = early_boot and ram == 1024
    geometry = None
    argv = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
            "-cpu", "cortex-a53", "-smp", "4", "-m", f"{ram}M", "-accel", "tcg,thread=multi",
            "-display", "none", "-monitor", "none", "-nic", "none", "-serial", "stdio",
            "-kernel", str(elf), "-no-reboot"]
    if disk is not None:
        argv += ["-global", "virtio-mmio.force-legacy=false",
                 "-drive", f"file={disk},if=none,id=scratch,format=raw,cache=none",
                 "-device", "virtio-blk-device,drive=scratch"]
    if expect_business:
        argv += ["-object", "rng-random,id=boot-rng,filename=/dev/urandom",
                 "-device", "virtio-rng-device,rng=boot-rng"]
    deadline = time.monotonic() + timeout
    capture = (tempfile.TemporaryDirectory(prefix="cyx-signed-qmp-")
               if budget_trace or (dense and epoch is not None) else nullcontext())
    with capture as socket_dir, (output / "qemu-stderr.log").open("wb") as stderr:
        socket_path = None
        if socket_dir is not None:
            socket_path = Path(socket_dir) / "q"
            argv += ["-qmp", f"unix:{socket_path},server=on,wait=off"]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        try:
            def wait_until(predicate) -> None:
                while not predicate():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0 and select.select([proc.stdout], [], [], remaining)[0],
                            "timed out waiting for resident activity")
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    require(chunk, "QEMU closed the serial channel")
                    data.extend(chunk)
                    require(len(data) <= 1024 * 1024, "resident evidence exceeded its limit")
                    lines.extend(frame.decode("ascii").rstrip("\n") for frame in decoder.feed(chunk))

            if epoch is None:
                wait_until(lambda: any(line.startswith("V020_STARTUP ") for line in lines))
                expected = UNQUALIFIED_ROSTER if unqualified_roster else STARTUP
                require(expected in lines, "startup did not report the expected refusal")
                proc.stdin.write(b"status\n")
                proc.stdin.flush()
                wait_until(lambda: bool(rows(lines, "V020_RESIDENT_STATUS")))
                require(rows(lines, "V020_RESIDENT_STATUS")[0][:2] == (15, 0),
                        "refused startup did not retain the read-only resident service")
                require(not any(line.startswith(("V020_SIGNED_RESIDENT_BOOT ",
                                                 "V020_SIGNED_RESIDENT_ROLE ",
                                                 "V020_SIGNED_RESIDENT_PROGRESS ",
                                                 "V020_SIGNED_RESIDENT_CPU ",
                                                 "V020_SIGNED_BUSINESS_READY ",
                                                 "V020_SIGNED_BUSINESS_PROGRESS "))
                                for line in lines), "EL0 progressed after refused startup")
                if unqualified_roster:
                    require(not any(line.startswith("V020_W11_MEDIA_") for line in lines),
                            "startup touched the media with an unqualified role roster")
                elif disk is not None:
                    io = rows(lines, "V020_W11_MEDIA_IO")
                    require(len(io) == 1 and io[0][0] > 0 and io[0][1:] == (0, 0),
                            "the reopen path wrote or flushed rejected media")
                    result["rejected_media_io"] = io[0]
            else:
                wait_until(lambda: len(rows(lines, "V020_SIGNED_RESIDENT_PROGRESS")) >= 5
                           or any(line.startswith("V020_STARTUP ") for line in lines))
                starts = rows(lines, "V020_SIGNED_RESIDENT_BOOT")
                require(starts == [(epoch, len(ROLES), 0)], "signed roles did not enter startup")
                require(lines.index(f"V020_W11_MEDIA_STEP a=4 b=1 c={epoch}")
                        < lines.index(f"V020_SIGNED_RESIDENT_BOOT a={epoch} b={len(ROLES)} c=0"),
                        "native startup preceded durable BootEpoch confirmation")
                status_label = "V020_RESIDENT_STATUS"
                for count in (1, 2):
                    proc.stdin.write(b"status\n")
                    proc.stdin.flush()
                    wait_until(lambda: len(rows(lines, status_label)) >= count)
                status = rows(lines, status_label)
                require(len(status) == 2 and all(row[:2] == (15, 0) for row in status)
                        and 0 < status[0][2] < status[1][2],
                        "signed resident console did not sustain read-only status")
                progress_count = len(rows(lines, "V020_SIGNED_RESIDENT_PROGRESS"))
                wait_until(lambda: len(rows(lines, "V020_SIGNED_RESIDENT_PROGRESS"))
                           > progress_count)
                progress = rows(lines, "V020_SIGNED_RESIDENT_PROGRESS")
                progress_ok = (len(progress) >= 5
                               and all(row[1:] == COMPLETE_PROGRESS for row in progress)
                               and all(right[0] - left[0] >= 4
                                       for left, right in zip(progress, progress[1:])))
                if not progress_ok:
                    result["progress"] = progress
                    if socket_path is not None and proc.poll() is None:
                        result["failed_progress_budget"] = retain_failed_progress_trace(
                            socket_path, elf, output, deadline)
                require(progress_ok, "all eight roles did not sustain authorized lifecycle progress")
                if expect_business:
                    wait_until(lambda: len(rows(lines, "V020_SIGNED_BUSINESS_PROGRESS")) >= 5
                               or any(line.startswith("V020_STARTUP ") for line in lines))
                    business = rows(lines, "V020_SIGNED_BUSINESS_PROGRESS")
                    business_start = f"V020_SIGNED_BUSINESS_READY a={epoch} b=14 c=0"
                    require(rows(lines, "V020_SIGNED_BUSINESS_READY") == [(epoch, 14, 0)]
                            and lines.index(f"V020_W11_MEDIA_STEP a=4 b=1 c={epoch}")
                            < lines.index(business_start),
                            "business cores did not open together after durable BootEpoch")
                    require(len(business) >= 5 and all(count > 0 for count in business[0])
                            and all(all(a < b for a, b in zip(left, right))
                                    for left, right in zip(business, business[1:])),
                            "business cores did not sustain native dispatches")
                    entropy = rows(lines, "V020_SIGNED_BUSINESS_ENTROPY")
                    require(len(entropy) == 1, "missing business ASLR budget")
                    batches, used, quota = entropy[0]
                    require(0 < used <= batches * quota and quota == RECOVERY_NS,
                            "invalid business ASLR budget")
                    result.update(business_progress=business, business_entropy_budget=entropy[0])
                else:
                    require(not rows(lines, "V020_SIGNED_BUSINESS_READY"),
                            "unexpected business workload on a lifecycle-only image")
                recovery = rows(lines, "V020_SIGNED_RESIDENT_RECOVERY")
                media_budget = rows(lines, "V020_SIGNED_MEDIA_BUDGET")
                first_step = 0 if early_boot else 1
                steps = [step for step, _, _ in recovery]
                complete_steps = list(range(first_step, 3 + len(ROLES) + (3 if expect_business else 0)))
                require(trace_size in (SIGNED_TRACE_BYTES, SIGNED_EARLY_TRACE_BYTES)
                        and (steps == complete_steps
                             or (not expect_business and steps == list(range(first_step, 3))))
                        and all(0 < used <= quota == RECOVERY_NS for _, used, quota in recovery),
                        "signed startup lacks a Recovery settlement")
                ready = lines.index(f"V020_SIGNED_RESIDENT_BOOT a={epoch} b={len(ROLES)} c=0")
                last_settlement = max(i for i, line in enumerate(lines)
                                      if line.startswith("V020_SIGNED_RESIDENT_RECOVERY "))
                require(last_settlement < ready, "role startup preceded Recovery settlement")
                require(len(media_budget) == int(early_boot), "missing or unexpected media Recovery settlement")
                if early_boot:
                    batches, used, quota = media_budget[0]
                    io = rows(lines, "V020_W11_MEDIA_IO")
                    require(batches > 0 and 0 < used <= batches * quota and quota == RECOVERY_NS
                            and len(io) == 1 and all(counter > 0 for counter in io[0]),
                            "missing read/write/FLUSH or invalid media Recovery settlement")
                    result.update(media_budget=media_budget[0], media_io=io[0])
                if dense:
                    frame_budget = rows(lines, "V020_SIGNED_FRAME_META_BUDGET")
                    require(len(frame_budget) == 1, "missing signed FrameMeta Recovery settlement")
                    geometry = frame_geometry(lines)
                    first_policy = next(i for i, line in enumerate(lines)
                                        if line.startswith("V020_SIGNED_RESIDENT_RECOVERY a=1 "))
                    memory_reports = [i for i, line in enumerate(lines) if line.startswith(
                        ("V020_SEC_M_DENSE_FRAME_", "V020_SIGNED_FRAME_META_BUDGET "))]
                    require(lines.index("SMP_BOOT_OK a=4 b=15 c=0") < min(memory_reports)
                            and max(memory_reports) < first_policy,
                            "FrameMeta publication did not precede policy verification")
                    result["frame_budget"] = frame_budget[0]
                require(not any(line.startswith("V020_STARTUP ") for line in lines),
                        "resident roles entered the fenced state")
                result.update(epoch=epoch, roles=rows(lines, "V020_SIGNED_RESIDENT_ROLE"),
                              progress=progress, recovery=recovery, status_replies=status)
            require(rows(lines, "SMP_BOOT_OK") == [(4, 15, 0)], "SMP startup failed")
            require(not any(line.startswith(("V020_PROD_", "FAIL", "PANIC")) for line in lines),
                    "legacy role authority or hardware failure")
            require(proc.poll() is None, "guest stopped after its last response")
            require(decoder.loss == decoder.corrupt == 0, "corrupt resident console trace")
            if socket_path is not None:
                result.update(capture_budget_trace(socket_path, elf, output, deadline,
                                                   frame_table=geometry,
                                                   expect_business=expect_business))
            if geometry is not None:
                samples = verify_resident_budget(lines, progress)
                result.update(verify_signed_trace(
                    (output / TRACE_FILE).read_bytes(), epoch, result["roles"],
                    [used for _, used, _ in recovery], samples,
                    media_budget=result["media_budget"], frame_budget=result["frame_budget"],
                    business_entropy_budget=result.get("business_entropy_budget"),
                ))
            require(sha(elf) == elf_digest, "kernel ELF changed during the run")
            result["status"] = "PASS"
        except (ValueError, OSError, RuntimeError) as error:
            result["error"] = f"{type(error).__name__}: {error}"
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
    if result["status"] == "PASS" and epoch is not None:
        result["policy_sha256"] = verify_disk(
            disk, epoch, result["roles"], expected_policy_sha256=expected_policy_sha256,
            expected_policy_envelope=expected_policy_envelope,
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh-elf", type=Path, required=True)
    parser.add_argument("--reopen-elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True, help="pinned accounting QEMU executable")
    parser.add_argument("--patch-sha256", required=True, help="pinned per-vCPU PMU source patch")
    policy = parser.add_mutually_exclusive_group()
    policy.add_argument("--policy-sha256", help="SHA-256 of the independently signed scratch catalog")
    policy.add_argument("--policy-envelope", type=Path,
                        help="independent signed lifecycle envelope for a specific volume")
    parser.add_argument("--budget-trace", action="store_true", help="replay stopped CPU0 per-role and per-window debits")
    parser.add_argument("--unqualified-roster-elf", type=Path, action="append", default=[],
                        help="default image whose missing or incorrect package signature must fence before media")
    parser.add_argument("--expect-business-reopen", action="store_true",
                        help="reopen image carries an independently signed business package")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    expected_envelope = None if args.policy_envelope is None else args.policy_envelope.read_bytes()
    require(1 <= args.timeout <= 120, "invalid run timeout")
    binary = shutil.which("qemu-system-aarch64")
    require(binary is not None, "qemu-system-aarch64 is missing")
    binary_digest = sha(Path(binary))
    require(binary_digest == args.qemu_sha256, "wrong accounting-enabled QEMU binary")
    patch_digest = sha(PMU_PATCH)
    require(patch_digest == args.patch_sha256, "wrong PMU accounting patch")
    version = subprocess.check_output([binary, "--version"], timeout=10, text=True).splitlines()[0]
    require(version.startswith("QEMU emulator version 10.2.2"), "unverified QEMU version")
    args.output.mkdir(parents=True, exist_ok=False)
    scope = ("native-signed-resident-business" if args.expect_business_reopen
             else "native-signed-scratch-role-lifecycle")
    summary = {"scope": scope, "status": "FAIL",
               "qemu_version": version, "qemu_sha256": binary_digest,
               "patch_sha256": patch_digest, "cpu_accounting": "pinned-per-vcpu-pmu",
               "complete_production_accounting": False}
    try:
        with tempfile.TemporaryDirectory(prefix="cyx-v020-signed-resident-") as temp:
            disk = Path(temp) / "scratch.raw"
            create_scratch(disk)
            blank_digest = sha(disk)
            for name, elf, medium, epoch in (
                ("absent", args.fresh_elf, None, None),
                ("blank_reopen", args.reopen_elf, disk, None),
                ("fresh", args.fresh_elf, disk, 1),
                ("reopen", args.reopen_elf, disk, 2),
            ):
                run = boot(binary, elf, args.output / name, args.timeout, medium, epoch,
                           expected_policy_sha256=args.policy_sha256,
                           expected_policy_envelope=expected_envelope,
                           budget_trace=args.budget_trace and epoch is not None,
                           expect_business=name == "reopen" and args.expect_business_reopen)
                summary[name] = run
                require(run["status"] == "PASS", f"{name}: {run.get('error')}")
                if name == "blank_reopen":
                    require(sha(disk) == blank_digest, "rejected scratch medium changed")
                    run["unchanged_media_sha256"] = blank_digest
                if epoch is not None:
                    serial = (args.output / name / "serial.txt").read_text(encoding="utf-8")
                    run["cpu0_pmu_ledger_idle_ns"] = verify_resident_budget(
                        serial.splitlines(), run["progress"]
                    )
                    if args.budget_trace and "frame_budget" not in run:
                        trace = (args.output / name / TRACE_FILE).read_bytes()
                        run.update(verify_signed_trace(
                            trace, epoch, run["roles"], [row[1] for row in run["recovery"]],
                            run["cpu0_pmu_ledger_idle_ns"],
                            media_budget=run.get("media_budget"),
                            business_entropy_budget=run.get("business_entropy_budget"),
                        ))
                if name == "fresh":
                    for index, unqualified in enumerate(args.unqualified_roster_elf):
                        case = f"unqualified_roster_{index + 1}"
                        before = sha(disk)
                        refused = boot(binary, unqualified, args.output / case, args.timeout,
                                       disk, None, unqualified_roster=True)
                        summary[case] = refused
                        require(refused["status"] == "PASS", f"{case}: {refused.get('error')}")
                        require(sha(disk) == before, "unqualified role roster changed the volume")
                        refused["unchanged_media_sha256"] = before
        summary["status"] = "PASS"
    except (ValueError, OSError, struct.error) as error:
        summary["error"] = f"{type(error).__name__}: {error}"
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return int(summary["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
