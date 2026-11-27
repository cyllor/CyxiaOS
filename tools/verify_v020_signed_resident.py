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
from v0199_budget_trace import SIGNED_TRACE_BYTES, verify_signed_trace
from v020_production_media import (
    BLOCK_BYTES, REDO_HEADER_BYTES, SECURITY_REDO, STAGING_UUID, verify_signed_disk,
)
from v020_production_modes import rows
from v020_production_qemu import STAGING_RAM, create_scratch, sha
from v020_snapshot_envelopes import DATA_START, crc32c_zeroed
from verify_smp import require


ROLES = (6, 7, 2, 8, 9, 3, 10, 11)
COMPLETE_PROGRESS = (0xFFFF, 0x8778)  # Clock/Yield for all, four Sleep and four refusals.
STARTUP = "V020_STARTUP state=SECURE_DEGRADED reason=signed_media_unavailable command=status"
RECOVERY_NS = 8_000_000
PMU_PATCH = Path(__file__).resolve().parent / "qemu/cyxia-per-vcpu-pmu.patch"
TRACE_FILE = "cpu0-budget-trace.bin"


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


def verify_disk(path: Path, epoch: int, roles: list, *, expected_policy_sha256: str | None = None) -> str:
    policy = verify_signed_disk(path, epoch, expected_policy_sha256=expected_policy_sha256)
    with path.open("rb") as disk:
        for offset, expected in (
            (DATA_START * BLOCK_BYTES, epoch - 1),
            ((SECURITY_REDO + 2) * BLOCK_BYTES + REDO_HEADER_BYTES, epoch),
        ):
            disk.seek(offset)
            image = disk.read(BLOCK_BYTES)
            prefix = struct.pack("<IHH16sQ", 0x43594245, 1, 40, STAGING_UUID, expected)
            require(len(image) == BLOCK_BYTES and image[:32] == prefix
                    and struct.unpack_from("<I", image, 32)[0] == crc32c_zeroed(image, 32),
                    "durable boot home or redo differs from the admitted BootEpoch")
        disk.seek(SECURITY_REDO * BLOCK_BYTES + REDO_HEADER_BYTES + 120)
        generations = struct.unpack("<8Q", disk.read(64))
        require(roles == list(zip(range(len(ROLES)), ROLES, generations)),
                "running role identities differ from the durable security pair")
    return policy


def capture_budget_trace(socket_path: Path, elf: Path, output: Path, deadline: float) -> dict:
    location = symbol(elf.read_bytes(), "V020_SIGNED_CPU_BUDGET_TRACE")
    require(location["size"] == SIGNED_TRACE_BYTES and location["pa"] % 4096 == 0,
            "invalid linked signed CPU0 trace extent")
    path = output / TRACE_FILE
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
        finally:
            (output / "budget-qmp.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in qmp.transcript), encoding="utf-8",
            )
    return {"budget_trace_sha256": sha(path), "budget_trace_physical": location["pa"]}


def boot(binary: str, elf: Path, output: Path, timeout: float, disk: Path | None,
         epoch: int | None, *, expected_policy_sha256: str | None = None,
         budget_trace: bool = False) -> dict:
    output.mkdir()
    elf_digest = sha(elf)
    result = {"elf_sha256": elf_digest, "status": "FAIL"}
    data = bytearray()
    lines = []
    decoder = FrameDecoder()
    argv = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
            "-cpu", "cortex-a53", "-smp", "4", "-m", STAGING_RAM, "-accel", "tcg,thread=multi",
            "-display", "none", "-monitor", "none", "-nic", "none", "-serial", "stdio",
            "-kernel", str(elf), "-no-reboot"]
    if disk is not None:
        argv += ["-global", "virtio-mmio.force-legacy=false",
                 "-drive", f"file={disk},if=none,id=scratch,format=raw,cache=none",
                 "-device", "virtio-blk-device,drive=scratch"]
    deadline = time.monotonic() + timeout
    capture = tempfile.TemporaryDirectory(prefix="cyx-signed-qmp-") if budget_trace else nullcontext()
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
                require(STARTUP in lines, "missing medium did not fence startup")
                proc.stdin.write(b"status\n")
                proc.stdin.flush()
                wait_until(lambda: bool(rows(lines, "V020_RESIDENT_STATUS")))
                require(rows(lines, "V020_RESIDENT_STATUS")[0][:2] == (15, 0),
                        "missing medium did not retain the read-only resident service")
                require(not any(line.startswith(("V020_SIGNED_RESIDENT_BOOT ",
                                                 "V020_SIGNED_RESIDENT_ROLE ",
                                                 "V020_SIGNED_RESIDENT_PROGRESS ",
                                                 "V020_SIGNED_RESIDENT_CPU "))
                                for line in lines), "EL0 roles started without confirmed media")
                if disk is not None:
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
                require(len(progress) >= 5 and all(row[1:] == COMPLETE_PROGRESS for row in progress)
                        and all(right[0] - left[0] >= 4 for left, right in zip(progress, progress[1:])),
                        "all eight roles did not sustain authorized lifecycle progress")
                recovery = rows(lines, "V020_SIGNED_RESIDENT_RECOVERY")
                require([step for step, _, _ in recovery] == [1, 2]
                        and all(0 < used <= quota == RECOVERY_NS for _, used, quota in recovery),
                        "signed verification or package loading lacks a Recovery settlement")
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
                result.update(capture_budget_trace(socket_path, elf, output, deadline))
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
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh-elf", type=Path, required=True)
    parser.add_argument("--reopen-elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True, help="pinned accounting QEMU executable")
    parser.add_argument("--patch-sha256", required=True, help="pinned per-vCPU PMU source patch")
    parser.add_argument("--policy-sha256", help="SHA-256 of the independently signed scratch catalog")
    parser.add_argument("--budget-trace", action="store_true", help="replay stopped CPU0 per-role and per-window debits")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
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
    summary = {"scope": "native-signed-scratch-role-lifecycle", "status": "FAIL",
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
                           budget_trace=args.budget_trace and epoch is not None)
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
                    if args.budget_trace:
                        trace = (args.output / name / TRACE_FILE).read_bytes()
                        run.update(verify_signed_trace(
                            trace, epoch, run["roles"], [row[1] for row in run["recovery"]],
                            run["cpu0_pmu_ledger_idle_ns"],
                        ))
        summary["status"] = "PASS"
    except (ValueError, OSError, struct.error) as error:
        summary["error"] = f"{type(error).__name__}: {error}"
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return int(summary["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
