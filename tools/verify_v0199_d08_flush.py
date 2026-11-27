#!/usr/bin/env python3
"""Exercise SEC-D08 on the signed scratch mount path of locked A53 QEMU.

Seed a writable signed volume with the existing resident verifier. Reopen the
same volume with the same ELF twice, toggling only the block cache feature
that advertises FLUSH. Judge the guest and device traces on the host.
"""

import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess
import time

from qmp_stdio import PipeTransport
from run_qemu import Qmp
from transport import FrameDecoder
from v020_production_modes import rows
from v020_production_qemu import SCRATCH_BYTES, create_scratch, qemu_args, sha, shutdown
from verify_smp import boot_ram_mib, require
from verify_unified import attest_qemu
from verify_v020_signed_resident import ROLES, STARTUP, boot, verify_disk


FLUSH = "VIRTIO_BLK_F_FLUSH"
READ_ONLY = "VIRTIO_BLK_F_RO"
VERSION_1 = "VIRTIO_F_VERSION_1"
DRIVER_OK = "VIRTIO_CONFIG_S_DRIVER_OK"
FAILED = "VIRTIO_CONFIG_S_FAILED"
COUNTERS = ("rd_operations", "wr_operations", "flush_operations")


def names(labels):
    return {label.partition(":")[0] for label in labels}


def device_snapshot(qmp, disk: Path) -> dict:
    device, = qmp.execute("x-query-virtio")
    status = qmp.execute("x-query-virtio-status", {"path": device["path"]})
    drive, = (item for item in qmp.execute("query-block") if item["device"] == "scratch")
    stats, = (item["stats"] for item in qmp.execute("query-blockstats")
              if item.get("device") == "scratch")
    require(drive.get("qdev") == "d08" and drive["inserted"]["file"] == str(disk),
            "QEMU block backend differs from the writable scratch input")
    return {"virtio": status, "drive": drive["inserted"], "operations": {k: stats[k] for k in COUNTERS}}


def check_device(snapshot: dict, flush: bool) -> dict:
    device = snapshot["virtio"]
    media = snapshot["drive"]
    features = names(device["host-features"]["dev-features"])
    require(device["device-id"] == 2 and VERSION_1 in names(device["host-features"]["transports"]),
            "expected a modern VirtIO block device")
    require(media["ro"] is False and media["drv"] == "raw" and READ_ONLY not in features
            and media["image"]["virtual-size"] == SCRATCH_BYTES,
            "expected a writable 512 MiB raw block backend")
    require((FLUSH in features) == flush and media["cache"]["no-flush"] is False,
            "observed device FLUSH support differs from the test input")
    return {"host_features": sorted(features), "status": sorted(names(device["status"]["statuses"]))}


def check_reopen(lines: list, snapshot: dict, *, flush: bool, before: str, after: str) -> dict:
    detail = check_device(snapshot, flush)
    operations = snapshot["operations"]
    require(rows(lines, "SMP_BOOT_OK") == [(4, 15, 0)], "four-vCPU boot did not complete")
    require(not any(line.startswith(("FAIL", "PANIC", "SMP_ERROR")) for line in lines), "guest failed")
    # A semantic mount refusal must not hide a transport failure or UNKNOWN
    # custody; nor can a successful writable mount carry either witness.
    for marker in ("V020_W11_MEDIA_IO_ERROR", "V020_SEC_D_BLOCK_MMIO_UNKNOWN"):
        require(not rows(lines, marker), "unexpected device failure: " + marker)
    attach_errors = rows(lines, "V020_W11_MEDIA_ATTACH_ERROR")
    boot_rows = rows(lines, "V020_SIGNED_RESIDENT_BOOT")
    media_steps = rows(lines, "V020_W11_MEDIA_STEP")
    states = [line for line in lines if line.startswith("V020_STARTUP ")]
    if flush:
        require(DRIVER_OK in detail["status"] and FAILED not in detail["status"]
                and FLUSH in names(snapshot["virtio"]["guest-features"]["dev-features"]),
                "driver did not negotiate FLUSH")
        require(not attach_errors and not states and boot_rows == [(2, len(ROLES), 0)]
                and (4, 1, 2) in media_steps, "signed mount did not confirm the next BootEpoch")
        require(lines.index("V020_W11_MEDIA_STEP a=4 b=1 c=2")
                < lines.index(f"V020_SIGNED_RESIDENT_BOOT a=2 b={len(ROLES)} c=0"),
                "signed roles started before durable BootEpoch confirmation")
        require(all(operations[key] > 0 for key in COUNTERS) and before != after,
                "the writable mount lacks observed media I/O and FLUSH")
    else:
        require(FAILED in detail["status"] and DRIVER_OK not in detail["status"],
                "driver did not refuse the device before setting DRIVER_OK")
        require(attach_errors == [(3, 0, 0)] and states == [STARTUP] and not boot_rows and not media_steps
                and not rows(lines, "V020_W11_MEDIA_IO") and not rows(lines, "V020_SIGNED_RESIDENT_ROLE")
                and not rows(lines, "V020_SIGNED_RESIDENT_PROGRESS")
                and not rows(lines, "V020_SIGNED_RESIDENT_CPU"),
                "guest did not fence the writable mount at device attachment")
        require(all(operations[key] == 0 for key in COUNTERS) and before == after,
                "rejected device performed media I/O or changed the volume")
    return {**detail, "operations": operations, "before_sha256": before, "after_sha256": after,
            "boot_rows": boot_rows, "attach_errors": attach_errors}


def reopen(binary: Path, elf: Path, disk: Path, output: Path, timeout: float, *, flush: bool) -> dict:
    output.mkdir()
    before = sha(disk)
    require("," not in str(disk), "scratch path cannot contain a comma in QEMU drive options")
    argv = qemu_args(str(binary), "", elf, 0, disk, nic=False, qmp_stdio=True)
    cache = "on" if flush else "off"
    argv[argv.index("virtio-blk-device,drive=scratch")] += f",id=d08,write-cache={cache},config-wce=off"
    argv.append("-S")
    (output / "argv.json").write_text(json.dumps(argv, indent=2) + "\n")
    raw = bytearray()
    frames = []
    decoder = FrameDecoder()
    with (output / "qemu-stderr.log").open("wb") as stderr:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0)
        qmp = None
        try:
            deadline = time.monotonic() + timeout
            qmp = Qmp(PipeTransport(proc))
            require("QMP" in qmp.receive(deadline), "invalid QMP greeting")
            qmp.execute("qmp_capabilities")
            cpus = qmp.execute("query-cpus-fast")
            memory = qmp.execute("query-memory-size-summary")
            require({(cpu["cpu-index"], cpu["qom-type"]) for cpu in cpus}
                    == {(index, "cortex-a53-arm-cpu") for index in range(4)} and len(cpus) == 4
                    and memory == {"base-memory": 1024**3, "plugged-memory": 0}, "unexpected QEMU topology")
            initial = device_snapshot(qmp, disk)
            check_device(initial, flush)
            require(all(initial["operations"][k] == 0 for k in COUNTERS), "unexpected I/O before guest start")
            qmp.execute("cont")
            while time.monotonic() < deadline:
                data = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 65536, "format": "base64"})
                chunk = base64.b64decode(data, validate=True)
                raw.extend(chunk)
                require(len(raw) <= 1024 * 1024, "serial evidence exceeded its limit")
                frames.extend(decoder.feed(chunk))
                if any(frame.startswith((b"V020_STARTUP ", b"V020_SIGNED_RESIDENT_PROGRESS ",
                                         b"FAIL", b"PANIC", b"SMP_ERROR")) for frame in frames):
                    qmp.execute("stop")
                    final = device_snapshot(qmp, disk)
                    break
                time.sleep(0.015)
            else:
                raise TimeoutError("no guest mount result")
            require(decoder.loss == decoder.corrupt == 0, "serial evidence contains lost or corrupt frames")
        finally:
            shutdown(proc, qmp)
            proc.stdin.close()
            proc.stdout.close()
            (output / "serial.bin").write_bytes(raw)
            (output / "serial.txt").write_bytes(b"".join(frames))
            if qmp is not None:
                (output / "qmp.jsonl").write_text("".join(json.dumps(row) + "\n" for row in qmp.transcript))
    require(proc.returncode == 0, "QEMU did not shut down cleanly")
    lines = b"".join(frames).decode("ascii").splitlines()
    detail = check_reopen(lines, final, flush=flush, before=before, after=sha(disk))
    if flush:
        detail["policy_sha256"] = verify_disk(disk, 2, rows(lines, "V020_SIGNED_RESIDENT_ROLE"))
    detail["capture_sha256"] = {name: sha(output / name) for name in ("argv.json", "serial.bin", "serial.txt", "qmp.jsonl", "qemu-stderr.log")}
    return detail


def preserve_disk(disk: Path, output: Path, expected: str) -> str:
    """Retain independently replayable bytes before the next writable boot."""
    require(disk.stat().st_size == SCRATCH_BYTES, "unexpected scratch image size")
    with disk.open("rb") as source, output.open("xb") as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    require(output.stat().st_size == SCRATCH_BYTES and sha(output) == expected
            and sha(disk) == expected, "preserved disk differs from the observed image")
    return expected


def seal_seed_capture(seed: dict, seed_dir: Path, disk: Path) -> None:
    """Seal a returned boot's raw evidence even when its semantic check failed."""
    seed["capture_sha256"] = {
        name: sha(seed_dir / name) for name in ("serial.bin", "serial.txt", "qemu-stderr.log")
    }
    # Successful budget capture has its own stopped bytes and QMP transcript.
    # Failed-progress capture is separately recorded by the resident verifier.
    for name in ("cpu0-budget-trace.bin", "budget-qmp.jsonl", "role-syscall-abi.bin",
                 "decision-returns.bin"):
        if (seed_dir / name).is_file():
            seed["capture_sha256"][name] = sha(seed_dir / name)
    seed["preserved_disk_sha256"] = preserve_disk(disk, seed_dir / "scratch-after.raw", sha(disk))
    require(seed["status"] == "PASS",
            "could not seed a signed volume at BootEpoch 1: " + str(seed.get("error", "unknown")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fresh-elf", "reopen-elf", "qemu", "qemu-source", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    require(1 <= args.timeout <= 120, "invalid run timeout")
    binary = args.qemu.resolve(strict=True)
    identity = attest_qemu(binary, args.qemu_source)
    require(identity["qemu_pmu_patch_attested"] and identity["qemu_sha256"] == args.qemu_sha256,
            "unexpected QEMU binary or source")
    fresh = args.fresh_elf.resolve(strict=True)
    reopen_elf = args.reopen_elf.resolve(strict=True)
    images = {"fresh_elf_sha256": sha(fresh), "reopen_elf_sha256": sha(reopen_elf)}
    require(all(boot_ram_mib(image.read_bytes()) == 1024 for image in (fresh, reopen_elf)),
            "expected linked 1 GiB boot profiles")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {"id": "D08", "proof_class": "RUNTIME_QEMU", "scope": "signed-scratch-mount-flush",
              "formal_status": "NOT_RUN", "status": "FAIL", "checker_sha256": sha(Path(__file__)),
              **identity, **images}
    try:
        disk = output / "scratch.raw"
        require("," not in str(disk), "scratch path cannot contain a comma in QEMU drive options")
        create_scratch(disk)
        result["initial_disk_sha256"] = sha(disk)
        seed_dir = output / "seed"
        result["seed"] = boot(str(binary), fresh, seed_dir, args.timeout, disk, 1,
                              budget_trace=True)
        seed = result["seed"]
        seal_seed_capture(seed, seed_dir, disk)
        negative_dir = output / "without-flush"
        result["without_flush"] = reopen(binary, reopen_elf, disk, negative_dir, args.timeout,
                                         flush=False)
        negative = result["without_flush"]
        negative["preserved_disk_sha256"] = preserve_disk(
            disk, negative_dir / "scratch-after.raw", negative["after_sha256"])
        require(seed["preserved_disk_sha256"] == negative["before_sha256"]
                == negative["preserved_disk_sha256"], "retained negative media differs from the seed")
        result["with_flush"] = reopen(binary, reopen_elf, disk, output / "with-flush", args.timeout, flush=True)
        positive = result["with_flush"]
        require(negative["after_sha256"] == positive["before_sha256"]
                and set(positive["host_features"]) - {FLUSH} == set(negative["host_features"]),
                "paired boots used different media or another device feature changed")
        require(sha(fresh) == images["fresh_elf_sha256"] and sha(reopen_elf) == images["reopen_elf_sha256"]
                and sha(binary) == identity["qemu_sha256"], "an input binary changed during the run")
        result["status"] = "PASS"
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    report = json.dumps(result, indent=2) + "\n"
    (output / "summary.json").write_text(report)
    print(report, end="")
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
