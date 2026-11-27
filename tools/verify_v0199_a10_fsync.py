#!/usr/bin/env python3
"""Retain and verify the signed scratch FSYNC clean cold-replay subcase."""

import argparse
import base64
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from check_prototype_evidence import _pairs, read_json, require, safe_path
from transport import FrameDecoder
from verify_v020_fsync_scratch import FINAL, FINAL_LSN, LEGACY_FINAL_LSN, verify_disk
from verify_v020_production import Production, run, source_manifest
from verify_v13_boot_receipt import _exchanges
from v020_production_media import FSYNC_POLICY_SHA256, verify_signed_disk, verify_signed_receipt_view
from v020_production_modes import Modes, rows
from v020_production_qemu import SCRATCH_BYTES, create_scratch, qemu_args, sha


ROOT = Path(__file__).resolve().parents[1]
PMU_PATCH = ROOT / "tools/qemu/cyxia-per-vcpu-pmu.patch"
BASELINE = ROOT / "docs/design/baselines/v0.19.9-implementation-spec.txt"
FRESH = Modes(authenticated_net=True, fsync_scratch=True)
REOPEN = replace(FRESH, media_reopen=True)
STAGES = (("boot-1", "fresh", "committed", FRESH), ("boot-2", "reopen", "reopened", REOPEN))
DATA_FILES = ("native-page.bin", "qmp.jsonl", "serial.bin", "serial.txt", "source-manifest.json")
RING_READ = {"device": "cyxlog", "size": 1048576, "format": "base64"}


def _copy_sparse(source, target):
    zeros = bytes(1024 * 1024)
    with source.open("rb") as src, target.open("xb") as dst:
        dst.truncate(SCRATCH_BYTES)
        for index, data in enumerate(iter(lambda: src.read(len(zeros)), b"")):
            if data != zeros:
                dst.seek(index * len(zeros))
                dst.write(data)


def _locked_build(root, commit):
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "invalid pinned source commit")
    build_path = safe_path(root, "build.json")
    build = read_json(build_path)
    tree = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", f"{commit}^{{tree}}"],
                                   text=True).strip()
    require(build["source_commit"] == commit and build["source_tree"] == tree,
            "build record differs from the pinned source")
    for _, profile, _, modes in STAGES:
        elf = safe_path(root, f"{profile}.elf")
        require(build["profiles"][profile] == {
            "elf_sha256": sha(elf), "features": ["smp-selftest", *modes.features(True).split(",")],
        }, "boot image or feature record differs from the build")
    return build_path, build


def capture(root: Path, qemu_sha256: str, timeout: float) -> None:
    """Run only the successful clean-cold-restart pair on dedicated media."""
    binary = shutil.which("qemu-system-aarch64")
    require(binary is not None and sha(Path(binary)) == qemu_sha256, "wrong pinned QEMU binary")
    require(all(not (root / path).exists() and not (root / path).is_symlink() for path in
                ("boot-1", "boot-2", "committed.raw", "reopened.raw")), "capture already started")
    committed, reopened = root / "committed.raw", root / "reopened.raw"
    create_scratch(committed)
    for folder, profile, disk_stem, modes in STAGES:
        disk = root / f"{disk_stem}.raw"
        report = run(safe_path(root, f"{profile}.elf"), root / folder, timeout, staging=True,
                     modes=modes, boot_disk=disk, qmp_stdio=True)
        require(report["status"] == "PASS" and report.get("qemu_exit") == 0,
                f"{folder} did not finish cleanly: {report.get('error')}")
        require(report["qemu_sha256"] == qemu_sha256 and sha(Path(binary)) == qemu_sha256,
                "QEMU binary changed during capture")
        verify_disk(disk, modes.media_reopen)
        if not modes.media_reopen:
            _copy_sparse(committed, reopened)
            require(sha(committed) == sha(reopened), "cold-reopen input differs from the committed disk")


def _launch(argv, profile, disk):
    require(isinstance(argv, list) and all(isinstance(arg, str) for arg in argv),
            "invalid QEMU launch record")
    kernel = Path(argv[argv.index("-kernel") + 1])
    net = re.fullmatch(r"user,id=n0,hostfwd=tcp:127\.0\.0\.1:([0-9]+)-:7",
                       argv[argv.index("-netdev") + 1])
    drive = re.fullmatch(r"file=([^,]+),if=none,id=scratch,format=raw,cache=none",
                         argv[argv.index("-drive") + 1])
    require(net is not None and 0 < int(net[1]) < 65536 and drive is not None
            and Path(argv[0]).is_absolute() and kernel.is_absolute(), "wrong local QEMU attachments")
    scratch = Path(drive[1])
    require(kernel.name == profile and scratch.name == disk and scratch.parent == kernel.parent,
            "wrong captured source or scratch path")
    require(argv == qemu_args(argv[0], "", kernel, int(net[1]), scratch=scratch, rng=True, qmp_stdio=True),
            "unexpected Cortex-A53 QEMU launch options")
    return kernel.parent


def _native_capture(path, serial, expected_page, location):
    require(path.stat().st_size <= 8 * 1024**2, "QMP trace size bound")
    with path.open(encoding="utf-8") as stream:
        trace = [json.loads(line, object_pairs_hook=_pairs) for line in stream]
    exchanges = _exchanges(trace)
    commands = [req["execute"] for req, _ in exchanges]
    require(len(commands) >= 6 and commands[:2] == ["qmp_capabilities", "query-cpus-fast"]
            and all(cmd == "ringbuf-read" for cmd in commands[2:-3])
            and commands[-3:] == ["stop", "pmemsave", "quit"], "wrong QMP capture ordering")
    greeting = trace[0]["message"]["QMP"]["version"]["qemu"]
    require(greeting == {"major": 10, "minor": 2, "micro": 2}, "wrong QMP emulator version")
    lifecycle = []
    for line in trace:
        message = line["message"]
        command = message.get("execute")
        if command in ("stop", "pmemsave", "quit"):
            lifecycle.append(command)
        if "event" in message:
            lifecycle.append(message["event"])
    require(lifecycle == ["stop", "STOP", "pmemsave", "quit", "SHUTDOWN"],
            "capture did not observe stop before the page read and shutdown after quit")
    cpus = exchanges[1][1]
    require(isinstance(cpus, list) and sorted(cpu["cpu-index"] for cpu in cpus) == [0, 1, 2, 3]
            and all(cpu["qom-type"] == "cortex-a53-arm-cpu" and cpu["target"] == "aarch64"
                    for cpu in cpus), "QMP did not enumerate four Cortex-A53 cores")
    raw = bytearray()
    for command, response in exchanges[2:-3]:
        require(command.get("arguments") == RING_READ, "wrong QMP UART source")
        raw.extend(base64.b64decode(response, validate=True))
        require(len(raw) <= 2 * 1024**2, "UART size bound")
    require(raw == serial, "UART bytes differ from the QMP capture")
    require(exchanges[-2][0].get("arguments") == {
        "val": location["pa"], "size": 4096, "filename": str(expected_page),
    }, "stopped guest page does not match the ELF evidence symbol")
    decoder = FrameDecoder()
    decoded = b"".join(decoder.feed(serial))
    require(decoder.frames > 0 and decoder.loss == decoder.corrupt == 0 and not decoder.buffer,
            "incomplete UART capture")
    return decoded


def _blank_sha256():
    hasher = sha256()
    zero = bytes(1024 * 1024)
    for _ in range(SCRATCH_BYTES // len(zero)):
        hasher.update(zero)
    return hasher.hexdigest()


def verify_archive(root: Path, commit: str, qemu_sha256: str, patch_sha256: str) -> dict:
    """Recheck QMP, UART, the stopped page, and both final disk images."""
    require(re.fullmatch(r"[0-9a-f]{64}", qemu_sha256) is not None and sha(PMU_PATCH) == patch_sha256,
            "invalid pinned emulator inputs")
    build_path, build = _locked_build(root, commit)
    baseline = sha(BASELINE)
    sources = source_manifest()
    last_disk_sha256 = _blank_sha256()
    result = []
    final_lsn = None
    for index, (folder, profile, disk_stem, modes) in enumerate(STAGES, 1):
        case = root / folder
        require(not case.is_symlink() and case.is_dir(), "missing or symlinked boot archive")
        report = read_json(safe_path(case, "summary.json"))
        require(report["status"] == "PASS" and report["qemu_exit"] == 0
                and report["qemu_sha256"] == qemu_sha256 and report["qmp_transport"] == "stdio",
                "broker did not capture a complete pinned QEMU run")
        require(report["scratch_before_sha256"] == last_disk_sha256,
                "cold reboot input differs from the preceding verified disk")
        evidence = {name: sha(safe_path(case, name)) for name in DATA_FILES}
        require(all(report["evidence_sha256"].get(name) == value for name, value in evidence.items())
                and read_json(safe_path(case, "source-manifest.json")) == sources, "boot archive changed")
        elf, disk = safe_path(root, f"{profile}.elf"), safe_path(root, f"{disk_stem}.raw")
        elf_digest = sha(elf)
        require(elf_digest == report["elf_sha256"]
                and elf_digest == build["profiles"][profile]["elf_sha256"],
                "boot image differs from the captured run")
        require(disk.stat().st_size == SCRATCH_BYTES, "wrong scratch image size")
        last_disk_sha256 = sha(disk)
        require(last_disk_sha256 == report["scratch_disk"]["scratch_after_sha256"],
                "archived disk differs from the stopped run")
        original_root = _launch(report["argv"], elf.name, disk.name)
        checker = Production(staging=True, modes=modes)
        uart_path = safe_path(case, "serial.bin")
        require(0 < uart_path.stat().st_size <= 2 * 1024**2, "UART size bound")
        decoded = _native_capture(safe_path(case, "qmp.jsonl"), uart_path.read_bytes(),
                                  original_root / folder / "native-page.bin",
                                  checker.profile(elf.read_bytes()))
        page = safe_path(case, "native-page.bin")
        require(decoded == safe_path(case, "serial.txt").read_bytes() and page.stat().st_size == 4096,
                "decoded UART or native page bytes differ")
        observations = checker.validate(decoded, page.read_bytes(), 4)
        lines = decoded.decode("ascii").splitlines()
        require(observations["staging_confirmed_epoch"] == index
                and observations["signed_config_bound_boot_epoch"] == index,
                "mounted signed epoch differs from the FSYNC sequence")
        event = "V020_FSYNC_RECOVERED" if modes.media_reopen else "V020_FSYNC_COMMITTED"
        if index == 1:
            final_lsn = next((lsn for lsn in (FINAL_LSN, LEGACY_FINAL_LSN)
                              if rows(lines, event) == [(lsn, 7, 29)]), None)
            require(final_lsn is not None, "unrecognized FSYNC terminal")
        fields = (2, final_lsn, 7) if modes.media_reopen else (final_lsn, 7, 29)
        flushes = 5 if modes.media_reopen else 12
        io = rows(lines, "V020_W11_MEDIA_IO")
        require(rows(lines, event) == [fields] and len(io) == 1 and io[0][2] == flushes,
                "native FSYNC terminal or flush count differs")
        require(verify_signed_disk(disk, index, fsync_scratch=True) == FSYNC_POLICY_SHA256,
                "wrong signed FSYNC disk policy")
        verify_signed_receipt_view(disk, observations["signed_receipt_view_sha256"])
        result.append({
            "boot_epoch": index, "elf_sha256": elf_digest,
            "disk_sha256": last_disk_sha256, "journal_sha256": verify_disk(disk, modes.media_reopen, final_lsn),
            "flush_requests": flushes, "qemu_exit": report["qemu_exit"], "raw_evidence_sha256": evidence,
        })
    return {
        "schema": "cyxia-v0199-runtime-subcase/v1",
        "status": "PASS",
        "scope": "A10-A confirmed signed scratch FSYNC after clean cold restart; SEC-F05 recovery subcase",
        "formal_runtime_qemu": {"A10": "NOT_RUN", "SEC-F05": "NOT_RUN"},
        "covered": ["confirmed DONE receipt", "highest committed file write sequence after cold replay"],
        "pending": ["all crash boundaries", "metadata corruption refusal matrix",
                    "cross-endpoint and cache eviction", "complete authorized production service"],
        "source_commit": commit, "source_tree": build["source_tree"], "build_sha256": sha(build_path),
        "baseline_sha256": baseline, "qemu_sha256": qemu_sha256, "patch_sha256": patch_sha256,
        "checker_sha256": sha(Path(__file__)),
        "file_write_seq": 7, "commit_lsn": final_lsn, "file_block_sha256": sha256(FINAL).hexdigest(),
        "boots": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--patch-sha256", required=True)
    parser.add_argument("--capture", action="store_true",
                        help="start the two boots in an archive already containing both ELFs and build.json")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    try:
        root = args.archive.resolve(strict=True)
        require(sha(PMU_PATCH) == args.patch_sha256, "wrong pinned QEMU source patch")
        if args.capture:
            _locked_build(root, args.source_commit)
            capture(root, args.qemu_sha256, args.timeout)
        result = verify_archive(root, args.source_commit, args.qemu_sha256, args.patch_sha256)
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as error:
        print(f"Invalid FSYNC subcase: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
