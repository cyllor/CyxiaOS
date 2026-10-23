#!/usr/bin/env python3
"""Run the exact official Rust std probe at EL0 and verify AI/reclamation receipts."""
import argparse
import hashlib
import json
import re
import time
from pathlib import Path

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes

STAGES = ["STARTUP_ALLOC", "HASHMAP", "ALTSTACK", "FILE", "THREAD_TLS_SYNC", "TIMEOUT", "FUTEX_BITSET", "CLOCK_SLEEP"]


def verify(elf, output, iterations=2):
    image = elf.read_bytes()
    inspect_elf(image)
    profile = boot_profile(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest(), checks=[])
    try:
        probe_path = ROOT / "artifacts/sysroot/aarch64-musl/rust-std-probe.elf"
        probe = probe_path.read_bytes()
        assert image.count(probe) == 1, "Current exact Rust std probe ELF is not embedded"
        report["probe_sha256"] = hashlib.sha256(probe).hexdigest()
        build = json.loads(probe_path.with_name("rust-std-probe-build-report.json").read_text())
        assert build["executable"]["sha256"] == report["probe_sha256"], "Build provenance does not match guest program"
        report["target"] = build["target"]
        report["rustc"] = build["rustc"]
        report["source_sha256"] = build["source_sha256"]
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            assert b"ENTROPY_READY VIRTIO MECHANISM" in guest.text
            for pid in range(1, iterations + 1):
                start = len(guest.text)
                guest.command("posix exec rust-std-probe")
                deadline = time.monotonic() + 45
                exited = re.compile(rb"EL0 pid=" + str(pid).encode() + rb" Exited code=(\d+)\b")
                while True:
                    guest.poll()
                    done = exited.search(bytes(guest.text[start:]))
                    if done:
                        assert int(done[1]) == 0, bytes(guest.text[start:])
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError(bytes(guest.text[start:]))
                    time.sleep(.01)
                data = bytes(guest.text[start:])
                actual = [line for line in data.splitlines() if line.startswith(b"RUST_STD_PROBE")]
                expected = [b"RUST_STD_PROBE START"] + [f"RUST_STD_PROBE {stage} PASS".encode() for stage in STAGES] + [b"RUST_STD_PROBE PASS"]
                assert actual == expected, data
                assert b"panicked" not in data and b"KERNEL_FAULT" not in data, data
                row = parse_processes(guest.command("posix list"))[pid]
                expected_status = dict(state="Exited", code=0, free_pages=64,
                    heap_pages=0, heap_free=profile["heap_pages"], image_pages=0, image_free=4096,
                    thread_count=0, thread_peak=3, thread_admissions=4, thread_denials=0,
                    thread_memory_model=8193, thread_rank_model=12289,
                    heap_model=8194, cpu_model=12290, rank_model=12289)
                assert all(row.get(key) == value for key, value in expected_status.items()), row
                assert row["thread_ai_selections"] > 0, row
                assert row["thread_ai_selections"] + row["thread_guard_selections"] == row["ai_slices"], row
                fallback = [line.decode() for line in data.splitlines() if b"LINUX_ABI_UNSUPPORTED" in line]
                report["checks"].append(dict(pid=pid, stages=STAGES, process=row, unsupported_fallback_calls=fallback))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report["kernel_sha256"]
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/rust-std")
    parser.add_argument("--iterations", type=int, choices=range(1, 11), default=2)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.iterations)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
