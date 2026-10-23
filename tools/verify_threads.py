"""Verify real musl pthreads and bounded local-AI accounting in an ARM guest."""
import argparse
import hashlib
import json
from pathlib import Path

from check_elf import inspect_elf, boot_profile
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import wait


STAGES = ["BASIC", "SYNC", "SIGNAL", "FUTEX", "LIMIT_REUSE", "GROUP_EXIT"]


def verify(elf, output, iterations=3):
    image = elf.read_bytes()
    inspect_elf(image)
    profile = boot_profile(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest(), checks=[])
    try:
        probe = (ROOT / "artifacts/sysroot/aarch64-musl/thread-probe.elf").read_bytes()
        assert image.count(probe) == 1, "Exact thread-probe ELF is not embedded"
        report["probe_sha256"] = hashlib.sha256(probe).hexdigest()
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            for pid in range(1, iterations + 1):
                start = len(guest.text)
                guest.command("posix exec thread-probe")
                wait(guest, start, f"EL0 pid={pid} Exited code=0".encode(), 30)
                data = bytes(guest.text[start:])
                actual = [line for line in data.splitlines() if line.startswith(b"THREAD_PROBE")]
                expected = [f"THREAD_PROBE {stage} PASS".encode() for stage in STAGES]
                assert actual == expected + [b"THREAD_PROBE PASS"], data
                row = parse_processes(guest.command("posix list"))[pid]
                expected_status = dict(
                    state="Exited", code=0, free_pages=64,
                    heap_pages=0, heap_free=profile['heap_pages'], image_pages=0, image_free=4096,
                    thread_count=0, thread_peak=8, thread_admissions=47, thread_denials=1,
                    thread_memory_model=8193, thread_rank_model=12289,
                    cpu_model=12290, rank_model=12289,
                )
                assert all(row.get(key) == value for key, value in expected_status.items()), row
                assert row["preemptions"] > 0 and row["thread_ai_selections"] > 0, row
                assert row["thread_ai_selections"] + row["thread_guard_selections"] == row["ai_slices"], row
                report["checks"].append(dict(pid=pid, stages=STAGES, process=row))
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
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/threads")
    parser.add_argument("--iterations", type=int, choices=range(1, 11), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.iterations)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
