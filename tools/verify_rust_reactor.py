#!/usr/bin/env python3
"""Verify genuine pinned Mio in EL0 with exact readiness and cleanup evidence."""
import argparse
import json
from pathlib import Path
import re

from build_sysroot import digest, inspect_elf as inspect_program
from check_elf import boot_profile, inspect_elf
from shell import Guest
from verify_egl import check_accounting
from verify_ported import parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import wait

CHECKS = [
    "poll-create", "empty-timeout", "waker-cycle-1", "waker-cycle-2", "waker-cycle-3",
    "waker-coalesces", "waker-thread", "socket-first-edge", "socket-unread-quiet",
    "socket-write-while-readable", "socket-drain", "socket-rearm-after-drain",
    "socket-reregister-token", "socket-deregister", "socket-register-again",
    "socket-peer-close", "timer-create", "timer-first-expiration", "timer-rearm",
    "timer-cancel", "cleanup",
]
START = "RUST_REACTOR START mio=1.1.1 static=1"
SUCCESS = "RUST_REACTOR PASS mio=1.1.1 cycles=3 cosmic_runtime=0"


def validate(data):
    rows = [row.decode() for row in re.findall(rb"(?m)^(?:cyxia:/> )?(RUST_REACTOR[^\r\n]*)\r?$", data)]
    expected = [START] + ["RUST_REACTOR CHECK name=" + name + " result=PASS" for name in CHECKS] + [SUCCESS]
    timers = []
    normal = []
    for row in rows:
        if row.startswith("RUST_REACTOR TIMER "):
            match = re.fullmatch(r"RUST_REACTOR TIMER cycle=([12]) expirations=1 elapsed_ns=(\d+)", row)
            assert match, row
            cycle, elapsed = map(int, match.groups())
            assert 20_000_000 <= elapsed < 2_000_000_000, row
            previous = "timer-first-expiration" if cycle == 1 else "timer-rearm"
            assert normal[-1:] == ["RUST_REACTOR CHECK name=" + previous + " result=PASS"], row
            timers.append(cycle)
        else:
            normal.append(row)
    assert normal == expected, (normal, expected)
    assert timers == [1, 2], timers
    assert data.count(b"RUST_REACTOR") == len(rows), "Damaged or interleaved marker"
    assert b"panicked" not in data and b"KERNEL_FAULT" not in data
    return rows


def verify(elf, probe, output, runs=3):
    if output.exists():
        raise FileExistsError("Select a fresh immutable evidence directory")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope="pinned Mio 1.1.1 readiness/waker/monotonic-timer foundation",
                  calloop_verified=False, cosmic_runtime_verified=False, runs=[])
    try:
        kernel = elf.read_bytes()
        inspect_elf(kernel)
        profile = report["profile"] = boot_profile(kernel)
        report["kernel_sha256"] = digest(elf)
        report["probe_sha256"] = digest(probe)
        assert kernel.count(probe.read_bytes()) == 1, "Exact reactor executable not embedded"
        build_path = probe.parent / "build-report.json"
        built = json.loads(build_path.read_text())
        assert built["status"] == "cross-built"
        actual = inspect_program(probe)
        for key in ("sha256", "bytes", "entry", "at_phdr", "at_phent", "at_phnum", "program_headers"):
            assert actual[key] == built["probe"][key], ("ELF layout changed", key)
        inputs = {Path(path): value for paths in
                  (built["inputs_sha256"], built["native_inputs_sha256"], built["rust_target_rlibs_sha256"])
                  for path, value in paths.items()}
        inputs[build_path] = digest(build_path)
        inputs[Path(__file__)] = digest(Path(__file__))
        inputs.update({probe.parent / "target" / name: value for name, value in built["compiled_crates_sha256"].items()})
        for path, value in inputs.items():
            assert digest(path) == value, ("Input changed", str(path))
        report["inputs_sha256"] = {str(path): value for path, value in inputs.items()}
        report["build_report_sha256"] = digest(build_path)
        report["crate_features"] = built["crate_features"]
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            before = snapshot(guest)
            reclaimed(before)
            report["before"] = before
            for pid in range(1, runs + 1):
                start = len(guest.text)
                guest.command("posix exec rust-reactor-probe")
                wait(guest, start, f"EL0 pid={pid} Exited code=".encode(), 40)
                data = bytes(guest.text[start:])
                process = parse_processes(guest.command("posix list"))[pid]
                after = snapshot(guest)
                row = {"pid": pid, "process": process, "after": after}
                report["runs"].append(row)
                expected = dict(state="Exited", code=0, exit_signal=0, esr=0, far=0,
                                free_pages=64, heap_pages=0, heap_free=profile["heap_pages"],
                                image_pages=0, image_free=4096, thread_count=0,
                                thread_peak=2, thread_admissions=1, thread_denials=0)
                assert all(process.get(key) == value for key, value in expected.items()), process
                assert process["ai_selections"] > 0 and process["thread_ai_selections"] > 0
                row["markers"] = validate(data)
                check_accounting(before, after, minimum_rejections=0)
                for name in ("thread", "unix"):
                    assert after["ai"][name]["committed"] > before["ai"][name]["committed"], name
                before = after
        assert digest(elf) == report["kernel_sha256"] and digest(probe) == report["probe_sha256"]
        for path, value in inputs.items():
            assert digest(path) == value, ("Input changed during run", str(path))
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.probe.resolve(), args.output.resolve(), args.runs)
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")
