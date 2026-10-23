"""Verify monotonic timerfd in real ARM EL0 processes, threads and epoll."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import wait


def release_reader(guest, start, stage):
    wait(guest, start, f"TIMERFD_PROBE {stage} WAIT".encode(), 30)
    before = parse_processes(guest.command("posix list"))[1]
    guest.command(f"touch /timer-{stage}-start")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        after = parse_processes(guest.command("posix list"))[1]
        assert after["state"] in ("Running", "Waiting"), after
        if after["waits"] > before["waits"]:
            guest.command(f"touch /timer-{stage}-finish")
            return dict(stage=stage, waits_before=before["waits"], waits_after=after["waits"])
    raise AssertionError(f"No blocked reader witnessed: {stage}")


def verify(elf, output, iterations=3):
    if (output / "summary.json").exists():
        raise FileExistsError(f"Preserve existing verification evidence: {output}")
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", scope="CLOCK_MONOTONIC timerfd; level/oneshot epoll; no REALTIME or ET", runs=[])
    try:
        kernel = elf.read_bytes()
        inspect_elf(kernel)
        profile = boot_profile(kernel)
        report["kernel_sha256"] = hashlib.sha256(kernel).hexdigest()
        probe_path = ROOT / "artifacts/sysroot/aarch64-musl/timerfd-probe.elf"
        probe = probe_path.read_bytes()
        assert kernel.count(probe) == 1, "Exact timerfd ELF not embedded"
        report["probe_sha256"] = hashlib.sha256(probe).hexdigest()
        report["source_sha256"] = hashlib.sha256((ROOT / "user/ported/timerfd_probe.c").read_bytes()).hexdigest()
        report["verifier_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        layout = json.loads(probe_path.with_name("timerfd-probe-layout.json").read_text())
        assert layout["sha256"] == report["probe_sha256"]
        assert layout["source_sha256"] == report["source_sha256"]
        report["build"] = layout
        for iteration in range(iterations):
            with Guest(elf, output / f"run-{iteration + 1}", rng=True) as guest:
                guest.until(b"cyxia:/> ")
                before = snapshot(guest)
                reclaimed(before)
                start = len(guest.text)
                guest.command("posix exec timerfd-probe")
                witnesses = [release_reader(guest, start, stage) for stage in ("REARM", "REUSE")]
                wait(guest, start, b"EL0 pid=1 Exited code=0", 30)
                data = bytes(guest.text[start:])
                stages = re.findall(rb"(?m)^(?:cyxia:/> )?TIMERFD_PROBE ([A-Z_]+) (PASS|WAIT)\r?$", data)
                assert stages == [(b"CHILD", b"PASS"), (b"ABI", b"PASS"),
                                  (b"REARM", b"WAIT"), (b"REARM", b"PASS"),
                                  (b"REUSE", b"WAIT"), (b"REUSE", b"PASS")], data
                counts = re.findall(rb"(?m)^TIMERFD_PROBE PASS checks=(\d+)\r?$", data)
                assert len(counts) == 1 and int(counts[0]) == 73, data
                assert b"TIMERFD_PROBE FAIL" not in data and b"KERNEL_FAULT" not in data and b"panicked" not in data
                assert re.findall(rb"EL0 pid=2 Exited code=(\d+) free_pages=(\d+) esr=(0x[0-9a-f]+) far=(0x[0-9a-f]+)", data) == [
                    (b"0", b"56", b"0x0", b"0x0")], data
                row = parse_processes(guest.command("posix list"))[1]
                for key, value in dict(state="Exited", code=0, exit_signal=0, esr=0, far=0, free_pages=64, heap_pages=0,
                                       heap_free=profile["heap_pages"], image_pages=0,
                                       image_free=4096, thread_count=0, thread_peak=2).items():
                    assert row[key] == value, (key, row)
                assert row["rank_model"] == 12289 and row["ai_selections"] > 0, row
                after = snapshot(guest)
                reclaimed(after)
                for domain in ("process", "thread", "anonymous", "elf", "spawn_receipt",
                               "unix", "pipe", "pty", "ancillary_messages", "ancillary_references",
                               "shared_pages", "shared_objects", "shared_mappings"):
                    counters = after["ai"][domain]
                    assert counters["requests"] == sum(counters[key] for key in
                                                        ("committed", "denied", "capacity", "invalid", "failed"))
                    assert counters["grant_units"] == counters["release_units"], (domain, counters)
                report["runs"].append(dict(iteration=iteration + 1, checks=int(counts[0]),
                                           blocked_read_witnesses=witnesses, process=row,
                                           before=before, after=after))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report["kernel_sha256"]
        assert hashlib.sha256(probe_path.read_bytes()).hexdigest() == report["probe_sha256"]
        assert hashlib.sha256((ROOT / "user/ported/timerfd_probe.c").read_bytes()).hexdigest() == report["source_sha256"]
        assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == report["verifier_sha256"]
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.iterations)
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")
