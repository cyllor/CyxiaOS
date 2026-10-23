#!/usr/bin/env python3
"""Verify shared OFDs across actual ARM EL0 processes and final object reclamation."""
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
from verify_x11 import wait


STAGES = ["FILE_DESCRIPTION", "UNLINK_LIFETIME", "EVENT_DESCRIPTION",
          "EPOLL_DESCRIPTION", "SOCKET_DESCRIPTION", "PEER_CREDENTIALS", "CREATOR_EXIT", "ATOMIC_REUSE"]
RETRY_STAGES = [f"RETRY_{kind}_{operation}" for kind in ("PIPE", "EVENT", "PTY")
                for operation in ("READ", "WRITE")]


def release_blocked_worker(guest, start, stage):
    wait(guest, start, f"FD_SHARE_PROBE {stage} WAIT".encode(), 30)
    before = parse_processes(guest.command("posix list"))[1]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        after = parse_processes(guest.command("posix list"))[1]
        assert after["state"] in ("Running", "Waiting"), after
        if after["waits"] > before["waits"]:
            # In this phase the leader only stats the absent gate and yields.
            # The I/O worker is the only thread that can increase waits. The
            # original object remains unready until after the gate opens.
            guest.command(f"touch /ofd-{stage}")
            return dict(stage=stage, waits_before=before["waits"], waits_after=after["waits"])
    raise AssertionError(f"No actual blocking I/O witnessed for {stage}")


def objects(output):
    rows = re.findall(rb"(?m)^OFD_OBJECTS live=(\d+) references=(\d+) retired=(\d+) capacity=(\d+) epolls=(\d+) watches=(\d+)(?: [a-z_]+=\d+)*\r?$", output)
    if len(rows) != 1:
        raise AssertionError("Missing or ambiguous global OFD receipt: " + repr(output))
    return dict(zip(("live", "references", "retired", "capacity", "epolls", "watches"), map(int, rows[0])))


def object_snapshot(guest):
    start = len(guest.text)
    guest.command("ai system")
    wait(guest, start, b"AI_SYSTEM_END\r\n", 10)
    return objects(bytes(guest.text[start:]))


def verify(elf, output, iterations=3):
    image = elf.read_bytes()
    inspect_elf(image)
    profile = boot_profile(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest(), checks=[])
    try:
        probe_path = ROOT / "artifacts/sysroot/aarch64-musl/fd-share-probe.elf"
        probe = probe_path.read_bytes()
        assert image.count(probe) == 1, "Exact fd-share-probe ELF missing"
        report["probe_sha256"] = hashlib.sha256(probe).hexdigest()
        report["source_sha256"] = hashlib.sha256((ROOT / "user/ported/fd_share_probe.c").read_bytes()).hexdigest()
        layout = json.loads(probe_path.with_name("fd-share-probe-layout.json").read_text())
        assert layout["sha256"] == report["probe_sha256"], "Probe build identity differs"
        assert layout["source_sha256"] == report["source_sha256"], "Probe source changed since link"
        report["libc_sha256"] = layout["libc_sha256"]
        report["driver_sha256"] = layout["driver_sha256"]
        for iteration in range(iterations):
            with Guest(elf, output / f"run-{iteration + 1}", rng=True) as guest:
                guest.until(b"cyxia:/> ")
                baseline = object_snapshot(guest)
                assert baseline["live"] == baseline["references"] == 0, baseline
                assert baseline["epolls"] == baseline["watches"] == 0, baseline
                start = len(guest.text)
                guest.command("posix exec fd-share-probe")
                retry_witnesses = [release_blocked_worker(guest, start, stage) for stage in RETRY_STAGES]
                wait(guest, start, b"EL0 pid=1 Exited code=0", 45)
                data = bytes(guest.text[start:])
                actual = re.findall(rb"(?m)^(?:cyxia:/> )?(FD_SHARE_PROBE[^\r\n]*)\r?$", data)
                expected = [f"FD_SHARE_PROBE {stage} PASS".encode() for stage in STAGES]
                expected += [f"FD_SHARE_PROBE {stage} {state}".encode() for stage in RETRY_STAGES
                             for state in ("WAIT", "PASS")]
                expected += [b"FD_SHARE_PROBE PASS"]
                assert actual == expected, data
                assert b"KERNEL_FAULT" not in data and b"panicked" not in data, data
                listing = guest.command("posix list")
                final = object_snapshot(guest)
                assert final == baseline, (baseline, final)
                processes = parse_processes(listing)
                assert len(processes) >= 3, processes
                for row in processes.values():
                    for field, expected_value in dict(state="Exited", code=0, free_pages=64,
                            heap_pages=0, image_pages=0, thread_count=0,
                            heap_free=profile["heap_pages"], image_free=4096).items():
                        assert row.get(field) == expected_value, (field, row)
                    assert row["rank_model"] == 12289 and row["ai_selections"] > 0, row
                report["checks"].append(dict(iteration=iteration + 1, stages=STAGES + RETRY_STAGES,
                                           retry_witnesses=retry_witnesses,
                                           objects_before=baseline, objects_after=final,
                                           processes=list(processes.values())))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report["kernel_sha256"]
        assert hashlib.sha256(probe_path.read_bytes()).hexdigest() == report["probe_sha256"]
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/fd-share")
    parser.add_argument("--iterations", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.iterations)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
