#!/usr/bin/env python3
"""Exercise genuine upstream wl_shm and keymap FD transport in native ARM guests."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_shared_objects import snapshot, reclaimed
from verify_x11 import wait


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def markers(data):
    return [row.decode() for row in re.findall(
        rb"(?m)^(?:cyxia:/> )?(WAYLAND_SHM[^\r\n]*)\r?$", data)]


def check_markers(rows):
    assert len(rows) == 17, rows
    expected = []
    for round_number in range(2):
        child = round_number + 2
        expected += [
            f"WAYLAND_SHM SPAWN parent=1 child={child} round={round_number}",
            f"WAYLAND_SHM KEYMAP PASS round={round_number} pid={child} shift=1 caps=1 ctrl=1",
        ]
        for frame, pixels in enumerate((3072, 1776)):
            expected += [
                f"WAYLAND_SHM PIXELS PASS round={round_number} frame={frame} pixels={pixels}",
                f"WAYLAND_SHM FRAME PASS round={round_number} frame={frame} done=1 release=1 after_import_write=1",
            ]
        expected += [
            f"WAYLAND_SHM CLIENT PASS round={round_number} pid={child} frames=2",
            f"WAYLAND_SHM RECONNECT PASS round={round_number} surfaces=0",
        ]
    expected += ["WAYLAND_SHM PASS connections=2 frames=4 keymaps=2 distinct_processes=3 render=0"]
    # Child completion and parent disconnect notification may interleave. Each
    # marker is unique and every payload is checked; sequence within each frame
    # is also checked to bind the pixel read to the callback acknowledgement.
    assert sorted(rows) == sorted(expected), (rows, expected)
    for round_number in range(2):
        for frame in range(2):
            pixel_row = next(row for row in rows if
                             row.startswith(f"WAYLAND_SHM PIXELS PASS round={round_number} frame={frame} "))
            frame_row = next(row for row in rows if
                             row.startswith(f"WAYLAND_SHM FRAME PASS round={round_number} frame={frame} "))
            assert rows.index(pixel_row) < rows.index(frame_row), rows


def verify(elf, output, program, iterations=3):
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "status": "FAIL",
        "scope": "upstream libwayland fixed wl_shm pools and keymap FD transport; no renderer, pool resize or COSMIC session",
        "runs": [],
    }
    try:
        kernel = elf.read_bytes()
        inspect_elf(kernel)
        report["kernel_sha256"] = hashlib.sha256(kernel).hexdigest()
        profile = report["profile"] = boot_profile(kernel)
        report["probe_sha256"] = sha(program)
        assert kernel.count(program.read_bytes()) == 1, "Exact wl_shm probe ELF not embedded"
        built = json.loads(program.with_name("build-report.json").read_text())
        assert built["status"] == "cross-built" and built["probe"]["sha256"] == report["probe_sha256"]
        source = ROOT / "user/ported/wayland_shm_probe.c"
        report["source_sha256"] = sha(source)
        assert built["source_sha256"] == report["source_sha256"], "Probe source does not match ELF build"
        assert built["spawn_header_sha256"] == sha(source.with_name("cyxia_spawn.h"))
        report["build_report_sha256"] = sha(program.with_name("build-report.json"))
        report["archives"] = built["archives"]
        for iteration in range(1, iterations + 1):
            with Guest(elf, output / f"run-{iteration}", rng=True) as guest:
                guest.until(b"cyxia:/> ")
                before = snapshot(guest)
                reclaimed(before)
                start = len(guest.text)
                guest.command("posix exec wayland-shm-probe")
                wait(guest, start, b"EL0 pid=1 Exited code=", 45)
                data = bytes(guest.text[start:])
                assert b"EL0 pid=1 Exited code=0" in data, data[-6000:]
                assert b"KERNEL_FAULT" not in data and b"WAYLAND_SHM FAIL" not in data, data[-6000:]
                actual = markers(data)
                check_markers(actual)
                exits = re.findall(
                    rb"EL0 pid=(\d+) Exited code=(\d+) free_pages=(\d+) esr=(0x[0-9a-f]+) far=(0x[0-9a-f]+)",
                    data)
                assert [int(row[0]) for row in exits] == [2, 3, 1], exits
                assert all(int(row[1]) == int(row[3], 16) == int(row[4], 16) == 0
                           for row in exits), exits
                assert int(exits[-1][2]) == 64, exits
                processes = parse_processes(guest.command("posix list"))
                # waitpid reaps child 2 before child 3 is spawned, allowing the
                # process slot to be reused. The kernel exit records above and
                # the parent's successful waitpid checks prove all three exits;
                # posix list reports only slots still retaining process records.
                assert {1, 3} <= set(processes) <= {1, 2, 3}, processes
                for process in processes.values():
                    expected = {
                        "state": "Exited", "code": 0, "exit_signal": 0,
                        "free_pages": 64, "heap_pages": 0,
                        "heap_free": profile["heap_pages"], "image_pages": 0,
                        "image_free": 4096, "thread_count": 0,
                    }
                    assert all(process.get(key) == value for key, value in expected.items()), process
                    assert process["ai_selections"] > 0, process
                after = snapshot(guest)
                reclaimed(after)
                for name in ("ancillary_messages", "ancillary_references",
                             "shared_pages", "shared_objects", "shared_mappings"):
                    counters = after["ai"][name]
                    assert counters["requests"] == sum(counters[key] for key in
                        ("committed", "denied", "capacity", "invalid", "failed")), (name, counters)
                    assert 0 < counters["ai"] <= counters["approved"] <= counters["proposals"] <= counters["requests"], (name, counters)
                    assert counters["grant_units"] == counters["release_units"] > 0, (name, counters)
                    assert counters["denied"] == counters["capacity"] == counters["invalid"] == counters["failed"] == 0, (name, counters)
                report["runs"].append({
                    "iteration": iteration, "markers": actual,
                    "exit_records": [[field.decode() for field in row] for row in exits],
                    "retained_processes": list(processes.values()), "before": before, "after": after,
                })
        assert sha(elf) == report["kernel_sha256"] and sha(program) == report["probe_sha256"]
        assert sha(source) == report["source_sha256"]
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
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--iterations", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.probe.resolve(), args.iterations)
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")
