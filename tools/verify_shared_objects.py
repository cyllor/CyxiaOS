"""Verify real EL0 SCM_RIGHTS/memfd behavior and object/AI grant conservation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ai_system import parse_snapshot
from verify_ported import parse_processes
from verify_x11 import wait

STAGES = {
    "scm-probe": ["CREATOR_EXIT", "INFLIGHT_IDENTITY", "STREAM_BOUNDARY", "FAILURE_ATOMICITY",
                  "CONTROL_TRUNCATION", "FD_CAPACITY", "QUEUE_BACKPRESSURE", "SHORT_WRITE",
                  "BLOCKING_SEND_BOUNDARY", "UNRECEIVED_RELEASE"],
    "memfd-probe": ["FILE_MAPPING_BOUNDS", "CROSS_PROCESS_ALIASES", "SCM_CREATOR_EXIT",
                    "PTE_PERMISSIONS", "AI_DENIAL_ATOMICITY", "RECLAIM_ZERO",
                    "POSITIONED_IO", "WRITE_SEAL_ATOMICITY", "CROSS_PROCESS_WRITE_SEAL",
                    "SEALED_PRIVATE_SNAPSHOT"],
}


def snapshot(guest):
    start = len(guest.text)
    guest.command("ai system")
    wait(guest, start, b"AI_SYSTEM_END\r\n", 10)
    data = bytes(guest.text[start:])
    result = {"ai": parse_snapshot(data)}
    for name in ("OFD_OBJECTS", "ANCILLARY_OBJECTS", "SHARED_OBJECTS"):
        rows = re.findall(rb"(?m)^" + name.encode() + rb" ([^\r\n]+)\r?$", data)
        assert len(rows) == 1, (name, data)
        fields = dict(field.decode().split("=", 1) for field in rows[0].split() if b"=" in field)
        result[name] = {key: int(value) if value.isdecimal() else value for key, value in fields.items()}
    return result


def reclaimed(state):
    for field in ("live", "references", "epolls", "watches", "fd_refs", "staged_refs",
                  "inflight_refs", "staged_messages", "inflight_messages"):
        assert state["OFD_OBJECTS"][field] == 0, state["OFD_OBJECTS"]
    for field in ("messages", "references", "staged_messages", "inflight_messages", "staged_refs", "inflight_refs"):
        assert state["ANCILLARY_OBJECTS"][field] == 0, state["ANCILLARY_OBJECTS"]
    shared = state["SHARED_OBJECTS"]
    for field in ("objects", "pages", "mappings", "description_refs", "mapping_refs", "grant_reserved", "grant_used"):
        assert shared[field] == 0, shared
    assert shared["available"] == "true" and shared["free_pages"] == shared["page_capacity"] == 4096, shared


def verify(elf, output, probe_name, iterations):
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "FAIL", "scope": "bounded SCM_RIGHTS/shared-file foundation; not wl_shm or COSMIC acceptance", "runs": []}
    try:
        kernel = elf.read_bytes()
        inspect_elf(kernel)
        profile = boot_profile(kernel)
        report["kernel_sha256"] = hashlib.sha256(kernel).hexdigest()
        program_path = ROOT / "artifacts/sysroot/aarch64-musl" / (probe_name + ".elf")
        program = program_path.read_bytes()
        assert kernel.count(program) == 1, "Exact probe not embedded"
        layout = json.loads(program_path.with_name(probe_name + "-layout.json").read_text())
        source = ROOT / "user/ported" / (probe_name.replace("-", "_") + ".c")
        report["probe_sha256"] = hashlib.sha256(program).hexdigest()
        report["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        assert layout["sha256"] == report["probe_sha256"] and layout["source_sha256"] == report["source_sha256"]
        report["libc_sha256"] = layout["libc_sha256"]
        prefix = probe_name.replace("-", "_").upper()
        for iteration in range(1, iterations + 1):
            with Guest(elf, output / f"run-{iteration}", rng=True) as guest:
                guest.until(b"cyxia:/> ")
                before = snapshot(guest)
                reclaimed(before)
                start = len(guest.text)
                guest.command("posix exec " + probe_name)
                wait(guest, start, b"EL0 pid=1 Exited code=", 45)
                data = bytes(guest.text[start:])
                assert b"EL0 pid=1 Exited code=0" in data and b"KERNEL_FAULT" not in data, data[-5000:]
                actual = re.findall(rb"(?m)^(?:cyxia:/> )?(" + prefix.encode() + rb"[^\r\n]*)\r?$", data)
                expected = [f"{prefix} {stage} PASS".encode() for stage in STAGES[probe_name]] + [f"{prefix} PASS".encode()]
                assert actual == expected, (actual, expected)
                processes = parse_processes(guest.command("posix list"))
                for row in processes.values():
                    if probe_name == "memfd-probe" and row["pid"] == 4:
                        assert row["state"] in ("Exited", "Fault") and row["code"] == 139 and row["exit_signal"] == 11, row
                        assert row["far"] == 0x06000000 and row["esr"] >> 26 == 0x24 and row["esr"] & 0x7f == 0x4f, row
                    else:
                        assert row["state"] == "Exited" and row["code"] == 0 and row["exit_signal"] == 0, row
                    for field, value in {"free_pages": 64, "heap_pages": 0, "image_pages": 0,
                                         "heap_free": profile["heap_pages"], "image_free": 4096, "thread_count": 0}.items():
                        assert row[field] == value, (field, row)
                    assert row["ai_selections"] > 0, row
                after = snapshot(guest)
                reclaimed(after)
                if probe_name == "memfd-probe":
                    assert after["ai"]["shared_pages"]["denied"] > before["ai"]["shared_pages"]["denied"]
                for name in ("ancillary_messages", "ancillary_references", "shared_pages", "shared_objects", "shared_mappings"):
                    counters = after["ai"][name]
                    assert counters["requests"] == sum(counters[k] for k in ("committed", "denied", "capacity", "invalid", "failed")), counters
                    assert counters["ai"] <= counters["approved"] <= counters["proposals"] <= counters["requests"], counters
                    assert counters["grant_units"] == counters["release_units"], (name, counters)
                    if name.startswith("ancillary") or probe_name == "memfd-probe":
                        assert counters["ai"] > 0 and counters["grant_units"] > 0, (name, counters)
                report["runs"].append({"iteration": iteration, "stages": STAGES[probe_name],
                                       "before": before, "after": after, "processes": list(processes.values())})
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report["kernel_sha256"]
        assert hashlib.sha256(program_path.read_bytes()).hexdigest() == report["probe_sha256"]
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
    parser.add_argument("--probe", choices=STAGES, required=True)
    parser.add_argument("--iterations", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.probe, args.iterations)
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")
