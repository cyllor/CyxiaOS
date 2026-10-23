"""Verify bounded EPOLLET notifications and connected Unix send in real ARM EL0."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from build_sysroot import inspect_elf as inspect_probe
from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import image_pages, parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import wait

CHECKS = 168
# The probe explicitly disables stdout buffering for chronological parent/child evidence.
STAGES = ("COUNTERS", "STREAMS", "SEND_ABI", "PIPE_PTY", "CHILD", "SHARING", "TIMERS", "POLL_EPOLL")
MARKERS = [f"EDGE_PROBE {stage} PASS" for stage in STAGES] + [f"EDGE_PROBE PASS checks={CHECKS}"]
EXITS = [
    "EL0 pid=2 Exited code=0 free_pages=56 esr=0x0 far=0x0",
    "EL0 pid=1 Exited code=0 free_pages=64 esr=0x0 far=0x0",
]
DOMAINS = (
    "process", "thread", "anonymous", "elf", "spawn_receipt", "unix", "pipe", "pty",
    "ancillary_messages", "ancillary_references", "shared_pages", "shared_objects", "shared_mappings",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(data):
    """Reject missing, duplicated, reordered, malformed or faulting observations."""
    assert not any(text in data for text in (b"KERNEL_FAULT", b"panicked", b"EL0 start failed")), data[-3000:]
    matches = list(re.finditer(rb"(?m)^(?:cyxia:/> )?(EDGE_PROBE[^\r\n]*)\r?$", data))
    actual = [match[1].decode() for match in matches]
    assert actual == MARKERS, (actual, MARKERS)
    assert data.count(b"EDGE_PROBE") == len(matches), "Damaged or extra probe marker"
    endings = list(re.finditer(rb"(?m)^(?:cyxia:/> )?(EL0 pid=\d+ [^\r\n]*)\r?$", data))
    assert [match[1].decode() for match in endings] == EXITS, [match[1] for match in endings]
    assert data.count(b"EL0 pid=") == len(endings), "Damaged or extra process terminal record"
    assert matches[4].start() < endings[0].start() < matches[5].start()
    assert matches[-1].start() < endings[1].start()
    return dict(checks=CHECKS, markers=actual, exit_records=EXITS)


def validate_processes(processes, heap_pages):
    # waitpid may remove the child row; its precise successful exit is mandatory above.
    assert set(processes) in ({1}, {1, 2}), processes
    for pid, row in processes.items():
        expected = dict(pid=pid, parent_pid=0 if pid == 1 else 1, state="Exited",
                        code=0, exit_signal=0, esr=0, far=0, free_pages=64,
                        heap_pages=0, heap_free=heap_pages, heap_model=0,
                        image_pages=0, image_free=4096, thread_count=0, thread_peak=1,
                        thread_admissions=0, thread_denials=0, rank_model=12289,
                        cpu_model=12290, guard_selections=0, thread_guard_selections=0)
        for key, value in expected.items():
            assert row.get(key) == value, (key, value, row)
        for key in ("syscalls", "ai_selections", "thread_ai_selections"):
            assert row.get(key, 0) > 0, (key, row)


def validate_accounting(before, after):
    reclaimed(before)
    reclaimed(after)
    for domain in DOMAINS:
        old, new = before["ai"][domain], after["ai"][domain]
        for counters in (old, new):
            assert counters["requests"] == sum(counters[key] for key in
                                                ("committed", "denied", "capacity", "invalid", "failed")), (domain, counters)
            assert counters["ai"] <= counters["approved"] <= counters["proposals"] <= counters["requests"], (domain, counters)
            assert counters["grant_units"] == counters["release_units"], (domain, counters)
        for key in ("requests", "committed", "denied", "capacity", "invalid", "failed",
                    "ai", "approved", "proposals", "grant_units", "release_units"):
            assert new[key] >= old[key], (domain, key, old, new)
        if domain in ("process", "elf", "spawn_receipt", "unix", "pipe", "pty"):
            assert new["committed"] > old["committed"], (domain, old, new)
            assert new["ai"] > old["ai"], (domain, old, new)
        if domain in ("process", "elf", "spawn_receipt"):
            assert new["grant_units"] > old["grant_units"], (domain, old, new)


def provenance(elf, probe):
    binary, program = elf.read_bytes(), probe.read_bytes()
    info = inspect_elf(binary)
    assert binary.count(program) == 1, "Exact edge probe must occur once in kernel"
    assert any(program in binary[seg["offset"]:seg["offset"] + seg["size"]]
               for seg in info["loads"] if not seg["flags"] & 2), "Probe is not in a read-only kernel load segment"
    layout_path = probe.with_name("edge-probe-layout.json")
    layout = json.loads(layout_path.read_text())
    actual = inspect_probe(probe)
    for key in ("sha256", "bytes", "entry", "at_phdr", "at_phent", "at_phnum", "program_headers"):
        assert actual[key] == layout[key], (key, actual[key], layout[key])
    source = ROOT / "user/ported/edge_probe.c"
    libc = probe.parent / "sysroot/usr/lib/libc.a"
    driver = probe.parent / "bin/aarch64-linux-musl-cc"
    for name, path in (("source", source), ("libc", libc), ("driver", driver)):
        assert layout[name + "_sha256"] == digest(path), (name, path)
    manifest_path = elf.parent / "kernel-source-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest and "kernel/src/user/linux.rs" in manifest and "crates/posix/src/epoll.rs" in manifest
    paths = [elf, probe, layout_path, source, libc, driver, manifest_path]
    for name, expected in manifest.items():
        path = (ROOT / name).resolve()
        assert path.is_relative_to(ROOT.resolve()), name
        assert digest(path) == expected, ("Kernel source differs from frozen manifest", name)
        paths.append(path)
    # These helpers/header are observed verifier inputs, not a new claim about compiler provenance.
    paths.extend(ROOT / name for name in (
        "tools/verify_edge.py", "tools/build_sysroot.py", "tools/check_elf.py",
        "tools/shell.py", "tools/doctor.py", "tools/run_qemu.py", "tools/transport.py",
        "tools/verify_ported.py", "tools/verify_shared_objects.py", "tools/verify_ai_system.py",
        "tools/verify_x11.py", "user/ported/cyxia_spawn.h",
    ))
    bindings = {str(path.resolve()): digest(path) for path in paths}
    return dict(kernel_sha256=digest(elf), probe_sha256=digest(probe),
                source_sha256=digest(source), verifier_sha256=digest(Path(__file__)),
                kernel_source_manifest=dict(path=str(manifest_path), sha256=digest(manifest_path),
                                            entries=len(manifest)),
                profile=boot_profile(binary), expected_image_pages=image_pages(program),
                build=layout, inputs=bindings)


def verify(elf, output, iterations=3):
    if output.exists():
        raise FileExistsError(f"Preserve existing verification evidence: {output}")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope="Bounded EPOLLET on eventfd/timerfd/Unix stream/pipe/PTY; connected Unix send",
                  full_linux_compatibility=False, full_cosmic_runtime=False,
                  iterations_requested=iterations, runs=[])
    try:
        assert 1 <= iterations <= 5, iterations
        probe = ROOT / "artifacts/sysroot/aarch64-musl/edge-probe.elf"
        report.update(provenance(elf, probe))
        for iteration in range(1, iterations + 1):
            row = dict(iteration=iteration, status="FAIL")
            report["runs"].append(row)
            run_path = output / f"run-{iteration}"
            try:
                with Guest(elf, run_path, rng=True) as guest:
                    guest.until(b"cyxia:/> ")
                    row["before"] = snapshot(guest)
                    reclaimed(row["before"])
                    start = len(guest.text)
                    guest.command("posix exec edge-probe")
                    wait(guest, start, b"EL0 pid=1 Exited code=", 45)
                    data = bytes(guest.text[start:])
                    row["processes"] = parse_processes(guest.command("posix list"))
                    row["after"] = snapshot(guest)
                    row.update(validate(data))
                    launches = re.findall(
                        rb"ELF pid=(\d+) started; ABI=Linux-AArch64-subset image AI_DIRECT model=8195 pages=(\d+)", data)
                    assert launches == [(b"1", str(report["expected_image_pages"]).encode())], launches
                    validate_processes(row["processes"], report["profile"]["heap_pages"])
                    validate_accounting(row["before"], row["after"])
                    row["status"] = "PASS"
            finally:
                row["artifacts"] = {str(path.relative_to(output)): digest(path)
                                    for path in sorted(run_path.glob("*")) if path.is_file()}
        for path, expected in report["inputs"].items():
            assert digest(Path(path)) == expected, ("Input changed during verification", path)
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
    print(json.dumps({key: value for key, value in result.items() if key not in ("inputs", "build", "runs")}, indent=2))
    raise SystemExit(result["status"] != "PASS")
