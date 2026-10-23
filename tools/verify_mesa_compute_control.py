"""Reproduce the original softpipe compute OOM fault with preserved r8 libraries.

An expected-control result is not an EGL, Smithay or COSMIC acceptance result.
The same strengthened probe must fail at its first large dispatch, then the
kernel must reclaim its resources and execute an independent native program.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_egl import OFFSCREEN_CHECKS, check_accounting
from verify_ported import STAGES, check_console, parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import wait


EXPECTED = "PASS_EXPECTED_ORIGINAL_COMPUTE_OOM_FAULT"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_fault(data):
    checks = re.findall(rb"(?m)^EGL_PROBE CHECK name=(\S+) result=PASS\r?$", data)
    end = OFFSCREEN_CHECKS.index("compute-oom-preflight-1") + 1
    assert [value.decode() for value in checks] == OFFSCREEN_CHECKS[:end], checks
    assert data.count(b"EGL_PROBE CHECK ") == end
    assert b"EGL_PROBE START mode=offscreen" in data
    assert re.search(rb"EGL_PROBE GL version=OpenGL ES 3\.[^\r\n]*renderer=softpipe\r?\n", data)
    assert b"result=FAIL" not in data and b"EGL_PROBE RESULT" not in data
    attempts = re.findall(rb"(?m)^EGL_PROBE COMPUTE_OOM_ATTEMPT ([^\r\n]+)\r?$", data)
    assert attempts == [b"cycle=1 local=8x8 grid=8x8"], attempts
    expected_exit = b"EL0 pid=1 Exited code=139 free_pages=64 esr=0x92000046 far=0x40618"
    exits = re.findall(rb"(?m)^EL0 pid=\d+ (?:Exited|Fault|Killed)[^\r\n]*", data)
    assert exits == [expected_exit], exits
    assert data.index(b"name=compute-oom-preflight-1 result=PASS") < data.index(
        b"EGL_PROBE COMPUTE_OOM_ATTEMPT ") < data.index(expected_exit)
    assert b"KERNEL_FAULT" not in data and b"panicked" not in data
    return [value.decode() for value in checks], expected_exit.decode()


def validate_process(row, profile, fault=False):
    expected = dict(state="Exited", code=139 if fault else 0,
                    exit_signal=11 if fault else 0,
                    esr=0x92000046 if fault else 0, far=0x40618 if fault else 0,
                    free_pages=64, heap_pages=0, heap_free=profile["heap_pages"],
                    image_pages=0, image_free=4096, thread_count=0)
    assert all(row.get(key) == value for key, value in expected.items()), row
    assert row["ai_selections"] > 0 and row["rank_model"] == 12289, row


def verify(elf, identity_path, output):
    if output.exists():
        raise FileExistsError("Select a fresh control evidence directory")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope=__doc__.splitlines()[0],
                  g_egl_pass=False, cosmic_runtime_verified=False)
    inputs = {}
    try:
        identity = json.loads(identity_path.read_text())
        probe = identity_path.parent / "egl-probe-unfixed.elf"
        source = ROOT / "user/ported/egl_probe.c"
        probe_object = identity_path.parent / "egl_probe.o"
        baseline_probe = ROOT / "artifacts/sysroot/aarch64-musl/probe.elf"
        kernel = elf.read_bytes()
        inspect_elf(kernel)
        profile = report["profile"] = boot_profile(kernel)
        inputs = {elf: digest(elf), identity_path: digest(identity_path),
                  probe: identity["elf_sha256"],
                  source: identity["probe_source_sha256"],
                  probe_object: identity["probe_object_sha256"],
                  baseline_probe: digest(baseline_probe)}
        inputs.update({Path(path): value for path, value in identity["r8_static_dependencies"].items()})
        for path, expected in inputs.items():
            assert digest(path) == expected, ("Input changed", str(path))
        assert kernel.count(probe.read_bytes()) == 1, "Exact r8 control ELF not embedded"
        assert kernel.count(baseline_probe.read_bytes()) == 1, "Independent native probe not embedded"
        report.update(kernel_sha256=inputs[elf], probe_sha256=inputs[probe],
                      identity_sha256=inputs[identity_path],
                      inputs_sha256={str(path): value for path, value in inputs.items()},
                      verifier_sha256=digest(Path(__file__)))
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            report["before"] = before = snapshot(guest)
            reclaimed(before)
            start = len(guest.text)
            guest.command("posix exec egl-probe")
            wait(guest, start, b"EL0 pid=1 Exited code=", 90)
            data = bytes(guest.text[start:])
            row = parse_processes(guest.command("posix list"))[1]
            report["fault_process"] = row
            report["after_fault"] = after_fault = snapshot(guest)
            checks, exit_record = validate_fault(data)
            validate_process(row, profile, fault=True)
            check_accounting(before, after_fault, minimum_rejections=1)
            report["successful_checks_before_fault"] = checks
            report["expected_fault_record"] = exit_record

            # Demonstrate a new EL0 process can execute real libc, memory, file
            # and floating-point work after the failed process was reclaimed.
            start = len(guest.text)
            guest.command("posix exec probe")
            wait(guest, start, b"EL0 pid=2 Exited code=", 45)
            data = bytes(guest.text[start:])
            check_console(data)
            rows = [line.removesuffix(b"\r") for line in data.splitlines()
                    if line.startswith(b"PORTED_PROBE")]
            assert len(rows) == 7 and rows[:5] + rows[6:] == STAGES, rows
            assert re.fullmatch(rb"PORTED_PROBE FP_IRQ PASS elapsed_ns=(\d+)", rows[5]), rows
            assert int(rows[5].split(b"=")[1]) >= 50_000_000
            exits = re.findall(rb"(?m)^EL0 pid=\d+ (?:Exited|Fault|Killed)[^\r\n]*", data)
            assert exits == [b"EL0 pid=2 Exited code=0 free_pages=64 esr=0x0 far=0x0"], exits
            row = parse_processes(guest.command("posix list"))[2]
            validate_process(row, profile)
            report["isolation_process"] = row
            report["isolation_markers"] = [line.decode() for line in rows]
            report["after_isolation"] = final = snapshot(guest)
            check_accounting(after_fault, final, minimum_rejections=0)
        for path, expected in inputs.items():
            assert digest(path) == expected, ("Input changed during run", str(path))
        report["status"] = EXPECTED
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.identity.resolve(), args.output.resolve())
    print(json.dumps({key: result[key] for key in ("status", "scope", "error") if key in result}, indent=2))
    raise SystemExit(result["status"] != EXPECTED)
