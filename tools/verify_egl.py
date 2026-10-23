"""Run the real Mesa offscreen GLES3 probe in CyxiaOS, never on the host.

This proves only the explicitly enumerated EGL/GLES foundation checks. It does
not accept G-EGL, X11 swap, COSMIC shaders, Smithay, or the COSMIC compositor.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from build_sysroot import inspect_elf as inspect_program
from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import wait


COMPUTE_OOM_CHECKS = ["compute-oom-programs", "compute-oom-initial-target"] + [
    f"compute-oom-{step}-{cycle}" for cycle in range(1, 4)
    for step in ("preflight", "error", "atomic", "recovery")
]

OFFSCREEN_CHECKS = [
    "platform-proc", "egl-initialize", "bind-gles", "choose-config", "gles3-context",
    "egl-surface", "make-current", "gles-version", "software-renderer", "bgra-extension",
    "gl-proc", "unknown-proc-rejected", "compile-shaders", "link-program", "rgba8-fbo",
    "fbo-exact-4096-pixels", "texture-program", "texture-linear-multiple-views-exact",
    "texture-bilinear-tile-boundaries-exact", "texture-unbound-update-invalidates-exact",
    "texture-rebind-exact", "texture-same-view-two-units-exact",
    "texture-image-store-program", "texture-unbound-image-store-rebind-exact",
    *COMPUTE_OOM_CHECKS,
    "texture-pressure-storage", "texture-cache-oom-visible", "texture-cache-oom-recovery-exact",
    "texture-cache-new-allocation-after-oom",
    "surface-exact-4096-pixels", "swap", "release-context",
    "destroy-surface", "destroy-context", "terminate",
]

X11_CHECKS = (["x11-open", *OFFSCREEN_CHECKS[1:5],
              "native-visual", "x11-visual", *OFFSCREEN_CHECKS[5:]])


def validate_offscreen(data: bytes, mode: str = "offscreen") -> list[str]:
    """Reject omitted, duplicate, failed or interleaved observations."""
    markers = [line.removesuffix(b"\r") for line in data.splitlines()
               if line.startswith(b"EGL_PROBE")]
    if ("EGL_PROBE START mode=" + mode).encode() not in markers:
        raise AssertionError("Missing selected mode start")
    checks = re.findall(rb"(?m)^EGL_PROBE CHECK name=([^\s]+) result=PASS\r?$", data)
    expected = OFFSCREEN_CHECKS if mode == "offscreen" else X11_CHECKS
    if [name.decode("ascii") for name in checks] != expected:
        raise AssertionError("Missing, duplicate, damaged or failed EGL checks")
    if data.count(b"EGL_PROBE CHECK ") != len(expected):
        raise AssertionError("Unparsed EGL check")
    if markers[-1:] != [("EGL_PROBE RESULT PASS mode=" + mode + " failures=0").encode()]:
        raise AssertionError("Missing complete offscreen result")
    if not re.search(rb"EGL_PROBE GL version=OpenGL ES 3\.[^\r\n]*renderer=softpipe\r?\n", data):
        raise AssertionError("Guest did not report Mesa softpipe GLES3")
    if b"result=FAIL" in data or b"EGL_PROBE RESULT FAIL" in data:
        raise AssertionError("Probe reported failure")
    attempts = re.findall(rb"(?m)^EGL_PROBE COMPUTE_OOM_ATTEMPT cycle=(\d) local=8x8 grid=8x8\r?$", data)
    if attempts != [b"1", b"2", b"3"]:
        raise AssertionError("Missing repeated 64-invocation compute OOM attempts")
    return [line.decode("utf-8", errors="strict") for line in markers]


def provenance(probe: Path, build_report: Path) -> dict:
    """Bind the runtime test to the checked target, source and build recipe."""
    record = json.loads(build_report.read_text())
    assert record["status"] == "libraries-compiled", record["status"]
    actual = inspect_program(probe)
    recorded = record["target"]["probe"]
    for key in ("sha256", "bytes", "entry", "at_phdr", "at_phent", "at_phnum", "program_headers"):
        assert actual[key] == recorded[key], ("target layout differs", key)
    inputs = {
        ROOT / "user/ported/egl_probe.c": record["probe_source_sha256"],
        ROOT / "tools/build_mesa.py": record["builder_sha256"],
        ROOT / "ports/cosmic/mesa-source.json": record["source"]["identity"]["manifest_sha256"],
        build_report: hashlib.sha256(build_report.read_bytes()).hexdigest(),
    }
    inputs.update({ROOT / path: value for path, value in record["source"]["identity"]["patches"].items()})
    for path, expected in inputs.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, ("source identity changed", str(path))
    return {"build_report": str(build_report), "build_run": record["run_id"],
            "program_layout": actual,
            "inputs_sha256": {str(path): value for path, value in inputs.items()},
            "static_inputs_sha256": record["target"]["link_dependencies_sha256"]}


def check_accounting(before: dict, after: dict, minimum_rejections: int = 4) -> None:
    reclaimed(after)
    for name in ("process", "thread", "anonymous", "elf", "unix", "pipe", "pty",
                 "ancillary_messages", "ancillary_references", "shared_pages",
                 "shared_objects", "shared_mappings"):
        row = after["ai"][name]
        assert row["requests"] == sum(row[key] for key in ("committed", "denied", "capacity", "invalid", "failed")), (name, row)
        assert row["ai"] <= row["approved"] <= row["proposals"] <= row["requests"], (name, row)
        assert row["grant_units"] == row["release_units"], (name, row)
    for name in ("process", "anonymous", "elf"):
        assert after["ai"][name]["ai"] > before["ai"][name]["ai"], (name, after["ai"][name])
    rejection_fields = ("denied", "capacity")
    assert (sum(after["ai"]["anonymous"][key] for key in rejection_fields) -
            sum(before["ai"]["anonymous"][key] for key in rejection_fields)
            >= minimum_rejections), after["ai"]["anonymous"]


def presented_pixels(path: Path) -> str:
    """Check the actual guest scanout, in X coordinates (GL rows inverted)."""
    with path.open("rb") as stream:
        assert stream.readline() == b"P6\n"
        assert stream.readline() == b"1024 768\n"
        assert stream.readline() == b"255\n"
        pixels = stream.read()
    assert len(pixels) == 1024 * 768 * 3
    colors = ((0, 0, 255), (255, 255, 0), (255, 0, 0), (0, 255, 0))
    for y in range(64):
        for x in range(64):
            at = ((100 + y) * 1024 + 120 + x) * 3
            assert pixels[at:at + 3] == bytes(colors[(x >= 32) + 2 * (y >= 32)]), (x, y, pixels[at:at + 3])
    return hashlib.sha256(pixels).hexdigest()


def verify(elf: Path, probe: Path, output: Path, runs: int = 3,
           build_report: Path | None = None, mode: str = "offscreen") -> dict:
    if (output / "summary.json").exists():
        raise FileExistsError("Select a fresh evidence directory; previous reports are immutable")
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "FAIL", "scope": f"Mesa softpipe {mode} GLES3 foundation only",
              "g_egl_pass": False, "cosmic_runtime_verified": False, "runs": []}
    try:
        image = elf.read_bytes()
        inspect_elf(image)
        program = probe.read_bytes()
        if image.count(program) != 1:
            raise AssertionError("Selected kernel does not contain exactly the selected probe ELF")
        report["kernel_sha256"] = hashlib.sha256(image).hexdigest()
        report["probe_sha256"] = hashlib.sha256(program).hexdigest()
        report["profile"] = profile = boot_profile(image)
        report["provenance"] = provenance(probe, build_report or probe.parent / "latest-report.json")
        if mode == "x11":
            xorg = (ROOT / "artifacts/sysroot/aarch64-musl/Xcyxia.elf").read_bytes()
            assert image.count(xorg) == 1, "Exact Xorg target image not embedded"
            report["xorg_sha256"] = hashlib.sha256(xorg).hexdigest()
        with Guest(elf, output / "session", graphics=mode == "x11", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            before = snapshot(guest)
            reclaimed(before)
            report["before"] = before
            process_pages_free = 64
            if mode == "x11":
                start = len(guest.text)
                guest.command("posix exec xorg")
                wait(guest, start, b"CYXIA_XORG_READY 1024x768 input=keyboard,mouse")
                process_pages_free = parse_processes(guest.command("posix list"))[1]["free_pages"]
            for pid in range(1 if mode == "offscreen" else 2,
                             runs + (1 if mode == "offscreen" else 2)):
                start = len(guest.text)
                guest.command("posix exec " + ("egl-probe" if mode == "offscreen" else "egl-x11-probe"))
                capture = None
                if mode == "x11":
                    wait(guest, start, b"EGL_PROBE PRESENT ", 90)
                    capture = output / f"present-{pid}.ppm"
                    deadline = time.monotonic() + 3
                    while True:
                        guest.qmp.execute("screendump", {"filename": str(capture.resolve())})
                        try:
                            presented_pixels(capture)
                            break
                        except AssertionError:
                            if time.monotonic() >= deadline:
                                raise
                            guest.poll()
                            time.sleep(.02)
                wait(guest, start, f"EL0 pid={pid} Exited code=".encode(), 90)
                data = bytes(guest.text[start:])
                process = parse_processes(guest.command("posix list"))[pid]
                if f"EL0 pid={pid} Exited code=0".encode() not in data:
                    report["failed_process"] = process
                    report["failed_process_snapshot"] = snapshot(guest)
                    raise AssertionError(data[-3000:])
                markers = validate_offscreen(data, mode)
                expected = {"state": "Exited", "code": 0, "exit_signal": 0, "esr": 0,
                            "far": 0, "free_pages": process_pages_free, "heap_pages": 0,
                            "heap_free": profile["heap_pages"], "image_pages": 0,
                            "image_free": 4096, "thread_count": 0}
                if not all(process.get(key) == value for key, value in expected.items()):
                    raise AssertionError(process)
                if process["ai_selections"] <= 0:
                    raise AssertionError("Missing actual AI CPU dispatch")
                row = {"pid": pid, "markers": markers, "process": process}
                if capture:
                    row["scanout_sha256"] = presented_pixels(capture)
                if mode == "offscreen":
                    after = snapshot(guest)
                    check_accounting(before, after)
                    row["after"] = after
                    before = after
                report["runs"].append(row)
            if mode == "x11":
                start = len(guest.text)
                guest.command("posix kill 1")
                wait(guest, start, b"EL0 pid=1 killed;")
                report["after"] = after = snapshot(guest)
                check_accounting(before, after, minimum_rejections=4 * runs)
                report["final_processes"] = final_processes = parse_processes(guest.command("posix list"))
                for row in final_processes.values():
                    assert all(row[key] == 0 for key in ("heap_pages", "image_pages", "thread_count")), row
                    assert row["free_pages"] == 64 and row["heap_free"] == profile["heap_pages"] and row["image_free"] == 4096, row
        if hashlib.sha256(elf.read_bytes()).hexdigest() != report["kernel_sha256"]:
            raise AssertionError("Kernel image changed during verification")
        if hashlib.sha256(probe.read_bytes()).hexdigest() != report["probe_sha256"]:
            raise AssertionError("Probe image changed during verification")
        for path, expected in report["provenance"]["inputs_sha256"].items():
            assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected, ("source changed during test", path)
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--probe", type=Path, default=ROOT / "artifacts/sysroot/aarch64-musl/egl-probe.elf")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/mesa-egl")
    parser.add_argument("--runs", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--build-report", type=Path)
    parser.add_argument("--mode", choices=("offscreen", "x11"), default="offscreen")
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.probe.resolve(), args.output.resolve(), args.runs,
                    args.build_report.resolve() if args.build_report else None, args.mode)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
