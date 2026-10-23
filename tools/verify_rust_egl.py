#!/usr/bin/env python3
"""Verify real native Rust generated EGL/GLES calls, pixels and resource cleanup."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_egl import check_accounting
from verify_ported import parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import wait

CHECKS = [
    "generated-egl-entrypoints", "unknown-symbol-null", "surfaceless-display",
    "egl-1.5", "gles-api", "rgba8-config", "gles3-context", "pbuffer-current",
    "generated-gles-entrypoints", "renderer-present", "real-softpipe",
    "clear-readback-16-pixels", "real-shader-compile-link",
    "shader-readback-16-pixels", "api-errors-clear", "egl-cleanup",
]
SUCCESS = "RUST_EGL PASS static=1 generated=smithay-e3d461a shader_pixels=16 high_level_smithay=0"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(data):
    rows = [row.decode() for row in re.findall(rb"(?m)^(?:cyxia:/> )?(RUST_EGL[^\r\n]*)\r?$", data)]
    expected = ["RUST_EGL CHECK name=" + name + " result=PASS" for name in CHECKS]
    expected.insert(10, "RUST_EGL RENDERER softpipe")
    expected.append(SUCCESS)
    assert rows == expected, (rows, expected)
    return rows


def verify(elf, probe, output, runs=3):
    if (output / "summary.json").exists():
        raise FileExistsError("Select a fresh evidence directory")
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "FAIL", "scope": "native Rust Smithay-generated EGL/GLES bindings with actual static Mesa",
              "smithay_high_level_context_verified": False, "cosmic_runtime_verified": False, "runs": []}
    try:
        kernel = elf.read_bytes()
        inspect_elf(kernel)
        report["kernel_sha256"] = digest(elf)
        report["probe_sha256"] = digest(probe)
        profile = report["profile"] = boot_profile(kernel)
        assert kernel.count(probe.read_bytes()) == 1, "Exact Rust EGL executable not embedded"
        build_path = probe.parent / "build-report.json"
        built = json.loads(build_path.read_text())
        assert built["status"] == "cross-built" and built["probe"]["sha256"] == report["probe_sha256"]
        inputs = {
            ROOT / "ports/cosmic/rust-egl/probe.rs": built["source_sha256"],
            ROOT / "ports/cosmic/rust-egl-source.json": built["manifest_sha256"],
            ROOT / "tools/build_rust_egl_probe.py": built["builder_sha256"],
            probe.parent / "mesa-build-report.json": built["mesa_report_sha256"],
        }
        inputs.update({probe.parent / "generated" / name: value
                       for name, value in built["generated_bindings"].items()})
        for path, value in inputs.items():
            assert digest(path) == value, str(path)
        report["build_report_sha256"] = digest(build_path)
        report["inputs_sha256"] = {str(path): value for path, value in inputs.items()}
        report["verifier_sha256"] = digest(Path(__file__))
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            report["before"] = before = snapshot(guest)
            reclaimed(before)
            for pid in range(1, runs + 1):
                start = len(guest.text)
                guest.command("posix exec rust-egl-probe")
                wait(guest, start, f"EL0 pid={pid} Exited code=".encode(), 90)
                data = bytes(guest.text[start:])
                process = parse_processes(guest.command("posix list"))[pid]
                after = snapshot(guest)
                if f"EL0 pid={pid} Exited code=0".encode() not in data:
                    report["failed_process"] = process
                    report["failed_snapshot"] = after
                    raise AssertionError(data[-6000:])
                markers = validate(data)
                expected = {"state": "Exited", "code": 0, "exit_signal": 0, "esr": 0,
                            "far": 0, "free_pages": 64, "heap_pages": 0,
                            "heap_free": profile["heap_pages"], "image_pages": 0,
                            "image_free": 4096, "thread_count": 0}
                assert all(process.get(key) == value for key, value in expected.items()), process
                check_accounting(before, after, minimum_rejections=0)
                report["runs"].append({"pid": pid, "markers": markers, "process": process, "after": after})
                before = after
        assert digest(elf) == report["kernel_sha256"] and digest(probe) == report["probe_sha256"]
        for path, value in inputs.items():
            assert digest(path) == value, str(path)
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
