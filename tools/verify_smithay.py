#!/usr/bin/env python3
"""Run the real high-level Smithay offscreen renderer inside the ARM guest."""
import argparse
import json
from pathlib import Path
import re

from build_cosmic import tree_identity
from build_sysroot import digest
from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_egl import check_accounting
from verify_ported import parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import wait

CHECKS = [
    "upstream-egl-display", "upstream-egl-context", "upstream-gles-renderer",
    "real-softpipe", "unknown-symbol-null", "upstream-offscreen-renderbuffer",
    "clear-256-pixels", "solid-shader-256-pixels", "texture-shader-256-pixels",
    "updated-texture-256-pixels", "replacement-target-63-pixels",
    "gl-errors-clear", "upstream-lifecycle-cleanup",
]
SUCCESS = "SMITHAY PASS static=1 upstream=egl-context-gles-renderer pixels=1087 cosmic=0"


def validate(data):
    rows = [row.decode() for row in re.findall(rb"(?m)^(?:cyxia:/> )?(SMITHAY[^\r\n]*)\r?$", data)]
    expected = ["SMITHAY CHECK name=" + name + " result=PASS" for name in CHECKS] + [SUCCESS]
    if rows != expected or data.count(b"SMITHAY ") != len(expected):
        raise AssertionError(("Incomplete or damaged Smithay observations", rows))
    return rows


def provenance(probe):
    base = probe.parent
    path = base / "build-report.json"
    report = json.loads(path.read_text())
    if report["status"] != "cross-built" or report["probe"]["sha256"] != digest(probe):
        raise ValueError("Executable differs from successful cross-build")
    inputs = {
        ROOT / "ports/cosmic/smithay-source.json": report["manifest_sha256"],
        ROOT / "ports/cosmic/smithay-probe.rs": report["source_sha256"],
        ROOT / "ports/cosmic/smithay-probe.Cargo.lock": report["cargo_lock_sha256"],
        ROOT / "tools/build_smithay_probe.py": report["builder_sha256"],
        base / "mesa-build-report.json": report["mesa_report_sha256"],
        base / "xkbcommon-build-report.json": report["xkbcommon_report_sha256"],
        base / "source/src/main.rs": report["source_sha256"],
        base / "source/Cargo.lock": report["cargo_lock_sha256"],
        base / "provenance/Cargo.lock": report["cosmic_lock_sha256"],
        base / "provenance/build_smithay_probe.py": report["builder_sha256"],
    }
    inputs.update({ROOT / name: value for name, value in report["patches_sha256"].items()})
    inputs.update({base / name: value for name, value in report["generated_bindings"].items()})
    inputs.update({base / name: value for name, value in report["cargo_inputs_sha256"].items()})
    inputs.update({base / "provenance" / Path(name).name: value
                   for name, value in report["helper_sha256"].items()})
    for path, value in inputs.items():
        if digest(path) != value:
            raise ValueError("Source or generated input changed: " + str(path))
    if tree_identity(base / "source/smithay")["sha256"] != report["patched_source_tree_sha256"]:
        raise ValueError("Patched upstream Smithay source changed")
    names = {p["id"]: p["name"] for p in report["resolved_packages"]}
    selected = [features for identity, features in report["resolved_features"].items()
                if names[identity] == "smithay"]
    if len(selected) != 1 or not {"backend_egl_static", "renderer_gl"} <= set(selected[0]):
        raise ValueError("Required real Smithay features absent")
    return dict(build_report_sha256=digest(base / "build-report.json"),
                inputs_sha256={str(path): value for path, value in inputs.items()},
                patched_source_tree_sha256=report["patched_source_tree_sha256"],
                smithay_features=selected[0], image_pages=report["image_pages"],
                registry_packages=sum(p["source"] is not None for p in report["resolved_packages"]))


def verify(elf, probe, output, runs=3, program="smithay-probe"):
    if program not in ("smithay-probe", "probe"):
        raise ValueError("Unsupported bounded catalog entry")
    if output.exists():
        raise FileExistsError("Select a fresh Smithay evidence directory")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope="Upstream Smithay EGL context and GLES offscreen renderer",
                  smithay_high_level_context_verified=False, smithay_renderer_verified=False,
                  cosmic_runtime_verified=False, catalog_program=program,
                  temporary_catalog_slot=program == "probe", runs=[])
    try:
        kernel = elf.read_bytes()
        inspect_elf(kernel)
        report["kernel_sha256"] = digest(elf)
        report["probe_sha256"] = digest(probe)
        report["verifier_sha256"] = digest(Path(__file__))
        profile = report["profile"] = boot_profile(kernel)
        if kernel.count(probe.read_bytes()) != 1:
            raise ValueError("Exact Smithay executable must be embedded once")
        report["provenance"] = provenance(probe)
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            before = report["before"] = snapshot(guest)
            reclaimed(before)
            for pid in range(1, runs + 1):
                start = len(guest.text)
                guest.command("posix exec " + program)
                wait(guest, start, f"EL0 pid={pid} Exited code=".encode(), 120)
                data = bytes(guest.text[start:])
                process = parse_processes(guest.command("posix list"))[pid]
                after = snapshot(guest)
                if f"EL0 pid={pid} Exited code=0".encode() not in data:
                    report["failed_process"] = process
                    report["failed_snapshot"] = after
                    raise AssertionError(data[-6000:])
                markers = validate(data)
                expected = dict(state="Exited", code=0, exit_signal=0, esr=0, far=0,
                                free_pages=64, heap_pages=0, heap_free=profile["heap_pages"],
                                image_pages=0, image_free=4096, thread_count=0)
                if not all(process.get(key) == value for key, value in expected.items()):
                    raise AssertionError(process)
                check_accounting(before, after, minimum_rejections=0)
                report["runs"].append(dict(pid=pid, markers=markers, process=process, after=after))
                before = after
        if (digest(elf) != report["kernel_sha256"] or digest(probe) != report["probe_sha256"]
                or digest(Path(__file__)) != report["verifier_sha256"]):
            raise ValueError("Runtime input changed during verification")
        if provenance(probe) != report["provenance"]:
            raise ValueError("Build provenance changed during verification")
        report.update(status="PASS", smithay_high_level_context_verified=True,
                      smithay_renderer_verified=True)
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runs", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--program", choices=("smithay-probe", "probe"), default="smithay-probe",
                        help="Use probe only with an explicit CYXIA_PORTED_ELF test image")
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.probe.resolve(), args.output.resolve(), args.runs, args.program)
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")
