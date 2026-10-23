#!/usr/bin/env python3
"""Link an independent real Wayland client using the checked static target SDK.

No download, target execution, shared sysroot change or previous artifact
replacement. Every build uses a fresh output and records its complete inputs.
"""
import argparse
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

from build_cosmic import clean_environment, new_output, run_bounded
from build_sysroot import ROOT, DEFAULT_OUTPUT, BuildError, digest, inspect_elf, toolchain

SOURCE = ROOT / "user/ported/smithay_wayland_client.c"
BUDGET = dict(timeout_seconds=60, min_free_bytes=512 * 1024 * 1024,
              max_build_bytes=32 * 1024 * 1024, max_download_bytes=0)


def prerequisite_inputs(prefix):
    """Reject stale SDK manifests or libraries before linking any code."""
    paths = {}
    reports = {}
    for name in ("wayland", "xkbcommon"):
        path = prefix / (name + "-build-report.json")
        manifest = ROOT / "ports/cosmic" / (name + "-source.json")
        report = json.loads(path.read_text())
        if report.get("status") != "cross-built" or digest(manifest) != report["manifest_sha256"]:
            raise BuildError("Unverified prerequisite: " + name)
        paths[path] = digest(path)
        paths[manifest] = digest(manifest)
        reports[name] = report
    library = prefix / "sysroot/usr/lib"
    expected = {
        "libwayland-client.a": reports["wayland"]["target"]["archives"]["libwayland-client.a"]["sha256"],
        "libffi.a": reports["wayland"]["target_libffi_sha256"],
        "libxkbcommon.a": reports["xkbcommon"]["target"]["archive"]["sha256"],
        "libc.a": reports["wayland"]["target_libc_sha256"],
    }
    if reports["xkbcommon"]["target_libc_sha256"] != expected["libc.a"]:
        raise BuildError("Prerequisite libc identities disagree")
    for name, expected_hash in expected.items():
        path = library / name
        if digest(path) != expected_hash:
            raise BuildError("Prerequisite archive changed: " + name)
        paths[path] = expected_hash
    return paths


def dependency_inputs(depfile, source, prefix):
    text = depfile.read_text().replace("\\\n", " ")
    target, separator, dependencies = text.partition(":")
    if separator != ":" or target.strip() != "smithay-wayland-client":
        raise BuildError("Unexpected compiler dependency record")
    paths = [Path(item).resolve() for item in shlex.split(dependencies)]
    if source.resolve() not in paths:
        raise BuildError("Source missing from compiler dependencies")
    for path in paths:
        if path != source.resolve() and not path.is_relative_to((prefix / "sysroot/usr/include").resolve()):
            raise BuildError("Target compilation used an unexpected header: " + str(path))
    return {path: digest(path) for path in paths}


def build(output):
    output = new_output(output)
    for name in ("logs", "provenance"):
        (output / name).mkdir()
    tools = toolchain()
    env = clean_environment("/usr/bin:/bin:/opt/homebrew/bin")
    report = dict(status="FAIL", guest_execution="not performed",
                  scope="Independent libwayland client; rendering/input require actual guest verification",
                  budgets=BUDGET, commands=[], inputs_sha256={}, protocol=dict(
                      fd=3, compositor_version=4, seat_version=7, shm_format="ARGB8888",
                      rounds=[1, 2], dimensions=[[64, 48], [64, 48], [96, 64]],
                      input_seed=[0, 30, 272], final_key=16))
    inputs = {}
    deadline = time.monotonic() + BUDGET["timeout_seconds"]

    def run(command, name):
        command = list(map(str, command))
        report["commands"].append(command)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BuildError("Build deadline exceeded")
        run_bounded(command, output, env, output / "logs" / name, remaining,
                    BUDGET["min_free_bytes"], BUDGET["max_build_bytes"], budget_root=output)

    try:
        # A shared read lock protects the existing SDK; this helper never installs.
        with (DEFAULT_OUTPUT / ".build.lock").open("r") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            inputs.update(prerequisite_inputs(DEFAULT_OUTPUT))
            library = DEFAULT_OUTPUT / "sysroot/usr/lib"
            driver = DEFAULT_OUTPUT / "bin/aarch64-linux-musl-cc"
            native = [driver, DEFAULT_OUTPUT / "bin/ld.lld",
                      *[library / name for name in
                        ("crt1.o", "crti.o", "crtn.o", "libclang_rt.builtins-aarch64.a")],
                      Path(tools["clang"]), Path(tools["rust-lld"]), Path(tools["llvm-strip"])]
            for path in [SOURCE, Path(__file__).resolve(),
                         ROOT / "tools/build_sysroot.py", ROOT / "tools/build_cosmic.py", *native]:
                inputs[path] = digest(path)
            report["toolchain"] = {name: tools[name] for name in ("clang", "rust-lld", "llvm-strip")}
            shutil.copyfile(SOURCE, output / "provenance" / SOURCE.name)
            for name in ("wayland", "xkbcommon"):
                shutil.copyfile(DEFAULT_OUTPUT / (name + "-build-report.json"),
                                output / "provenance" / (name + "-build-report.json"))
            depfile = output / "target-dependencies.d"
            run([driver, "-M", "-MF", depfile, "-MT", "smithay-wayland-client", SOURCE],
                "dependencies.log")
            inputs.update(dependency_inputs(depfile, SOURCE, DEFAULT_OUTPUT))
            report["inputs_sha256"] = {str(path): value for path, value in inputs.items()}
            symbols = output / "smithay-wayland-client.symbols.elf"
            run([driver, "-std=c11", "-Os", "-ffunction-sections", "-fdata-sections",
                 "-fno-stack-protector", "-Wall", "-Wextra", "-Werror",
                 "-Wl,--gc-sections", SOURCE, "-Wl,--start-group",
                 library / "libwayland-client.a", library / "libffi.a",
                 library / "libxkbcommon.a", "-Wl,--end-group", "-o", symbols], "link.log")
            report["symbols"] = inspect_elf(symbols)
            program = output / "smithay-wayland-client.elf"
            shutil.copyfile(symbols, program)
            run([tools["llvm-strip"], "--strip-all", program], "strip.log")
            report["client"] = inspect_elf(program)
            for path, expected in inputs.items():
                if digest(path) != expected:
                    raise BuildError("Build input changed: " + str(path))
            report["status"] = "cross-built"
    except Exception as error:
        report["error"] = repr(error)
        raise
    finally:
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.output.resolve()), indent=2))
    except (OSError, ValueError, BuildError, subprocess.SubprocessError) as error:
        print("smithay-wayland-client: " + str(error), file=sys.stderr)
        raise SystemExit(1)
