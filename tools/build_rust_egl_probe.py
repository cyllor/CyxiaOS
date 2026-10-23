#!/usr/bin/env python3
"""Build a bounded native Rust probe using pinned Smithay-generated API bindings.

Only four host crates are compiled, directly from the checked COSMIC lock pins.
The upstream Smithay build.rs runs unchanged. No shared Cargo configuration,
sysroot, Mesa tree or kernel is modified; target code is never executed here.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import time
import tomllib
import urllib.request

from build_cosmic import clean_environment, new_output, run_bounded
from build_sysroot import ROOT, DEFAULT_OUTPUT, digest, inspect_elf, toolchain

MANIFEST = ROOT / "ports/cosmic/rust-egl-source.json"
PROBE = ROOT / "ports/cosmic/rust-egl/probe.rs"
LOCK = ROOT / "artifacts/cosmic-sources/cosmic-comp-epoch/Cargo.lock"


def source_input(cache, item, filename, fetch):
    relative = PurePosixPath(filename)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("Source input path escapes cache")
    path = cache / filename
    if not path.resolve().is_relative_to(cache.resolve()):
        raise ValueError("Source input link escapes cache")
    if not path.is_file():
        if not fetch:
            raise ValueError("Missing verified input; use --fetch: " + str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(item["url"], timeout=25) as response:
            data = response.read(item["bytes"] + 1)
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("Downloaded input differs from its pin: " + filename)
        path.write_bytes(data)
    if path.is_symlink() or path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
        raise ValueError("Input differs from its pin: " + str(path))
    return path


def extract(archive, destination, root, budget):
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        expanded = sum(item.size for item in members)
        if expanded > budget:
            raise ValueError("Expanded source exceeds budget")
        for item in members:
            path = PurePosixPath(item.name)
            if (path.is_absolute() or ".." in path.parts or path.parts[0] != root
                    or not (item.isdir() or item.isfile())):
                raise ValueError("Unsupported or escaping crate member: " + item.name)
        bundle.extractall(destination, members=members, filter="data")
    return destination / root, expanded


def build(output, cache, mesa_report, fetch=False):
    manifest = json.loads(MANIFEST.read_text())
    budget = manifest["budgets"]
    if sum(item["bytes"] for item in manifest["host_crates"] + manifest["smithay_files"]) > budget["max_download_bytes"]:
        raise ValueError("Pinned download closure exceeds budget")
    if digest(LOCK) != manifest["cosmic_lock_sha256"]:
        raise ValueError("COSMIC lock changed")
    locked = tomllib.loads(LOCK.read_text())["package"]
    for crate in manifest["host_crates"]:
        if not any(row.get("name") == crate["name"] and row["version"] == crate["version"]
                   and row.get("checksum") == crate["sha256"] for row in locked):
            raise ValueError("Host crate differs from the COSMIC lock: " + crate["name"])
    if not any(row["name"] == "smithay" and row.get("source", "").endswith("#" + manifest["smithay_commit"])
               for row in locked):
        raise ValueError("Smithay revision differs from the COSMIC lock")
    mesa = json.loads(mesa_report.read_text())
    if mesa.get("status") != "libraries-compiled" or mesa["target"]["status"] != "compiled":
        raise ValueError("Mesa static libraries must already be compiled")
    output = new_output(output)
    for directory in ("logs", "source", "host", "generated", "native"):
        (output / directory).mkdir()
    cache.mkdir(parents=True, exist_ok=True)
    env = clean_environment(str(Path.home() / ".cargo/bin") + ":/usr/bin:/bin:/opt/homebrew/bin")
    rustc = str(Path.home() / ".cargo/bin/rustc")
    report = {
        "status": "FAIL", "guest_execution": "not performed", "scope": manifest["scope"],
        "manifest_sha256": digest(MANIFEST), "builder_sha256": digest(Path(__file__)),
        "source_sha256": digest(PROBE), "cosmic_lock_sha256": digest(LOCK),
        "mesa_report_sha256": digest(mesa_report), "commands": [], "budgets": budget,
        "smithay_commit": manifest["smithay_commit"],
        "target": manifest["target"], "target_external_rust_crates": [],
        "rustc": subprocess.check_output([rustc, "-vV"], env=env, text=True),
    }
    deadline = time.monotonic() + budget["timeout_seconds"]

    def run(command, label, cwd=output, extra_env=None):
        record = {"command": list(map(str, command)), "cwd": str(cwd), "environment": extra_env or {}}
        report["commands"].append(record)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Whole build timeout reached")
        run_bounded(record["command"], cwd, {**env, **(extra_env or {})},
                    output / "logs" / (label + ".log"), remaining,
                    budget["min_free_bytes"], budget["max_build_bytes"], budget_root=output)

    try:
        libraries = mesa["target"]["link_dependencies_sha256"]
        for path, expected in libraries.items():
            if digest(Path(path)) != expected:
                raise ValueError("Mesa link input changed: " + path)
        report["mesa_link_dependencies_sha256"] = libraries
        shutil.copyfile(mesa_report, output / "mesa-build-report.json")
        smithay = output / "source/smithay"
        for item in manifest["smithay_files"]:
            source = source_input(cache, item, item["path"], fetch)
            destination = smithay / item["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        sources, expanded = {}, 0
        for item in manifest["host_crates"]:
            name = item["name"] + "-" + item["version"]
            archive = source_input(cache, item, name + ".crate", fetch)
            sources[item["name"]], size = extract(
                archive, output / "source", name, budget["max_expanded_bytes"] - expanded)
            expanded += size
        report["expanded_crate_bytes"] = expanded
        khronos = sources["khronos_api"]
        generated = output / "generated"
        run([rustc, khronos / "build.rs", "--edition=2015", "-o", output / "host/khronos-build"],
            "khronos-build-compile")
        run([output / "host/khronos-build"], "khronos-build-run", khronos,
            {"OUT_DIR": str(generated)})
        for package in ("khronos_api", "log", "xml-rs", "gl_generator"):
            source = sources[package]
            metadata = tomllib.loads((source / "Cargo.toml").read_text())
            name = metadata.get("lib", {}).get("name", package.replace("-", "_"))
            lib = source / metadata.get("lib", {}).get("path", "src/lib.rs")
            arguments = [rustc, lib, "--crate-type=rlib", "--crate-name", name,
                         "--edition=" + metadata["package"].get("edition", "2015"),
                         "-L", "dependency=" + str(output / "host"), "-C", "opt-level=1",
                         "-o", output / "host" / ("lib" + name + ".rlib")]
            if package == "gl_generator":
                for dependency in ("khronos_api", "log", "xml"):
                    arguments += ["--extern", dependency + "=" + str(output / "host" / ("lib" + dependency + ".rlib"))]
            run(arguments, name + "-compile", source, {"OUT_DIR": str(generated)})
        run([rustc, smithay / "build.rs", "--edition=2024", "--extern",
             "gl_generator=" + str(output / "host/libgl_generator.rlib"),
             "-L", "dependency=" + str(output / "host"),
             "--cfg", 'feature="backend_egl"', "--cfg", 'feature="renderer_gl"',
             "-o", output / "host/smithay-bindgen"], "smithay-bindgen-compile")
        run([output / "host/smithay-bindgen"], "smithay-bindgen-run", smithay, {
            "OUT_DIR": str(generated), "CARGO_FEATURE_BACKEND_EGL": "1",
            "CARGO_FEATURE_RENDERER_GL": "1",
        })
        report["generated_bindings"] = {
            name: digest(generated / name) for name in ("egl_bindings.rs", "gl_bindings.rs")
        }
        target = manifest["target"]
        target_lib = Path(subprocess.check_output(
            [rustc, "--print", "target-libdir", "--target", target], env=env, text=True).strip())
        std = list(target_lib.glob("libstd-*.rlib"))
        if len(std) != 1:
            raise ValueError("Official target Rust std unavailable")
        unwind = target_lib / "self-contained/libunwind.a"
        shutil.copyfile(unwind, output / "native/libunwind.a")
        report["rust_std_sha256"] = digest(std[0])
        report["rust_unwind_sha256"] = digest(unwind)
        report["rust_target_rlibs_sha256"] = {
            path.name: digest(path) for path in sorted(target_lib.glob("*.rlib"))
        }
        cc = DEFAULT_OUTPUT / "bin/aarch64-linux-musl-cc"
        report["target_driver_sha256"] = digest(cc)
        symbols = output / "rust-egl-probe.symbols.elf"
        arguments = [
            rustc, PROBE, "--edition=2024", "--target", target,
            "-C", "linker=" + str(cc), "-C", "link-self-contained=no",
            "-C", "relocation-model=static", "-C", "target-feature=+crt-static",
            "-C", "panic=abort", "-C", "opt-level=2", "-C", "debuginfo=1",
            "-L", "native=" + str(output / "native"), "-o", symbols,
            "-C", "link-arg=-Wl,--start-group",
        ]
        for path in libraries:
            if path.endswith(".a") and Path(path).name not in ("libc.a", "libclang_rt.builtins-aarch64.a"):
                arguments += ["-C", "link-arg=" + path]
        arguments += ["-C", "link-arg=-Wl,--end-group"]
        run(arguments, "rust-egl-link", extra_env={"OUT_DIR": str(generated)})
        report["symbols"] = inspect_elf(symbols)
        program = output / "rust-egl-probe.elf"
        shutil.copyfile(symbols, program)
        run([toolchain()["llvm-strip"], "--strip-all", program], "strip")
        report["probe"] = inspect_elf(program)
        for path, expected in libraries.items():
            if digest(Path(path)) != expected:
                raise ValueError("Mesa link input changed during build: " + path)
        if (digest(PROBE) != report["source_sha256"] or digest(MANIFEST) != report["manifest_sha256"]
                or digest(mesa_report) != report["mesa_report_sha256"]):
            raise ValueError("Probe inputs changed during build")
        report["status"] = "cross-built"
    except Exception as error:
        report["error"] = repr(error)
        raise
    finally:
        report["logs"] = {path.name: digest(path) for path in sorted((output / "logs").glob("*.log"))}
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--mesa-report", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    result = build(args.output.resolve(), args.cache.resolve(), args.mesa_report.resolve(), args.fetch)
    print(json.dumps(result, indent=2))
