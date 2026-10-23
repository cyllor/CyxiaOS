#!/usr/bin/env python3
"""Compile a bounded, genuine pinned Mio closure without shared Cargo changes."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
import tomllib

from build_cosmic import clean_environment, new_output, run_bounded
from build_mesa import tree_digest
from build_rust_egl_probe import source_input, extract
from build_sysroot import ROOT, DEFAULT_OUTPUT, digest, inspect_elf, toolchain

MANIFEST = ROOT / "ports/cosmic/reactor-source.json"
PROBE = ROOT / "ports/cosmic/reactor/probe.rs"
LOCK = ROOT / "artifacts/cosmic-sources/cosmic-comp-epoch/Cargo.lock"


def build(output, cache, fetch=False):
    manifest = json.loads(MANIFEST.read_text())
    budget = manifest["budgets"]
    if digest(LOCK) != manifest["cosmic_lock_sha256"]:
        raise ValueError("COSMIC lock changed")
    locked = tomllib.loads(LOCK.read_text())["package"]
    for item in manifest["crates"]:
        if not any(row["name"] == item["name"] and row["version"] == item["version"]
                   and row.get("checksum") == item["sha256"] for row in locked):
            raise ValueError("Crate does not match COSMIC lock")
    if sum(item["bytes"] for item in manifest["crates"]) > budget["max_download_bytes"]:
        raise ValueError("Download closure exceeds budget")
    output = new_output(output)
    for name in ("source", "host", "target", "native", "logs", "generated"):
        (output / name).mkdir()
    cache.mkdir(parents=True, exist_ok=True)
    env = clean_environment(str(Path.home() / ".cargo/bin") + ":/usr/bin:/bin:/opt/homebrew/bin")
    rustc = str(Path.home() / ".cargo/bin/rustc")
    target = manifest["target"]
    inputs = {MANIFEST: digest(MANIFEST), PROBE: digest(PROBE), LOCK: digest(LOCK)}
    for name in ("build_rust_reactor.py", "build_rust_egl_probe.py", "build_cosmic.py", "build_mesa.py", "build_sysroot.py"):
        path = ROOT / "tools" / name
        inputs[path] = digest(path)
    report = dict(status="FAIL", scope=manifest["scope"], guest_execution="not performed",
                  target=target, budgets=budget, commands=[], inputs_sha256={str(p): v for p, v in inputs.items()},
                  rustc=subprocess.check_output([rustc, "-vV"], env=env, text=True),
                  crate_features={item["name"]: item["features"] for item in manifest["crates"]})
    deadline = time.monotonic() + budget["timeout_seconds"]

    def run(command, label, cwd=output, extra_env=None):
        record = dict(command=list(map(str, command)), cwd=str(cwd), environment=extra_env or {})
        report["commands"].append(record)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Whole build timeout reached")
        run_bounded(record["command"], cwd, {**env, **(extra_env or {})}, output / "logs" / (label + ".log"),
                    remaining, budget["min_free_bytes"], budget["max_build_bytes"], budget_root=output)

    try:
        sources, expanded = {}, 0
        for item in manifest["crates"]:
            name = item["name"] + "-" + item["version"]
            archive = source_input(cache, item, name + ".crate", fetch)
            source, size = extract(archive, output / "source", name, budget["max_expanded_bytes"] - expanded)
            sources[item["name"]] = source
            expanded += size
        report["expanded_source_bytes"] = expanded
        report["source_trees_sha256"] = {name: tree_digest(path) for name, path in sources.items()}
        # Run the unchanged upstream libc build script on the host, with the
        # exact target metadata. Apply its emitted cfg/check-cfg instructions.
        run([rustc, sources["libc"] / "build.rs", "--edition=2021", "-o", output / "host/libc-build"],
            "libc-build-compile")
        run([output / "host/libc-build"], "libc-build-run", sources["libc"], {
            "RUSTC": rustc, "TARGET": target, "CARGO_CFG_TARGET_ENV": "musl",
            "CARGO_CFG_TARGET_OS": "linux", "CARGO_CFG_TARGET_ARCH": "aarch64",
            "CARGO_CFG_TARGET_POINTER_WIDTH": "64", "OUT_DIR": str(output / "generated"),
        })
        cfg = []
        for line in (output / "logs/libc-build-run.log").read_text().splitlines():
            if line.startswith("cargo:rustc-cfg="):
                cfg += ["--cfg", line.removeprefix("cargo:rustc-cfg=")]
            elif line.startswith("cargo:rustc-check-cfg="):
                cfg += ["--check-cfg", line.removeprefix("cargo:rustc-check-cfg=")]
        report["libc_build_cfg"] = cfg
        for item in manifest["crates"]:
            name, source = item["name"], sources[item["name"]]
            metadata = tomllib.loads((source / "Cargo.toml").read_text())
            args = [rustc, source / metadata.get("lib", {}).get("path", "src/lib.rs"),
                    "--crate-name", name, "--crate-type=rlib", "--edition=" + metadata["package"]["edition"],
                    "--target", target, "-C", "opt-level=2", "-C", "panic=abort",
                    "-C", "relocation-model=static", "-L", "dependency=" + str(output / "target"),
                    "--check-cfg", "cfg(docsrs,test)",
                    "-o", output / "target" / ("lib" + name + ".rlib")]
            for feature in item["features"]:
                args += ["--cfg", 'feature="' + feature + '"']
            allowed_features = set(metadata.get("features", {})) | set(item["features"])
            allowed_features.update(name for name, dependency in metadata.get("dependencies", {}).items()
                                    if isinstance(dependency, dict) and dependency.get("optional"))
            args += ["--check-cfg", "cfg(feature,values(" +
                     ",".join(json.dumps(value) for value in sorted(allowed_features)) + "))"]
            for value in metadata.get("lints", {}).get("rust", {}).get("unexpected_cfgs", {}).get("check-cfg", []):
                args += ["--check-cfg", value]
            if name == "libc":
                args += cfg
            for dep in item["dependencies"]:
                args += ["--extern", dep + "=" + str(output / "target" / ("lib" + dep + ".rlib"))]
            run(args, name + "-compile", source)
        target_lib = Path(subprocess.check_output([rustc, "--print", "target-libdir", "--target", target],
                                                  env=env, text=True).strip())
        if len(list(target_lib.glob("libstd-*.rlib"))) != 1:
            raise ValueError("Official target std unavailable")
        unwind = target_lib / "self-contained/libunwind.a"
        shutil.copyfile(unwind, output / "native/libunwind.a")
        native = [DEFAULT_OUTPUT / "bin/aarch64-linux-musl-cc", DEFAULT_OUTPUT / "bin/ld.lld",
                  *[DEFAULT_OUTPUT / "sysroot/usr/lib" / name for name in
                    ("crt1.o", "crti.o", "crtn.o", "libc.a", "libclang_rt.builtins-aarch64.a")], unwind]
        report["native_inputs_sha256"] = {str(path): digest(path) for path in native}
        report["rust_target_rlibs_sha256"] = {str(path): digest(path) for path in sorted(target_lib.glob("*.rlib"))}
        symbols = output / "rust-reactor-probe.symbols.elf"
        run([rustc, PROBE, "--edition=2024", "--target", target,
             "-C", "linker=" + str(native[0]), "-C", "link-self-contained=no",
             "-C", "relocation-model=static", "-C", "target-feature=+crt-static",
             "-C", "panic=abort", "-C", "opt-level=2", "-C", "debuginfo=1",
             "-L", "native=" + str(output / "native"), "-L", "dependency=" + str(output / "target"),
             "--extern", "mio=" + str(output / "target/libmio.rlib"),
             "--extern", "libc=" + str(output / "target/liblibc.rlib"),
             "-o", symbols], "probe-link")
        program = output / "rust-reactor-probe.elf"
        shutil.copyfile(symbols, program)
        run([toolchain()["llvm-strip"], "--strip-all", program], "strip")
        report["probe"] = inspect_elf(program)
        report["symbols"] = inspect_elf(symbols)
        report["compiled_crates_sha256"] = {path.name: digest(path) for path in sorted((output / "target").glob("*.rlib"))}
        for name, path in sources.items():
            if tree_digest(path) != report["source_trees_sha256"][name]:
                raise ValueError("Upstream source changed during build: " + name)
        for paths in (report["inputs_sha256"], report["native_inputs_sha256"], report["rust_target_rlibs_sha256"]):
            for path, expected in paths.items():
                if digest(Path(path)) != expected:
                    raise ValueError("Build input changed: " + path)
        report["status"] = "cross-built"
    except Exception as error:
        report["error"] = repr(error)
        raise
    finally:
        report["logs_sha256"] = {p.name: digest(p) for p in sorted((output / "logs").glob("*.log"))}
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    result = build(args.output.resolve(), args.cache.resolve(), args.fetch)
    print(json.dumps(result, indent=2))
