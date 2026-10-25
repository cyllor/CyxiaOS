#!/usr/bin/env python3
"""Link real static Xlib/XCB/XInput2/XKB bindings needed by COSMIC's Winit path.

Requires the pinned COSMIC Cargo cache and a private xkbcommon-X11 SDK. This
small executable tests that dependency boundary; it is not cosmic-comp.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

import build_cosmic as build
from build_rust_egl_probe import extract
from build_sysroot import DEFAULT_OUTPUT, ROOT, digest, inspect_elf


PORT = ROOT / "ports/cosmic/static-x11"
PACKAGES = ("x11-dl", "xkbcommon-dl", "x11rb")


def prepare_dependencies(output, cache):
    lock = ROOT / "artifacts/cosmic-sources/cosmic-comp-epoch/Cargo.lock"
    manifest = json.loads((ROOT / "ports/cosmic/manifest.json").read_text())
    if digest(lock) != manifest["compositor"]["cargo_lock_sha256"]:
        raise ValueError("COSMIC lock identity changed")
    packages = tomllib.loads(lock.read_text())["package"]
    records = []
    for name in PACKAGES:
        selected = [p for p in packages if p["name"] == name]
        if len(selected) != 1:
            raise ValueError("ambiguous pinned package: " + name)
        package = selected[0]
        stem = name + "-" + package["version"]
        archives = list((cache / "registry/cache").glob("*/" + stem + ".crate"))
        if len(archives) != 1 or archives[0].is_symlink() or digest(archives[0]) != package["checksum"]:
            raise ValueError("verified crate archive missing: " + stem)
        directory, _ = extract(archives[0], output, stem, 32 * 1024**2)
        patch = ROOT / "ports/cosmic/patches" / (stem + "-cyxia-static.patch")
        subprocess.run(["git", "apply", "--check", str(patch)], cwd=directory, check=True)
        subprocess.run(["git", "apply", str(patch)], cwd=directory, check=True)
        records.append({"name": name, "version": package["version"], "path": str(directory),
                        "archive_sha256": package["checksum"], "patch_sha256": digest(patch),
                        "source_tree": build.tree_identity(directory)})
    return records


def compile_probe(output, cache, xkb_sdk):
    cache = build.validate_cache(cache)
    sdk = json.loads((xkb_sdk / "build-report.json").read_text())
    if sdk["status"] != "cross-built" or sdk["target"] != "aarch64-linux-musl":
        raise ValueError("real target xkbcommon-X11 SDK required")
    sdk_lib = xkb_sdk / "sdk/usr/lib"
    for name, record in sdk["libraries"].items():
        if digest(sdk_lib / name) != record["sha256"]:
            raise ValueError("target SDK library identity changed")
    output = build.new_output(output)
    (output / "source/src").mkdir(parents=True)
    (output / "source/vendor").mkdir()
    report = {"status": "building", "guest_execution": "not performed",
              "cosmic_session_ready": False, "builder_sha256": digest(Path(__file__)),
              "probe_sha256": digest(PORT / "main.rs"),
              "sdk_report_sha256": digest(xkb_sdk / "build-report.json")}
    try:
        dependencies = prepare_dependencies(output / "source/vendor", cache)
        report["dependencies"] = dependencies
        source = output / "source"
        source.joinpath("Cargo.toml").write_text(
            '[package]\nname="cyxia-cosmic-x11"\nversion="0.1.0"\nedition="2021"\n'
            '[workspace]\n[dependencies]\nx11-dl={version="=2.21.0",features=["static-link"]}\n'
            'xkbcommon-dl={version="=0.4.2",features=["static-link","x11"]}\n'
            'x11rb={version="=0.13.2",default-features=false,features=["cyxia-static","dl-libxcb","xkb"]}\n'
            '[patch.crates-io]\n' + ''.join(
                p["name"] + '={path=' + json.dumps('vendor/' + p["name"] + '-' + p["version"]) + '}\n'
                for p in dependencies))
        shutil.copyfile(PORT / "main.rs", source / "src/main.rs")
        shutil.copyfile(PORT / "Cargo.lock", source / "Cargo.lock")
        before = build.tree_identity(source)
        recipe = {"native_inputs": [{"path": "sysroot/usr/lib/" + name,
                    "sha256": digest(DEFAULT_OUTPUT / "sysroot/usr/lib" / name)}
                    for name in ("libc.a", "libclang_rt.builtins-aarch64.a", "crt1.o", "crti.o", "crtn.o")]}
        tools, identities = build.tools_and_sysroot(DEFAULT_OUTPUT, recipe)
        report["toolchain"] = identities
        with tempfile.TemporaryDirectory(prefix="cyxia-static-x11-") as temp:
            control = Path(temp)
            env = build.cargo_environment(tools, identities, DEFAULT_OUTPUT, output, cache, control)
            env.update(CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_DEV_PANIC="abort",
                       CARGO_PROFILE_DEV_OPT_LEVEL="1")
            env["CARGO_ENCODED_RUSTFLAGS"] += '\x1f'.join((
                "", "-L", "native=" + str(sdk_lib), "-L", "native=" + str(DEFAULT_OUTPUT / "sysroot/usr/lib"),
                "-l", "static=xcb-xkb", "-l", "static=xcb", "-l", "static=Xau"))
            command = [str(tools["cargo"]), "build", "--manifest-path", str(source / "Cargo.toml"),
                       "--locked", "--offline", "--target", build.TARGET, "--jobs", "1"]
            report["command"] = command
            build.run_bounded(command, control, env, output / "cargo.log", 300,
                              512 * 1024**2, 256 * 1024**2, budget_root=output)
        binary = output / "target" / build.TARGET / "debug/cyxia-cosmic-x11"
        executable = output / "cosmic-x11.elf"
        shutil.copyfile(binary, executable)
        subprocess.run([str(tools["strip"]), "--strip-all", str(executable)], check=True)
        if build.tree_identity(source) != before:
            raise ValueError("build modified pinned source")
        report.update(status="cross-built", executable=inspect_elf(executable), source_tree=before)
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=build.CARGO_CACHE)
    parser.add_argument("--xkb-sdk", type=Path, required=True)
    args = parser.parse_args()
    result = compile_probe(args.output.resolve(), args.cache.resolve(), args.xkb_sdk.resolve())
    print(json.dumps({"status": result["status"], "report": str(args.output / "build-report.json")}))
