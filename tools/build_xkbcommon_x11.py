#!/usr/bin/env python3
"""Build the pinned real xkbcommon X11 adapter in a private target SDK.

This extends the existing core-only port without replacing its libraries or
receipts. It does not execute target code or certify a COSMIC session.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import sys

from build_cosmic import clean_environment, new_output, run_bounded, tree_identity
from build_gtk_foundation import archive_architecture
from build_sysroot import BUILD_TOOLS, DEFAULT_OUTPUT, ROOT, digest, toolchain, unpack
import desktop_ports


MANIFEST = ROOT / "ports/cosmic/xkbcommon-source.json"


def build(output, jobs=1):
    if not 1 <= jobs <= 4:
        raise ValueError("jobs must be in 1..4")
    package = json.loads(MANIFEST.read_text())
    cached = desktop_ports.verify(package, desktop_ports.DEFAULT_CACHE,
                                  max_bytes=8 * 1024 * 1024)
    previous = json.loads((DEFAULT_OUTPUT / "xkbcommon-build-report.json").read_text())
    bison = DEFAULT_OUTPUT / "xkbcommon-host-tools/bin/bison"
    if (previous.get("status") != "cross-built"
            or previous["manifest_sha256"] != digest(MANIFEST)
            or previous["native_bison"]["sha256"] != digest(bison)):
        raise ValueError("verified native Bison/core build is required")
    sysroot = DEFAULT_OUTPUT / "sysroot"
    tools = toolchain()
    output = new_output(output)
    for name in ("source", "logs", "sdk"):
        (output / name).mkdir()
    report = {"status": "building", "guest_execution": "not performed",
              "cosmic_session_ready": False, "target": "aarch64-linux-musl",
              "builder_sha256": digest(Path(__file__)),
              "manifest_sha256": digest(MANIFEST), "source": cached,
              "bison_sha256": digest(bison), "commands": []}
    env = clean_environment(os.pathsep.join((str(bison.parent), str(BUILD_TOOLS / "bin"),
                                            "/usr/bin", "/bin", "/opt/homebrew/bin")))
    pcdirs = os.pathsep.join(str(sysroot / p) for p in
                            ("usr/lib/pkgconfig", "usr/share/pkgconfig"))
    env.update(PKG_CONFIG_PATH="", PKG_CONFIG_LIBDIR=pcdirs,
               PKG_CONFIG_SYSROOT_DIR=str(sysroot))
    meson = str(BUILD_TOOLS / "bin/meson")
    cross = output / "cross.ini"
    cc = DEFAULT_OUTPUT / "bin/aarch64-linux-musl-cc"
    pkgconfig = DEFAULT_OUTPUT / "bin/xkbcommon-target-pkg-config"
    cross.write_text("[binaries]\n" + "c = " + repr(str(cc)) + "\n"
                     + "ar = " + repr(tools["llvm-ar"]) + "\n"
                     + "strip = " + repr(tools["llvm-strip"]) + "\n"
                     + "pkg-config = " + repr(str(pkgconfig)) + "\n"
                     + "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\n"
                     + "cpu = 'cortex-a53'\nendian = 'little'\n[properties]\n"
                     + "needs_exe_wrapper = true\nsys_root = " + repr(str(sysroot)) + "\n"
                     + "pkg_config_libdir = " + repr(pcdirs.split(os.pathsep)) + "\n")

    def run(command, label, extra=None):
        report["commands"].append(list(map(str, command)))
        run_bounded(list(map(str, command)), output, {**env, **(extra or {})},
                    output / "logs" / (label + ".log"), 180, 512 * 1024**2,
                    256 * 1024**2, budget_root=output)

    try:
        with (DEFAULT_OUTPUT / ".build.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            source = unpack(package, cached, output / "source")
            before = tree_identity(source)
            report["source_tree"] = before
            native_paths = [sysroot / "usr/lib" / name for name in
                            ("libc.a", "libxcb.a", "libxcb-xkb.a", "libXau.a")]
            report["native_inputs"] = {str(p): digest(p) for p in native_paths}
            directory = output / "build"
            options = ["--prefix=/usr", "--libdir=lib", "--wrap-mode=nofallback",
                       "--cross-file=" + str(cross), "-Dbuildtype=release",
                       "-Ddefault_library=static", "-Db_staticpic=false",
                       "-Denable-x11=true", "-Denable-wayland=false", "-Denable-docs=false",
                       "-Denable-xkbregistry=false", "-Denable-tools=false",
                       "-Denable-bash-completion=false", "-Dxkb-config-root=/usr/share/X11/xkb",
                       "-Dc_args=-ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables"]
            report["options"] = options
            run([meson, "setup", directory, source, *options], "setup")
            run([meson, "compile", "-C", directory, "-j", str(jobs),
                 "xkbcommon", "xkbcommon-x11"], "compile")
            run([meson, "install", "-C", directory, "--no-rebuild"], "install",
                {"DESTDIR": str(output / "sdk")})
            report["libraries"] = {name: archive_architecture(output / "sdk/usr/lib" / name)
                                   for name in ("libxkbcommon.a", "libxkbcommon-x11.a")}
            if tree_identity(source) != before:
                raise ValueError("build modified verified source")
            if report["native_inputs"] != {str(p): digest(p) for p in native_paths}:
                raise ValueError("build inputs changed during execution")
            report["status"] = "cross-built"
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    try:
        report = build(args.output.resolve(), args.jobs)
        print(json.dumps({"status": report["status"], "report": str(args.output / "build-report.json")}))
    except (OSError, ValueError, RuntimeError) as error:
        print("xkbcommon-x11: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
