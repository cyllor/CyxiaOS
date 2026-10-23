#!/usr/bin/env python3
"""Build pinned host xkbcomp and a verified US XKM; never run target code.

`inventory` is read-only. `build` is offline by default; --fetch permits missing
pinned archives to be downloaded. Every build uses a fresh isolated directory,
including all host X11 libraries. No X server or DISPLAY connection is needed.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

if __package__:
    from . import build_sysroot, desktop_ports
else:
    import build_sysroot
    import desktop_ports

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ports/xkb/manifest.json"
DEFAULT_OUTPUT = ROOT / "artifacts/xkb-host"
DEFAULT_ROOTFS = ROOT / "artifacts/sysroot/aarch64-musl/rootfs"
PACKAGE_NAMES = ("xorgproto", "xtrans", "libXau", "xcb-proto", "libxcb", "libX11",
                 "libxkbfile", "xkbcomp", "xkeyboard-config")
BuildError = build_sysroot.BuildError
digest = build_sysroot.digest


def load_manifest(path: Path = MANIFEST) -> dict:
    data = desktop_ports.load_manifest(path)
    packages = data["packages"]
    if tuple(p["name"] for p in packages) != PACKAGE_NAMES:
        raise BuildError("Unexpected host XKB dependency closure")
    for package in packages:
        desktop_ports.identity(package)
        if not re.fullmatch(r"[0-9a-f]{64}", package.get("expected_sha256") or ""):
            raise BuildError("Every source archive needs a SHA256 pin")
        for field in ("archive_root", "license_file"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", package.get(field, "")):
                raise BuildError(f"Invalid source {field}")
    for entry in data.get("host_patches", []):
        if entry.get("package") not in PACKAGE_NAMES:
            raise BuildError("Unknown host patch package")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", entry.get("file", "")):
            raise BuildError("Host patch must be a local plain filename")
        original = PurePosixPath(entry.get("original_file", ""))
        if not original.parts or original.is_absolute() or ".." in original.parts:
            raise BuildError("Host patch original file must remain inside source")
        for field in ("sha256", "original_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", entry.get(field, "")):
                raise BuildError("Host patch and original source need SHA256 pins")
    return data


def host_env(prefix: Path) -> dict[str, str]:
    env = build_sysroot.clean_env()
    for name in ("DISPLAY", "XAUTHORITY", "PYTHONPATH", "PKG_CONFIG_SYSROOT_DIR", "LIBS",
                 "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH", "CONFIG_SITE"):
        env.pop(name, None)
    for name in list(env):
        if name.endswith(("_CFLAGS", "_LIBS")) or name.startswith(("ac_cv_", "xorg_cv_")):
            env.pop(name)
    env.update(CC=shutil.which("clang") or "clang", CFLAGS="-O2",
               PKG_CONFIG=shutil.which("pkg-config") or "pkg-config",
               PKG_CONFIG_PATH="", PKG_CONFIG_LIBDIR=os.pathsep.join(
                   str(prefix / p) for p in ("lib/pkgconfig", "share/pkgconfig")),
               PYTHON=sys.executable, CONFIG_SITE="/dev/null")
    return env


class Builder:
    def __init__(self, output: Path, jobs: int):
        self.output = output
        self.jobs = jobs
        runs = output / "runs"
        runs.mkdir(parents=True, exist_ok=True)
        self.run_dir = Path(tempfile.mkdtemp(prefix="build-", dir=runs))
        self.prefix = self.run_dir / "host"
        for directory in ("source", "logs", "licenses", "build"):
            (self.run_dir / directory).mkdir()
        self.env = host_env(self.prefix)
        self.commands: list[list[str]] = []

    def run(self, command: list[str], log: str, cwd: Path | None = None) -> None:
        self.commands.append(command)
        log_path = self.run_dir / "logs" / log
        with log_path.open("w") as stream:
            result = subprocess.run(command, cwd=cwd, env=self.env, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise BuildError(f"Command failed ({result.returncode}): {log_path}")

    def build(self, manifest: dict, records: list[dict], rootfs: Path) -> dict:
        sources = {}
        for package, record in zip(manifest["packages"], records):
            name = package["name"]
            source = build_sysroot.unpack(package, record, self.run_dir / "source")
            sources[name] = source
            licenses = self.run_dir / "licenses" / name
            licenses.mkdir()
            for notice in source.glob("COPYING*"):
                shutil.copyfile(notice, licenses / notice.name)
            for entry in manifest.get("host_patches", []):
                if entry["package"] != name:
                    continue
                patch = ROOT / "ports/xkb" / entry["file"]
                if (digest(patch) != entry["sha256"] or
                        digest(source / entry["original_file"]) != entry["original_sha256"]):
                    raise BuildError("Host patch or original source checksum mismatch")
                self.run(["patch", "-p1", "--batch", "--forward", "-i", str(patch)],
                         name + "-patch.log", source)
            if name == "xkeyboard-config":
                continue  # Explicit component includes need no generated rules.
            print(f"Building host {name} {package['version']}", flush=True)
            build = self.run_dir / "build" / name
            build.mkdir()
            command = [str(source / "configure"), "--prefix=" + str(self.prefix)]
            if name in ("xorgproto", "xtrans"):
                command.append("--disable-specs")
            elif name not in ("xcb-proto", "xkbcomp"):
                command.extend(("--disable-shared", "--enable-static"))
            if name == "libxcb":
                self.env["PYTHONPATH"] = str(sources["xcb-proto"])
                command.extend(("--disable-xdmcp", "--disable-doxygen-doc", "--without-launchd"))
            elif name == "libX11":
                command.extend(("--disable-specs", "--disable-xf86bigfont", "--without-xmlto"))
            elif name == "xkbcomp":
                command.append("--with-xkb-config-root=" + str(self.run_dir / "source/xkeyboard-config-2.42"))
                # Upstream's normal pkg-config query omits X11's private XCB
                # dependency. This host closure deliberately builds only .a files.
                self.env["XKBCOMP_LIBS"] = subprocess.check_output(
                    [self.env["PKG_CONFIG"], "--libs", "--static", "x11", "xkbfile"],
                    env=self.env, text=True).strip()
            self.run(command, name + "-configure.log", build)
            self.run(["make", f"-j{self.jobs}"], name + "-make.log", build)
            self.run(["make", "install"], name + "-install.log", build)
        compiler = self.prefix / "bin/xkbcomp"
        version = subprocess.check_output([str(compiler), "-version"], env=self.env,
                                          text=True, stderr=subprocess.STDOUT).strip()
        if version != "xkbcomp 1.4.7":
            raise BuildError(f"Unexpected compiler version: {version}")
        data = sources["xkeyboard-config"]
        keymap = ROOT / "ports/xkb/cyxia-us.xkb"
        first = self.run_dir / "cyxia-us.xkm"
        second = self.run_dir / "cyxia-us-repeat.xkm"
        # Bare -I clears all implicit include paths, including host installations.
        for index, target in enumerate((first, second)):
            self.run([str(compiler), "-w", "3", "-I", "-I" + str(data), "-xkm",
                      str(keymap), str(target)], f"compile-{index}.log", self.run_dir)
        if first.read_bytes() != second.read_bytes():
            raise BuildError("Repeated XKM compilation is not byte-identical")
        self.run([str(compiler), "-xkb", str(first), str(self.run_dir / "cyxia-us-expanded.xkb")],
                 "decompile.log", self.run_dir)
        flags = subprocess.check_output([self.env["PKG_CONFIG"], "--cflags", "--libs",
                                         "--static", "xkbfile"], env=self.env, text=True)
        probe = self.run_dir / "verify-xkm"
        self.run([self.env["CC"], "-O2", "-Wall", "-Wextra", "-Werror",
                  str(ROOT / "ports/xkb/verify_xkm.c"), *shlex.split(flags), "-o", str(probe)],
                 "reader-build.log")
        self.run([str(probe), str(first)], "reader-check.log")
        # Verify the reader is testing content: truncation must fail, not pass.
        truncated = self.run_dir / "truncated.xkm"
        truncated.write_bytes(first.read_bytes()[:16])
        with (self.run_dir / "logs/reader-negative.log").open("w") as stream:
            negative = subprocess.run([str(probe), str(truncated)], env=self.env,
                                      stdout=stream, stderr=subprocess.STDOUT, check=False)
        if negative.returncode != 4:
            raise BuildError(f"XKM reader did not cleanly reject truncated data: {negative.returncode}")
        target = rootfs / "usr/share/X11/xkb/cyxia-us.xkm"
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".cyxia-us-", delete=False) as f:
            staging = Path(f.name)
            f.write(first.read_bytes())
        staging.chmod(0o644)
        staging.replace(target)
        report = {"status": "PASS", "host": platform.platform(), "host_machine": platform.machine(),
                  "asset_byte_order": sys.byteorder,
                  "sources": records, "host_patches": manifest.get("host_patches", []),
                  "commands": self.commands, "run_directory": str(self.run_dir),
                  "compiler": str(compiler), "compiler_version": version,
                  "compiler_sha256": digest(compiler), "keymap_source": str(keymap),
                  "keymap_source_sha256": digest(keymap), "xkb_data": str(data),
                  "asset": str(target), "asset_bytes": target.stat().st_size,
                  "asset_sha256": digest(target), "repeat_identical": True,
                  "upstream_reader": "PASS", "truncated_data_rejected": True,
                  "target_execution": "not performed; target must load with XkmReadFile",
                  "scope": "US evdev pc105 data; no desktop or input runtime claim"}
        (self.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "build"), default="inventory", nargs="?")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--rootfs", type=Path, default=DEFAULT_ROOTFS)
    parser.add_argument("--cache", type=Path, default=desktop_ports.DEFAULT_CACHE)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        if args.command == "inventory":
            if args.fetch:
                raise BuildError("--fetch requires build")
            print(json.dumps({"packages": [p["name"] for p in manifest["packages"]],
                              "output": str(args.output), "asset_rootfs": str(args.rootfs)}, indent=2))
            return 0
        if not 1 <= args.jobs <= 16:
            raise BuildError("--jobs must be between 1 and 16")
        if sys.byteorder != "little":
            raise BuildError("This XKM asset is for the little-endian AArch64 guest; use a matching host")
        for name in ("clang", "make", "pkg-config", "patch"):
            if shutil.which(name) is None:
                raise BuildError(f"Required host tool missing: {name}")
        args.output = args.output.resolve()
        args.output.mkdir(parents=True, exist_ok=True)
        desktop_ports.require_space(args.output, 256 * 1024 * 1024)
        with (args.output / ".build.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            records = [desktop_ports.fetch(p, args.cache, online=True, max_bytes=8 * 1024 * 1024)
                       if args.fetch else desktop_ports.verify(p, args.cache, 8 * 1024 * 1024)
                       for p in manifest["packages"]]
            report = Builder(args.output, args.jobs).build(manifest, records, args.rootfs.resolve())
        print(json.dumps({k: report[k] for k in ("status", "asset", "asset_bytes", "asset_sha256")}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError) as error:
        print(f"XKB build failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
