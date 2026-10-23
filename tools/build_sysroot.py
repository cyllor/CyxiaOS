#!/usr/bin/env python3
"""Build a static AArch64 musl sysroot and CyxiaOS executable, never run it.

Default inventory is read-only. `build` uses cached verified archives; add
`--fetch` for explicit network retrieval. Upstream configure/make run only
under the explicit build/bootstrap commands. `probes` links local probes
against an existing sysroot. No host includes, libc or compiler runtime are linked.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile

if __package__:
    from . import desktop_ports
else:
    import desktop_ports

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ports/libc/manifest.json"
XORG_MANIFEST = ROOT / "ports/libc/xorg-bootstrap.json"
DEFAULT_OUTPUT = ROOT / "artifacts/sysroot/aarch64-musl"
BASE = 0x01000000
LIMIT = 0x02000000
RESERVE_BYTES = 512 * 1024 * 1024
BUILD_TOOLS = ROOT / "artifacts/sysroot/build-tools"
PROBES = {
    "probe": ("probe.c", []),
    "xau-probe": ("xau_probe.c", ["-lXau"]),
    "socket-probe": ("socket_probe.c", []),
    "signal-probe": ("signal_probe.c", []),
    "desktop-api-probe": ("desktop_api_probe.c", []),
    "pipe-probe": ("pipe_probe.c", []),
    "file-probe": ("file_probe.c", []),
    "clock-probe": ("clock_probe.c", []),
    "event-probe": ("event_probe.c", []),
    "timerfd-probe": ("timerfd_probe.c", []),
    "edge-probe": ("edge_probe.c", []),
    "fd-share-probe": ("fd_share_probe.c", []),
    "scm-probe": ("scm_probe.c", []),
    "memfd-probe": ("memfd_probe.c", []),
    "cyxia-save": ("cyxia_save.c", ["-lX11", "-lxcb", "-lXau"]),
    "thread-probe": ("thread_probe.c", []),
    "spawn-probe": ("spawn_probe.c", []),
    "pty-probe": ("pty_probe.c", []),
    "cyxia-sh": ("cyxia_sh.c", []),
    "cyxia-terminal": ("cyxia_terminal.c", ["-lX11", "-lxcb", "-lXau"]),
    "x11-probe": ("x11_probe.c", ["-lX11", "-lxcb", "-lXau"]),
    "x11-inspect": ("x11_inspect.c", ["-lX11", "-lxcb", "-lXau"]),
}
XSERVER_OPTIONS = [
    "--prefix=/usr", "--host=aarch64-linux-musl", "--disable-shared", "--enable-static",
    "--enable-kdrive", "--disable-xorg", "--disable-xephyr", "--disable-xvfb",
    "--disable-xnest", "--disable-xquartz", "--disable-xwin", "--disable-glx",
    "--disable-glamor", "--disable-dri", "--disable-dri2", "--disable-dri3",
    "--disable-config-udev", "--disable-config-udev-kms", "--disable-config-hal",
    "--disable-systemd-logind", "--disable-libdrm", "--disable-record", "--disable-xv",
    "--disable-xvmc", "--disable-xdmcp", "--disable-xdm-auth-1", "--disable-secure-rpc",
    "--disable-docs", "--disable-devel-docs", "--without-xmlto", "--without-doxygen",
    "--without-fop", "--disable-unit-tests", "--disable-input-thread", "--with-sha1=libmd",
    "--disable-tcp-transport", "--disable-ipv6", "--disable-mitshm",
]


class BuildError(RuntimeError):
    """A source or target invariant was not satisfied."""


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_manifest(path: Path = MANIFEST, *, xorg: bool = False) -> dict:
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1 or (not xorg and data.get("target") != "aarch64-linux-musl"):
        raise BuildError("Unsupported sysroot manifest")
    packages = data.get("packages", [])
    expected = ["xorgproto", "xtrans", "libXau", "xcb-proto", "libxcb", "libX11"] if xorg else ["musl", "compiler-rt"]
    if [p.get("name") for p in packages] != expected:
        raise BuildError(f"Manifest must contain exactly {expected}")
    validate_packages(packages)
    return data


def validate_packages(packages: list[dict]) -> None:
    for package in packages:
        desktop_ports.identity(package)
        for field in ("archive_root", "license_file"):
            value = package.get(field, "")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value):
                raise BuildError(f"Invalid {field}")
        if not re.fullmatch(r"[0-9a-f]{64}", package.get("expected_sha256", "")):
            raise BuildError("An archive SHA256 pin is required")


def server_manifest() -> dict:
    directory = ROOT / "ports/libc"
    pixman = json.loads((directory / "pixman-source.json").read_text())
    server = json.loads((directory / "xserver-source.json").read_text())
    dependencies = json.loads((directory / "xserver-dependencies.json").read_text())["packages"]
    packages = [pixman, *dependencies, server]
    if [p.get("name") for p in packages] != ["pixman", "zlib", "freetype", "libfontenc", "libXfont2", "libxkbfile", "libmd", "xorg-server"]:
        raise BuildError("Unexpected X server bootstrap package set/order")
    validate_packages(packages)
    return {"target": "aarch64-linux-musl", "packages": packages}


def clean_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH",
                 "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "CFLAGS", "CPPFLAGS",
                 "CXXFLAGS", "LDFLAGS", "CC", "CXX", "LD", "AR", "RANLIB",
                 "COMPILER_PATH", "GCC_EXEC_PREFIX", "MAKEFLAGS"):
        env.pop(name, None)
    env.update(LC_ALL="C", SOURCE_DATE_EPOCH="1773964800")
    return env


def toolchain() -> dict[str, str]:
    clang = shutil.which("clang")
    rustc = shutil.which("rustc", path=str(Path.home() / ".cargo/bin") + os.pathsep + os.environ.get("PATH", ""))
    make = shutil.which("make")
    if not all((clang, rustc, make)):
        raise BuildError("clang, rustc (with LLVM tools) and GNU make are required")
    sysroot = subprocess.check_output([rustc, "--print", "sysroot"], text=True).strip()
    version = subprocess.check_output([rustc, "-vV"], text=True)
    host = next(line.split(": ", 1)[1] for line in version.splitlines()
                if line.startswith("host: "))
    llvm = Path(sysroot) / "lib/rustlib" / host / "bin"
    result = {"clang": clang, "make": make}
    for name in ("rust-lld", "llvm-ar", "llvm-readobj", "llvm-nm", "llvm-objdump", "llvm-strip"):
        path = llvm / name
        if not path.is_file():
            raise BuildError(f"Required LLVM tool missing: {path}")
        result[name] = str(path)
    return result


def unpack(package: dict, record: dict, source: Path) -> Path:
    """Extract verified data, allowing only archive-internal relative links."""
    archive = Path(record["directory"]) / "source.archive"
    if digest(archive) != package["expected_sha256"]:
        raise BuildError("Source archive changed after verification")
    destination = source / package["archive_root"]
    # Re-extract each build: modified previous source cannot masquerade as pinned.
    with tempfile.TemporaryDirectory(prefix=".extract-", dir=source) as temporary:
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            if sum(m.size for m in members) > 256 * 1024 * 1024:
                raise BuildError("Expanded source exceeds 256 MiB")
            for member in members:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or not path.parts
                        or path.parts[0] != package["archive_root"]
                        or not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                    raise BuildError(f"Unsafe archive member: {member.name}")
                if member.issym() or member.islnk():
                    target = PurePosixPath(posixpath.normpath(posixpath.join(
                        str(path.parent) if member.issym() else "", member.linkname)))
                    if (PurePosixPath(member.linkname).is_absolute() or not target.parts
                            or target.parts[0] != package["archive_root"] or ".." in target.parts):
                        raise BuildError(f"Unsafe archive link: {member.name}")
            bundle.extractall(temporary, members=members, filter="data")
        extracted = Path(temporary) / package["archive_root"]
        license_file = extracted / package["license_file"]
        if not license_file.is_file():
            raise BuildError("Source license file is missing")
        if package.get("license_sha256") and digest(license_file) != package["license_sha256"]:
            raise BuildError("Source license checksum mismatch")
        if destination.exists():
            shutil.rmtree(destination)
        extracted.rename(destination)
    return destination


def inspect_elf(path: Path) -> dict:
    """Check the bounded static ELF contract consumed by the CyxiaOS loader."""
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise BuildError("Expected little-endian ELF64")
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    _, kind, machine, version, entry, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, _ = h
    if (kind, machine, version, ehsize, phsize) != (2, 183, 1, 64, 56):
        raise BuildError("Expected AArch64 ET_EXEC with 56-byte program headers")
    if not phnum or phnum > 32 or phoff + phnum * phsize > len(data):
        raise BuildError("Invalid program-header table")
    if shsize != 64 or shoff + shnum * shsize > len(data):
        raise BuildError("Invalid section-header table")
    for i in range(shnum):
        section = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize)
        if section[1] != 2:  # SHT_SYMTAB
            continue
        offset, size, entsize = section[4], section[5], section[9]
        if entsize != 24 or size % 24 or offset + size > len(data):
            raise BuildError("Invalid symbol table")
        for pos in range(offset, offset + size, 24):
            _, info, _, index, _, _ = struct.unpack_from("<IBBHQQ", data, pos)
            if info >> 4 == 1 and index == 0:  # STB_GLOBAL, SHN_UNDEF
                raise BuildError("Unresolved strong symbol in static ELF")
    headers = []
    loads = []
    for i in range(phnum):
        fields = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize)
        p = dict(zip(("type", "flags", "offset", "vaddr", "paddr",
                      "filesz", "memsz", "align"), fields))
        headers.append(p)
        if p["type"] in (2, 3):
            raise BuildError("Dynamic/INTERP images are outside this static baseline")
        if p["type"] == 1:
            if (p["filesz"] > p["memsz"] or p["offset"] + p["filesz"] > len(data)
                    or not BASE <= p["vaddr"] < LIMIT
                    or p["vaddr"] + p["memsz"] > LIMIT
                    or p["flags"] & 3 == 3
                    or p["align"] != 4096
                    or (p["vaddr"] - p["offset"]) % 4096):
                raise BuildError("Invalid LOAD bounds, alignment or W^X permissions")
            start = p["vaddr"] & ~4095
            end = (p["vaddr"] + p["memsz"] + 4095) & ~4095
            if any(start < previous[1] and previous[0] < end for previous in loads):
                raise BuildError("Overlapping LOAD pages")
            loads.append((start, end))
    if not any(p["type"] == 1 and p["flags"] & 1 and
               p["vaddr"] <= entry < p["vaddr"] + p["filesz"] for p in headers):
        raise BuildError("Entry point must be inside file-backed executable LOAD")
    phdr = next((p for p in headers if p["type"] == 6), None)
    if phdr is None or not any(p["type"] == 1 and p["flags"] & 4 and
                               p["vaddr"] <= phdr["vaddr"] and
                               phdr["vaddr"] + phnum * phsize <= p["vaddr"] + p["filesz"]
                               for p in headers):
        raise BuildError("Program headers must be mapped for musl TLS startup")
    return {"file": str(path), "sha256": digest(path), "bytes": len(data),
            "entry": entry, "at_phdr": phdr["vaddr"], "at_phent": phsize,
            "at_phnum": phnum, "program_headers": headers}


def compiler_runtime_sources(source: Path) -> list[str]:
    text = (source / "lib/builtins/CMakeLists.txt").read_text()
    names = []
    for group in ("GENERIC_SOURCES", "GENERIC_TF_SOURCES"):
        match = re.search(r"set\(" + group + r"\s+([^)]*)\)", text)
        if match is None:
            raise BuildError(f"Missing upstream source group {group}")
        entries = match.group(1).split()
        if not entries or any(not re.fullmatch(r"[a-zA-Z0-9_]+\.c", x) for x in entries):
            raise BuildError("Unexpected compiler-rt source group")
        names.extend(entries)
    names.remove("fp_mode.c")
    names.append("aarch64/fp_mode.c")
    names.append("clear_cache.c")
    return names


class Builder:
    def __init__(self, output: Path, tools: dict[str, str], jobs: int):
        self.output, self.tools, self.jobs = output, tools, jobs
        self.env = clean_env()
        self.commands: list[list[str]] = []

    def run(self, command: list[str], log: str, cwd: Path | None = None) -> None:
        self.commands.append(command)
        with (self.output / "logs" / log).open("w") as stream:
            process = subprocess.run(command, cwd=cwd, env=self.env, stdout=stream,
                                     stderr=subprocess.STDOUT, check=False)
        if process.returncode:
            raise BuildError(f"Command failed ({process.returncode}); see {self.output / 'logs' / log}")

    def shell_wrapper(self, name: str, arguments: list[str]) -> Path:
        path = self.output / "bin" / name
        path.write_text("#!/bin/sh\nexec " + shlex.join(arguments) + ' "$@"\n')
        path.chmod(0o755)
        return path

    def build(self, manifest: dict, records: list[dict]) -> dict:
        out = self.output
        for directory in ("source", "logs", "bin", "licenses", "musl-build", "compiler-rt-build"):
            (out / directory).mkdir(parents=True, exist_ok=True)
        sources = [unpack(package, record, out / "source")
                   for package, record in zip(manifest["packages"], records)]
        # A fresh pinned extraction may have older timestamps than stale objects.
        # Do not let make reuse objects from edited or different-version sources.
        shutil.rmtree(out / "musl-build")
        (out / "musl-build").mkdir()
        for package, source in zip(manifest["packages"], sources):
            shutil.copyfile(source / package["license_file"], out / "licenses" / (package["name"] + ".txt"))
        linker = self.shell_wrapper("ld.lld", [self.tools["rust-lld"], "-flavor", "gnu"])
        ranlib = self.shell_wrapper("aarch64-linux-musl-ranlib", [self.tools["llvm-ar"], "s"])
        self.shell_wrapper("aarch64-linux-musl-ar", [self.tools["llvm-ar"]])
        cc = [self.tools["clang"], "--target=aarch64-linux-musl", "-march=armv8-a",
              "-mno-outline-atomics", "--ld-path=" + str(linker)]
        # Prefix /usr is safe only with the mandatory project-local DESTDIR below.
        self.run([str(sources[0] / "configure"), "--target=aarch64-linux-musl",
                  "--prefix=/usr", "--disable-shared", "--disable-wrapper",
                  "CC=" + shlex.join(cc), "AR=" + self.tools["llvm-ar"],
                  "RANLIB=" + str(ranlib), "LIBCC="], "configure.log", out / "musl-build")
        self.run([self.tools["make"], f"-j{self.jobs}"], "make.log", out / "musl-build")
        self.run([self.tools["make"], "install", "DESTDIR=" + str(out / "sysroot")],
                 "install.log", out / "musl-build")
        headers = out / "sysroot/usr/include"
        lib = out / "sysroot/usr/lib"
        target_cc = [self.tools["clang"], "--target=aarch64-linux-musl", "-march=armv8-a",
                     "-mno-outline-atomics", "-nostdinc", "-isystem", str(headers)]
        names = compiler_runtime_sources(sources[1])

        def compile_builtin(name: str) -> Path:
            obj = out / "compiler-rt-build" / (name.replace("/", "_") + ".o")
            self.run(target_cc + ["-O2", "-ffreestanding", "-fno-builtin", "-fvisibility=hidden",
                                 "-c", str(sources[1] / "lib/builtins" / name), "-o", str(obj)],
                     "builtins-" + name.replace("/", "_") + ".log")
            return obj

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.jobs) as executor:
            objects = list(executor.map(compile_builtin, names))
        builtins = lib / "libclang_rt.builtins-aarch64.a"
        builtins.unlink(missing_ok=True)
        self.run([self.tools["llvm-ar"], "rcs", str(builtins), *map(str, objects)], "builtins-ar.log")
        self.run(target_cc + ["-O2", "-ffp-contract=off", "-fno-stack-protector", "-fno-pie",
                              "-c", str(ROOT / "user/ported/probe.c"), "-o", str(out / "probe.o")], "probe-compile.log")
        temporary = out / "probe.elf.tmp"
        self.run([str(linker), "-m", "aarch64elf", "--image-base=0x01000000", "-z",
                  "max-page-size=4096", "-z", "separate-code", "-static", "--no-pie", "--build-id=sha1",
                  "-o", str(temporary), str(lib / "crt1.o"), str(lib / "crti.o"), str(out / "probe.o"),
                  "--start-group", str(lib / "libc.a"), str(builtins), "--end-group", str(lib / "crtn.o")], "probe-link.log")
        elf = inspect_elf(temporary)
        temporary.replace(out / "probe.elf")
        elf["file"] = str(out / "probe.elf")
        (out / "probe-layout.json").write_text(json.dumps(elf, indent=2) + "\n")
        self.run([self.tools["llvm-objdump"], "-d", str(out / "probe.elf")], "probe-disassembly.txt")
        self.write_cc_wrapper(target_cc, lib, linker)
        report = {"target": manifest["target"], "sources": records,
                  "toolchain": self.tools, "commands": self.commands,
                  "compiler_rt_sources": names, "probe": elf,
                  "guest_execution": "not performed by this build tool",
                  "libc_sha256": digest(lib / "libc.a"), "builtins_sha256": digest(builtins),
                  "probe_source_sha256": digest(ROOT / "user/ported/probe.c"),
                  "licenses": {str(p.relative_to(out / "licenses")): digest(p)
                               for p in (out / "licenses").rglob("*") if p.is_file()}}
        (out / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report

    def write_cc_wrapper(self, cc: list[str], lib: Path, linker: Path) -> None:
        """A target-only compiler driver for static dependency configure/builds."""
        path = self.output / "bin/aarch64-linux-musl-cc"
        script = '''#!/usr/bin/env python3
import os, subprocess, sys
CC = %r
LIB = %r
LD = %r
args = sys.argv[1:]
env = dict(os.environ)
for key in ('CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','LIBRARY_PATH','SDKROOT','MACOSX_DEPLOYMENT_TARGET','COMPILER_PATH','GCC_EXEC_PREFIX'):
    env.pop(key, None)
compile_only = any(x in args for x in ('-c','-S','-E','-M','-MM','-fsyntax-only','--version','-dumpmachine','-dumpversion','-print-search-dirs'))
cmd = CC + ['-fno-pie']
if compile_only:
    cmd += args
else:
    if '-shared' in args or '-pie' in args:
        sys.exit('This bootstrap sysroot supports static ET_EXEC only')
    cmd += ['-nostdlib','-static','--ld-path='+LD,'-Wl,--image-base=0x01000000,-z,max-page-size=4096,-z,separate-code','-L'+LIB,LIB+'/crt1.o',LIB+'/crti.o']
    cmd += args + ['-Wl,--start-group',LIB+'/libc.a',LIB+'/libclang_rt.builtins-aarch64.a','-Wl,--end-group',LIB+'/crtn.o']
sys.exit(subprocess.call(cmd, env=env))
''' % (cc, str(lib), str(linker))
        path.write_text(script)
        path.chmod(0o755)

    def build_xorg(self, manifest: dict, records: list[dict]) -> dict:
        out = self.output
        if not (out / "build-report.json").is_file():
            raise BuildError("Build the libc sysroot successfully before xorg-bootstrap")
        pkgconfig = shutil.which("pkg-config")
        if not pkgconfig:
            raise BuildError("Host pkg-config is required; no host target libraries will be used")
        sysroot = out / "sysroot"
        self.env.update(CC=str(out / "bin/aarch64-linux-musl-cc"),
                        AR=self.tools["llvm-ar"], RANLIB=str(out / "bin/aarch64-linux-musl-ranlib"),
                        PKG_CONFIG=pkgconfig, PKG_CONFIG_PATH="",
                        PKG_CONFIG_LIBDIR=os.pathsep.join(str(sysroot / x) for x in
                                                         ("usr/lib/pkgconfig", "usr/share/pkgconfig")),
                        PKG_CONFIG_SYSROOT_DIR=str(sysroot), PYTHON=sys.executable,
                        CC_FOR_BUILD=self.tools["clang"],
                        PYTHONPATH=str(out / "source/xcb-proto-1.17.0"))
        for package, record in zip(manifest["packages"], records):
            source = unpack(package, record, out / "source")
            license_dir = out / "licenses" / package["name"]
            license_dir.mkdir(exist_ok=True)
            for notice in source.glob("COPYING*"):
                shutil.copyfile(notice, license_dir / notice.name)
            build_dir = out / (package["name"] + "-build")
            if build_dir.exists():
                shutil.rmtree(build_dir)
            build_dir.mkdir()
            guess = source / "config.guess"
            if not guess.is_file():
                guess = out / "source/xorgproto-2024.1/config.guess"
            build_triplet = subprocess.check_output(["sh", str(guess)], text=True).strip()
            command = [str(source / "configure"), "--prefix=/usr", "--host=aarch64-linux-musl",
                       "--build=" + build_triplet]
            if package["name"] in ("xorgproto", "xtrans"):
                command.append("--disable-specs")
            elif package["name"] != "xcb-proto":
                command.extend(("--disable-shared", "--enable-static"))
            if package["name"] == "libxcb":
                command.extend(("--disable-xdmcp", "--disable-doxygen-doc", "--without-launchd"))
            if package["name"] == "libX11":
                command.extend(("--disable-specs", "--disable-xf86bigfont", "--without-xmlto"))
            self.run(command, package["name"] + "-configure.log", build_dir)
            self.run([self.tools["make"], f"-j{self.jobs}"], package["name"] + "-make.log", build_dir)
            self.run([self.tools["make"], "install", "DESTDIR=" + str(sysroot)],
                     package["name"] + "-install.log", build_dir)
            # Libtool .la dependency paths refer to target /usr, not the host.
            # Static .a plus pkg-config metadata suffice and avoid host leakage.
            for archive in (sysroot / "usr/lib").glob("*.la"):
                archive.unlink()
        probe = out / "xau-probe.elf.tmp"
        self.run([self.env["CC"], "-O2", str(ROOT / "user/ported/xau_probe.c"),
                  "-lXau", "-o", str(probe)], "xau-probe-link.log")
        elf = inspect_elf(probe)
        probe.replace(out / "xau-probe.elf")
        elf["file"] = str(out / "xau-probe.elf")
        report = {"sources": records, "commands": self.commands,
                  "library": str(sysroot / "usr/lib/libXau.a"),
                  "library_sha256": digest(sysroot / "usr/lib/libXau.a"),
                  "probe": elf, "guest_execution": "not performed by this build tool",
                  "scope": "X.Org protocol/transport headers, static Xau/XCB/X11; X server is not built"}
        (out / "xorg-bootstrap-report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report

    def target_environment(self) -> None:
        out = self.output
        sysroot = out / "sysroot"
        pkgconfig = shutil.which("pkg-config")
        if not pkgconfig:
            raise BuildError("Host pkg-config is required")
        self.env.update(CC=str(out / "bin/aarch64-linux-musl-cc"),
                        AR=self.tools["llvm-ar"], RANLIB=str(out / "bin/aarch64-linux-musl-ranlib"),
                        PKG_CONFIG=pkgconfig, PKG_CONFIG_PATH="",
                        PKG_CONFIG_LIBDIR=os.pathsep.join(str(sysroot / x) for x in
                                                         ("usr/lib/pkgconfig", "usr/share/pkgconfig")),
                        PKG_CONFIG_SYSROOT_DIR=str(sysroot), PYTHON=sys.executable,
                        CC_FOR_BUILD=self.tools["clang"])

    def build_probes(self, selected: list[str]) -> dict:
        """Rebuild only the named local probes; never fetch or run target code."""
        out = self.output
        cc = out / "bin/aarch64-linux-musl-cc"
        lib = out / "sysroot/usr/lib"
        required = [cc, lib / "libc.a", lib / "libclang_rt.builtins-aarch64.a"]
        if any("-lXau" in PROBES[name][1] for name in selected):
            required.append(lib / "libXau.a")
        if any("-lX11" in PROBES[name][1] for name in selected):
            required.extend((lib / "libX11.a", lib / "libxcb.a"))
        for path in required:
            if not path.is_file():
                raise BuildError(f"Build the prerequisite target sysroot first: missing {path}")
        report = {"probes": {}, "source_sha256": {}, "commands": self.commands,
                  "libc_sha256": digest(lib / "libc.a"),
                  "builtins_sha256": digest(lib / "libclang_rt.builtins-aarch64.a"),
                  "driver_sha256": digest(cc), "guest_execution": "not performed by this build tool"}
        for name in selected:
            filename, libraries = PROBES[name]
            source = ROOT / "user/ported" / filename
            temporary = out / (name + ".elf.tmp")
            report["source_sha256"][name] = digest(source)
            self.run([str(cc), "-O2", "-ffp-contract=off", "-fno-stack-protector",
                      "-Wall", "-Wextra", "-Werror", str(source), *libraries,
                      "-o", str(temporary)], name + "-link.log")
            if "-lX11" in libraries:
                shutil.copyfile(temporary, out / (name + ".symbols.elf"))
                self.run([self.tools["llvm-strip"], "--strip-debug", str(temporary)], name + "-strip.log")
            elf = inspect_elf(temporary)
            target = out / (name + ".elf")
            temporary.replace(target)
            elf["file"] = str(target)
            elf["source_sha256"] = report["source_sha256"][name]
            elf["libc_sha256"] = report["libc_sha256"]
            elf["driver_sha256"] = report["driver_sha256"]
            (out / (name + "-layout.json")).write_text(json.dumps(elf, indent=2) + "\n")
            report["probes"][name] = elf
        (out / "probes-build-report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report

    def build_xserver(self, manifest: dict, records: list[dict]) -> dict:
        out = self.output
        sysroot = out / "sysroot"
        for library in ("libc.a", "libX11.a", "libxcb.a", "libXau.a"):
            if not (sysroot / "usr/lib" / library).is_file():
                raise BuildError("Build libc and xorg-bootstrap before server-bootstrap")
        self.target_environment()
        meson = BUILD_TOOLS / "bin/meson"
        if not meson.is_file():
            raise BuildError("Install the project-local build tools using ports/libc/build-tools.lock first")
        self.env["PATH"] = str(BUILD_TOOLS / "bin") + os.pathsep + self.env.get("PATH", "")
        triplet = subprocess.check_output(["sh", str(out / "source/xorgproto-2024.1/config.guess")], text=True).strip()
        sources = {}
        for package, record in zip(manifest["packages"], records):
            source = unpack(package, record, out / "source")
            sources[package["name"]] = source
            notices = [source / package["license_file"], *source.glob("COPYING*")]
            if package["name"] == "freetype":
                notices.extend((source / "docs/FTL.TXT", source / "docs/GPLv2.TXT"))
            license_dir = out / "licenses" / package["name"]
            license_dir.mkdir(exist_ok=True)
            for notice in notices:
                shutil.copyfile(notice, license_dir / notice.name)
            build_dir = out / (package["name"] + "-build")
            if package["name"] == "xorg-server":
                continue
            if build_dir.exists():
                shutil.rmtree(build_dir)
            if package["name"] == "pixman":
                cross = out / "pixman-cross.ini"
                cross.write_text("[binaries]\n" +
                                 "c = " + repr(self.env["CC"]) + "\n" +
                                 "ar = " + repr(self.tools["llvm-ar"]) + "\n" +
                                 "strip = " + repr(self.tools["llvm-strip"]) + "\n" +
                                 "pkg-config = " + repr(self.env["PKG_CONFIG"]) + "\n" +
                                 "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\ncpu = 'cortex-a53'\nendian = 'little'\n" +
                                 "[properties]\nneeds_exe_wrapper = true\nsys_root = " + repr(str(sysroot)) + "\n" +
                                 "pkg_config_libdir = " + repr(self.env["PKG_CONFIG_LIBDIR"].split(os.pathsep)) + "\n")
                self.run([str(meson), "setup", str(build_dir), str(source), "--cross-file", str(cross),
                          "--prefix=/usr", "--libdir=lib", "--default-library=static", "-Dtests=disabled",
                          "-Ddemos=disabled", "-Dgtk=disabled", "-Dlibpng=disabled", "-Da64-neon=disabled"], "pixman-setup.log")
                self.run([str(meson), "compile", "-C", str(build_dir), "-j", str(self.jobs)], "pixman-build.log")
                self.env["DESTDIR"] = str(sysroot)
                self.run([str(meson), "install", "-C", str(build_dir)], "pixman-install.log")
                self.env.pop("DESTDIR")
                continue
            build_dir.mkdir()
            options = ["--prefix=/usr", "--host=aarch64-linux-musl", "--build=" + triplet,
                       "--disable-shared", "--enable-static"]
            if package["name"] == "zlib":
                options = ["--prefix=/usr", "--static"]
                self.env["CHOST"] = "aarch64-linux-musl"
            if package["name"] == "freetype":
                options += ["--with-zlib=yes", "--with-bzip2=no", "--with-png=no", "--with-harfbuzz=no", "--with-brotli=no"]
            if package["name"] == "libXfont2":
                options += ["--disable-devel-docs", "--without-xmlto", "--without-fop"]
            self.run([str(source / "configure"), *options], package["name"] + "-configure.log", build_dir)
            self.env.pop("CHOST", None)
            self.run([self.tools["make"], f"-j{self.jobs}"], package["name"] + "-make.log", build_dir)
            self.run([self.tools["make"], "install", "DESTDIR=" + str(sysroot)], package["name"] + "-install.log", build_dir)
            for archive in (sysroot / "usr/lib").glob("*.la"):
                archive.unlink()

        source = sources["xorg-server"]
        patch_file = ROOT / "ports/libc/patches/xorg-cyxia-precompiled-xkm.patch"
        self.run(["patch", "--batch", "-p1", "-i", str(patch_file)], "xserver-patch.log", source)
        build_dir = out / "xserver-build"
        if build_dir.exists():
            shutil.rmtree(build_dir)
        build_dir.mkdir()
        triplet = subprocess.check_output(["sh", str(source / "config.guess")], text=True).strip()
        # The kernel implements poll, not epoll; select the real upstream fallback.
        self.env.update(ac_cv_func_epoll_create1="no", CPPFLAGS="-DCYXIA_OS=1")
        self.run([str(source / "configure"), *XSERVER_OPTIONS, "--build=" + triplet], "xserver-configure.log", build_dir)
        self.run([self.tools["make"], f"-j{self.jobs}"], "xserver-make.log", build_dir)
        elf = self.link_xserver()
        report = {"sources": records, "commands": self.commands, "probe": elf,
                  "patch_sha256": digest(patch_file),
                  "ddx_sha256": digest(ROOT / "user/ported/xorg/cyxia_ddx.c"),
                  "abi_header_sha256": digest(ROOT / "user/ported/xorg/cyxia_abi.h"),
                  "guest_execution": "not performed by this build tool",
                  "scope": "Real upstream X.Org core/Kdrive with CyxiaOS display/input DDX; requires target XKM asset"}
        (out / "xserver-build-report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report

    def link_xserver(self) -> dict:
        out = self.output
        src = out / "source/xorg-server-21.1.25"
        include_dirs = [p for p in src.iterdir() if p.is_dir()]
        include_dirs += [src / x for x in ("hw/kdrive/src", "miext/shadow", "miext/damage", "miext/sync")]
        cc = str(out / "bin/aarch64-linux-musl-cc")
        self.run([cc, "-O2", "-D_GNU_SOURCE", "-DHAVE_DIX_CONFIG_H", "-DCYXIA_OS=1",
                  "-I" + str(out / "xserver-build/include"), "-I" + str(out / "sysroot/usr/include/pixman-1"),
                  *["-I" + str(p) for p in include_dirs], "-c", str(ROOT / "user/ported/xorg/cyxia_ddx.c"),
                  "-o", str(out / "cyxia-ddx.o")], "cyxia-ddx-compile.log")
        names = ["dix/libmain", "dix/libdix", "hw/kdrive/src/libkdrive", "fb/libfb", "mi/libmi",
                 "xfixes/libxfixes", "Xext/libXext", "Xext/libhashtable", "dbe/libdbe", "randr/librandr",
                 "render/librender", "damageext/libdamageext", "present/libpresent", "miext/sync/libsync",
                 "miext/damage/libdamage", "miext/shadow/libshadow", "Xi/libXi", "xkb/libxkb",
                 "xkb/libxkbstubs", "composite/libcomposite", "os/libos", "config/libconfig"]
        archives = [out / "xserver-build" / Path(x).parent / ".libs" / (Path(x).name + ".a") for x in names]
        temporary = out / "Xcyxia.elf.tmp"
        self.run([cc, str(out / "cyxia-ddx.o"), "-Wl,--start-group", *map(str, archives),
                  "-lXfont2", "-lfontenc", "-lfreetype", "-lxkbfile", "-lX11", "-lxcb", "-lXau",
                  "-lpixman-1", "-lmd", "-lz", "-lm", "-lpthread", "-Wl,--end-group", "-o", str(temporary)], "xcyxia-link.log")
        self.run([self.tools["llvm-strip"], "--strip-debug", str(temporary)], "xcyxia-strip.log")
        elf = inspect_elf(temporary)
        temporary.replace(out / "Xcyxia.elf")
        elf["file"] = str(out / "Xcyxia.elf")
        (out / "xcyxia-layout.json").write_text(json.dumps(elf, indent=2) + "\n")
        return elf


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("inventory", "build", "inspect", "xorg-bootstrap", "server-bootstrap", "probes"), default="inventory")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache", type=Path, default=desktop_ports.DEFAULT_CACHE)
    parser.add_argument("--fetch", action="store_true", help="Allow retrieval of the two pinned source archives")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 6))
    parser.add_argument("--probe", choices=tuple(PROBES), action="append", help="For probes: select a named probe (repeatable); default all")
    args = parser.parse_args()
    try:
        if args.jobs < 1 or args.jobs > 32:
            raise BuildError("jobs must be between 1 and 32")
        if args.fetch and args.command not in ("build", "xorg-bootstrap", "server-bootstrap"):
            raise BuildError("--fetch requires the explicit build command")
        if args.probe and args.command != "probes":
            raise BuildError("--probe requires the probes command")
        manifest = (server_manifest() if args.command == "server-bootstrap" else
                    load_manifest(XORG_MANIFEST, xorg=True) if args.command == "xorg-bootstrap" else load_manifest())
        if args.command == "inventory":
            print(json.dumps({"manifest": manifest, "toolchain": toolchain(),
                              "output": str(args.output), "network": False}, indent=2))
            return 0
        if args.command == "inspect":
            print(json.dumps(inspect_elf(args.output / "probe.elf"), indent=2))
            return 0
        output = args.output.resolve()
        if not output.is_relative_to(ROOT / "artifacts"):
            raise BuildError("Build output must remain inside this project's artifacts directory")
        output.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(output).free < RESERVE_BYTES:
            raise BuildError("At least 512 MiB free space required for build and reserve")
        with (output / ".build.lock").open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise BuildError("Another sysroot build is active") from error
            report_name = ("probes-build-report.json" if args.command == "probes" else
                           "xserver-build-report.json" if args.command == "server-bootstrap" else
                           "xorg-bootstrap-report.json" if args.command == "xorg-bootstrap" else "build-report.json")
            (output / report_name).unlink(missing_ok=True)
            records = []
            for package in ([] if args.command == "probes" else manifest["packages"]):
                if args.fetch:
                    records.append(desktop_ports.fetch(package, args.cache, online=True, max_bytes=8 * 1024 * 1024))
                else:
                    records.append(desktop_ports.verify(package, args.cache, max_bytes=8 * 1024 * 1024))
            builder = Builder(output, toolchain(), args.jobs)
            report = (builder.build_probes(list(dict.fromkeys(args.probe or PROBES))) if args.command == "probes" else
                      builder.build_xserver(manifest, records) if args.command == "server-bootstrap" else
                      builder.build_xorg(manifest, records) if args.command == "xorg-bootstrap"
                      else builder.build(manifest, records))
        print(json.dumps({"status": "cross-built", "probes" if args.command == "probes" else "probe": report.get("probes", report.get("probe")),
                          "report": str(output / report_name), "guest_execution": report["guest_execution"]}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError,
            subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"sysroot: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
