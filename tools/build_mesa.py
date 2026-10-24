#!/usr/bin/env python3
"""Cross-build pinned Mesa softpipe for CyxiaOS without executing target code.

The build is opt-in, uses an isolated work lock, and keeps timestamped failure
reports. Inventory never downloads or builds. A target archive is not evidence
that EGL, Smithay, or COSMIC has run in the guest.
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
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import Request, build_opener

from build_sysroot import (BUILD_TOOLS, DEFAULT_OUTPUT, ROOT, Builder, BuildError,
                          clean_env, digest, inspect_elf, toolchain, validate_packages)
from build_gtk_foundation import archive_architecture
import desktop_ports

MANIFEST = ROOT / "ports/cosmic/mesa-source.json"
WORK = DEFAULT_OUTPUT / "mesa-port"
TARGET = DEFAULT_OUTPUT / "sysroot"
OPTIONS = ["--prefix=/usr", "--libdir=lib", "--wrap-mode=nofallback",
           "-Dbuildtype=minsize", "-Ddebug=false", "-Ddefault_library=static", "-Db_staticpic=false",
           "-Dplatforms=x11", "-Dgallium-drivers=softpipe", "-Dvulkan-drivers=",
           "-Dllvm=disabled", "-Ddraw-use-llvm=false", "-Dglx=disabled",
           "-Degl=enabled", "-Dgles1=disabled", "-Dgles2=enabled", "-Dgbm=disabled",
           "-Dglvnd=disabled", "-Dvideo-codecs=", "-Dgallium-va=disabled",
           "-Dbuild-tests=false", "-Dshared-glapi=disabled", "-Dopengl=false",
           "-Dcyxia-static-softpipe=true", "-Dshader-cache=disabled", "-Dallow-kcmp=disabled"]
OPTIONS.append("-Dcyxia-demand-texture-cache=true")
OPTIONS.append("-Dcyxia-compute-oom=true")
OPTIONS.append("-Dcyxia-nir-small-slabs=true")


def tree_digest(directory: Path) -> str:
    """Detect edited source before an incremental build is allowed."""
    value = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        value.update(path.relative_to(directory).as_posix().encode() + b"\0")
        if path.is_symlink():
            value.update(b"L" + os.readlink(path).encode())
        elif path.is_file():
            value.update(b"F" + digest(path).encode())
        elif path.is_dir():
            value.update(b"D")
        else:
            raise BuildError("Unexpected source object: " + str(path))
    return value.hexdigest()


def unpack_mesa(package: dict, record: dict, destination: Path) -> None:
    """Use the existing extraction rules with Mesa's explicit larger limit."""
    archive = Path(record["directory"]) / "source.archive"
    if digest(archive) != package["expected_sha256"]:
        raise BuildError("Mesa archive changed after verification")
    with tempfile.TemporaryDirectory(prefix=".mesa-extract-", dir=WORK) as temporary:
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            if sum(member.size for member in members) > package["expanded_max_bytes"]:
                raise BuildError("Mesa expanded source exceeds its manifest limit")
            for member in members:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or not path.parts
                        or path.parts[0] != package["archive_root"]
                        or not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                    raise BuildError("Unsafe archive member: " + member.name)
                if member.issym() or member.islnk():
                    target = PurePosixPath(posixpath.normpath(posixpath.join(
                        str(path.parent) if member.issym() else "", member.linkname)))
                    if (PurePosixPath(member.linkname).is_absolute() or not target.parts
                            or target.parts[0] != package["archive_root"] or ".." in target.parts):
                        raise BuildError("Unsafe archive link: " + member.name)
            bundle.extractall(temporary, members=members, filter="data")
        extracted = Path(temporary) / package["archive_root"]
        if not (extracted / package["license_file"]).is_file():
            raise BuildError("Mesa license file missing")
        if destination.exists():
            raise BuildError("Source already exists; use --resume or a fresh explicit work directory")
        extracted.rename(destination)


def prepare_source(builder: Builder, package: dict, fetch: bool, resume: bool) -> tuple[Path, dict]:
    cached = desktop_ports.destination(desktop_ports.DEFAULT_CACHE, package)
    if fetch and not cached.exists():
        archive = download_mesa(package)
        record = desktop_ports.fetch(package, desktop_ports.DEFAULT_CACHE, offline_file=archive,
                                     max_bytes=package["source_max_bytes"])
        record["download_url"] = package["source_url"]
    else:
        record = desktop_ports.verify(package, desktop_ports.DEFAULT_CACHE,
                                      max_bytes=package["source_max_bytes"])
    patches = [ROOT / value for value in package.get("patches", [])]
    identity = {"manifest_sha256": digest(MANIFEST),
                "patches": {str(path.relative_to(ROOT)): digest(path) for path in patches}}
    source = WORK / package["archive_root"]
    stamp = WORK / "source-state.json"
    if source.exists():
        if not resume or not stamp.is_file():
            raise BuildError("Existing Mesa source requires --resume and a source-state record")
        # Earlier Python generators can have created bytecode beside pinned
        # modules. These are disposable build outputs, not upstream source.
        # Do not accept or execute an edited cached module on a resumed build.
        for cache in source.rglob("__pycache__"):
            if cache.is_symlink() or any(not p.is_file() or p.suffix != ".pyc" for p in cache.iterdir()):
                raise BuildError("Unexpected content in generated Python cache")
            shutil.rmtree(cache)
        previous = json.loads(stamp.read_text())
        if previous["identity"] != identity or previous["tree_sha256"] != tree_digest(source):
            raise BuildError("Mesa source or patch identity changed; preserve it and select a fresh --work")
    else:
        unpack_mesa(package, record, source)
        for index, patch in enumerate(patches):
            builder.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)],
                        f"patch-{index}.log", source)
        stamp.write_text(json.dumps({"identity": identity, "tree_sha256": tree_digest(source)}, indent=2) + "\n")
    return source, {"archive": record, **json.loads(stamp.read_text()),
                    "license_sha256": digest(source / package["license_file"])}


def download_mesa(package: dict) -> Path:
    """Retry rate-limited exact ranges without relaxing the pinned release hash."""
    from range_download import DownloadError, download_ranges

    try:
        return download_ranges(
            package["source_url"], WORK / "mesa-verified-download.tar.xz",
            size=package["source_bytes"], sha256=package["expected_sha256"],
            max_bytes=package["source_max_bytes"],
            opener=build_opener(desktop_ports.HTTPSRedirects()),
        )
    except DownloadError as error:
        raise BuildError(str(error)) from error


def target_uapi(builder: Builder, package: dict, fetch: bool) -> dict:
    """Export only pinned arm64 UAPI headers with Linux's real export tool.

    These declarations do not implement DRM, memfd or any other syscall. The
    selected software driver still has to pass the guest ABI/runtime gates.
    """
    lock = package["target_uapi"]
    base = lock["source_url"]
    expected_base = "https://raw.githubusercontent.com/torvalds/linux/" + lock["source_commit"] + "/"
    if base != expected_base or lock["architecture"] != "arm64":
        raise BuildError("Unexpected target UAPI provenance")
    source = WORK / "uapi-source"
    exported = WORK / "uapi-include"
    pinned = {item["source_path"]: item["sha256"] for item in lock["files"].values()}
    pinned.update(lock["provenance"])
    for relative, expected in pinned.items():
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts:
            raise BuildError("Unsafe UAPI source path")
        destination = source / relative
        cache = DEFAULT_OUTPUT / "mesa-uapi-source" / relative
        if destination.is_symlink():
            raise BuildError("Refusing linked UAPI source")
        if not destination.is_file():
            if cache.is_file() and digest(cache) == expected:
                content = cache.read_bytes()
            elif fetch:
                with build_opener(desktop_ports.HTTPSRedirects()).open(base + relative, timeout=30) as response:
                    content = response.read(256 * 1024 + 1)
                if len(content) > 256 * 1024:
                    raise BuildError("UAPI header/source exceeds bounded size")
            else:
                raise BuildError("Missing pinned UAPI file; use --fetch: " + relative)
            if hashlib.sha256(content).hexdigest() != expected:
                raise BuildError("UAPI source hash mismatch: " + relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        if digest(destination) != expected:
            raise BuildError("Edited UAPI source: " + relative)
    # Native tool, never linked into a target library or run as target code.
    builder.run([builder.tools["clang"], "-O2", str(source / "scripts/unifdef.c"),
                 "-o", str(source / "scripts/unifdef")], "uapi-export-tool.log")
    # The official script uses two GNU-sed spellings that BSD sed rejects.
    # Equivalent POSIX spellings change no header contents or export rules.
    export_script = WORK / "bin/uapi-headers-install.sh"
    export_script.write_text((source / "scripts/headers_install.sh").read_text()
        .replace('/!p}"', '/!p;}"')
        .replace('compiler(|_types)', 'compiler(_types)?'))
    for index, (header, item) in enumerate(lock["files"].items()):
        path = PurePosixPath(header)
        if path.is_absolute() or ".." in path.parts:
            raise BuildError("Unsafe exported UAPI header path")
        destination = exported / header
        destination.parent.mkdir(parents=True, exist_ok=True)
        builder.run(["sh", str(export_script),
                     str(source / item["source_path"]), str(destination)],
                    f"uapi-export-{index}.log", source)
    mandatory = (source / "include/uapi/asm-generic/Kbuild").read_text()
    for header, target in lock["generic_wrappers"].items():
        name = PurePosixPath(header).name
        if (header != "asm/" + name or target != "asm-generic/" + name
                or "mandatory-y += " + name not in mandatory or target not in lock["files"]):
            raise BuildError("UAPI wrapper is not prescribed by the pinned arm64 export")
        destination = exported / header
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("#include <" + target + ">\n")
    return {"commit": lock["source_commit"], "include_directory": str(exported),
            "tree_sha256": tree_digest(exported), "source_files": pinned,
            "host_export_script_sha256": digest(export_script),
            "scope": lock["scope"]}


def environment(builder: Builder) -> tuple[Path, Path, list[str]]:
    builder.env = clean_env()
    for key in list(builder.env):
        if key.startswith("PKG_CONFIG") or key in ("DESTDIR", "RUSTFLAGS", "PYTHONPATH"):
            builder.env.pop(key)
    pkg = shutil.which("pkg-config")
    if not pkg:
        raise BuildError("pkg-config is required")
    builder.env.update(
        CC=str(DEFAULT_OUTPUT / "bin/aarch64-linux-musl-cc"),
        CXX=str(WORK / "bin/mesa-target-cxx"),
        AR=builder.tools["llvm-ar"],
        PKG_CONFIG_LIBDIR=os.pathsep.join(str(TARGET / p) for p in ("usr/lib/pkgconfig", "usr/share/pkgconfig")),
        PKG_CONFIG_SYSROOT_DIR=str(TARGET), PKG_CONFIG_PATH="",
        PATH=os.pathsep.join((str(WORK / "host-python/bin"),
                              str(DEFAULT_OUTPUT / "xkbcommon-host-tools/bin"),
                              str(BUILD_TOOLS / "bin"), builder.env.get("PATH", ""))),
        PYTHON=str(WORK / "host-python/bin/python3"),
        PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(WORK / "python-cache"))
    target_pkg = builder.shell_wrapper("mesa-target-pkg-config", [pkg, "--static"])
    builder.env["PKG_CONFIG"] = str(target_pkg)
    # Native generators must not discover target libraries or target headers.
    host_pkg = builder.shell_wrapper("mesa-host-pkg-config", ["env", "-u", "PKG_CONFIG_SYSROOT_DIR",
        "-u", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR=" + str(WORK / "host-empty-pkgconfig"), pkg])
    cross = WORK / "cross.ini"
    resource = subprocess.check_output([builder.tools["clang"], "-print-resource-dir"], text=True).strip()
    builtin_headers = Path(resource) / "include"
    if not (builtin_headers / "arm_neon.h").is_file():
        raise BuildError("Clang's target ARM intrinsic headers are missing")
    compile_args = ["-ffunction-sections", "-fdata-sections", "-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables", "-isystem", str(builtin_headers),
                    "-isystem", str(WORK / "uapi-include")]
    cross.write_text("[binaries]\n" +
        "c = " + repr(builder.env["CC"]) + "\ncpp = " + repr(builder.env["CXX"]) + "\n" +
        "ar = " + repr(builder.tools["llvm-ar"]) + "\nstrip = " + repr(builder.tools["llvm-strip"]) + "\n" +
        "pkg-config = " + repr(str(target_pkg)) + "\n" +
        "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\ncpu = 'cortex-a53'\nendian = 'little'\n" +
        "[properties]\nneeds_exe_wrapper = true\nsys_root = " + repr(str(TARGET)) + "\n" +
        "pkg_config_libdir = " + repr(builder.env["PKG_CONFIG_LIBDIR"].split(os.pathsep)) + "\n" +
        "[built-in options]\nc_args = " + repr(compile_args) + "\ncpp_args = " + repr(compile_args) + "\n")
    native = WORK / "native.ini"
    native.write_text("[binaries]\nc = " + repr(builder.tools["clang"]) + "\ncpp = " +
                      repr(builder.tools["clang"] + "++") + "\npkg-config = " + repr(str(host_pkg)) + "\n")
    return cross, native, compile_args


def target_cxx(builder: Builder, package: dict, fetch: bool) -> dict:
    """Build the real upstream allocation/mutex/guard runtime used by Mesa.

    This intentionally does not advertise a complete libc++ or exception ABI.
    All C++ headers come from the pinned libc++ archive, never the host SDK.
    """
    spec = package["target_cxx"]
    roots, records = {}, {}
    for item in spec["packages"]:
        cache = desktop_ports.destination(desktop_ports.DEFAULT_CACHE, item)
        if not cache.exists():
            archive = DEFAULT_OUTPUT / "mesa-cxx-source" / (item["archive_root"] + ".tar.xz")
            if archive.is_file():
                record = desktop_ports.fetch(item, desktop_ports.DEFAULT_CACHE, offline_file=archive,
                                             max_bytes=item["source_max_bytes"])
            elif fetch:
                record = desktop_ports.fetch(item, desktop_ports.DEFAULT_CACHE,
                                             max_bytes=item["source_max_bytes"])
            else:
                raise BuildError("Missing pinned C++ source: " + item["name"])
        else:
            record = desktop_ports.verify(item, desktop_ports.DEFAULT_CACHE,
                                           max_bytes=item["source_max_bytes"])
        destination = WORK / item["archive_root"]
        state = WORK / (item["name"] + "-source-state.json")
        if destination.exists():
            previous = json.loads(state.read_text())
            if previous["archive_sha256"] != item["expected_sha256"] or previous["tree_sha256"] != tree_digest(destination):
                raise BuildError("Edited C++ runtime source: " + item["name"])
        else:
            unpack_mesa(item, record, destination)
            previous = {"archive_sha256": item["expected_sha256"], "tree_sha256": tree_digest(destination)}
            state.write_text(json.dumps(previous, indent=2) + "\n")
        roots[item["name"]], records[item["name"]] = destination, previous
    config = WORK / "cxx-config"
    config.mkdir(exist_ok=True)
    values = {"_LIBCPP_ABI_VERSION": "1", "_LIBCPP_ABI_NAMESPACE": "__1",
              "_LIBCPP_HAS_THREADS": "1", "_LIBCPP_HAS_MONOTONIC_CLOCK": "1",
              "_LIBCPP_HAS_MUSL_LIBC": "1", "_LIBCPP_HAS_THREAD_API_PTHREAD": "1",
              "_LIBCPP_HAS_UNICODE": "1", "_LIBCPP_HAS_WIDE_CHARACTERS": "1",
              "_LIBCPP_PSTL_BACKEND_SERIAL": "", "_LIBCPP_HARDENING_MODE_DEFAULT": "2"}
    configured = []
    for line in (roots["libcxx"] / "include/__config_site.in").read_text().splitlines():
        if line.startswith("#cmakedefine"):
            directive, name, *_ = line.split()
            if name in values or directive == "#cmakedefine01":
                configured.append("#define " + name + " " + values.get(name, "0"))
            else:
                configured.append("/* #undef " + name + " */")
        elif line in ("@_LIBCPP_ABI_DEFINES@", "@_LIBCPP_EXTRA_SITE_DEFINES@"):
            continue
        else:
            configured.append(line)
    (config / "__config_site").write_text("\n".join(configured) + "\n")
    shutil.copyfile(roots["libcxx"] / "vendor/llvm/default_assertion_handler.in", config / "__assertion_handler")
    cpp = builder.shell_wrapper("mesa-target-cxx", [str(DEFAULT_OUTPUT / "bin/aarch64-linux-musl-cc"),
        "-std=c++17", "-nostdinc++", "-I" + str(config), "-I" + str(roots["libcxx"] / "include"),
        "-fno-exceptions", "-fno-rtti"])
    objects = WORK / "cxx-runtime"
    objects.mkdir(exist_ok=True)
    sources = []
    for relative in spec["sources"]:
        component, rest = relative.split("/", 1)
        source = roots[component] / rest
        if not source.is_file() or ".." in PurePosixPath(rest).parts:
            raise BuildError("Invalid C++ runtime source path")
        obj = objects / (component + "-" + source.stem + ".o")
        builder.run([str(cpp), "-std=c++20", "-Oz", "-ffunction-sections", "-fdata-sections",
            "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-D_LIBCPP_BUILDING_LIBRARY",
            "-D_LIBCXXABI_BUILDING_LIBRARY", "-I" + str(roots["libcxx"] / "src"),
            "-I" + str(roots["libcxxabi"] / "include"), "-isystem", str(WORK / "uapi-include"),
            "-c", str(source), "-o", str(obj)], "cxx-" + obj.stem + ".log")
        sources.append(obj)
    archive = objects / "libcyxia-mesa-cxx.a"
    archive.unlink(missing_ok=True)
    builder.run([builder.tools["llvm-ar"], "rcs", str(archive), *map(str, sources)], "cxx-archive.log")
    return {"scope": spec["scope"], "source_commit": spec["source_commit"], "sources": records,
            "configuration_sha256": tree_digest(config), "archive": str(archive),
            "archive_sha256": digest(archive), "bytes": archive.stat().st_size}


def host_python(builder: Builder, package: dict, fetch: bool) -> dict:
    python = WORK / "host-python/bin/python3"
    state = WORK / "host-python-state.json"
    desired = package["host_python"]
    if python.is_file() and state.is_file():
        previous = json.loads(state.read_text())
        if previous["requirements"] == desired:
            builder.run([str(python), "-c", "import mako, markupsafe, packaging, yaml"], "host-python-check.log")
            return previous
    if not fetch:
        raise BuildError("Missing isolated Mesa Python generators; use --fetch to install pinned host requirements")
    if not python.is_file():
        builder.run([sys.executable, "-m", "venv", str(WORK / "host-python")], "host-python-venv.log")
    report = WORK / "host-python-pip-report.json"
    builder.run([str(python), "-m", "pip", "install", "--only-binary=:all:",
                 "--report", str(report), *desired], "host-python-install.log")
    result = {"requirements": desired, "pip_report": json.loads(report.read_text()),
              "python": str(python), "purpose": "native generators only"}
    state.write_text(json.dumps(result, indent=2) + "\n")
    return result


def build_libraries(builder: Builder, source: Path, resume: bool) -> dict:
    cross, native, compile_args = environment(builder)
    meson = str(BUILD_TOOLS / "bin/meson")
    directory = WORK / "build"
    exists = (directory / "build.ninja").exists()
    if exists and not resume:
        raise BuildError("Existing Mesa build requires --resume")
    builder.run([meson, "setup", *( ["--reconfigure"] if exists else []), str(directory), str(source),
                 "--cross-file=" + str(cross), "--native-file=" + str(native), *OPTIONS,
                 "-Dc_args=" + repr(compile_args), "-Dcpp_args=" + repr(compile_args),
                 "-Dcpp_link_args=" + repr([str(WORK / "cxx-runtime/libcyxia-mesa-cxx.a"), "-Wl,--error-limit=0"]),
                 "-Dcyxia-probe-source=" + str(ROOT / "user/ported/egl_probe.c")], "setup.log")
    builder.run([meson, "compile", "-C", str(directory), "-j", str(builder.jobs)], "compile.log")
    raw = directory / "src/cyxia-egl-probe"
    # Validate strong-symbol resolution and every mapped segment before strip.
    unstripped = inspect_elf(raw)
    output = WORK / "egl-probe.elf"
    builder.run([builder.tools["llvm-strip"], "--strip-all", "-o", str(output), str(raw)], "probe-strip.log")
    final = inspect_elf(output)
    loads = [segment for segment in final["program_headers"] if segment["type"] == 1]
    final["mapped_bytes"] = sum((segment["memsz"] + 4095) // 4096 * 4096 for segment in loads)
    # Keep the exact final link recipe and hash its actual static library inputs.
    commands = subprocess.check_output([str(BUILD_TOOLS / "bin/ninja"), "-C", str(directory),
                                        "-t", "commands", "src/cyxia-egl-probe"], text=True)
    link = commands.splitlines()[-1]
    dependencies = {}
    for argument in shlex.split(link):
        path = Path(argument) if argument.endswith(".a") else None
        if argument.startswith("-l") and argument not in ("-link",):
            path = TARGET / "usr/lib" / ("lib" + argument[2:] + ".a")
        if path is not None:
            path = path if path.is_absolute() else directory / path
            if not path.is_file():
                raise BuildError("Final static dependency is absent: " + str(path))
            dependencies[str(path)] = digest(path)
    for name in ("crt1.o", "crti.o", "crtn.o", "libc.a", "libclang_rt.builtins-aarch64.a"):
        path = TARGET / "usr/lib" / name
        dependencies[str(path)] = digest(path)
    return {"options": OPTIONS, "directory": str(directory), "status": "compiled",
            "unstripped_probe": unstripped, "probe": final, "link_command": link,
            "link_dependencies_sha256": dependencies,
            "note": "No target libraries installed into the shared sysroot; no guest execution"}


def main() -> int:
    global WORK
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "prepare", "build"), nargs="?", default="inventory")
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--work", type=Path, default=WORK)
    args = parser.parse_args()
    try:
        WORK = args.work.resolve()
        if not WORK.is_relative_to(DEFAULT_OUTPUT.resolve()) or WORK == DEFAULT_OUTPUT.resolve():
            raise BuildError("Mesa work directory must be a child of the isolated target output")
        package = json.loads(MANIFEST.read_text())
        notice = PurePosixPath(package["license_file"])
        if notice.is_absolute() or ".." in notice.parts or not notice.parts:
            raise BuildError("Invalid Mesa license path")
        validate_packages([{**package, "license_file": notice.name}])
        if not 1 <= args.jobs <= 16:
            raise BuildError("--jobs must be in 1..16")
        if args.command == "inventory":
            if args.fetch or args.resume:
                raise BuildError("--fetch/--resume require prepare or build")
            print(json.dumps({"source": package, "options": OPTIONS, "work": str(WORK),
                              "guest_execution": "not performed", "network": False}, indent=2))
            return 0
        if shutil.disk_usage(DEFAULT_OUTPUT).free < 3 * 1024 ** 3:
            raise BuildError("At least 3 GiB free disk required for the Mesa source/build")
        WORK.mkdir(parents=True, exist_ok=True)
        with (WORK / ".build.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise BuildError("Another Mesa build is active in this work directory") from error
            for name in ("logs", "bin", "reports"):
                (WORK / name).mkdir(parents=True, exist_ok=True)
            run_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "-" + str(os.getpid())
            builder = Builder(WORK, toolchain(), args.jobs)
            report = {"status": "building", "run_id": run_id, "builder_sha256": digest(Path(__file__)),
                      "commands": builder.commands, "toolchain": builder.tools,
                      "guest_execution": "not performed", "g_egl_pass": False,
                      "cosmic_built": False,
                      "probe_source_sha256": digest(ROOT / "user/ported/egl_probe.c")}
            try:
                source, source_record = prepare_source(builder, package, args.fetch, args.resume)
                report["source"] = source_record
                report["status"] = "source-prepared"
                if args.command == "build":
                    report["host_python"] = host_python(builder, package, args.fetch)
                    report["target_uapi"] = target_uapi(builder, package, args.fetch)
                    report["target_cxx"] = target_cxx(builder, package, args.fetch)
                    report["target"] = build_libraries(builder, source, args.resume)
                    if digest(ROOT / "user/ported/egl_probe.c") != report["probe_source_sha256"]:
                        raise BuildError("Probe source changed during compilation")
                    report["status"] = "libraries-compiled"
            except Exception as error:
                report["status"], report["error"] = "failed", str(error)
                raise
            finally:
                logs = WORK / "reports" / (run_id + "-logs")
                shutil.copytree(WORK / "logs", logs)
                report["logs"] = str(logs)
                output = WORK / "reports" / (run_id + ".json")
                output.write_text(json.dumps(report, indent=2) + "\n")
                (WORK / "latest-report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"status": report["status"], "report": str(output), "g_egl_pass": False}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("mesa: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
