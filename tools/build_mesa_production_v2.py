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
from target_profile import profile_for

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
OPTIONS.append("-Db_ndebug=true")

PRODUCTION_PROFILE = {
    "name": "cyxia-mesa-production-v2",
    "configuration_change": "Explicit upstream b_ndebug=true and cpp-only preservation of prior libc++ FAST hardening; retain minsize/-Oz and every existing platform/feature",
    "assertion_scope": "Disables Mesa internal assertions/debug validation; explicitly preserves prior libc++ FAST input-range/element-access checks in Mesa C++ translation units; shader variants and ordinary optimizer passes remain",
    "cxx_runtime_scope": "The separate support-runtime build and its existing default configuration are unchanged",
    "ndebug_warning_policy": "Upstream Mesa may add unused-variable and unused-but-set-variable warning suppressions when assertions are disabled; actual counts are recorded",
    "acceptance_scope": "Compilation is not guest rendering or protocol acceptance; original diagnostic artifacts remain separate",
}
MAX_CONFIGURATION_BYTES = 16 * 1024 * 1024
LIBCPP_FAST_ARGUMENT = "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST"
PINNED_NATIVE_X86_CPP_COMMANDS = 64
NDEBUG_WARNING_SUPPRESSIONS = ("-Wno-unused-variable", "-Wno-unused-but-set-variable")


def options_for(profile='x11'):
    if profile == 'x11':
        return list(OPTIONS)
    if profile == 'native-surfaceless':
        return [value if not value.startswith('-Dplatforms=') else '-Dplatforms='
                for value in OPTIONS] + ['-Degl-native-platform=surfaceless']
    raise BuildError('Unknown Mesa platform profile: ' + str(profile))


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
    with tempfile.TemporaryDirectory(prefix=".mesa-extract-", dir=destination.parent) as temporary:
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
    work = getattr(builder, "output", WORK)
    prefix = getattr(builder, "sdk_prefix", DEFAULT_OUTPUT)
    sdkroot = prefix / "sysroot"
    cached = desktop_ports.destination(desktop_ports.DEFAULT_CACHE, package)
    if fetch and not cached.exists():
        archive = download_mesa(package, work)
        record = desktop_ports.fetch(package, desktop_ports.DEFAULT_CACHE, offline_file=archive,
                                     max_bytes=package["source_max_bytes"])
        record["download_url"] = package["source_url"]
    else:
        record = desktop_ports.verify(package, desktop_ports.DEFAULT_CACHE,
                                      max_bytes=package["source_max_bytes"])
    patches = [ROOT / value for value in package.get("patches", [])]
    identity = {"manifest_sha256": digest(MANIFEST),
                "patches": {str(path.relative_to(ROOT)): digest(path) for path in patches}}
    source = work / package["archive_root"]
    stamp = work / "source-state.json"
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


def download_mesa(package: dict, work=None) -> Path:
    """Retry rate-limited exact ranges without relaxing the pinned release hash."""
    from range_download import DownloadError, download_ranges
    work = work or WORK

    try:
        return download_ranges(
            package["source_url"], work / "mesa-verified-download.tar.xz",
            size=package["source_bytes"], sha256=package["expected_sha256"],
            max_bytes=package["source_max_bytes"],
            opener=build_opener(desktop_ports.HTTPSRedirects()),
        )
    except DownloadError as error:
        raise BuildError(str(error)) from error


def target_uapi_spec(package, target="aarch64"):
    selected = profile_for(target)
    original = package["target_uapi"]
    lock = original if selected.architecture == "aarch64" else json.loads((ROOT / "ports/cosmic/mesa-uapi-x86_64.json").read_text())
    expected_arch = "arm64" if selected.architecture == "aarch64" else "x86_64"
    if (lock["source_commit"] != original["source_commit"] or lock["source_url"] != original["source_url"]
            or lock["architecture"] != expected_arch):
        raise BuildError("UAPI target/source identity mismatch")
    return lock


def target_uapi(builder: Builder, package: dict, fetch: bool) -> dict:
    """Export the selected ISA's pinned UAPI with Linux's real export tool.

    These declarations do not implement DRM, memfd or any other syscall. The
    selected software driver still has to pass the guest ABI/runtime gates.
    """
    work = getattr(builder, "output", WORK)
    prefix = getattr(builder, "sdk_prefix", DEFAULT_OUTPUT)
    sdkroot = prefix / "sysroot"
    lock = target_uapi_spec(package, builder.target)
    base = lock["source_url"]
    expected_base = "https://raw.githubusercontent.com/torvalds/linux/" + lock["source_commit"] + "/"
    if base != expected_base:
        raise BuildError("Unexpected target UAPI provenance")
    source = work / "uapi-source"
    exported = work / "uapi-include"
    pinned = {item["source_path"]: item["sha256"] for item in lock["files"].values()}
    pinned.update(lock["provenance"])
    for relative, expected in pinned.items():
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts:
            raise BuildError("Unsafe UAPI source path")
        destination = source / relative
        cache = prefix / "mesa-uapi-source" / relative
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
    export_script = work / "bin/uapi-headers-install.sh"
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
            raise BuildError("UAPI wrapper is not prescribed by the pinned selected-architecture export")
        destination = exported / header
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("#include <" + target + ">\n")
    return {"commit": lock["source_commit"], "architecture": builder.target.architecture,
            "include_directory": str(exported),
            "tree_sha256": tree_digest(exported), "source_files": pinned,
            "host_export_script_sha256": digest(export_script),
            "scope": lock["scope"]}


def environment(builder: Builder) -> tuple[Path, Path, list[str]]:
    work = getattr(builder, "output", WORK)
    prefix = getattr(builder, "sdk_prefix", DEFAULT_OUTPUT)
    sdkroot = prefix / "sysroot"
    builder.target.require_report(json.loads((prefix / 'build-report.json').read_text()))
    builder.target.inspect_archive(sdkroot / 'usr/lib/libc.a')
    python = getattr(builder, 'mesa_host_python', work / 'host-python/bin/python3')
    builder.env = clean_env()
    for key in list(builder.env):
        if key.startswith("PKG_CONFIG") or key in ("DESTDIR", "RUSTFLAGS", "PYTHONPATH"):
            builder.env.pop(key)
    pkg = shutil.which("pkg-config")
    if not pkg:
        raise BuildError("pkg-config is required")
    builder.env.update(
        CC=str(builder.target.cc(prefix)),
        CXX=str(work / "bin/mesa-target-cxx"),
        AR=builder.tools["llvm-ar"],
        PKG_CONFIG_LIBDIR=os.pathsep.join(str(sdkroot / p) for p in ("usr/lib/pkgconfig", "usr/share/pkgconfig")),
        PKG_CONFIG_SYSROOT_DIR=str(sdkroot), PKG_CONFIG_PATH="",
        PATH=os.pathsep.join((str(python.parent),
                              str(prefix / "xkbcommon-host-tools/bin"),
                              str(BUILD_TOOLS / "bin"), builder.env.get("PATH", ""))),
        PYTHON=str(python),
        PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(work / "python-cache"))
    target_pkg = builder.shell_wrapper("mesa-target-pkg-config", [pkg, "--static"])
    builder.env["PKG_CONFIG"] = str(target_pkg)
    # Native generators must not discover target libraries or target headers.
    host_pkg = builder.shell_wrapper("mesa-host-pkg-config", ["env", "-u", "PKG_CONFIG_SYSROOT_DIR",
        "-u", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR=" + str(work / "host-empty-pkgconfig"), pkg])
    cross = work / "cross.ini"
    resource = subprocess.check_output([builder.tools["clang"], "-print-resource-dir"], text=True).strip()
    builtin_headers = Path(resource) / "include"
    intrinsic = "arm_neon.h" if builder.target.architecture == "aarch64" else "emmintrin.h"
    if not (builtin_headers / intrinsic).is_file():
        raise BuildError("Clang target intrinsic header is missing: " + intrinsic)
    compile_args = ["-ffunction-sections", "-fdata-sections", "-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables", "-isystem", str(builtin_headers),
                    "-isystem", str(work / "uapi-include")]
    cross.write_text("[binaries]\n" +
        "c = " + repr(builder.env["CC"]) + "\ncpp = " + repr(builder.env["CXX"]) + "\n" +
        "ar = " + repr(builder.tools["llvm-ar"]) + "\nstrip = " + repr(builder.tools["llvm-strip"]) + "\n" +
        "pkg-config = " + repr(str(target_pkg)) + "\n" +
        builder.target.meson_machine() +
        "[properties]\nneeds_exe_wrapper = true\nsys_root = " + repr(str(sdkroot)) + "\n" +
        "pkg_config_libdir = " + repr(builder.env["PKG_CONFIG_LIBDIR"].split(os.pathsep)) + "\n" +
        "[built-in options]\nc_args = " + repr(compile_args) + "\ncpp_args = " + repr(compile_args) + "\n")
    native = work / "native.ini"
    native.write_text("[binaries]\nc = " + repr(builder.tools["clang"]) + "\ncpp = " +
                      repr(builder.tools["clang"] + "++") + "\npkg-config = " + repr(str(host_pkg)) + "\n")
    return cross, native, compile_args


def target_cxx(builder: Builder, package: dict, fetch: bool) -> dict:
    """Build the real upstream allocation/mutex/guard runtime used by Mesa.

    This intentionally does not advertise a complete libc++ or exception ABI.
    All C++ headers come from the pinned libc++ archive, never the host SDK.
    """
    work = getattr(builder, "output", WORK)
    prefix = getattr(builder, "sdk_prefix", DEFAULT_OUTPUT)
    sdkroot = prefix / "sysroot"
    spec = package["target_cxx"]
    roots, records = {}, {}
    for item in spec["packages"]:
        cache = desktop_ports.destination(desktop_ports.DEFAULT_CACHE, item)
        if not cache.exists():
            archive = prefix / "mesa-cxx-source" / (item["archive_root"] + ".tar.xz")
            if archive.is_file():
                record = desktop_ports.fetch(item, desktop_ports.DEFAULT_CACHE, offline_file=archive,
                                             max_bytes=item["source_max_bytes"])
            elif fetch:
                record = desktop_ports.fetch(item, desktop_ports.DEFAULT_CACHE, online=True,
                                             max_bytes=item["source_max_bytes"])
            else:
                raise BuildError("Missing pinned C++ source: " + item["name"])
        else:
            record = desktop_ports.verify(item, desktop_ports.DEFAULT_CACHE,
                                           max_bytes=item["source_max_bytes"])
        destination = work / item["archive_root"]
        state = work / (item["name"] + "-source-state.json")
        if destination.exists():
            previous = json.loads(state.read_text())
            if previous["archive_sha256"] != item["expected_sha256"] or previous["tree_sha256"] != tree_digest(destination):
                raise BuildError("Edited C++ runtime source: " + item["name"])
        else:
            unpack_mesa(item, record, destination)
            previous = {"archive_sha256": item["expected_sha256"], "tree_sha256": tree_digest(destination)}
            state.write_text(json.dumps(previous, indent=2) + "\n")
        roots[item["name"]], records[item["name"]] = destination, previous
    config = work / "cxx-config"
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
    cpp = builder.shell_wrapper("mesa-target-cxx", [str(builder.target.cc(prefix)),
        "-std=c++17", "-nostdinc++", "-I" + str(config), "-I" + str(roots["libcxx"] / "include"),
        "-fno-exceptions", "-fno-rtti"])
    objects = work / "cxx-runtime"
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
            "-I" + str(roots["libcxxabi"] / "include"), "-isystem", str(work / "uapi-include"),
            "-c", str(source), "-o", str(obj)], "cxx-" + obj.stem + ".log")
        sources.append(obj)
    archive = objects / "libcyxia-mesa-cxx.a"
    archive.unlink(missing_ok=True)
    builder.run([builder.tools["llvm-ar"], "rcs", str(archive), *map(str, sources)], "cxx-archive.log")
    return {"scope": spec["scope"], "source_commit": spec["source_commit"], "sources": records,
            "configuration_sha256": tree_digest(config), "archive": str(archive),
            "archive_sha256": digest(archive), "bytes": archive.stat().st_size}


def select_host_python(candidates=None) -> dict:
    """Use a native interpreter supported by the fixed generator wheel set.

    In particular MarkupSafe 3.0.3 predates CPython 3.15 wheels. Keep that
    package pin and choose a compatible native generator, rather than upgrading
    dependencies or invoking an unpinned source build implicitly.
    """
    if candidates is None:
        candidates = [sys.executable, *[shutil.which('python3.' + str(minor))
                      for minor in range(14, 8, -1)], '/usr/bin/python3']
    for candidate in dict.fromkeys(path for path in candidates if path):
        path = Path(candidate).resolve()
        if not path.is_file():
            continue
        try:
            version = json.loads(subprocess.check_output([str(path), '-c',
                'import json,sys; print(json.dumps(list(sys.version_info[:3])))'],
                text=True, timeout=10))
        except (subprocess.SubprocessError, OSError, ValueError):
            continue
        if (isinstance(version, list) and len(version) == 3
                and all(type(number) is int for number in version)
                and version[0] == 3 and 9 <= version[1] <= 14):
            return {'executable': str(path), 'version': version, 'sha256': digest(path)}
    raise BuildError('Pinned Mesa generator wheels require native Python 3.9 through 3.14')


def host_python(builder: Builder, package: dict, fetch: bool) -> dict:
    work = getattr(builder, "output", WORK)
    prefix = getattr(builder, "sdk_prefix", DEFAULT_OUTPUT)
    sdkroot = prefix / "sysroot"
    interpreter = select_host_python(getattr(builder, 'mesa_python_candidates', None))
    minor = '.'.join(map(str, interpreter['version'][:2]))
    directory = work / ('host-python-' + minor)
    python = directory / 'bin/python3'
    builder.mesa_host_python = python
    state = work / ('host-python-' + minor + '-state.json')
    desired = package["host_python"]
    if python.is_file() and state.is_file():
        previous = json.loads(state.read_text())
        if previous["requirements"] == desired and previous.get('interpreter') == interpreter:
            builder.run([str(python), "-c", "import mako, markupsafe, packaging, yaml"], "host-python-check.log")
            return previous
    if not fetch:
        raise BuildError("Missing isolated Mesa Python generators; use --fetch to install pinned host requirements")
    if not python.is_file():
        builder.run([interpreter['executable'], "-m", "venv", str(directory)], "host-python-venv.log")
    report = work / "host-python-pip-report.json"
    builder.run([str(python), "-m", "pip", "install", "--only-binary=:all:",
                 "--report", str(report), *desired], "host-python-install.log")
    result = {"requirements": desired, "pip_report": json.loads(report.read_text()),
              "python": str(python), "interpreter": interpreter, "purpose": "native generators only"}
    state.write_text(json.dumps(result, indent=2) + "\n")
    return result



def production_configuration_document(path: Path):
    """Read bounded actual Meson metadata without following path symlinks."""
    for current in (path, *path.parents):
        if current.is_symlink():
            raise BuildError("Symlink in production configuration: " + str(current))
    if not path.is_file() or path.stat().st_size > MAX_CONFIGURATION_BYTES:
        raise BuildError("Missing or oversized production configuration: " + str(path))
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIGURATION_BYTES:
        raise BuildError("Production configuration grew beyond its bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("Invalid production configuration JSON: " + str(path)) from error
    return value, {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def validate_production_configuration(builder: Builder, directory: Path,
                                      options: list[str], compile_args: list[str]) -> dict:
    """Bind the actual upstream production profile before and after compilation.

    This inspects Meson's generated metadata, not a claimed command-line profile.
    It does not execute target code or establish graphics/protocol acceptance.
    """
    if options != options_for(getattr(builder, 'mesa_profile', 'x11')):
        raise BuildError("Production options differ from the versioned recipe")
    work = getattr(builder, "output", WORK)
    prefix = getattr(builder, "sdk_prefix", DEFAULT_OUTPUT)
    if directory != work / "build":
        raise BuildError("Unexpected production build directory")
    metadata, metadata_identity = production_configuration_document(directory / "meson-info/intro-buildoptions.json")
    commands, commands_identity = production_configuration_document(directory / "compile_commands.json")
    if not isinstance(metadata, list) or not metadata or not isinstance(commands, list) or not commands:
        raise BuildError("Missing actual production options or compile commands")
    observed = {}
    for option in metadata:
        if (not isinstance(option, dict) or not isinstance(option.get("name"), str)
                or "value" not in option or option["name"] in observed):
            raise BuildError("Malformed or duplicate actual Meson option")
        observed[option["name"]] = option["value"]
    expected = {}
    arrays = {"platforms", "gallium-drivers", "vulkan-drivers", "video-codecs"}
    for option in options:
        if option.startswith("-D"):
            name, value = option[2:].split("=", 1)
        elif option.startswith("--"):
            name, value = option[2:].split("=", 1)
            name = name.replace("-", "_")
        else:
            raise BuildError("Unknown production recipe option")
        if name in expected:
            raise BuildError("Duplicate production recipe option")
        if name in arrays:
            value = value.split(",") if value else []
        elif name != "b_ndebug" and value in ("true", "false"):
            value = value == "true"
        expected[name] = value
    expected.update(optimization="s", c_args=compile_args, cpp_args=[*compile_args, LIBCPP_FAST_ARGUMENT],
                    cpp_link_args=[str(work / "cxx-runtime/libcyxia-mesa-cxx.a"), "-Wl,--error-limit=0"],
                    **{"cyxia-probe-source": str(ROOT / "user/ported/egl_probe.c")})
    for name, value in expected.items():
        if name not in observed or type(observed[name]) is not type(value) or observed[name] != value:
            raise BuildError("Actual production option differs: " + name)
    compilers = {"c": str(builder.target.cc(prefix)), "cpp": str(work / "bin/mesa-target-cxx")}
    counts = {"c": 0, "cpp": 0, "assembly": 0}
    warning_counts = {flag: 0 for flag in NDEBUG_WARNING_SUPPRESSIONS}
    outputs = set()
    for record in commands:
        if (not isinstance(record, dict) or not all(isinstance(record.get(key), str)
                for key in ("directory", "command", "file", "output"))
                or record["directory"] != str(directory)):
            raise BuildError("Malformed or relocated actual compile command")
        suffix = Path(record["file"]).suffix
        language = "cpp" if suffix in (".cc", ".cpp", ".cxx") else "c" if suffix == ".c" else "assembly" if suffix == ".S" else None
        if language is None:
            raise BuildError("Unexpected production compile source type")
        try:
            argv = shlex.split(record["command"])
        except ValueError as error:
            raise BuildError("Malformed production compiler command quoting") from error
        compiler = compilers["cpp" if language == "cpp" else "c"]
        if not argv or argv[0] != compiler or any(arg.startswith("@") for arg in argv):
            raise BuildError("Unexpected compiler or hidden response-file options")
        if argv.count("-DNDEBUG") != 1 or any("NDEBUG" in arg and arg != "-DNDEBUG" for arg in argv):
            raise BuildError("Actual compile command lacks an unambiguous production NDEBUG")
        if argv.count("-DMESA_DEBUG=0") != 1 or any("MESA_DEBUG" in arg and arg != "-DMESA_DEBUG=0" for arg in argv):
            raise BuildError("Actual compile command changed Mesa debug mode")
        if [arg for arg in argv if arg.startswith("-O")] != ["-Oz"]:
            raise BuildError("Actual compile command changed minsize optimization")
        hardening_args = [arg for arg in argv if "_LIBCPP_HARDENING_MODE" in arg]
        if language == "cpp":
            if hardening_args != [LIBCPP_FAST_ARGUMENT]:
                raise BuildError("Actual C++ command must preserve exactly one unambiguous libc++ FAST hardening definition")
        elif hardening_args:
            raise BuildError("C/assembly command received a C++ hardening override")
        if any("_LIBCPP_ENABLE_ASSERTIONS" in arg or "_LIBCPP_DEBUG" in arg for arg in argv):
            raise BuildError("Unsupported libc++ assertion-mode override")
        for flag in NDEBUG_WARNING_SUPPRESSIONS:
            warning_counts[flag] += argv.count(flag)
        if (any(arg == "-undef" or arg.startswith(("-include", "-imacros", "-Wp,", "-Xclang", "-Xpreprocessor", "--config")) for arg in argv)
                or any(arg in {";", "&&", "||", "|", "&", ">", "<"} for arg in argv)):
            raise BuildError("Unsupported compiler macro or shell override")
        if (argv.count("-c") != 1 or argv.count("-o") != 1
                or argv.index("-c") + 1 >= len(argv) or argv[argv.index("-c") + 1] != record["file"]
                or argv.index("-o") + 1 >= len(argv) or argv[argv.index("-o") + 1] != record["output"]
                or record["output"] in outputs):
            raise BuildError("Actual compile source/output identity differs")
        outputs.add(record["output"])
        counts[language] += 1
    if not counts["c"] or not counts["cpp"]:
        raise BuildError("Incomplete actual C/C++ production command set")
    if (getattr(builder, "mesa_profile", "x11") == "native-surfaceless"
            and builder.target.architecture == "x86_64"
            and counts["cpp"] != PINNED_NATIVE_X86_CPP_COMMANDS):
        raise BuildError("Pinned native x86 Mesa must retain all 64 C++ compile commands")
    return {"status": "GENERATED_PRODUCTION_CONFIGURATION_VERIFIED_NOT_GUEST_RUN",
            "profile": PRODUCTION_PROFILE, "options": expected,
            "metadata": metadata_identity, "compile_commands": commands_identity,
            "command_counts": counts, "command_count": len(commands),
            "compiler_paths": compilers, "optimization": "-Oz", "ndebug": True,
            "libcpp_hardening": {"definition": LIBCPP_FAST_ARGUMENT, "mode": "FAST",
                                  "cpp_command_count": counts["cpp"], "c_and_assembly_override_count": 0},
            "ndebug_warning_suppression_counts": warning_counts}


def build_libraries(builder: Builder, source: Path, resume: bool) -> dict:
    work = getattr(builder, "output", WORK)
    prefix = getattr(builder, "sdk_prefix", DEFAULT_OUTPUT)
    sdkroot = prefix / "sysroot"
    cross, native, compile_args = environment(builder)
    options = options_for(getattr(builder, 'mesa_profile', 'x11'))
    meson = str(BUILD_TOOLS / "bin/meson")
    directory = work / "build"
    exists = (directory / "build.ninja").exists()
    if exists and not resume:
        raise BuildError("Existing Mesa build requires --resume")
    builder.run([meson, "setup", *( ["--reconfigure"] if exists else []), str(directory), str(source),
                 "--cross-file=" + str(cross), "--native-file=" + str(native), *options,
                 "-Dc_args=" + repr(compile_args), "-Dcpp_args=" + repr([*compile_args, LIBCPP_FAST_ARGUMENT]),
                 "-Dcpp_link_args=" + repr([str(work / "cxx-runtime/libcyxia-mesa-cxx.a"), "-Wl,--error-limit=0"]),
                 "-Dcyxia-probe-source=" + str(ROOT / "user/ported/egl_probe.c")], "setup.log")
    configuration = validate_production_configuration(builder, directory, options, compile_args)
    builder.mesa_production_configuration = configuration
    builder.run([meson, "compile", "-C", str(directory), "-j", str(builder.jobs)], "compile.log")
    if validate_production_configuration(builder, directory, options, compile_args) != configuration:
        raise BuildError("Production configuration changed during compilation")
    raw = directory / "src/cyxia-egl-probe"
    # Validate strong-symbol resolution and every mapped segment before strip.
    unstripped = inspect_elf(raw, builder.target)
    output = work / "egl-probe.elf"
    builder.run([builder.tools["llvm-strip"], "--strip-all", "-o", str(output), str(raw)], "probe-strip.log")
    final = inspect_elf(output, builder.target)
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
            path = sdkroot / "usr/lib" / ("lib" + argument[2:] + ".a")
        if path is not None:
            path = path if path.is_absolute() else directory / path
            if not path.is_file():
                raise BuildError("Final static dependency is absent: " + str(path))
            dependencies[str(path)] = digest(path)
    for name in ("crt1.o", "crti.o", "crtn.o", "libc.a", builder.target.builtins_archive):
        path = sdkroot / "usr/lib" / name
        dependencies[str(path)] = digest(path)
    return {"options": options, "directory": str(directory), "status": "compiled",
            "production_configuration": configuration,
            "unstripped_probe": unstripped, "probe": final, "link_command": link,
            "link_dependencies_sha256": dependencies,
            "note": "No target libraries installed into the shared sysroot; no guest execution"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "prepare", "build"), nargs="?", default="inventory")
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--arch", choices=("aarch64", "x86_64"), default="aarch64")
    parser.add_argument("--sysroot", type=Path)
    parser.add_argument('--host-python', type=Path, help='Compatible native Python for pinned generators')
    parser.add_argument('--profile', choices=('x11', 'native-surfaceless'), default='x11')
    args = parser.parse_args()
    selected = profile_for(args.arch)
    prefix = (args.sysroot or selected.default_output(ROOT)).resolve()
    work = (args.work or prefix / ('mesa-port' if args.profile == 'x11' else 'mesa-native-port')).resolve()
    try:
        if not work.is_relative_to(prefix) or work == prefix:
            raise BuildError("Mesa work directory must be a child of the isolated target output")
        package = json.loads(MANIFEST.read_text())
        if args.profile == 'native-surfaceless':
            package['patches'] = [*package['patches'], 'ports/cosmic/patches/mesa-26.2.3-cyxia-surfaceless-probe.patch']
        notice = PurePosixPath(package["license_file"])
        if notice.is_absolute() or ".." in notice.parts or not notice.parts:
            raise BuildError("Invalid Mesa license path")
        validate_packages([{**package, "license_file": notice.name}])
        if not 1 <= args.jobs <= 16:
            raise BuildError("--jobs must be in 1..16")
        if args.command == "inventory":
            if args.fetch or args.resume:
                raise BuildError("--fetch/--resume require prepare or build")
            print(json.dumps({"source": package, "profile": args.profile, "options": options_for(args.profile), "work": str(work),
                              "guest_execution": "not performed", "network": False}, indent=2))
            return 0
        if shutil.disk_usage(prefix).free < 3 * 1024 ** 3:
            raise BuildError("At least 3 GiB free disk required for the Mesa source/build")
        work.mkdir(parents=True, exist_ok=True)
        with (work / ".build.lock").open("a") as lock, (prefix / '.build.lock').open('r') as sdk_lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise BuildError("Another Mesa build is active in this work directory") from error
            fcntl.flock(sdk_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            for name in ("logs", "bin", "reports"):
                (work / name).mkdir(parents=True, exist_ok=True)
            run_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "-" + str(os.getpid())
            builder = Builder(work, toolchain(), args.jobs, selected)
            builder.sdk_prefix = prefix
            builder.mesa_profile = args.profile
            if args.host_python:
                builder.mesa_python_candidates = [args.host_python]
            producer_paths = [Path(__file__).resolve(), ROOT / 'tools/target_profile.py', ROOT / 'tools/build_sysroot.py',
                              MANIFEST, ROOT / 'user/ported/egl_probe.c',
                              *[ROOT / path for path in package.get('patches', [])]]
            if selected.architecture == 'x86_64':
                producer_paths.append(ROOT / 'ports/cosmic/mesa-uapi-x86_64.json')
            producers = {str(path): digest(path) for path in producer_paths}
            report = {"status": "building", "architecture": selected.architecture, "target_triple": selected.rust_target, "run_id": run_id, "builder_sha256": digest(Path(__file__)),
                      'platform_profile': args.profile, 'profile_options': options_for(args.profile),
                      "production_profile": PRODUCTION_PROFILE,
                      "target_profile": selected.identity(), "producer_inputs_sha256": producers,
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
                if any(digest(Path(path)) != expected for path, expected in producers.items()):
                    raise BuildError('Mesa producer inputs changed during compilation')
            except Exception as error:
                report["status"], report["error"] = "failed", str(error)
                raise
            finally:
                if hasattr(builder, "mesa_production_configuration"):
                    report["production_configuration_before_compile"] = builder.mesa_production_configuration
                logs = work / "reports" / (run_id + "-logs")
                shutil.copytree(work / "logs", logs)
                report["logs"] = str(logs)
                output = work / "reports" / (run_id + ".json")
                output.write_text(json.dumps(report, indent=2) + "\n")
                (work / "latest-report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"status": report["status"], "report": str(output), "g_egl_pass": False}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("mesa: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
