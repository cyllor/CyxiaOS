#!/usr/bin/env python3
"""Link an independent real Wayland client using the checked static target SDK.

No download, target execution, shared sysroot change or previous artifact
replacement. Every build uses a fresh output and records its complete inputs.
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import time

from build_cosmic import clean_environment, new_output, run_bounded
from build_sysroot import ROOT, DEFAULT_OUTPUT, BuildError, digest, inspect_elf, toolchain
from build_smithay_wayland_client import prerequisite_inputs

SOURCE = ROOT / "user/ported/smithay_dynamic_client.c"
BUDGET = dict(timeout_seconds=60, min_free_bytes=512 * 1024 * 1024,
              max_build_bytes=32 * 1024 * 1024, max_download_bytes=0)


MANIFEST = ROOT / "ports/cosmic/smithay-dynamic-client-source.json"
DEFAULT_CRATE = ROOT / "artifacts/smithay-wayland-research/wayland-protocols-0.32.13.crate"


def protocol_source(crate, prefix, output):
    """Extract the exact pinned upstream XML using a verified host scanner.

    XML bytes are checked independently of the archive identity. No cached
    vendor tree is trusted; no archive path is extracted to the filesystem.
    """
    manifest = json.loads(MANIFEST.read_text())
    smithay_manifest = ROOT / "ports/cosmic/smithay-wayland-source.json"
    pinned = json.loads(smithay_manifest.read_text())
    expected = manifest["crate"]
    candidates = [item for item in pinned["crates"] if item["name"] == expected["name"]]
    if len(candidates) != 1 or any(candidates[0][key] != expected[key]
                                   for key in ("version", "sha256", "bytes", "url")):
        raise BuildError("xdg protocol pin disagrees with Smithay dependency")
    if crate.stat().st_size != expected["bytes"] or digest(crate) != expected["sha256"]:
        raise BuildError("xdg protocol crate identity changed")
    member_name = manifest["xml_member"]
    with tarfile.open(crate, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.name == member_name]
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 256 * 1024:
            raise BuildError("Invalid or duplicate xdg protocol XML archive member")
        member = archive.extractfile(members[0])
        if member is None:
            raise BuildError("Missing xdg protocol XML contents")
        xml = member.read()
    if hashlib.sha256(xml).hexdigest() != manifest["xml_sha256"]:
        raise BuildError("xdg protocol XML identity changed")
    scanner_report = prefix / "wayland-build-report.json"
    report = json.loads(scanner_report.read_text())
    scanner = prefix / "wayland-host-tools/bin/wayland-scanner"
    if (report.get("status") != "cross-built" or
            report["native_scanner"]["path"] != str(scanner) or
            report["native_scanner"]["version"] != "wayland-scanner 1.24.0" or
            digest(scanner) != report["native_scanner"]["sha256"]):
        raise BuildError("Unverified native Wayland protocol scanner")
    destination = output / "generated/xdg-shell.xml"
    with destination.open("xb") as handle:
        handle.write(xml)
    shutil.copyfile(MANIFEST, output / "provenance" / MANIFEST.name)
    inputs = {path: digest(path) for path in
              (MANIFEST, smithay_manifest, crate, scanner, scanner_report)}
    return inputs, scanner


def dependency_inputs(depfile, source, prefix, generated):
    text = depfile.read_text().replace("\\\n", " ")
    target, separator, dependencies = text.partition(":")
    if separator != ":" or target.strip() != "smithay-dynamic-client":
        raise BuildError("Unexpected compiler dependency record")
    paths = [Path(item).resolve() for item in shlex.split(dependencies)]
    if source.resolve() not in paths:
        raise BuildError("Source missing from compiler dependencies")
    allowed_generated = {item.resolve() for item in generated}
    include = (prefix / "sysroot/usr/include").resolve()
    for path in paths:
        if path != source.resolve() and path not in allowed_generated and not path.is_relative_to(include):
            raise BuildError("Target compilation used an unexpected header: " + str(path))
    return {path: digest(path) for path in paths}


def build(output, crate=DEFAULT_CRATE):
    output = new_output(output)
    for name in ("logs", "provenance", "generated"):
        (output / name).mkdir()
    tools = toolchain()
    env = clean_environment("/usr/bin:/bin:/opt/homebrew/bin")
    report = dict(status="FAIL", guest_execution="not performed",
                  scope="Independent named-socket libwayland clients; dynamic admission, capacity EOF, slot reuse and abrupt owner cleanup require guest verification",
                  budgets=BUDGET, commands=[], inputs_sha256={}, protocol=dict(
                      connection="wl_display_connect(NULL)", inherited_socket=False,
                      environment={"XDG_RUNTIME_DIR": "/tmp", "WAYLAND_DISPLAY": "cyxia-wayland-0",
                                   "WAYLAND_SOCKET": None},
                      socket_path="/tmp/cyxia-wayland-0", peer_credentials="SO_PEERCRED",
                      capacity_probe_identity=0, capacity_probe="connect-without-requests-then-EOF",
                      compositor_version=4, seat_version=7, shm_format="ARGB8888",
                      identities=[1, 2, 3], xdg_wm_base_version=1,
                      frame_sizes={"1": [[64, 48]] * 4, "2": [[64, 48]] * 2, "3": [[64, 48]] * 2},
                      frame_seeds={"1": [0, 32, 32, 32], "2": [0, 32], "3": [0, 32]},
                      configure_states={"1": [[64, 48, 1], [64, 48, 0], [64, 48, 1],
                                               [64, 48, 0], [64, 48, 1]],
                                        "2": [[64, 48, 1]], "3": [[64, 48, 1]]},
                      callback_scenes={"1": [1, 2, 6, 10], "2": [3, 4], "3": [7, 8]},
                      keyboard_focus_counts={"1": [3, 2], "2": [1, 0], "3": [1, 0]},
                      pointer_bound=False, normal_close_identities=[1, 2], final_key=16,
                      abrupt_identity=3, abrupt_key=45,
                      abrupt_teardown="wl_display_disconnect-then-_exit-with-live-objects",
                      shared_pixels_written_after_import=True))
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
                         ROOT / "tools/build_sysroot.py", ROOT / "tools/build_cosmic.py",
                         ROOT / "tools/build_smithay_wayland_client.py", MANIFEST,
                         DEFAULT_OUTPUT / "wayland-source/wayland-1.24.0/src/wayland-client.c",
                         DEFAULT_OUTPUT / "wayland-source/wayland-1.24.0/src/wayland-os.c", *native]:
                inputs[path] = digest(path)
            report["toolchain"] = {name: tools[name] for name in ("clang", "rust-lld", "llvm-strip")}
            shutil.copyfile(SOURCE, output / "provenance" / SOURCE.name)
            for name in ("wayland", "xkbcommon"):
                shutil.copyfile(DEFAULT_OUTPUT / (name + "-build-report.json"),
                                output / "provenance" / (name + "-build-report.json"))
            protocol_inputs, scanner = protocol_source(crate, DEFAULT_OUTPUT, output)
            inputs.update(protocol_inputs)
            generated = output / "generated"
            xml = generated / "xdg-shell.xml"
            header = generated / "xdg-shell-client-protocol.h"
            code = generated / "xdg-shell-protocol.c"
            run([scanner, "client-header", xml, header], "scanner-header.log")
            run([scanner, "private-code", xml, code], "scanner-code.log")
            for path in (xml, header, code):
                inputs[path] = digest(path)
            report["generated"] = {path.name: dict(path=str(path), sha256=digest(path))
                                   for path in (xml, header, code)}
            depfile = output / "target-dependencies.d"
            run([driver, "-M", "-MF", depfile, "-MT", "smithay-dynamic-client", "-I", generated, SOURCE],
                "dependencies.log")
            inputs.update(dependency_inputs(depfile, SOURCE, DEFAULT_OUTPUT, [header]))
            generated_depfile = output / "protocol-dependencies.d"
            run([driver, "-M", "-MF", generated_depfile, "-MT", "smithay-dynamic-client", code],
                "protocol-dependencies.log")
            inputs.update(dependency_inputs(generated_depfile, code, DEFAULT_OUTPUT, []))
            report["inputs_sha256"] = {str(path): value for path, value in inputs.items()}
            symbols = output / "smithay-dynamic-client.symbols.elf"
            run([driver, "-std=c11", "-Os", "-ffunction-sections", "-fdata-sections",
                 "-fno-stack-protector", "-Wall", "-Wextra", "-Werror",
                 "-Wl,--gc-sections", "-I", generated, SOURCE, code, "-Wl,--start-group",
                 library / "libwayland-client.a", library / "libffi.a",
                 library / "libxkbcommon.a", "-Wl,--end-group", "-o", symbols], "link.log")
            report["symbols"] = inspect_elf(symbols)
            program = output / "smithay-dynamic-client.elf"
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
    parser.add_argument("--protocol-crate", default=DEFAULT_CRATE, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.output.resolve(), args.protocol_crate.resolve()), indent=2))
    except (OSError, ValueError, BuildError, subprocess.SubprocessError) as error:
        print("smithay-dynamic-client: " + str(error), file=sys.stderr)
        raise SystemExit(1)
