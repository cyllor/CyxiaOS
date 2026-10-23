#!/usr/bin/env python3
"""Link the real wl_shm/keymap probe against the verified static target libraries.

No download, shared sysroot mutation, or ARM execution. Each output directory is
new, preserving previous probes, logs and failures.
"""
import argparse
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from build_sysroot import (
    ROOT, DEFAULT_OUTPUT, Builder, BuildError, digest, inspect_elf, toolchain,
)

SOURCE = ROOT / "user/ported/wayland_shm_probe.c"


def build(output):
    output.mkdir(parents=True, exist_ok=False)
    (output / "logs").mkdir()
    builder = Builder(DEFAULT_OUTPUT, toolchain(), 1)
    builder.target_environment()
    # Read the target prefix, but keep all generated files in the isolated output.
    builder.output = output
    report = {
        "status": "FAIL", "guest_execution": "not performed",
        "scope": "real wl_shm and keyboard keymap transport; no rendering or COSMIC session",
        "commands": builder.commands, "toolchain": builder.tools,
        "source_sha256": digest(SOURCE),
        "spawn_header_sha256": digest(SOURCE.with_name("cyxia_spawn.h")),
        "builder_sha256": digest(Path(__file__)),
    }
    try:
        with (DEFAULT_OUTPUT / ".build.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            reports = {}
            for name in ("wayland", "xkbcommon"):
                path = DEFAULT_OUTPUT / (name + "-build-report.json")
                original = json.loads(path.read_text())
                if original["status"] != "cross-built":
                    raise BuildError("Prerequisite build did not succeed: " + name)
                manifest = ROOT / "ports/cosmic" / (name + "-source.json")
                if digest(manifest) != original["manifest_sha256"]:
                    raise BuildError("Prerequisite manifest changed: " + name)
                reports[name] = original
                shutil.copyfile(path, output / path.name)
            library = DEFAULT_OUTPUT / "sysroot/usr/lib"
            expected = {
                name: reports["wayland"]["target"]["archives"][name]["sha256"]
                for name in ("libwayland-client.a", "libwayland-server.a")
            }
            expected.update({
                "libxkbcommon.a": reports["xkbcommon"]["target"]["archive"]["sha256"],
                "libffi.a": reports["wayland"]["target_libffi_sha256"],
                "libc.a": reports["wayland"]["target_libc_sha256"],
            })
            if reports["xkbcommon"]["target_libc_sha256"] != expected["libc.a"]:
                raise BuildError("Prerequisites use different libc builds")
            for name, value in expected.items():
                if digest(library / name) != value:
                    raise BuildError("Prerequisite archive changed: " + name)
            report["archives"] = expected
            report["driver_sha256"] = digest(Path(builder.env["CC"]))
            report["builtins_sha256"] = digest(library / "libclang_rt.builtins-aarch64.a")
            flags = shlex.split(subprocess.check_output(
                [builder.env["PKG_CONFIG"], "--static", "--cflags", "--libs",
                 "wayland-client", "wayland-server", "xkbcommon"],
                env=builder.env, text=True))
            temporary = output / "wayland-shm-probe.symbols.elf"
            builder.run([builder.env["CC"], "-Os", "-ffunction-sections", "-fdata-sections",
                         "-fno-stack-protector", "-Wall", "-Wextra", "-Werror",
                         "-Wl,--gc-sections", str(SOURCE), *flags, "-o", str(temporary)],
                        "link.log")
            report["symbols"] = inspect_elf(temporary)
            program = output / "wayland-shm-probe.elf"
            shutil.copyfile(temporary, program)
            builder.run([builder.tools["llvm-strip"], "--strip-all", str(program)], "strip.log")
            report["probe"] = inspect_elf(program)
            if digest(SOURCE) != report["source_sha256"]:
                raise BuildError("Probe source changed during build")
            report["status"] = "cross-built"
    except Exception as error:
        report["error"] = repr(error)
        raise
    finally:
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(args.output.resolve())
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, BuildError, subprocess.SubprocessError) as error:
        print("wayland-shm: " + str(error), file=sys.stderr)
        raise SystemExit(1)
