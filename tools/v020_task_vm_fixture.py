#!/usr/bin/env python3
"""Build a signed-business test input or decode its native task/VM probe."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from elf64 import decode, require, symbol


PAGE = 4096
IMAGE_BYTES = 16 * PAGE
STACK_BYTES = 8 * PAGE
BACKING_BYTES = 29 * PAGE
ENTRY_STACK_BYTES = 48
PROBE_BYTES = 128
PROBE_CPU = 2
TASK_GRANT = struct.pack("<IIQQHHI", 0x2000, 0, 7, 20_000_000, 2, 1, 4)
STAGES = (
    "entry", "unauthorized spawn", "spawn", "spawn replay and conflict", "stale join",
    "join", "VM reserve", "owned page map", "unmap and replay", "anonymous page fault",
    "unauthorized report", "done",
)
LINKER = """ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); }
SECTIONS {
  . = 0x1000;
  .text : { *(.text) } :text
  /DISCARD/ : { *(.dynamic .dynsym .dynstr .hash .gnu.hash .comment) }
}
"""


def toolchain_bin():
    rustc = os.environ.get("RUSTC", "rustc")
    sysroot = subprocess.check_output([rustc, "--print", "sysroot"], text=True).strip()
    host = next(line[6:] for line in subprocess.check_output([rustc, "-vV"], text=True).splitlines()
                if line.startswith("host: "))
    return Path(sysroot) / "lib" / "rustlib" / host / "bin"


def build(config: Path, output: Path):
    source = Path(__file__).with_name("fixtures") / "v020-task-vm.S"
    output.mkdir(parents=True)
    elf = output / "business-package.elf"
    with tempfile.TemporaryDirectory(prefix="cyx-task-vm-build-") as tmp:
        work = Path(tmp)
        obj, script = work / "probe.o", work / "probe.ld"
        script.write_text(LINKER, encoding="ascii")
        subprocess.run([os.environ.get("CYXIA_CC", "clang"), "--target=aarch64-none-elf",
                        "-c", source, "-o", obj], check=True)
        subprocess.run([toolchain_bin() / "rust-lld", "-flavor", "gnu", "-m", "aarch64elf",
                        "-pie", "-z", "max-page-size=4096", "-T", script, obj, "-o", elf], check=True)
    package = elf.read_bytes()
    parsed = decode(package)
    require((parsed["kind"], parsed["machine"], parsed["entry"]) == (3, 183, PAGE)
            and len(parsed["segments"]) == 1, "fixture is not a static AArch64 PIE")
    load = parsed["segments"][0]
    require((load["type"], load["flags"], load["align"]) == (1, 5, PAGE)
            and load["mem"] > 0 and load["va"] + load["mem"] <= IMAGE_BYTES,
            "fixture does not fit the executable image")
    binding = hashlib.sha256(config.read_bytes()).digest() + hashlib.sha256(package).digest()
    (output / "business-package-to-sign.bin").write_bytes(b"CYX/STARTUP-BUSINESS-PACKAGE/v1" + binding)
    (output / "business-task-services.bin").write_bytes(TASK_GRANT)
    (output / "business-task-services-to-sign.bin").write_bytes(
        b"CYX/STARTUP-BUSINESS-TASK-SERVICES/v1" + binding + TASK_GRANT)


def probe_address(kernel: Path):
    elf = kernel.read_bytes()
    names = subprocess.check_output([toolchain_bin() / "llvm-nm", "--defined-only", "-P", kernel],
                                    text=True).splitlines()
    backings = [line.split()[0] for line in names if "signed_business7BACKING" in line]
    require(len(backings) == 1, "missing signed business backing symbol")
    loads = [segment for segment in decode(elf)["segments"] if segment["type"] == 1]
    backing = symbol(elf, backings[0], loads)
    require(backing["size"] == 3 * BACKING_BYTES, "unexpected business backing layout")
    return (backing["pa"] + (PROBE_CPU - 1) * BACKING_BYTES + IMAGE_BYTES + STACK_BYTES
            - ENTRY_STACK_BYTES - PROBE_BYTES)


def verify_probe(raw: bytes):
    require(len(raw) == PROBE_BYTES, "incomplete task/VM probe")
    tag, stage, result, task, generation, exit_code, region, base, marker, failed, anon = (
        struct.unpack_from("<8sQq8Q", raw)
    )
    require(tag == b"CYXTVM01" and 1 <= stage <= len(STAGES), "missing signed task/VM workload")
    require(failed == 0 and stage == len(STAGES), f"{STAGES[stage - 1]} failed or pending ({result})")
    require(task > 0 and generation > 0 and exit_code == 37 and region > 0 and base > 0
            and base % PAGE == 0 and marker.to_bytes(8, "little") == b"CYXFRAME"
            and anon.to_bytes(8, "little") == b"CYXANON1",
            "signed task/VM results are inconsistent")
    return {"status": "PASS", "cpu": PROBE_CPU, "task_generation": generation,
            "child_exit": exit_code, "verified_phases": STAGES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    build_args = subs.add_parser("build")
    build_args.add_argument("--config", type=Path, required=True)
    build_args.add_argument("--output", type=Path, required=True)
    locate = subs.add_parser("locate-probe")
    locate.add_argument("--kernel", type=Path, required=True)
    check = subs.add_parser("verify-probe")
    check.add_argument("--probe", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        build(args.config, args.output)
    elif args.command == "locate-probe":
        print(json.dumps({"address": probe_address(args.kernel), "bytes": PROBE_BYTES}))
    else:
        print(json.dumps(verify_probe(args.probe.read_bytes())))


if __name__ == "__main__":
    main()
