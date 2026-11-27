#!/usr/bin/env python3
"""Check the reviewed linked signed-scratch VirtIO-blk admission path."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

if __package__:
    from . import elf64
    from .check_elf import inspect_elf
    from .check_v0199_el1_fp import executable_rows
    from .doctor import llvm_dir
else:
    import elf64
    from check_elf import inspect_elf
    from check_v0199_el1_fp import executable_rows
    from doctor import llvm_dir


FLUSH = 1 << 9
READ_ONLY = 1 << 5
LABEL = re.compile(r"^[0-9a-f]+ <([^<>\n]+)>:$", re.MULTILINE)
ADDRESS = re.compile(r"0x[0-9a-f]+$")
PREFIX = ["mov w8,#0x3", "mov w10,#0x1", "str w8,[x9,#0x70]", "str w10,[x9,#0x14]", "dsb sy"]
CHECKER_FILES = (
    "check_v0199_virtio_blk_admission.py", "check_v0199_el1_fp.py", "check_elf.py", "elf64.py", "doctor.py",
)


def check(words, pc, sequence):
    for index, expected in enumerate(sequence):
        address = pc + 4 * index
        elf64.require(words.get(address) == expected,
                      f"expected {expected!r} at {address:#x}; found {words.get(address)!r}")
    return pc + 4 * len(sequence)


def unique_start(words, sequence):
    starts = [pc for pc, word in words.items() if word == sequence[0] and all(
        words.get(pc + 4 * i) == op for i, op in enumerate(sequence)
    )]
    elf64.require(len(starts) == 1, f"missing or ambiguous linked instruction sequence: {sequence[0]}")
    return starts[0]


def destination(instruction):
    match = ADDRESS.search(instruction or "")
    elf64.require(match is not None, "expected a linked direct branch destination")
    return int(match[0], 16)


def negotiation(words, start):
    pc = check(words, start, PREFIX)
    failure = destination(words.get(pc + 16))
    version_test = ["str wzr,[x9,#0x14]", "dsb sy"]
    strict = words.get(pc) == "ldr w10,[x9,#0x10]"
    if strict:
        pc = check(words, pc, [
            "ldr w10,[x9,#0x10]", *version_test, "ldr w8,[x9,#0x10]", f"tbz w10,#0x0,{failure:#x}",
            "mov w10,#0x220", "and w8,w8,w10", "cmp w8,#0x200", f"b.ne {failure:#x}",
            "str wzr,[x9,#0x24]", "mov w10,#0x1", "str w8,[x9,#0x20]",
        ])
        # The same w8 must compare equal to FLUSH before it is written. The
        # READ_ONLY bit participates in the guard and cannot reach the write.
        possible_low = [FLUSH]
    else:
        pc = check(words, pc, [
            "ldr w8,[x9,#0x10]", *version_test, "ldr w20,[x9,#0x10]", f"tbz w8,#0x0,{failure:#x}",
            f"tbz w20,#0x9,{failure:#x}", "mov w8,#0x220", "str wzr,[x9,#0x24]",
            "and w8,w20,w8", "str w8,[x9,#0x20]",
        ])
        possible_low = [FLUSH, FLUSH | READ_ONLY]
    accepted = check(words, pc, [
        "mov w8,#0xb", "str w10,[x9,#0x24]", "str w10,[x9,#0x20]",
        "mov w10,#0xc8", "str w8,[x9,#0x70]", "dsb sy",
        "ldr w8,[x9,#0x70]", "and w8,w8,w10", "cmp w8,#0x8", f"b.ne {failure:#x}",
    ])
    error = check(words, failure, ["ldr w8,[x9,#0x70]", "orr w8,w8,#0x80", "str w8,[x9,#0x70]"])
    check(words, error, ["mov w23,#0x3"])
    return {
        "possible_low_driver_features": possible_low,
        "high_driver_features": 1,
        "rejects_read_only_before_publishing_features": strict,
        "feature_success": accepted,
        "feature_failure": failure,
        "attach_error": error,
    }


def paths_to_exits(words, start, exits):
    """Follow both sides of direct branches to the two reviewed attach exits."""
    remaining = [start]
    reached = set()
    inspected = set()
    while remaining:
        pc = remaining.pop()
        if pc in exits:
            reached.add(pc)
            continue
        if pc in inspected:
            continue
        inspected.add(pc)
        op = words.get(pc)
        elf64.require(op is not None, f"admission reaches unverified bytes at {pc:#x}")
        mnemonic = op.partition(" ")[0]
        if mnemonic == "b":
            remaining.append(destination(op))
            continue
        if mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
            remaining.append(destination(op))
        else:
            elf64.require(mnemonic not in ("bl", "blr", "br", "ret", "eret", "udf", "brk", "svc"),
                          f"unexpected control transfer before attach exit: {op}")
        remaining.append(pc + 4)
    elf64.require(reached == exits, "linked attach exits differ")
    return inspected


def inspect(raw, disassembly):
    loads = inspect_elf(raw)["loads"]
    linked = dict(executable_rows(raw, loads, disassembly))
    labels = LABEL.findall(disassembly)

    def symbol(stem):
        names = [name for name in labels if stem in name]
        elf64.require(len(names) == 1, f"missing or ambiguous linked function {stem}")
        return elf64.symbol(raw, names[0], loads)

    owner = symbol("cyxia_kernel3smp10production15signed_resident3run17h")
    words = {pc: op for pc, op in linked.items() if owner["va"] <= pc < owner["va"] + owner["size"]}
    queue = symbol("cyxia_driver_virtio5queue10BatchQueue9configure17h")["va"]
    start = symbol("cyxia_driver_virtio9transport9Transport5start17h")["va"]
    memcpy = symbol("memcpy")["va"]
    configured = unique_start(words, [f"bl {queue:#x}"])
    started = unique_start(words, [f"bl {start:#x}"])
    feature_start = unique_start(words, PREFIX)
    result = negotiation(words, feature_start)
    ok, error = result["feature_success"], result["attach_error"]

    identity = unique_start(words, ["ldr w8,[x9,#0x8]", "cmp w8,#0x2", f"b.ne {error:#x}"])
    reset = check(words, identity + 12, ["str wzr,[x9,#0x70]", "dsb sy"])
    before_features = paths_to_exits(words, reset, {feature_start, error})
    after_features = paths_to_exits(words, ok, {configured, error})
    queue_ok = check(words, configured + 4, ["ldr x19,[sp,#0x1770]", "cmp x19,#0x2", f"b.eq {error:#x}"])
    elf64.require(queue_ok < started, "queue success does not precede DRIVER_OK")
    for pc in range(queue_ok, started, 4):
        operation = words.get(pc)
        elf64.require(operation is not None, "unverified bytes after queue success")
        mnemonic = operation.partition(" ")[0]
        if mnemonic in ("b", "bl", "blr", "br", "ret", "eret", "cbz", "cbnz", "tbz", "tbnz", "udf", "brk", "svc") or mnemonic.startswith("b."):
            elf64.require(operation == f"bl {memcpy:#x}", "unexpected control transfer before DRIVER_OK")
    check(words, started + 4, ["and w8,w0,#0xff", "cmp w8,#0x9", f"b.ne {error:#x}"])
    check(linked, start, ["ldr x8,[x0]", "cmp x8,#0x2"])
    elf64.require((linked.get(start + 8) or "").startswith("b.ne "), "unknown Transport backend dispatch")
    read_back = check(linked, start + 12, [
        "ldr x8,[x0,#0x8]", "mov w9,#0xf", "str w9,[x8,#0x70]", "dsb sy", "ldr w9,[x8,#0x70]", "cmp w9,#0xf",
    ])
    start_error = destination(linked.get(read_back))
    check(linked, read_back, [f"b.ne {start_error:#x}", "mov w0,#0x9", "ret"])
    check(linked, start_error, ["ldr w9,[x8,#0x70]", "mov w0,#0x6", "orr w9,w9,#0x80", "str w9,[x8,#0x70]", "ret"])

    low = result.pop("possible_low_driver_features")
    strict = result["rejects_read_only_before_publishing_features"]
    witnesses = before_features | after_features | set(range(identity, reset, 4))
    for first, end in ((feature_start, ok), (result["feature_failure"], error + 4),
                       (configured, started + 16), (start, read_back + 12), (start_error, start_error + 20)):
        witnesses.update(range(first, end, 4))
    return {
        "status": "PASS" if strict and low == [FLUSH] else "FAIL",
        "device_id": 2,
        "possible_low_driver_features": low,
        "features_ok_gate_verified": True,
        "queue_then_driver_ok_verified": True,
        "queue_call": f"{configured:#x}", "driver_ok_call": f"{started:#x}",
        **{key: f"{value:#x}" if type(value) is int and key != "high_driver_features" else value
           for key, value in result.items()},
    }, "".join(f"{pc:#x}: {linked[pc]}\n" for pc in sorted(witnesses))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--elf-sha256", required=True)
    parser.add_argument("--objdump-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.elf.read_bytes()
    objdump = llvm_dir() / "llvm-objdump"
    elf64.require(sha256(raw).hexdigest() == args.elf_sha256, "ELF SHA-256 differs from pinned input")
    elf64.require(sha256(objdump.read_bytes()).hexdigest() == args.objdump_sha256,
                  "llvm-objdump SHA-256 differs from pinned input")
    args.output.mkdir(parents=True, exist_ok=False)
    command = [str(objdump), "--disassemble", "--disassemble-zeroes", "--mcpu=cortex-a53", str(args.elf)]
    summary = {
        "scope": "linked-signed-scratch-mmio-block-admission-subcheck", "related_id": "D12",
        "proof_class": "STATIC_EL1", "formal_verdict": False, "status": "NOT_RUN",
        "elf_sha256": args.elf_sha256, "objdump_sha256": args.objdump_sha256, "argv": command,
        "checker_file_sha256": {
            name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in CHECKER_FILES
        },
    }
    try:
        disassembly = subprocess.check_output(command, timeout=60)
        elf64.require(sha256(args.elf.read_bytes()).hexdigest() == args.elf_sha256, "ELF changed during audit")
        elf64.require(sha256(objdump.read_bytes()).hexdigest() == args.objdump_sha256, "objdump changed during audit")
        summary["disassembly_sha256"] = sha256(disassembly).hexdigest()
        inspected, witness = inspect(raw, disassembly.decode("utf-8"))
        summary.update(inspected)
        summary["instructions_sha256"] = sha256(witness.encode("ascii")).hexdigest()
        (args.output / "instructions.txt").write_text(witness, encoding="ascii")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    content = json.dumps(summary, indent=2) + "\n"
    (args.output / "summary.json").write_text(content, encoding="utf-8")
    print(content, end="")
    return int(summary["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
