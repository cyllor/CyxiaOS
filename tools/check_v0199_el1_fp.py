#!/usr/bin/env python3
"""Audit linked AArch64 EL1 FP/SIMD instructions under baseline §§1.2 and 13.2."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

if __package__:
    from . import elf64
    from .check_elf import inspect_elf
    from .doctor import llvm_dir
else:
    import elf64
    from check_elf import inspect_elf
    from doctor import llvm_dir


CONTEXTS = ("cyxia_enter_user", "cyxia_user_return")
ROW = re.compile(r"^\s*([0-9a-f]+):\s+(.+)$", re.IGNORECASE)
INSTRUCTION = re.compile(r"^([0-9a-f]{8})\s+(.+)$", re.IGNORECASE)
LITERAL = re.compile(r"^((?:[0-9a-f]{2}\s+){4})\.word\s+0x[0-9a-f]+$", re.IGNORECASE)
FP_REGISTER = re.compile(r"\b(?:[vqdshbzp]\d+|fpcr|fpsr|fpmr|ffr|za|zt0)\b")


def executable_rows(raw, loads, text):
    """Match disassembled words to every file-backed RX load byte in order."""
    segments = sorted((load for load in loads if load["flags"] & 1), key=lambda load: load["va"])
    elf64.require(segments and all(load["va"] % 4 == load["size"] % 4 == 0 for load in segments),
                  "unaligned executable load")
    words = ((load["va"] + i, load["offset"] + i)
             for load in segments for i in range(0, load["size"], 4))
    for line in text.splitlines():
        row = ROW.fullmatch(line)
        if row is None:
            continue
        address, decoded = int(row[1], 16), row[2].strip()
        expected = next(words, None)
        elf64.require(expected is not None and address >= expected[0],
                      "duplicate or unordered executable word")
        elf64.require(address == expected[0], f"missing executable bytes at {expected[0]:#x}")
        offset = expected[1]
        literal = LITERAL.fullmatch(decoded)
        if literal:
            witness = bytes.fromhex(literal[1])
            operation = None
        else:
            instruction = INSTRUCTION.fullmatch(decoded)
            elf64.require(instruction is not None and "<unknown>" not in instruction[2].lower(),
                          f"unrecognized executable word at {address:#x}")
            witness = int(instruction[1], 16).to_bytes(4, "little")
            operation = canonical_instruction(instruction[2])
        elf64.require(raw[offset:offset + 4] == witness, f"disassembly bytes differ at {address:#x}")
        yield address, operation
    elf64.require(next(words, None) is None, "missing executable bytes at end of disassembly")


def canonical_instruction(instruction):
    text = instruction.lower().split("//", 1)[0].strip()
    text = re.sub(r"\s*<[^>]*>", "", text)
    return re.sub(r",\s*", ",", " ".join(text.split()))


def uses_fp(instruction):
    text = canonical_instruction(instruction)
    mnemonic = text.partition(" ")[0]
    return bool(FP_REGISTER.search(text) or mnemonic.startswith("f") or mnemonic in ("smstart", "smstop"))


def context_sequence(name):
    restoring = name == CONTEXTS[0]
    pair_op = "ldp" if restoring else "stp"
    pairs = []
    for first in range(0, 32, 2):
        offset = f",#{first * 16:#x}" if first else ""
        pairs.append(f"{pair_op} q{first},q{first + 1},[x9{offset}]")
    base = "add x9,x30,#0x130"
    if restoring:
        return ["ldr x9,[x30,#0x330]", "msr fpcr,x9", "ldr x9,[x30,#0x338]", "msr fpsr,x9", base, *pairs]
    return [base, *pairs, "mrs x9,fpcr", "str x9,[x30,#0x330]", "mrs x9,fpsr", "str x9,[x30,#0x338]"]


def context_matches(name, instructions):
    expected = context_sequence(name)
    expected_fp = [insn for insn in expected if uses_fp(insn)]
    actual_fp = [insn for insn in instructions if uses_fp(insn)]
    return expected_fp == actual_fp and any(
        instructions[start:start + len(expected)] == expected
        for start in range(len(instructions) - len(expected) + 1)
    )


def inspect(raw, disassembly):
    loads = inspect_elf(raw)["loads"]
    bounds = {}
    for name in CONTEXTS:
        try:
            bounds[name] = elf64.symbol(raw, name, loads)
        except ValueError as error:
            if str(error) != f"missing symbol {name}":
                raise
    elf64.require(all(span["size"] > 0 and span["size"] % 4 == span["va"] % 4 == 0
                      for span in bounds.values()), "invalid FP context transition size")
    routines = {name: [] for name in bounds}
    instruction_count = literal_count = outside_count = 0
    violations = []
    for address, operation in executable_rows(raw, loads, disassembly):
        owner = next((name for name, span in bounds.items()
                      if span["va"] <= address < span["va"] + span["size"]), None)
        if operation is None:
            elf64.require(owner is None, "literal inside FP context transition")
            literal_count += 1
            continue
        instruction_count += 1
        if owner is not None:
            routines[owner].append(operation)
        elif uses_fp(operation):
            outside_count += 1
            if len(violations) < 32:
                violations.append({"address": f"{address:#x}", "instruction": operation})
    mismatch = [name for name in CONTEXTS if bounds and not context_matches(name, routines.get(name, []))]
    context_status = "FAIL" if mismatch else "PASS" if bounds else "NOT_RUN"
    return {"status": "FAIL" if violations or mismatch else context_status,
            "outside_context_policy": "FAIL" if violations else "PASS", "context_state_moves": context_status,
            "instruction_count": instruction_count, "elf_mapping_literal_words": literal_count,
            "fp_outside_context_count": outside_count, "fp_outside_context_sample": violations,
            "context_fp_operations": {name: sum(map(uses_fp, ops)) for name, ops in routines.items()},
            "context_sequence_mismatch": mismatch}


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
    summary = {"scope": "linked-el1-fp-audit-subcheck", "related_ids": ["M08", "A06"],
               "proof_class": "STATIC_EL1", "formal_verdict": False, "status": "FAIL",
               "elf_sha256": args.elf_sha256, "objdump_sha256": args.objdump_sha256,
               "argv": command, "checker_sha256": sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        disassembly = subprocess.check_output(command, timeout=60)
        (args.output / "objdump.txt").write_bytes(disassembly)
        summary["disassembly_sha256"] = sha256(disassembly).hexdigest()
        elf64.require(sha256(args.elf.read_bytes()).hexdigest() == args.elf_sha256,
                      "ELF changed during audit")
        summary.update(inspect(raw, disassembly.decode("utf-8")))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    result = json.dumps(summary, indent=2) + "\n"
    (args.output / "summary.json").write_text(result, encoding="utf-8")
    print(result, end="")
    return int(summary["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
