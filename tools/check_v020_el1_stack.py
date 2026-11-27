#!/usr/bin/env python3
"""Measure the linked default AArch64 execution and IRQ call stacks."""
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
    from .check_v0199_el1_vectors import FRAME_BYTES, inspect as inspect_vectors
    from .doctor import llvm_dir
else:
    import elf64
    from check_elf import inspect_elf
    from check_v0199_el1_fp import executable_rows
    from check_v0199_el1_vectors import FRAME_BYTES, inspect as inspect_vectors
    from doctor import llvm_dir

ROOTS = ("boot_entry", "secondary_entry", "exception_dispatch", "exception_quiescent_stop")
LIMIT = 16 * 1024
EMERGENCY_LIMIT = 8 * 1024
SP_ARITHMETIC = re.compile(r"(add|sub) sp,sp,#(0x[0-9a-f]+|\d+)(?:,lsl #12)?")
SP_PRE = re.compile(r"\[sp,#(-?(?:0x[0-9a-f]+|\d+))\]!")
SP_POST = re.compile(r"\[sp\],#(-?(?:0x[0-9a-f]+|\d+))$")
DIRECT_BRANCH = re.compile(r"(?:b(?:l|\.[a-z]{2})?|(?:cb|tb)n?z)\b.*?(0x[0-9a-f]+)$")


def stack_change(op, scope):
    arithmetic = SP_ARITHMETIC.fullmatch(op)
    if arithmetic:
        immediate = int(arithmetic[2], 0) << (12 if "lsl #12" in op else 0)
        return immediate if arithmetic[1] == "sub" else -immediate
    operand = SP_PRE.search(op) or SP_POST.search(op)
    if operand:
        return -int(operand[1], 0)
    elf64.require(not re.search(r"\[sp,#-|\[sp[^]]*\]!|\[sp\],|^\w+ sp,", op)
                  or op.startswith(("cmp sp,", "tst sp,")), f"unmeasured SP update in {scope}: {op}")
    return 0


def linked_frames(metadata, instructions, require_stack_notes=False):
    elf64.require(metadata["FileSummary"]["Arch"] == "aarch64", "stack metadata is not AArch64")
    functions = {}
    addresses = {}
    for row in metadata["Symbols"]:
        symbol = row["Symbol"]
        if symbol["Type"]["Name"] != "Function":
            continue
        name, start, size = symbol["Name"]["Name"], symbol["Value"], symbol["Size"]
        elf64.require(name not in addresses and size > 0 and start % 4 == size % 4 == 0,
                      f"invalid function symbol {name}")
        addresses[name] = start
        if start in functions:
            elf64.require(functions[start]["size"] == size, f"mismatched function alias {name}")
        else:
            functions[start] = {"name": name, "size": size}
    previous_end = 0
    for start, function in sorted(functions.items()):
        elf64.require(start >= previous_end, "overlapping function sections")
        previous_end = start + function["size"]
    notes = {}
    for row in metadata["StackSizes"]:
        entry = row["Entry"]
        elf64.require(entry["Size"] >= 0 and entry["Size"] % 16 == 0, "invalid compiler stack note")
        for name in entry["Functions"]:
            elf64.require(name in addresses, f"unresolved compiler stack note {name}")
            address = addresses[name]
            elf64.require(address not in notes or notes[address] == entry["Size"],
                          f"conflicting compiler stack notes for {name}")
            notes[address] = entry["Size"]
    elf64.require(all(root in addresses for root in ROOTS), "missing default EL1 roots")
    if require_stack_notes:
        elf64.require(all(addresses[root] in notes for root in ROOTS),
                      "missing compiler stack notes for default EL1 roots")

    def walk(start, active):
        if start in finished:
            return finished[start]
        name, size = functions[start]["name"], functions[start]["size"]
        elf64.require(start not in active, f"recursive stack path through {name}")
        end = start + size
        operations = {}
        for pc in range(start, end, 4):
            elf64.require(pc in instructions and instructions[pc] is not None,
                          f"unclassified function bytes in {name} at {pc:#x}")
            op = instructions[pc]
            change = stack_change(op, name)
            elf64.require(abs(change) % 16 == 0, f"unaligned stack operation in {name}")
            mnemonic = op.split()[0]
            elf64.require(not (mnemonic not in ("ret", "brk")
                               and mnemonic.startswith(("br", "blr", "eret", "ret")))
                          and not op.startswith(("ret ", "msr spsel,", "msr sp_el0,")),
                          f"unmeasured control transfer in {name} at {pc:#x}: {op}")
            branch = DIRECT_BRANCH.fullmatch(op)
            target = int(branch[1], 16) if branch else None
            if target is not None:
                elf64.require(target % 4 == 0, f"unaligned branch in {name}")
            operations[pc] = (mnemonic, change, target)

        # Revisit a loop only at the same stack height. A different height
        # at any merge is outside the supported static-frame proof.
        seen, pending, children = {}, [(start, 0)], {}
        frame, returns = notes.get(start, 0), False
        while pending:
            pc, height = pending.pop()
            elf64.require(pc in operations, f"control leaves {name} at {pc:#x}")
            if pc in seen:
                elf64.require(seen[pc] == height, f"conflicting SP at {pc:#x} in {name}")
                continue
            seen[pc] = height
            mnemonic, change, target = operations[pc]
            elf64.require(mnemonic != "brk", f"reachable compiler trap in {name} at {pc:#x}")
            height += change
            elf64.require(height >= 0, f"stack restored above its entry SP in {name}")
            frame = max(frame, height)
            if mnemonic == "ret":
                elf64.require(height == 0, f"unbalanced return in {name}")
                returns = True
                continue
            if target is not None:
                if mnemonic == "bl" or not start <= target < end:
                    elf64.require(target in functions, f"unmeasured branch target in {name}: {target:#x}")
                    child, child_returns = walk(target, active | {start})
                    children[target] = child
                    if mnemonic != "bl" and child_returns:
                        elf64.require(height == 0, f"unbalanced tail return in {name}")
                        returns = True
                    if mnemonic == "bl" and not child_returns:
                        continue
                else:
                    pending.append((target, height))
            if mnemonic != "b":
                pending.append((pc + 4, height))
        child_peak = max(children.values(), key=lambda child: child["bytes"], default={"bytes": 0, "path": []})
        result = {"path": [name, *child_peak["path"]], "bytes": frame + child_peak["bytes"]}
        finished[start] = (result, returns)
        return result, returns

    finished = {}
    roots = {root: walk(addresses[root], set())[0] for root in ROOTS}
    return roots, len(finished), [functions[pc]["name"] for pc in sorted(finished) if pc not in notes]


def inspect(raw, metadata, disassembly, require_stack_notes=False):
    vectors = inspect_vectors(raw, disassembly)
    loads = inspect_elf(raw)["loads"]
    instructions = dict(executable_rows(raw, loads, disassembly))
    roots, count, no_notes = linked_frames(metadata, instructions, require_stack_notes)
    # The validated vector enters Rust only after reserving 512 bytes. It
    # allows one nested synchronous dispatch and moves IRQs to another stack.
    dispatch = roots["exception_dispatch"]["bytes"]
    trap_reserve = 2 * (FRAME_BYTES + dispatch)
    execution = max(roots[entry]["bytes"] for entry in ROOTS[:2]) + trap_reserve
    emergency = roots["exception_quiescent_stop"]["bytes"]
    return {
        "status": "PASS" if max(execution, trap_reserve) <= LIMIT and emergency <= EMERGENCY_LIMIT else "FAIL",
        "scope": "linked-default-aarch64-el1-direct-call-stack-subcheck",
        "formal_verdict": False,
        "frozen_limit_bytes": LIMIT,
        "execution_bound_bytes": execution,
        "irq_bound_bytes": trap_reserve,
        "emergency_bound_bytes": emergency,
        "primary_execution_stack_bytes": vectors["primary_exec_stack_bytes"],
        "secondary_execution_stack_bytes": (LIMIT if vectors["primary_exec_stack_bytes"] == LIMIT
                                            else 64 * 1024),
        "entry_frame_bytes": vectors["frame_bytes"],
        "nested_dispatch_limit": 2,
        "reachable_functions": count,
        "reachable_functions_with_compiler_note": count - len(no_notes),
        "frames": roots,
        "instruction_accounted_without_compiler_note": no_notes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-stack-notes", action="store_true")
    args = parser.parse_args()
    raw = args.elf.read_bytes()
    llvm = llvm_dir()
    tools = {name: llvm / name for name in ("llvm-objdump", "llvm-readobj")}
    digests = {name: sha256(path.read_bytes()).hexdigest() for name, path in tools.items()}
    try:
        disassembly = subprocess.check_output([
            tools["llvm-objdump"], "--disassemble", "--disassemble-zeroes", "--mcpu=cortex-a53", args.elf,
        ], text=True, timeout=60)
        metadata = json.loads(subprocess.check_output([
            tools["llvm-readobj"], "--symbols", "--stack-sizes", "--elf-output-style=JSON", args.elf,
        ], timeout=60))
        elf64.require(args.elf.read_bytes() == raw, "ELF changed during inspection")
        elf64.require(all(sha256(path.read_bytes()).hexdigest() == digests[name] for name, path in tools.items()),
                      "LLVM tools changed during inspection")
        elf64.require(len(metadata) == 1, "stack metadata did not describe one ELF")
        report = inspect(raw, metadata[0], disassembly, args.require_stack_notes)
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        report = {"status": "FAIL", "error": str(error)}
    report.update(elf_sha256=sha256(raw).hexdigest(), tool_sha256=digests,
                  checker_sha256=sha256(Path(__file__).read_bytes()).hexdigest())
    result = json.dumps(report, indent=2) + "\n"
    args.output.write_text(result, encoding="utf-8")
    print(result, end="")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
