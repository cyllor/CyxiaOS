#!/usr/bin/env python3
"""Check linked AArch64 EL1 vector routing, stack entry and integer frames."""

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


FRAME_BYTES = 512
RUST_FRAME_BYTES = 288
PAGE = 4096
STACK_BANK_BYTES = 32768
VECTOR_STRIDE = 128
VECTOR_COUNT = 16
TABLE_BYTES = VECTOR_STRIDE * VECTOR_COUNT
PAN_TCR = 0x00000002B5593519
WRITER_OFFSETS = {"high_entry": 20, "secondary_high": 32}
VBAR_STORE = "msr vbar_el1,x0"
LDR_LITERAL = re.compile(r"ldr (x[0-9]+),(0x[0-9a-f]+)")
CHECKER_FILES = (
    "check_v0199_el1_vectors.py", "check_v0199_el1_fp.py", "check_elf.py", "elf64.py", "doctor.py",
)


def memory(base, offset):
    return f"[{base},#{offset:#x}]" if offset else f"[{base}]"


def register_pairs(operation, base):
    return [
        f"{operation} x{reg},x{reg + 1},{memory(base, reg * 8)}"
        for reg in range(2, 30, 2)
    ]


def check_sequence(instructions, address, expected, scope, read_literal):
    for index, operation in enumerate(expected):
        pc = address + 4 * index
        actual = instructions.get(pc)
        if isinstance(operation, tuple):
            register, value = operation
            match = LDR_LITERAL.fullmatch(actual or "")
            elf64.require(match and match[1] == register and read_literal(int(match[2], 16)) == value,
                          f"{scope} at {pc:#x}: expected {register} literal {value:#x}")
        else:
            elf64.require(actual == operation,
                          f"{scope} at {pc:#x}: expected {operation!r}, found {actual!r}")
    return address + 4 * len(expected)


def vector_route(kind, pc, symbols):
    scratch, saved, busy = symbols["__exception_scratch"], pc + 0x44, pc + 0x70
    return [
        "msr tpidr_el1,x0", "msr daifset,#0xf", "mrs x0,contextidr_el1",
        f"cbz x0,{pc + 0x30:#x}", "cmp x0,#0x1", f"b.eq {pc + 0x38:#x}",
        "cmp x0,#0x2", f"b.eq {pc + 0x40:#x}", "cmp x0,#0x3",
        f"b.ne {symbols['exception_unregistered']:#x}",
        ("x0", scratch + PAGE * 3), f"b {saved:#x}", ("x0", scratch), f"b {saved:#x}",
        ("x0", scratch + PAGE), f"b {saved:#x}", ("x0", scratch + PAGE * 2),
        "str x1,[x0,#0x8]", "ldr x1,[x0,#0x160]", f"cbnz x1,{busy:#x}",
        "mov x1,#0x1", "str x1,[x0,#0x160]", "mrs x1,tpidr_el1", "str x1,[x0]",
        "mrs x1,contextidr_el1", "msr tpidr_el1,x1",
        f"mov x1,#{kind:#x}", f"b {symbols['exception_entry']:#x}",
        f"mov x1,#{kind:#x}", f"b {symbols['exception_busy']:#x}",
    ]


def check_vectors(instructions, table, frames, symbols, read_literal):
    elf64.require(table % TABLE_BYTES == 0, "exception vector table is unaligned")
    elf64.require(len(frames) == VECTOR_COUNT, "wrong exception vector count")
    routes = []
    next_frame = table + TABLE_BYTES
    for kind, frame in enumerate(frames):
        elf64.require(frame == next_frame, f"vector {kind} body overlaps or is out of order")
        slot = table + kind * VECTOR_STRIDE
        check_sequence(instructions, slot, [f"b {frame:#x}"] + ["nop"] * 31,
                       f"vector slot {kind}", read_literal)
        next_frame = check_sequence(instructions, frame, vector_route(kind, frame, symbols),
                                    f"vector route {kind}", read_literal)
        routes.append({"kind": kind, "slot_va": f"{slot:#x}", "frame_va": f"{frame:#x}"})
    elf64.require(next_frame == symbols["exception_entry"], "vector routes do not end at common entry")
    return routes


def fence_user_translation(empty):
    return ["mrs x2,ttbr1_el1", "and x2,x2,#0xffffffffffff", "msr ttbr1_el1,x2", "isb",
            ("x2", empty), "msr ttbr0_el1,x2", "isb"]


def user_translation_registers(root, asid):
    return [f"msr ttbr0_el1,{root}", "isb", f"mrs {root},ttbr1_el1", f"and {root},{root},#0xffffffffffff",
            f"orr {root},{root},{asid}",
            f"msr ttbr1_el1,{root}", "isb"]


def entry_sequencing(symbols, prefix, dispatch):
    if "empty_l1" not in symbols:
        return {"exception_entry": [*prefix, *dispatch]}
    empty = symbols["empty_l1"]
    emergency = symbols["exception_emergency"]
    return {
        "exception_entry": [
            *prefix, "cmp x1,#0x8", f"b.lo {symbols['exception_check_kernel_translation']:#x}",
            "mrs x2,ttbr0_el1", "mrs x4,ttbr1_el1", "and x4,x4,#0xffff000000000000",
            "orr x2,x2,x4", "str x2,[x0,#0x118]", *fence_user_translation(empty),
            f"b {symbols['exception_translation_ready']:#x}",
        ],
        "exception_check_kernel_translation": [
            "mrs x2,ttbr1_el1", "tst x2,#0xffff000000000000", f"b.ne {emergency:#x}",
            "mrs x2,ttbr0_el1", ("x4", empty), "cmp x2,x4", f"b.ne {emergency:#x}",
        ],
        "exception_translation_ready": dispatch,
    }


def stack_gate_sequences(symbols):
    gate = symbols["EXCEPTION_ADMISSION_CLOSED"]
    stacks = symbols["__exception_stacks"]
    emergency = symbols["exception_emergency"]
    terminal = symbols["exception_emergency_with_reason"]
    observed = symbols["exception_stop_observed"]
    select = symbols["exception_select_stack"]
    sw_pan = "empty_l1" in symbols
    fence = fence_user_translation(symbols["empty_l1"]) if sw_pan else []
    capture = [
        *register_pairs("stp", "x0"), "str x30,[x0,#0xf0]",
        "mrs x2,elr_el1", "mrs x3,spsr_el1", "stp x2,x3,[x0,#0xf8]",
        "mrs x2,esr_el1", "mrs x3,far_el1", "stp x2,x3,[x0,#0x108]",
        "str xzr,[x0,#0x118]", "mrs x2,sp_el0", "mov x3,sp", "stp x2,x3,[x0,#0x120]",
        "mrs x2,tpidr_el0", "stp x2,x1,[x0,#0x130]",
    ]
    admission = [
        ("x2", gate), "ldar x2,[x2]", f"cbnz x2,{observed:#x}", "cmp x1,#0x4", f"b.lo {emergency:#x}",
        "cmp x1,#0xa", f"b.hs {emergency:#x}", "cmp x1,#0x6", f"b.eq {emergency:#x}",
        "cmp x1,#0x7", f"b.eq {emergency:#x}", "ldr x2,[x0,#0x168]",
        f"cbz x2,{symbols['exception_outer']:#x}", "cmp x2,#0x1", f"b.ne {emergency:#x}",
        "cmp x1,#0x4", f"b.ne {emergency:#x}", "ldp x4,x5,[x0,#0x180]",
        f"b {symbols['exception_check_sp']:#x}",
    ]
    copies = [
        instruction for offset in range(0, 320, 16)
        for instruction in (f"ldp x7,x8,{memory('x0', offset)}",
                            f"stp x7,x8,{memory('x6', offset)}")
    ]
    # These labels mark the only software PAN metadata stores in the frame
    # transfer and return. Legacy linked images have neither store.
    transfer_prefix = [f"sub x6,x3,#{FRAME_BYTES:#x}", *copies, "str x0,[x6,#0x140]",
                       "ldp x7,x8,[x0,#0x180]", "stp x7,x8,[x6,#0x148]"]
    transfer_tail = [
        "add x2,x2,#0x1", "str x2,[x0,#0x168]", "stp x4,x6,[x0,#0x180]", "mov sp,x6",
        "str xzr,[x0,#0x160]", "mov x0,sp", f"bl {symbols['exception_dispatch']:#x}",
        "mov x30,sp", "ldr x0,[x30,#0x140]", "mov x2,#0x1", "str x2,[x0,#0x160]",
        ("x2", gate), "ldar x2,[x2]", "ldr x1,[x30,#0x138]", f"cbnz x2,{observed:#x}",
        "ldp x2,x3,[x30,#0xf8]", "and x4,x3,#0x1f", f"cbz x4,{symbols['exception_restore_user']:#x}",
        "cmp x4,#0x5", f"b.ne {emergency:#x}", f"b {symbols['exception_restore_status']:#x}",
    ]
    restore_prefix = [
        "msr elr_el1,x2", "msr spsr_el1,x3", "ldp x2,x3,[x30,#0x120]", "msr sp_el0,x2",
        "ldr x2,[x30,#0x130]", "msr tpidr_el0,x2", "ldp x7,x8,[x30,#0x148]", "stp x7,x8,[x0,#0x180]",
        "ldr x2,[x0,#0x168]", "sub x2,x2,#0x1", "str x2,[x0,#0x168]",
    ]
    restore_tail = ["mov sp,x3", *register_pairs("ldp", "x30"), "str xzr,[x0,#0x160]",
                    "ldp x0,x1,[x30]", "ldr x30,[x30,#0xf0]", "eret"]
    restore_user = ["and x3,x3,#0xffffffffffdfffff"]
    if sw_pan:
        transfer_prefix += [f"cbnz x2,{symbols['exception_publish_stack']:#x}",
                            "ldr x9,[x6,#0x118]", "str x9,[x0,#0x1c8]"]
        restore_user += ["ldr x4,[x30,#0x118]", "and x5,x4,#0xffff000000000000", f"cbz x5,{emergency:#x}",
                         "and x4,x4,#0xffffffffffff", *user_translation_registers("x4", "x5")]
        restore_prefix += [f"cbnz x2,{symbols['exception_restore_sp']:#x}", "str xzr,[x0,#0x1c8]"]

    return {
        **entry_sequencing(symbols, capture, admission),
        "exception_outer": ["ldp x4,x5,[x0,#0x170]"],
        "exception_check_sp": [
            "tst x3,#0xf", f"b.ne {emergency:#x}", "cmp x3,x5", f"b.hi {emergency:#x}",
            f"add x6,x4,#{FRAME_BYTES:#x}", "cmp x3,x6", f"b.lo {emergency:#x}",
            "cmp x1,#0x4", f"b.ne {select:#x}", "ldr x6,[x0,#0x108]", "lsr x7,x6,#26",
            "cmp x7,#0x26", f"b.eq {emergency:#x}", "cmp x7,#0x25", f"b.ne {select:#x}",
            f"tbnz w6,#0xa,{select:#x}", "ldr x6,[x0,#0x110]", "sub x7,x4,#0x1,lsl #12",
            "cmp x6,x7", f"b.lo {select:#x}", "cmp x6,x4", f"b.hs {select:#x}", f"b {emergency:#x}",
        ],
        "exception_select_stack": [
            "cmp x1,#0x5", f"b.eq {symbols['exception_irq_stack']:#x}",
            "cmp x1,#0x9", f"b.ne {symbols['exception_use_stack']:#x}",
        ],
        "exception_irq_stack": [
            ("x4", stacks), "mrs x5,contextidr_el1", "add x4,x4,x5,lsl #15",
            "add x4,x4,#0x1,lsl #12", "add x3,x4,#0x4,lsl #12",
        ],
        "exception_use_stack": transfer_prefix if sw_pan else [*transfer_prefix, *transfer_tail],
        **({"exception_publish_stack": transfer_tail} if sw_pan else {}),
        "exception_restore_user": restore_user,
        "exception_restore_status": restore_prefix if sw_pan else [*restore_prefix, *restore_tail],
        **({"exception_restore_sp": restore_tail} if sw_pan else {}),
        "exception_stop_observed": ["orr x1,x1,#0x80", f"b {emergency:#x}"],
        "exception_busy": [
            "ldr x2,[x0,#0x190]", f"cbz x2,{emergency:#x}", "mov x2,#0x3", "str x2,[x0,#0x190]",
            f"b {symbols['exception_unregistered']:#x}",
        ],
        "exception_emergency": ["mov x7,xzr"],
        "exception_emergency_with_reason": [
            "mov x2,#0x1", "str x2,[x0,#0x190]", "str x7,[x0,#0x1c0]", *fence, "mov x3,sp", "cmp x1,#0x4",
            f"b.hs {terminal + 28 + 4 * len(fence):#x}", "mrs x3,sp_el0", "mrs x2,contextidr_el1", "msr tpidr_el1,x2",
            ("x4", stacks), "add x4,x4,x2,lsl #15", "add x4,x4,#0x8,lsl #12", "msr spsel,#0x1", "mov sp,x4",
            ("x5", gate), "mov x4,#0x1", "stlr x4,[x5]", "str x1,[x0,#0x198]", "str x3,[x0,#0x1a0]",
            "mrs x2,elr_el1", "mrs x3,esr_el1", "stp x2,x3,[x0,#0x1a8]", "mrs x2,far_el1",
            "str x2,[x0,#0x1b8]", "add x2,x0,#0x190", "mov x3,#0x2", "stlr x3,[x2]",
            "mov x0,x1", f"b {symbols['exception_quiescent_stop']:#x}",
        ],
        "exception_unregistered": [("x0", gate), "mov x1,#0x1", "stlr x1,[x0]"],
        "exception_stop": [
            "msr daifset,#0xf", "dsb ishst", "sev", "wfe", f"b {symbols['exception_stop'] + 12:#x}",
        ],
        "exception_register_stack": [
            "cmp x0,#0x4", f"b.hs {symbols['exception_unregistered']:#x}",
            "msr contextidr_el1,x0", ("x3", symbols["__exception_scratch"]),
            "add x3,x3,x0,lsl #12", "stp x1,x2,[x3,#0x170]", "ret",
        ],
        "cyxia_terminal_stop": [
            "msr daifset,#0xf", "mov x7,x0", "mrs x2,contextidr_el1", "cmp x2,#0x4",
            f"b.hs {symbols['exception_unregistered']:#x}", "mrs x3,tpidr_el1", "cmp x2,x3",
            f"b.ne {symbols['exception_unregistered']:#x}", ("x0", symbols["__exception_scratch"]),
            "add x0,x0,x2,lsl #12", "ldp x4,x5,[x0,#0x170]",
            f"cbz x4,{symbols['exception_unregistered']:#x}", "cmp x4,x5",
            f"b.hs {symbols['exception_unregistered']:#x}", "ldr x3,[x0,#0x160]",
            f"cbnz x3,{symbols['exception_unregistered']:#x}", "mov x3,#0x1", "str x3,[x0,#0x160]",
            "mov x1,#0x10", ("x3", gate), "ldar x3,[x3]",
            f"cbz x3,{symbols['exception_software_stop']:#x}", "orr x1,x1,#0x80",
        ],
        "exception_software_stop": [f"b {terminal:#x}"],
    }


STACK_GATE_LABELS = (
    "exception_entry", "exception_outer", "exception_check_sp", "exception_select_stack",
    "exception_irq_stack", "exception_use_stack", "exception_restore_user", "exception_restore_status",
    "exception_stop_observed", "exception_busy", "exception_emergency", "exception_emergency_with_reason",
    "exception_unregistered", "exception_stop", "exception_register_stack", "cyxia_terminal_stop",
    "exception_software_stop",
)
PAN_VECTOR_LABELS = ("exception_check_kernel_translation", "exception_translation_ready",
                     "exception_publish_stack", "exception_restore_sp")


def check_stack_gate(instructions, symbols, read_literal):
    elf64.require(instructions.get(symbols["exception_dispatch"]) is not None,
                  "dispatcher is not executable code")
    elf64.require(instructions.get(symbols["exception_quiescent_stop"]) is not None,
                  "terminal stop coordinator is not executable code")
    next_entry = symbols["exception_entry"]
    for name, expected in stack_gate_sequences(symbols).items():
        elf64.require(symbols[name] == next_entry, f"unexpected instructions before {name}")
        next_entry = check_sequence(instructions, next_entry, expected, name, read_literal)


def loaded_literal(raw, loads, address):
    for segment in loads:
        delta = address - segment["va"]
        if 0 <= delta and delta + 8 <= segment["size"]:
            at = segment["offset"] + delta
            return int.from_bytes(raw[at:at + 8], "little")
    raise ValueError("VBAR literal is outside file-backed loads")


def check_writers(instructions, table, symbols, read_literal):
    installed = {entry: symbols[entry] + offset for entry, offset in WRITER_OFFSETS.items()}
    actual = {pc for pc, insn in instructions.items() if insn and insn.startswith("msr vbar_el1,")}
    elf64.require(actual == set(installed.values()), "EL1 vector base writer set differs")
    register = symbols["exception_register_stack"]
    boot_stack = symbols["__stack_top"] - symbols["__stack_base"]
    elf64.require(boot_stack in (16 * 1024, 256 * 1024), "wrong primary execution stack size")
    secondary_pages = 4 if boot_stack == 16 * 1024 else 16
    check_sequence(instructions, symbols["high_entry"], [
        "mov x0,#0x0", ("x1", symbols["__stack_base"]), ("x2", symbols["__stack_top"]),
    ], "primary stack registration", read_literal)
    check_sequence(instructions, symbols["secondary_high"], [
        ("x0", symbols["SMP_STACK_TOPS"]), "ldr x2,[x0,x19,lsl #3]",
        f"cbz x2,{symbols['secondary_high_halt']:#x}", "mov sp,x2", "mov x0,x19",
        f"sub x1,x2,#{secondary_pages:#x},lsl #12",
    ], "secondary stack registration", read_literal)
    writers = []
    for name, pc in installed.items():
        check_sequence(instructions, pc - 8, [f"bl {register:#x}", ("x0", table), VBAR_STORE, "isb"],
                       name, read_literal)
        writers.append({"entry": name, "store_va": f"{pc:#x}",
                        "literal_va": LDR_LITERAL.fullmatch(instructions[pc - 4])[2]})
    context_writers = {pc for pc, op in instructions.items() if op and op.startswith("msr contextidr_el1,")}
    elf64.require(context_writers == {register + 8}, "entry CPU slot has an unexpected writer")
    return writers


def check_software_pan(instructions, symbols, read_literal):
    empty = symbols["empty_l1"]
    tcr_writers = {pc for pc, op in instructions.items() if op and op.startswith("msr tcr_el1,")}
    boot_ranges = (("_start", "boot_halt"), ("cyxia_secondary_start", "secondary_halt"))
    for start, end in boot_ranges:
        sites = {pc for pc in tcr_writers if symbols[start] <= pc < symbols[end]}
        elf64.require(len(sites) == 1, f"{start} must install TCR once")
        check_sequence(instructions, sites.pop() - 4, [("x0", PAN_TCR), "msr tcr_el1,x0"], start, read_literal)
    elf64.require(len(tcr_writers) == 2, "unexpected software PAN TCR writer")
    for entry, writer in WRITER_OFFSETS.items():
        flush = "tlbi vmalle1is" if entry == "high_entry" else "tlbi vmalle1"
        check_sequence(instructions, symbols[entry] + writer + 8,
                       [("x0", empty), "msr ttbr0_el1,x0", "isb", flush, "dsb ish", "isb"],
                       f"{entry} boot root retirement", read_literal)

    missing = symbols["captured_root_unavailable"]
    failed = f"b.ne {missing:#x}"
    check_sequence(instructions, symbols["cyxia_captured_user_root"], [
        "mrs x0,tcr_el1", f"tbz w0,#0x16,{missing:#x}", "mrs x0,ttbr1_el1",
        "tst x0,#0xffff000000000000", failed, "mrs x0,ttbr0_el1", ("x1", empty), "cmp x0,x1", failed,
        "mrs x0,contextidr_el1", "cmp x0,#0x4", f"b.hs {missing:#x}",
        ("x1", symbols["__exception_scratch"]), "add x1,x1,x0,lsl #12", "ldr x0,[x1,#0x168]",
        "cmp x0,#0x1", failed, "ldr x0,[x1,#0x1c8]", "ret", "mov x0,xzr", "ret",
    ], "PAN capture invocation", read_literal)

    enter = symbols.get("cyxia_enter_user")
    user_return = symbols.get("cyxia_user_return")
    elf64.require((enter is None) == (user_return is None), "incomplete linked EL0 transition")
    invalidations = [(pc, op) for pc, op in instructions.items() if op and op.startswith("tlbi aside1is,")]
    for pc, op in invalidations:
        check_sequence(instructions, pc - 4, ["dsb ishst", op, "dsb ish", "isb"],
                       "dynamic ASID invalidation", read_literal)
    evidence = {"tcr": f"{PAN_TCR:#x}", "kernel_asid": 0, "empty_root_pa": f"{empty:#x}",
                "initial_el0_epilogue_linked": enter is not None,
                "asid_invalidation_sites": len(invalidations)}
    if enter is None:
        return evidence
    installs = [pc for pc in range(enter, user_return, 4) if instructions.get(pc) == "msr ttbr0_el1,x9"]
    elf64.require(len(installs) == 1, "missing unique normal EL0 root installation")
    user_epilogue = [
        "msr ttbr0_el1,x9", "isb", "and x9,x2,#0xffff000000000000", "mrs x10,ttbr1_el1",
        "and x10,x10,#0xffffffffffff", "orr x10,x10,x9", "msr ttbr1_el1,x10", "isb",
        "ldp x0,x1,[x30]", *register_pairs("ldp", "x30"),
        "ldr x30,[x30,#0xf0]", "eret",
    ]
    park = installs[0] + 4 * len(user_epilogue)
    check_sequence(instructions, installs[0] - 16, [
        ("x9", symbols["EXCEPTION_ADMISSION_CLOSED"]), "ldar x9,[x9]",
        f"cbnz x9,{park:#x}", "and x9,x2,#0xffffffffffff", *user_epilogue,
        "wfe", f"b {park:#x}",
    ], "PAN installed in trusted EL0 epilogue", read_literal)
    return evidence


def inspect(raw, disassembly):
    loads = inspect_elf(raw)["loads"]
    instructions = dict(executable_rows(raw, loads, disassembly))

    def address(name):
        return elf64.symbol(raw, name, loads)["va"]

    def read_literal(pc):
        elf64.require(pc in instructions and instructions[pc] is None
                      and pc + 4 in instructions and instructions[pc + 4] is None,
                      f"unmarked linked literal at {pc:#x}")
        return loaded_literal(raw, loads, pc)

    table = address("exception_vectors")
    symbols = {name: address(name) for name in (*STACK_GATE_LABELS, *WRITER_OFFSETS,
               "exception_dispatch", "exception_quiescent_stop", "__exception_scratch", "__exception_stacks",
               "__stack_base", "__stack_top", "SMP_STACK_TOPS", "secondary_high_halt",
               "EXCEPTION_ADMISSION_CLOSED")}
    try:
        symbols["empty_l1"] = address("empty_l1")
    except ValueError as error:
        if str(error) != "missing symbol empty_l1":
            raise
    sw_pan = "empty_l1" in symbols
    if sw_pan:
        required = (*PAN_VECTOR_LABELS, "_start", "boot_halt", "cyxia_secondary_start", "secondary_halt",
                    "cyxia_captured_user_root", "captured_root_unavailable")
        symbols.update({name: address(name) for name in required})
        for name in ("cyxia_enter_user", "cyxia_user_return"):
            try:
                symbols[name] = address(name)
            except ValueError as error:
                if str(error) != f"missing symbol {name}":
                    raise
        empty = symbols["empty_l1"]
        elf64.require(empty % PAGE == 0 and any(
            segment["flags"] == 6 and segment["va"] == segment["pa"] and segment["size"] == 0
            and segment["pa"] <= empty and empty + PAGE <= segment["pa"] + segment["mem"] for segment in loads
        ), "empty L1 is not a reserved physical page in zero-filled boot tables")
    for base, size in (("__exception_scratch", 4 * PAGE), ("__exception_stacks", 4 * STACK_BANK_BYTES)):
        va = symbols[base]
        end = address(f"{base}_end")
        elf64.require(va % PAGE == 0 and end - va == size, f"bad per-CPU reservation {base}")
        elf64.require(any(load["flags"] == 6 and load["va"] <= va < end <= load["va"] + load["mem"]
                          for load in loads), f"per-CPU reservation {base} outside RW data load")
    scratch_start = symbols["__exception_scratch"]
    stack_start = symbols["__exception_stacks"]
    elf64.require(scratch_start + 4 * PAGE <= stack_start, "per-CPU scratch and stacks overlap")
    frames = [address(f"vector_{kind}") for kind in range(VECTOR_COUNT)]
    routes = check_vectors(instructions, table, frames, symbols, read_literal)
    check_stack_gate(instructions, symbols, read_literal)
    writers = check_writers(instructions, table, symbols, read_literal)
    pan = check_software_pan(instructions, symbols, read_literal) if sw_pan else None
    return {
        "status": "PASS",
        "frame_bytes": FRAME_BYTES,
        "rust_frame_bytes": RUST_FRAME_BYTES,
        "defined_frame_bytes": RUST_FRAME_BYTES if sw_pan else 280,
        "vector_table_va": f"{table:#x}",
        "dispatch_va": f"{symbols['exception_dispatch']:#x}",
        "software_terminal_va": f"{symbols['cyxia_terminal_stop']:#x}",
        "software_pan": pan,
        "vector_slots": routes,
        "vbar_installations": writers,
        "entry_scratch_bytes_per_cpu": PAGE,
        "irq_stack_bytes_per_cpu": 16384,
        "emergency_stack_bytes_per_cpu": 8192,
        "primary_exec_stack_bytes": symbols["__stack_top"] - symbols["__stack_base"],
        "entry_stack_minimum_headroom_bytes": FRAME_BYTES,
        "lower_aarch32_vector_kinds": list(range(12, 16)),
        "matched_executable_words": len(instructions),
    }


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
        "scope": "linked-el1-vector-stack-and-integer-frame-subcheck",
        "related_ids": ["S09", "P11", "M12"],
        "proof_class": "STATIC_EL1",
        "formal_verdict": False,
        "status": "FAIL",
        "elf_sha256": args.elf_sha256,
        "objdump_sha256": args.objdump_sha256,
        "checker_file_sha256": {
            name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in CHECKER_FILES
        },
        "argv": command,
    }
    try:
        disassembly = subprocess.check_output(command, timeout=60)
        (args.output / "objdump.txt").write_bytes(disassembly)
        summary["disassembly_sha256"] = sha256(disassembly).hexdigest()
        elf64.require(sha256(args.elf.read_bytes()).hexdigest() == args.elf_sha256,
                      "ELF changed during audit")
        elf64.require(sha256(objdump.read_bytes()).hexdigest() == args.objdump_sha256,
                      "llvm-objdump changed during audit")
        summary.update(inspect(raw, disassembly.decode("utf-8")))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    result = json.dumps(summary, indent=2) + "\n"
    (args.output / "summary.json").write_text(result, encoding="utf-8")
    print(result, end="")
    return int(summary["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
