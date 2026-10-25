"""Check the sizeable native preparation frames in an actual AArch64 ELF.

This is a regression check for the known preparation call chain, not a complete
stack proof: indirect callbacks and interrupt handlers are not reconstructed.
The selected direct-call peak must leave 4 KiB of the fixed 64 KiB stack free.
Unknown prologues or a missing preparation chain fail closed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


STACK_BYTES = 65_536
EXCEPTION_RESERVE = 4_096
CHECKER_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
NAMES = {
    "secondary_entry": "secondary_entry",
    "run_turn": "cyxia_kernel::smp::prototype_runtime::native::run_turn::",
    "next_input": "cyxia_kernel::smp::prototype_runtime::native::next_input::",
    "next_paid": "cyxia_kernel::domain_control::next_paid::",
    "next_locked": "cyxia_kernel::domain_control::next_locked::",
    "next_locked_inner": "cyxia_kernel::domain_control::next_locked_inner::",
    "next_normal": "cyxia_kernel::domain_control::next_normal::",
    "read_only": "cyxia_kernel::domain_control::core_replay::next::",
    "candidate_new": "cyxia_prototype::policy::CandidateSet::new::",
    "encode_job": "cyxia_kernel::domain_control::encode_job::",
}


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _run(argv, environment=None):
    result = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise ValueError(f"stack inspection command failed: {Path(argv[0]).name}")
    if len(result.stdout) > 64 * 1024 * 1024:
        raise ValueError("stack inspection output exceeded bound")
    return result.stdout


def objdump_metadata(path, environment=None):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("llvm-objdump is not an executable file")
    digest = _sha(path)
    version = _run([str(path), "--version"], environment).strip()
    if "LLVM" not in version or digest != _sha(path):
        raise ValueError("unrecognized or changed llvm-objdump")
    return dict(path=str(path), sha256=digest, version=version, source="explicit")


def toolchain_objdump(environment=None):
    """Require llvm-tools-preview from the selected rustc, never PATH fallback."""
    environment = os.environ if environment is None else environment
    rustc = environment.get("RUSTC", "rustc")
    version = _run([rustc, "--version", "--verbose"], environment).strip()
    hosts = re.findall(r"^host: ([A-Za-z0-9_-]+)$", version, re.MULTILINE)
    if len(hosts) != 1:
        raise ValueError("cannot identify rustc host for llvm-tools-preview")
    sysroot = Path(_run([rustc, "--print", "sysroot"], environment).strip()).resolve(strict=True)
    path = sysroot / "lib" / "rustlib" / hosts[0] / "bin" / "llvm-objdump"
    if not path.is_file() or not path.resolve().is_relative_to(sysroot):
        raise ValueError("install llvm-tools-preview for the selected rustc toolchain")
    result = objdump_metadata(path, environment)
    result.update(source="rustc-sysroot", sysroot=str(sysroot), host=hosts[0], rustc=version)
    return result


def inspect_elf(elf, objdump, environment=None):
    """Recompute from the named image; no prior JSON result is read or trusted."""
    elf = Path(elf).resolve(strict=True)
    if _sha(objdump["path"]) != objdump["sha256"]:
        raise ValueError("objdump changed since toolchain selection")
    if _sha(__file__) != CHECKER_SHA256:
        raise ValueError("stack checker changed after import")
    digest = _sha(elf)
    disassembly = _run(
        [objdump["path"], "--demangle", "--no-show-raw-insn", "-d", str(elf)],
        environment,
    )
    if _sha(elf) != digest:
        raise ValueError("ELF changed while disassembling")
    if _sha(objdump["path"]) != objdump["sha256"] or _sha(__file__) != CHECKER_SHA256:
        raise ValueError("stack inspection tool changed during execution")
    result = inspect(disassembly)
    result.update(elf=str(elf), elf_sha256=digest, objdump=objdump,
                  checker_sha256=CHECKER_SHA256)
    return result


def instructions(disassembly):
    functions = {}
    current = None
    for line in disassembly.splitlines():
        header = re.fullmatch(r"([0-9a-f]+) <(.+)>:", line)
        if header:
            address, name = header.groups()
            current = (int(address, 16), name)
            functions[current] = []
            continue
        insn = re.match(r"\s*([0-9a-f]+):\s+(\S+)\s*(.*)", line)
        if current and insn:
            address, opcode, operands = insn.groups()
            functions[current].append((int(address, 16), opcode, operands.split(" //")[0]))
    return functions


def frame_size(code):
    """Interpret the straight-line AArch64 prologue and LLVM page probe loop."""
    size = 0
    probe = None
    allocations = set()
    for address, opcode, operands in code:
        reserve = re.fullmatch(r"sp, sp, #(0x[0-9a-f]+|[0-9]+)(?:, lsl #12)?", operands)
        if opcode == "sub" and reserve:
            size += int(reserve[1], 0) << (12 if "lsl" in operands else 0)
            allocations.add(address)
            continue
        target = re.fullmatch(r"x9, sp, #(0x[0-9a-f]+|[0-9]+), lsl #12", operands)
        if opcode == "sub" and target:
            probe = size + (int(target[1], 0) << 12)
            continue
        pushed = re.search(r"\[sp, #-(0x[0-9a-f]+|[0-9]+)\]!", operands)
        if pushed:
            size += int(pushed[1], 0)
            allocations.add(address)
            continue
        if opcode == "b.ne" and probe is not None:
            destination = int(operands.split()[0], 16)
            if destination >= address or probe < size:
                raise ValueError("unrecognized stack probe loop")
            size = probe
            probe = None
            continue
        if opcode in ("bl", "blr", "br", "ret", "b", "cbz", "cbnz", "tbz", "tbnz") or opcode.startswith("b."):
            break
        if (operands.startswith("sp,") and opcode != "cmp") or (
            "[sp" in operands and operands.endswith("!")
        ):
            raise ValueError(f"unrecognized stack prologue: {opcode} {operands}")
        if re.search(r"(?:^|, )sp(?:,|$)", operands) and opcode not in (
            "mov", "add", "stp", "str", "stur", "cmp"
        ):
            raise ValueError(f"unrecognized stack prologue: {opcode} {operands}")
    if probe is not None or size == 0:
        raise ValueError("missing or incomplete stack allocation")
    # Reject shrink-wrapped/dynamic growth hidden after the first call/branch.
    # Known epilogues may only return stack bytes already charged above.
    for address, opcode, operands in code:
        if address in allocations:
            continue
        if operands.startswith("sp,") and opcode != "cmp":
            if opcode == "add" and re.fullmatch(
                r"sp, sp, #(0x[0-9a-f]+|[0-9]+)(?:, lsl #12)?", operands
            ):
                continue
            raise ValueError(f"unrecognized stack write: {opcode} {operands}")
        if "[sp" in operands and (operands.endswith("!") or "], #" in operands):
            if opcode in ("ldp", "ldr") and re.search(
                r"\[sp\], #(0x[0-9a-f]+|[0-9]+)$", operands
            ):
                continue
            raise ValueError(f"unrecognized stack write: {opcode} {operands}")
    return size


def inspect(disassembly):
    functions = instructions(disassembly)
    selected = {}
    for (address, name), code in functions.items():
        for key, prefix in NAMES.items():
            if name == prefix or name.startswith(prefix):
                if key in selected:
                    raise ValueError(f"ambiguous function {key}")
                selected[key] = dict(address=address, frame_bytes=frame_size(code), code=code)
    for required in ("secondary_entry", "run_turn", "next_input", "candidate_new", "encode_job"):
        if required not in selected:
            raise ValueError(f"missing function {required}")
    by_address = {v["address"]: key for key, v in selected.items()}
    for value in selected.values():
        calls = set()
        for _, opcode, operands in value.pop("code"):
            if opcode not in ("bl", "b"):
                continue
            destination = re.match(r"0x([0-9a-f]+)", operands)
            target = by_address.get(int(destination[1], 16)) if destination else None
            if target:
                # Conservatively count a tail branch as retaining its frame.
                calls.add(target)
        value["calls"] = sorted(calls)
    paths = []

    def visit(key, path, total):
        if key in path:
            raise ValueError("recursive preparation call chain")
        path = path + [key]
        total += selected[key]["frame_bytes"]
        paths.append(dict(path=path, frame_bytes=total))
        for child in selected[key]["calls"]:
            visit(child, path, total)

    visit("secondary_entry", [], 0)
    for required in selected:
        if not any(required in path["path"] for path in paths):
            raise ValueError(f"missing direct preparation path to {required}")
    peak = max(paths, key=lambda path: path["frame_bytes"])
    return dict(
        passed=peak["frame_bytes"] + EXCEPTION_RESERVE <= STACK_BYTES,
        stack_bytes=STACK_BYTES,
        exception_reserve_bytes=EXCEPTION_RESERVE,
        peak=peak,
        functions=selected,
        scope="selected direct preparation calls; not a complete stack proof",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--objdump", type=Path,
                        help="explicit tool; defaults to selected rustc llvm-tools-preview")
    args = parser.parse_args()
    tool = objdump_metadata(args.objdump) if args.objdump else toolchain_objdump()
    result = inspect_elf(args.elf, tool)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
