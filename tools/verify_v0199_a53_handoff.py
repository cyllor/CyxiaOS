#!/usr/bin/env python3
"""Check the offline archive for a previously authenticated A53 platform lock."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys

if __package__:
    from .check_prototype_evidence import _pairs, exact_keys, require
    from .elf64 import decode as decode_elf
else:
    from check_prototype_evidence import _pairs, exact_keys, require
    from elf64 import decode as decode_elf


SCHEMA = "cyxia-a53-platform-lock/v1"
MAX_LOCK_BYTES = 256 * 1024
MAX_DTB_BYTES = 2 * 1024**2
MAX_CAPTURE_BYTES = 32 * 1024**2
MAX_ELF_BYTES = 128 * 1024**2
AFFINITY_MASK = 0xff00ffffff
OPEN_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
OPEN_MEMBER = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY


def _hex(value, digits):
    return (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(digits) + r"}", value)
            is not None and value != "0" * digits)


def _uint(value, bits):
    return type(value) is int and 0 <= value < 1 << bits


def _label(value):
    require(isinstance(value, str) and 0 < len(value) <= 256
            and value.strip() == value and value.isprintable(), "invalid platform identifier")
    return value


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _artifact(root_fd, record, limit=None):
    """Read one pinned regular file beneath the already opened archive root."""
    exact_keys(record, {"path", "bytes", "sha256"})
    name, size, digest = record["path"], record["bytes"], record["sha256"]
    path = PurePosixPath(_label(name))
    require(path.parts and not path.is_absolute() and ".." not in path.parts
            and path.as_posix() == name and "\\" not in name, "unsafe or noncanonical evidence path")
    require(_uint(size, 64) and size > 0 and _hex(digest, 64)
            and (limit is None or size <= limit), "invalid artifact size or digest")
    with ExitStack() as opened:
        parent = root_fd
        try:
            for part in path.parts[:-1]:
                parent = os.open(part, OPEN_DIRECTORY, dir_fd=parent)
                opened.callback(os.close, parent)
            entry = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(entry.st_mode), "symlink or nonregular evidence file")
            fd = os.open(path.name, OPEN_MEMBER, dir_fd=parent)
        except OSError as exc:
            raise ValueError(f"cannot open evidence path {name}: {exc.strerror}") from exc
        with os.fdopen(fd, "rb") as stream:
            require(_metadata(os.fstat(fd)) == _metadata(entry) and entry.st_size == size,
                    f"artifact size or identity mismatch: {name}")
            body = bytearray() if limit is not None else None
            hasher = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))
                require(chunk, f"short artifact: {name}")
                hasher.update(chunk)
                if body is not None:
                    body.extend(chunk)
                remaining -= len(chunk)
            require(not stream.read(1) and _metadata(os.fstat(fd)) == _metadata(entry)
                    and hasher.hexdigest() == digest, f"artifact digest or identity mismatch: {name}")
    return body


def _terminated(data, start):
    end = data.find(b"\0", start)
    require(start < len(data) and 0 <= end - start <= 255, "invalid DTB string")
    return data[start:end].decode("ascii"), end + 1


def _dtb_nodes(data):
    """Read FDT v17 nodes without using the QEMU-specific platform parser."""
    require(len(data) >= 40, "truncated DTB")
    magic, total, tree, strings, reserve, version, compat, boot_cpu, strings_size, tree_size = (
        struct.unpack_from(">10I", data)
    )
    require(magic == 0xd00dfeed and total == len(data) and version == 17 and compat == 16
            and 40 <= tree < total and 40 <= strings < total and 40 <= reserve < total
            and tree % 4 == tree_size % 4 == reserve % 8 == 0 and tree_size >= 4
            and tree + tree_size <= total and strings + strings_size <= total
            and (tree + tree_size <= strings or strings + strings_size <= tree)
            and not (tree <= reserve < tree + tree_size or strings <= reserve < strings + strings_size),
            "invalid DTB header or ranges")
    reserve_end = min(offset for offset in (tree, strings, total) if offset > reserve)
    while True:
        require(reserve + 16 <= reserve_end, "unterminated DTB reservation table")
        address, length = struct.unpack_from(">QQ", data, reserve)
        reserve += 16
        if address == length == 0:
            break
        require(length > 0 and address + length <= 1 << 64, "invalid DTB memory reservation")

    block = data[tree:tree + tree_size]
    names = data[strings:strings + strings_size]
    nodes, stack = {}, []
    offset = 0
    while offset < len(block):
        token, = struct.unpack_from(">I", block, offset)
        offset += 4
        if token == 1:
            name, offset = _terminated(block, offset)
            offset = (offset + 3) & ~3
            require(len(stack) < 32 and "/" not in name and name not in (".", "..")
                    and (bool(name) if stack else not nodes and name == ""),
                    "invalid DTB node or nesting")
            path = (stack[-1].rstrip("/") + "/" + name) if stack else "/"
            require(path not in nodes and len(nodes) < 4096, "duplicate or excessive DTB nodes")
            nodes[path] = {}
            stack.append(path)
        elif token == 2:
            require(stack, "invalid DTB end node")
            stack.pop()
        elif token == 3:
            require(stack and offset + 8 <= len(block), "invalid DTB property header")
            width, name_at = struct.unpack_from(">II", block, offset)
            offset += 8
            key, _ = _terminated(names, name_at)
            props = nodes[stack[-1]]
            require(key and key not in props and offset + width <= len(block),
                    "duplicate or invalid DTB property")
            props[key] = bytes(block[offset:offset + width])
            offset = (offset + width + 3) & ~3
        elif token == 9:
            require(not stack and "/" in nodes and not any(block[offset:]), "invalid DTB end")
            return nodes, boot_cpu
        else:
            require(token == 4, "unknown DTB token")
    raise ValueError("missing DTB end")


def _compatibles(node):
    raw = node.get("compatible", b"")
    require(raw.endswith(b"\0") and all(raw[:-1].split(b"\0")), "invalid DTB compatible list")
    return raw[:-1].decode("ascii").split("\0")


def _enabled(node):
    return node.get("status", b"okay\0") in (b"okay\0", b"ok\0")


def _cells(node, key, fallback, permitted):
    raw = node.get(key, fallback.to_bytes(4, "big"))
    value = int.from_bytes(raw, "big")
    require(len(raw) == 4 and value in permitted, f"invalid DTB {key}")
    return value


def _ram(nodes, declared):
    root = nodes["/"]
    address = _cells(root, "#address-cells", 2, (1, 2)) * 4
    sizes = _cells(root, "#size-cells", 1, (1, 2)) * 4
    width = address + sizes
    observed = []
    for path, node in nodes.items():
        if (path == "/" or path.count("/") != 1 or node.get("device_type") != b"memory\0"
                or not _enabled(node)):
            continue
        reg = node.get("reg", b"")
        require(reg and len(reg) % width == 0, "invalid DTB RAM extent")
        for base in range(0, len(reg), width):
            observed.append([int.from_bytes(reg[base:base + address], "big"),
                             int.from_bytes(reg[base + address:base + width], "big")])
    require(isinstance(declared, list) and declared, "missing locked RAM extents")
    end = 0
    for pair in declared:
        require(isinstance(pair, list) and len(pair) == 2 and all(_uint(v, 64) for v in pair),
                "invalid locked RAM extent")
        base, size = pair
        require(base >= end and 0 < size and base + size <= 1 << 64,
                "overlapping, unsorted or empty RAM extent")
        end = base + size
    require(sorted(observed) == declared, "RAM topology differs from the locked DTB")


def _cpus(nodes, declared, boot_cpu):
    require(isinstance(declared, list) and 0 < len(declared) <= 256, "invalid locked CPU inventory")
    affinities = set()
    for index, cpu in enumerate(declared):
        exact_keys(cpu, {"index", "mpidr_el1", "midr_el1"})
        mpidr, midr = cpu["mpidr_el1"], cpu["midr_el1"]
        require(type(cpu["index"]) is int and cpu["index"] == index and _uint(mpidr, 64)
                and mpidr & (1 << 31), "invalid locked CPU index or MPIDR_EL1")
        require(_uint(midr, 32) and midr >> 24 == 0x41 and (midr >> 4) & 0xfff == 0xd03,
                "MIDR_EL1 is not Arm Cortex-A53")
        affinity = mpidr & AFFINITY_MASK
        require(affinity not in affinities, "duplicate CPU affinity")
        affinities.add(affinity)
    require((declared[0]["mpidr_el1"] & AFFINITY_MASK) == boot_cpu,
            "DTB boot CPU ID differs from the locked CPU index 0 MPIDR affinity")
    require("/cpus" in nodes and _enabled(nodes["/cpus"]), "missing DTB CPU topology")
    width = _cells(nodes["/cpus"], "#address-cells", 1, (1, 2)) * 4
    _cells(nodes["/cpus"], "#size-cells", 0, (0,))
    observed = set()
    for path, node in nodes.items():
        if (not path.startswith("/cpus/") or path.count("/") != 2
                or node.get("device_type") != b"cpu\0" or not _enabled(node)):
            continue
        reg = node.get("reg", b"")
        require(len(reg) == width and "arm,cortex-a53" in _compatibles(node),
                "invalid DTB Cortex-A53 CPU node")
        affinity = int.from_bytes(reg, "big")
        require(affinity not in observed, "duplicate DTB CPU affinity")
        observed.add(affinity)
    require(observed == affinities, "DTB CPU affinities differ from the locked MPIDRs")


def _devices(root_fd, nodes, entries):
    require(isinstance(entries, list) and 0 < len(entries) <= len(nodes), "missing device inventory")
    paths = set()
    artifacts = set()
    for entry in entries:
        exact_keys(entry, {"node", "compatible", "driver"})
        path, compatible, driver = _label(entry["node"]), _label(entry["compatible"]), entry["driver"]
        node = nodes.get(path)
        require(path != "/" and path not in paths and node is not None and _enabled(node)
                and all(_enabled(nodes[str(parent)]) for parent in PurePosixPath(path).parents)
                and compatible in _compatibles(node), "device binding differs from the locked DTB")
        paths.add(path)
        exact_keys(driver, {"id", "version", "artifact"})
        _label(driver["id"])
        _label(driver["version"])
        record = driver["artifact"]
        exact_keys(record, {"path", "bytes", "sha256"})
        # Several statically linked drivers may refer to the same boot ELF.
        binding = (_label(record["path"]), record["bytes"], record["sha256"])
        require(_uint(binding[1], 64) and _hex(binding[2], 64), "invalid native driver artifact")
        if binding not in artifacts:
            _artifact(root_fd, record)
            artifacts.add(binding)


def _capture(data, lock):
    bindings = {
        "CYX_A53_BOARD": lock["board"]["serial"],
        "CYX_A53_SOURCE": lock["source_commit"],
        "CYX_A53_FIRMWARE": lock["firmware"]["sha256"],
        "CYX_A53_IMAGE": lock["boot_image"]["sha256"],
        "CYX_A53_DTB": lock["dtb"]["sha256"],
    }
    expected = {f"{tag} {value}".encode("utf-8") for tag, value in bindings.items()}
    expected.update(f"CYX_A53_CPU {cpu['index']} 0x{cpu['mpidr_el1']:016x} 0x{cpu['midr_el1']:08x}".encode()
                    for cpu in lock["cpus"])
    tags = {tag.encode() for tag in bindings} | {b"CYX_A53_CPU"}
    for raw in io.BytesIO(data):
        tag = raw.partition(b" ")[0]
        if tag not in tags:
            continue
        line = raw.removesuffix(b"\n").removesuffix(b"\r")
        require(raw.endswith(b"\n") and line in expected,
                f"duplicate or mismatched capture record {tag.decode('ascii')}")
        expected.remove(line)
    require(not expected, "missing identity or per-CPU capture record")


def validate_handoff(lock_raw: bytes, locked_digest: str, evidence_root: Path) -> dict:
    """Verify custody and topology against the supplied authenticated lock digest."""
    require(0 < len(lock_raw) <= MAX_LOCK_BYTES and _hex(locked_digest, 64)
            and hashlib.sha256(lock_raw).hexdigest() == locked_digest, "manifest is not the locked input")
    try:
        lock = json.loads(lock_raw.decode("utf-8"), object_pairs_hook=_pairs)
    except RecursionError as exc:
        raise ValueError("platform lock nesting exceeds parser bounds") from exc
    exact_keys(lock, {"schema", "source", "source_commit", "board", "cpus", "ram",
                      "firmware", "boot_image", "dtb", "raw_capture", "devices"})
    require(lock["schema"] == SCHEMA and lock["source"] == "physical-board"
            and _hex(lock["source_commit"], 40), "invalid physical platform lock or source commit")
    board = lock["board"]
    exact_keys(board, {"vendor", "model", "serial", "soc", "dt_compatible"},
               {"pcb_revision", "silicon_revision"})
    require("pcb_revision" in board or "silicon_revision" in board, "missing PCB or silicon revision")
    for value in board.values():
        _label(value)

    root_fd = os.open(evidence_root.resolve(strict=True), OPEN_DIRECTORY)
    try:
        _artifact(root_fd, lock["firmware"])
        boot = decode_elf(_artifact(root_fd, lock["boot_image"], MAX_ELF_BYTES))
        require(boot["kind"] == 2 and boot["machine"] == 183
                and all(segment["type"] not in (2, 3) for segment in boot["segments"]) and any(
            segment["type"] == 1 and segment["flags"] & 1
            and segment["va"] <= boot["entry"] < segment["va"] + segment["size"]
            for segment in boot["segments"]
        ), "boot image is not a native AArch64 kernel ELF")
        nodes, boot_cpu = _dtb_nodes(_artifact(root_fd, lock["dtb"], MAX_DTB_BYTES))
        compatible = _compatibles(nodes["/"])
        require(not any(c == "linux,dummy-virt" or c.startswith("qemu,") for c in compatible),
                "emulated platform DTB")
        require(_enabled(nodes["/"]) and board["dt_compatible"] == compatible[0],
                "board identity differs from the locked DTB")
        _cpus(nodes, lock["cpus"], boot_cpu)
        _ram(nodes, lock["ram"])
        _devices(root_fd, nodes, lock["devices"])
        _capture(_artifact(root_fd, lock["raw_capture"], MAX_CAPTURE_BYTES), lock)
    finally:
        os.close(root_fd)
    return {
        "schema": "cyxia-a53-platform-handoff-check/v1",
        "status": "STRUCTURE_VALID",
        "ARCH_A53": "NOT_RUN",
        "manifest_sha256": locked_digest,
        "source_commit": lock["source_commit"],
        "boot_image_sha256": lock["boot_image"]["sha256"],
        "raw_capture_sha256": lock["raw_capture"]["sha256"],
    }


def load_handoff(manifest: Path, locked_digest: str, evidence_root: Path) -> dict:
    require(manifest.is_file(), "manifest must be a regular file")
    with manifest.open("rb") as stream:
        return validate_handoff(stream.read(MAX_LOCK_BYTES + 1), locked_digest, evidence_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True, help="digest from the authenticated lock")
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = load_handoff(args.manifest, args.manifest_sha256, args.evidence_root)
    except (ValueError, OSError) as exc:
        print(f"Invalid A53 platform handoff: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
