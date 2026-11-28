#!/usr/bin/env python3
"""Cold-start SEC-F power-cut images and a signed nonempty unified v1 volume."""

import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import struct

import v020_g1_snapshot_wire as snapshot_wire
from v020_g1_genesis import ACL, BOOT, INDEX, ROOT, SECURITY, _genesis_blocks
from v020_snapshot_catalog_vectors import Catalog, Entry, encode as encode_catalog
from v020_snapshot_envelopes import (BITMAP_START, BLOCK_BYTES, BLOCK_COUNT, INODE_START,
                                     crc32c_zeroed, encode_envelope)
import v020_snapshot_slot_vectors as slot
from verify_v020_signed_resident import PMU_PATCH, boot, require, rows, sha


FILE_BYTES = b"SEC-F ordinary transactions survive the durable COMMIT boundary.\n"
LIVE = b"live checkpoint bytes\n"
HISTORY = b"preserved historical bytes\n"
CASES = (
    ("before-prepare-flush", False), ("before-commit-flush", False), ("committed", True),
    ("homes-before-checkpoint", True), ("checkpointed-before-retire", True),
)


def seal(raw, offset):
    struct.pack_into("<I", raw, offset, crc32c_zeroed(raw, offset))
    return bytes(raw)


def at(handle, block, size=BLOCK_BYTES):
    handle.seek(block * BLOCK_BYTES)
    raw = handle.read(size)
    require(len(raw) == size, f"short read at block {block}")
    return raw


@contextmanager
def create_raw(path):
    with path.open("xb") as handle:
        handle.truncate(BLOCK_COUNT * BLOCK_BYTES)
        yield handle


def write_pages(handle, pages):
    for block, raw in sorted(pages.items()):
        handle.seek(block * BLOCK_BYTES)
        handle.write(raw)


def clone_raw(source, destination):
    with source.open("rb") as src, create_raw(destination) as dst:
        require(source.stat().st_size == BLOCK_COUNT * BLOCK_BYTES, "incomplete power fixture")
        for first in range(0, BLOCK_COUNT, 256):
            raw = at(src, first, 256 * BLOCK_BYTES)
            if any(raw):
                dst.seek(first * BLOCK_BYTES)
                dst.write(raw)


def nonempty_pages(config):
    """Independent little-endian genesis, current tree and older snapshot."""
    uuid = config[16:32]
    principals = tuple(struct.iter_unpack("<QQ", config[256:512]))
    rule, security, key = struct.unpack_from("<QQQ", config, 40)
    cfg_generation, = struct.unpack_from("<Q", config, 32)
    blocks = _genesis_blocks()
    for number in (0, 1):
        raw = bytearray(blocks[number])
        raw[16:32] = uuid
        blocks[number] = seal(raw, 76)
    raw = bytearray(blocks[BOOT])
    raw[8:24] = uuid
    blocks[BOOT] = seal(raw, 32)
    raw = bytearray(blocks[INDEX])
    raw[8:24] = uuid
    for group, (principal, _) in enumerate(principals):
        struct.pack_into("<Q", raw, 64 + 24 * group + 16, principal)
    blocks[INDEX] = seal(raw, 4092)
    raw = bytearray(blocks[SECURITY])
    raw[8:24] = uuid
    struct.pack_into("<3Q", raw, 32, rule, security, key)
    struct.pack_into("<Q", raw, 80, cfg_generation)
    raw[88:120] = sha256(config).digest()
    blocks[SECURITY] = seal(raw, 72)

    def tree(root_block, file_block, contents):
        return slot.inode(2, 1, 128, root_block) + slot.inode(1, 1, len(contents), file_block)

    def dir_page():
        name = b"readme.txt"
        prefix = struct.pack("<IHHQ", 1, len(name), 0, 1) + name
        first = seal(bytearray(prefix.ljust(128, b"\0")), 124)
        return first + blocks[ROOT][128:]

    root_page = dir_page()
    raw = bytearray(blocks[INODE_START])
    raw[:512] = tree(ROOT, ROOT + 1, LIVE)
    blocks[INODE_START] = bytes(raw)
    for block in range(ROOT + 1, ROOT + 4):
        index = block // 8
        raw = bytearray(blocks[BITMAP_START])
        raw[index] |= 1 << (block % 8)
        blocks[BITMAP_START] = bytes(raw)
    blocks[ROOT] = root_page
    blocks[ROOT + 1] = LIVE.ljust(BLOCK_BYTES, b"\0")
    blocks[ROOT + 2] = root_page
    blocks[ROOT + 3] = HISTORY.ljust(BLOCK_BYTES, b"\0")

    # The independently signed manifest uses the first actual principal for
    # this fixture. All hidden ACLs are bound to that same signed identity.
    principal = principals[0]
    for offset in range(4):
        raw = bytearray(blocks[ACL + offset])
        for index in range(64):
            start = index * 64
            row = bytearray(raw[start:start + 64])
            inode_id = offset * 64 + index
            if inode_id == 1:
                struct.pack_into("<IQQQIIQ", row, 4, 1, 1, *principal, 1 << 8, 0, 1)
            elif struct.unpack_from("<I", row, 4)[0] == 1:
                struct.pack_into("<QQ", row, 16, *principal)
            raw[start:start + 64] = seal(row, 60)
        blocks[ACL + offset] = bytes(raw)

    historical = tree(ROOT + 2, ROOT + 3, HISTORY) + b"".join(
        blocks[block] for block in range(INODE_START, INODE_START + 14))[512:]
    capture = slot.Identity(uuid, 1, 0, 1, 1, 0, 10)
    descriptor = slot.encode(capture, 1, sha256(historical).digest())
    catalog = Catalog(uuid, 2, 2, (Entry(1, capture, sha256(descriptor).digest()),) + (Entry(),) * 7)
    blocks[4131] = encode_catalog(catalog)
    blocks[4132] = descriptor
    for page in range(14):
        blocks[4133 + page] = historical[page * BLOCK_BYTES:(page + 1) * BLOCK_BYTES]
    blocks[4252] = encode_envelope("request", uuid)
    protect = bytearray(encode_envelope("protection", uuid, 2))
    struct.pack_into("<HH", protect, 40, 1, 168)
    struct.pack_into("<4Q", protect, 48, 1, 1, 20, 21_600_000_000_000)
    blocks[4268] = seal(protect, 32)
    return blocks


def restored_pages(config):
    """A disposable checkpoint after RESTORE committed and before OPEN_WRITES."""
    blocks = nonempty_pages(config)
    uuid = config[16:32]
    raw = bytearray(blocks[1])
    struct.pack_into("<3Q", raw, 32, 2, 4, 2)
    blocks[1] = seal(raw, 76)
    raw = bytearray(blocks[BOOT])
    struct.pack_into("<Q", raw, 24, 1)
    blocks[BOOT] = seal(raw, 32)
    raw = bytearray(blocks[SECURITY])
    previous, = struct.unpack_from("<Q", raw, 24)
    struct.pack_into("<Q", raw, 24, previous + 1)
    struct.pack_into("<Q", raw, 64, 1)
    blocks[SECURITY] = seal(raw, 72)

    blocks[INODE_START] = blocks[4133]
    raw = bytearray(blocks[BITMAP_START])
    for block in (ROOT, ROOT + 1):
        raw[block // 8] &= ~(1 << (block % 8))
    blocks[BITMAP_START] = bytes(raw)

    key = struct.pack("<16sIQQ", uuid, 15, 1, 1)
    source = struct.pack("<16sQIIQ", uuid, 1, 0, 0, 1)
    body = source + struct.pack("<II", 2, 0)
    result = source + struct.pack("<QQ16sQQII", 1, 2, uuid, 1, 1, 1, 0)
    request = snapshot_wire.read_request(snapshot_wire.frame(0x23, 1, body, key, 1), 9)
    record = snapshot_wire.record(request, state=2, snapshot=source, new_view=2,
                                  log=1, txid=1, payload=result, lsn=4)
    _, state, _, _, _, lsn, view, digest = snapshot_wire.read_record(record)
    require((state, lsn, view) == (2, 4, 2), "independent RESTORE record differs")
    blocks[4252] = snapshot_wire.header({15: (1, 1)}, uuid=uuid, generation=2)
    blocks[4260] = record.ljust(BLOCK_BYTES, b"\0")
    raw = bytearray(blocks[4268])
    struct.pack_into("<Q", raw, 56, 2)
    raw[137:139] = bytes((2, 1))
    raw[176:208] = digest
    blocks[4268] = seal(raw, 32)
    return blocks


def verify_retained_restore(args, config):
    pages = restored_pages(config)
    name = "retained-restore"
    image = args.output / f"{name}.raw"
    with create_raw(image) as disk:
        write_pages(disk, pages)
    result = boot(str(args.qemu), args.unified_elf, args.output / name, args.timeout,
                  image, 2, expected_policy_envelope=config)
    require(result["status"] == "PASS", f"{name}: {result.get('error')}")
    lines = (args.output / name / "serial.txt").read_text().splitlines()
    require(rows(lines, "V020_SEC_F_SNAPSHOT_RESTORE_RETAINED") == [(1, 2, 4)]
            and rows(lines, "V020_SEC_F_SNAPSHOT_MOUNT") == [(1, 0, 0)],
            "authenticated cold reopen did not retain the exact closed restore")
    with image.open("rb") as disk:
        require(at(disk, 4260) == pages[4260] and at(disk, 4268) == pages[4268]
                and at(disk, INODE_START) == pages[INODE_START]
                and at(disk, ROOT + 3) == pages[ROOT + 3],
                "restore receipt, protection or committed live root changed on boot")

    name = "restore-missing-receipt"
    image = args.output / f"{name}.raw"
    pages[4260] = bytes(BLOCK_BYTES)
    with create_raw(image) as disk:
        write_pages(disk, pages)
    refused = rejected(args, args.unified_elf, name, image)
    return {"boot_epoch": 2, "live_view_epoch": 2, "restore_lsn": 4,
            "writes_open": False, "missing_receipt": refused}


def independent_file_readback(image, completed):
    with image.open("rb") as disk:
        copies = [at(disk, index) for index in range(2)]
        for raw in copies:
            require(struct.unpack_from("<I", raw, 76)[0] == crc32c_zeroed(raw, 76),
                    "checkpoint CRC differs")
        generation, lsn, log_epoch = max(struct.unpack_from("<3Q", raw, 32) for raw in copies)
        require(generation == 2 and log_epoch == 2 and lsn > 4,
                "ordinary replay did not advance a single checkpoint")
        inodes = at(disk, INODE_START)
        parent = inodes[256:512]
        file = inodes[512:768]
        for row in (parent, file):
            require(struct.unpack_from("<I", row, 252)[0] == crc32c_zeroed(row, 252),
                    "replayed inode CRC differs")
        parent_home = struct.unpack_from("<I", parent, 52)[0]
        entry = at(disk, parent_home, 128)
        require(struct.unpack_from("<IHHQ", entry) == (2, 9, 0, 1) and entry[16:25] == b"notes.txt",
                "replayed directory does not reference exact file generation")
        size, write_seq = struct.unpack_from("<QQ", file, 16)
        require((size, write_seq) == ((len(FILE_BYTES), 1) if completed else (0, 0)),
                "file data crossed the wrong COMMIT boundary")
        if completed:
            home = struct.unpack_from("<I", file, 52)[0]
            data = at(disk, home)
            require(data == FILE_BYTES.ljust(BLOCK_BYTES, b"\0"), "FSYNC body differs")
        receipts = at(disk, BOOT + 1, 6 * BLOCK_BYTES)
        key = (1 << 56) | (2 << 53) | 1
        matched = [raw for offset in range(0, len(receipts), 192)
                   if struct.unpack_from("<Q", raw := receipts[offset:offset + 192], 172)[0] == key]
        require(len(matched) == 1, "FSYNC receipt was duplicated or lost")
        raw = matched[0]
        require(struct.unpack_from("<I", raw, 188)[0] == crc32c_zeroed(raw, 188)
                and struct.unpack_from("<H", raw, 96)[0] == (3 if completed else 2),
                "FSYNC receipt state differs from the durable cut")
        return {"generation": generation, "checkpoint_lsn": lsn, "size": size, "write_seq": write_seq,
                "receipt_state": 3 if completed else 2}


def run(args):
    args.output.mkdir()
    config = (args.catalog / "offline-config.bin").read_bytes()
    require(sha(args.qemu) == args.qemu_sha256, "wrong per-vCPU PMU QEMU")
    require(sha(PMU_PATCH) == args.patch_sha256, "wrong per-vCPU PMU patch")
    evidence = {"qemu_sha256": args.qemu_sha256, "patch_sha256": args.patch_sha256, "cases": {}}
    for name, completed in CASES:
        image = args.output / f"{name}.raw"
        clone_raw(args.power_inputs / f"{name}.raw", image)
        result = boot(str(args.qemu), args.baseline_elf, args.output / name, args.timeout, image, 2,
                      expected_policy_envelope=config)
        require(result["status"] == "PASS", f"{name}: {result.get('error')}")
        evidence["cases"][name] = independent_file_readback(image, completed)

    name = "torn-ordinary-commit"
    image = args.output / f"{name}.raw"
    clone_raw(args.power_inputs / "committed.raw", image)
    with image.open("r+b") as disk:
        last_commit = max(block for block in range(2, BITMAP_START)
                          if struct.unpack("<IHH", at(disk, block, 8)) == (0x43594C47, 1, 3))
        disk.seek(last_commit * BLOCK_BYTES + 96)
        byte = disk.read(1)
        disk.seek(-1, 1)
        disk.write(bytes((byte[0] ^ 1,)))
    evidence["cases"][name] = rejected(args, args.baseline_elf, name, image)

    pages = nonempty_pages(config)
    for name in ("nonempty", "nonempty-without-manifest", "historical-bitmap-missing", "root-owner-mismatch"):
        image = args.output / f"{name}.raw"
        raw_pages = dict(pages)
        if name == "historical-bitmap-missing":
            bitmap = bytearray(raw_pages[BITMAP_START])
            block = ROOT + 3
            bitmap[block // 8] &= ~(1 << (block % 8))
            raw_pages[BITMAP_START] = bytes(bitmap)
        if name == "root-owner-mismatch":
            acl = bytearray(raw_pages[ACL])
            root_acl = bytearray(acl[:64])
            root_acl[16:32] = config[272:288]
            acl[:64] = seal(root_acl, 60)
            raw_pages[ACL] = bytes(acl)
        with create_raw(image) as disk:
            write_pages(disk, raw_pages)
        accepted = name == "nonempty"
        elf = args.baseline_elf if name == "nonempty-without-manifest" else args.unified_elf
        if accepted:
            result = boot(str(args.qemu), elf, args.output / name, args.timeout, image, 1,
                          expected_policy_envelope=config)
            require(result["status"] == "PASS", f"{name}: {result.get('error')}")
            lines = (args.output / name / "serial.txt").read_text().splitlines()
            require(rows(lines, "V020_SEC_F_SNAPSHOT_MOUNT") == [(0, 2, 0)],
                    "mount did not separately account for both historical blocks")
            reopened = boot(str(args.qemu), elf, args.output / "nonempty-cold-reopen", args.timeout,
                            image, 2, expected_policy_envelope=config)
            require(reopened["status"] == "PASS", f"nonempty cold reopen: {reopened.get('error')}")
            lines = (args.output / "nonempty-cold-reopen" / "serial.txt").read_text().splitlines()
            require(rows(lines, "V020_SEC_F_SNAPSHOT_MOUNT") == [(1, 2, 0)],
                    "cold reopen changed historical ownership or ordinary write admission")
            with image.open("rb") as disk:
                require(at(disk, ROOT + 1) == raw_pages[ROOT + 1] and at(disk, ROOT + 3) == raw_pages[ROOT + 3],
                        "boot changed live or historical file data")
            evidence["cases"][name] = {"boot_epochs": [1, 2], "historical_only_blocks": 2, "writes_open": False}
        else:
            evidence["cases"][name] = rejected(args, elf, name, image)
    evidence["cases"]["retained-restore"] = verify_retained_restore(args, config)
    evidence["status"] = "PASS"
    (args.output / "verification.json").write_text(json.dumps(evidence, indent=2) + "\n")


def rejected(args, elf, name, image):
    before = sha(image)
    result = boot(str(args.qemu), elf, args.output / name, args.timeout, image, None)
    require(result["status"] == "PASS", f"{name}: {result.get('error')}")
    require(sha(image) == before, "rejected media changed")
    return {"rejected_media_io": result["rejected_media_io"], "unchanged_media_sha256": before}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("qemu", "baseline-elf", "unified-elf", "power-inputs", "catalog", "output"):
        parser.add_argument(f"--{argument}", type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--patch-sha256", required=True)
    parser.add_argument("--timeout", type=float, default=180)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
