#!/usr/bin/env python3
"""Prepare a RecoveryProof carrier locator and its detached signing message."""

import argparse
from hashlib import sha256
import os
from pathlib import Path
import struct

if __package__:
    from .v020_g1_genesis import ACL, ROOT
    from .v020_snapshot_envelopes import BLOCK_BYTES, BLOCK_COUNT, INODE_BYTES, INODE_START, crc32c_zeroed
else:
    from v020_g1_genesis import ACL, ROOT
    from v020_snapshot_envelopes import BLOCK_BYTES, BLOCK_COUNT, INODE_BYTES, INODE_START, crc32c_zeroed


LOCATOR_LABEL = b"CYX/RECOVERY-STORE/v1"
MAX_CONFIG = 256 + 65_536 + 64
ACL_BYTES = 64
BUSINESS_INODES = 224


def _read(disk, offset, length):
    disk.seek(offset)
    data = disk.read(length)
    if len(data) != length:
        raise ValueError("short read in recovery carrier metadata")
    return data


def _crc_matches(data, offset):
    return struct.unpack_from("<I", data, offset)[0] == crc32c_zeroed(data, offset)


def prepare(config, disk, inode_id):
    if not 576 <= len(config) <= MAX_CONFIG:
        raise ValueError("expected the complete signed offline-config.bin")
    if struct.unpack_from("<IHHII", config) != (0x43594F46, 1, 256, len(config), len(config) - 320):
        raise ValueError("invalid offline configuration header")
    if not 0 < inode_id < BUSINESS_INODES:
        raise ValueError("the carrier must be an ordinary non-root file")
    if os.fstat(disk.fileno()).st_size != BLOCK_COUNT * BLOCK_BYTES:
        raise ValueError("expected a complete canonical 512 MiB V0.20 raw volume")
    uuid = config[16:32]
    for slot in range(2):
        checkpoint = _read(disk, slot * BLOCK_BYTES, BLOCK_BYTES)
        if (not any(uuid) or checkpoint[16:32] != uuid
                or struct.unpack_from("<IHHII", checkpoint) != (0x43594653, 1, 80, BLOCK_BYTES, BLOCK_COUNT)
                or not _crc_matches(checkpoint, 76)):
            raise ValueError("the volume and offline configuration identity differ")

    inode = _read(disk, INODE_START * BLOCK_BYTES + inode_id * INODE_BYTES, INODE_BYTES)
    magic, kind, reserved, generation, size = struct.unpack_from("<IHHQQ", inode)
    count, padding, parent, parent_generation = struct.unpack_from("<HHIQ", inode, 32)
    logical, physical, blocks = struct.unpack_from("<III", inode, 48)
    if ((magic, kind, reserved, size, count, padding, logical, blocks)
            != (0x4359494E, 1, 0, 2 * BLOCK_BYTES, 1, 0, 0, 2)
            or generation == 0 or parent >= 256 or parent_generation == 0
            or not ROOT <= physical < BLOCK_COUNT - 1
            or any(inode[60:252]) or not _crc_matches(inode, 252)):
        raise ValueError("the recovery carrier must own one contiguous two-block extent")

    acl = _read(disk, ACL * BLOCK_BYTES + inode_id * ACL_BYTES, ACL_BYTES)
    if (struct.unpack_from("<IIQ", acl) != (inode_id, 1, generation)
            or struct.unpack_from("<II", acl, 32) != (0, 0)
            or struct.unpack_from("<III", acl, 48) != (parent, 0, 0)
            or not _crc_matches(acl, 60)):
        raise ValueError("the recovery carrier must have a live ACL without EL0 rights")

    wire = struct.pack("<8s16s32sIIQ32s", b"CYXRPF01", uuid, sha256(config).digest(),
                       inode_id, physical, generation, sha256(inode + acl).digest())
    return wire, LOCATOR_LABEL + wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-config", type=Path, required=True)
    parser.add_argument("--volume", type=Path, required=True)
    parser.add_argument("--inode", type=int, required=True, help="existing recovery carrier inode")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.offline_config.open("rb") as config, args.volume.open("rb") as disk:
            wire, message = prepare(config.read(MAX_CONFIG + 1), disk, args.inode)
        args.output.mkdir()
        (args.output / "recovery-store.bin").write_bytes(wire)
        (args.output / "recovery-store-to-sign.bin").write_bytes(message)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
