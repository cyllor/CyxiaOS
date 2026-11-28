#!/usr/bin/env python3
"""Prepare the signed manifest for a canonical unified-v1 startup volume."""

import argparse
from hashlib import sha256
from pathlib import Path
import struct


LABEL = b"CYX/STARTUP-FILE-VOLUME/v1"
CONFIG_HEADER = 256
CONFIG_MAX = CONFIG_HEADER + 65_536 + 64


def prepare(config: bytes, owner: tuple[int, int]) -> tuple[bytes, bytes]:
    if not 576 <= len(config) <= CONFIG_MAX:
        raise ValueError("expected a complete signed OfflineConfigEnvelope v1")
    header = struct.unpack_from("<IHHII16s", config)
    if header[:5] != (0x43594F46, 1, 256, len(config), len(config) - 320) or not any(header[5]):
        raise ValueError("invalid offline configuration header")
    principals = tuple(struct.iter_unpack("<QQ", config[256:512]))
    if min(owner) <= 0 or owner not in principals:
        raise ValueError("root owner must be present in the signed principal map")
    objects = (
        (224, 1, 4131), (225, 1, 4118), (226, 120, 4132), (227, 1, 4268),
        (228, 16, 4252), (229, 7, 4119), (230, 4, 4126), (231, 1, 4130),
    )
    wire = struct.pack("<8s16sQQ", b"CYXFVOL1", header[5], *owner)
    wire += b"".join(struct.pack("<HHIQ", inode, blocks, first, 1)
                     for inode, blocks, first in objects)
    return wire, LABEL + sha256(config).digest() + wire


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-config", type=Path, required=True)
    parser.add_argument("--root-owner", type=int, required=True)
    parser.add_argument("--root-owner-generation", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.offline_config.open("rb") as source:
            config = source.read(CONFIG_MAX + 1)
        wire, message = prepare(config, (args.root_owner, args.root_owner_generation))
        args.output.mkdir()
        (args.output / "file-volume.bin").write_bytes(wire)
        (args.output / "file-volume-to-sign.bin").write_bytes(message)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
