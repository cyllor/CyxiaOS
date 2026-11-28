#!/usr/bin/env python3
"""Prepare a D2 snapshot authority and its detached offline signing message."""

import argparse
from hashlib import sha256
from pathlib import Path
import struct

from package_v020_file_volume import CONFIG_MAX, prepare as file_volume
from package_v020_role_services import ROLES, ROSTER_LABEL


LABEL = b"CYX/STARTUP-SNAPSHOT-AUTHORITY/v1"
RECOVERY_SLOT = 15
RECOVERY_ROLE = 1
PROTECTION_ROLE = 11
RESTORE = 1 << 3
PROTECTION = 1 << 6
ROSTER_BYTES = len(ROSTER_LABEL) + 32 + 66 * len(ROLES)


def prepare(config: bytes, volume: bytes, roster: bytes) -> tuple[bytes, bytes]:
    if len(volume) != 168:
        raise ValueError("expected a complete file-volume.bin")
    owner = struct.unpack_from("<QQ", volume, 24)
    if volume != file_volume(config, owner)[0]:
        raise ValueError("file volume differs from the canonical signed layout")
    digest = sha256(config).digest()
    start = len(ROSTER_LABEL) + len(digest)
    if (len(roster) != ROSTER_BYTES or not roster.startswith(ROSTER_LABEL + digest)
            or tuple(struct.unpack_from("<H", roster, start + 66 * i)[0]
                     for i in range(len(ROLES))) != ROLES):
        raise ValueError("expected lifecycle signing bytes for this exact configuration")
    principal_id, principal_generation = struct.unpack_from("<QQ", config, 256 + 16 * RECOVERY_SLOT)
    if min(principal_id, principal_generation) == 0:
        raise ValueError("the recovery principal must exist in the signed configuration")
    wire = struct.pack("<8s16sQQHHHHII", b"CYXSNA01", volume[8:24], principal_id,
                       principal_generation, RECOVERY_SLOT, RECOVERY_ROLE, PROTECTION_ROLE, 0,
                       RESTORE, PROTECTION)
    return wire, LABEL + sha256(roster).digest() + sha256(volume).digest() + wire


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-config", type=Path, required=True)
    parser.add_argument("--file-volume", type=Path, required=True)
    parser.add_argument("--lifecycle-message", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.offline_config.open("rb") as source:
            config = source.read(CONFIG_MAX + 1)
        with args.file_volume.open("rb") as source:
            volume = source.read(169)
        with args.lifecycle_message.open("rb") as source:
            roster = source.read(ROSTER_BYTES + 1)
        wire, message = prepare(config, volume, roster)
        args.output.mkdir()
        (args.output / "snapshot-authority.bin").write_bytes(wire)
        (args.output / "snapshot-authority-to-sign.bin").write_bytes(message)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
