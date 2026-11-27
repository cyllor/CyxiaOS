#!/usr/bin/env python3
"""Prepare the public SEC-S role-services grant and its detached signing message."""

import argparse
import hashlib
from pathlib import Path
import struct


ROLES = (6, 7, 2, 8, 9, 3, 10, 11)
ROSTER_LABEL = b"CYX/STARTUP-LIFECYCLE-PACKAGES/v1"
GRANT_LABEL = b"CYX/STARTUP-ROLE-SERVICES/v1"


def prepare(roster, control, query, ipc):
    start = len(ROSTER_LABEL) + 32
    if (len(roster) != start + len(ROLES) * 66 or not roster.startswith(ROSTER_LABEL)
            or tuple(struct.unpack_from("<H", roster, start + i * 66)[0]
                     for i in range(len(ROLES))) != ROLES):
        raise ValueError("expected the exact lifecycle-packages-to-sign.bin")

    caps = [0] * len(ROLES)
    for item in control:
        role, mask = item.split(":")
        index = ROLES.index(int(role))
        value = int(mask, 0)
        if caps[index] or not 0 < value < 2**64:
            raise ValueError("expected one nonzero u64 mask per control role")
        caps[index] = value

    task_query = 0
    for role in query:
        task_query |= 1 << ROLES.index(role)

    peers = bytearray(len(ROLES))
    for item in ipc:
        source, destination = item.split(":")
        sender = ROLES.index(int(source))
        receiver = ROLES.index(int(destination))
        if sender == receiver or peers[sender] & (1 << receiver):
            raise ValueError("expected unique IPC edges between different roles")
        peers[sender] |= 1 << receiver
    if sum(mask.bit_count() for mask in peers) > len(ROLES):
        raise ValueError("expected at most eight IPC edges")

    wire = struct.pack("<8s8QB8s7x", b"CYXSVC01", *caps, task_query, peers)
    return wire, GRANT_LABEL + hashlib.sha256(roster).digest() + wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifecycle-message", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--control", metavar="ROLE:MASK", action="append", default=[])
    parser.add_argument("--query-self", type=int, choices=ROLES, action="append", default=[])
    parser.add_argument("--ipc", metavar="SENDER:RECEIVER", action="append", default=[])
    args = parser.parse_args()
    try:
        with args.lifecycle_message.open("rb") as source:
            roster = source.read(len(ROSTER_LABEL) + 32 + len(ROLES) * 66 + 1)
        wire, message = prepare(roster, args.control, args.query_self, args.ipc)
        args.output.mkdir()
        (args.output / "role-services.bin").write_bytes(wire)
        (args.output / "role-services-to-sign.bin").write_bytes(message)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
