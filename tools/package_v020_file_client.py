#!/usr/bin/env python3
"""Prepare the detached startup grant for one mounted CPU3 file client."""

import argparse
from hashlib import sha256
from pathlib import Path
import struct


def prepare(config, business, owner, slot, inode, inode_generation, acl_generation, *, writable=False):
    if not 576 <= len(config) <= 65856 or len(config[16:32]) != 16:
        raise ValueError("expected a bounded signed offline configuration")
    if any(not 64 <= len(elf) <= 128 * 1024 or elf[:6] != b"\x7fELF\x02\x01"
           for elf in (business, owner)):
        raise ValueError("expected two bounded little-endian ELF64 packages")
    if not 0 <= slot < 16 or not 1 <= inode < 224:
        raise ValueError("invalid principal slot or ordinary file inode")
    if not all(0 < n < 1 << 64 for n in (inode_generation, acl_generation)):
        raise ValueError("expected nonzero inode and ACL generations")
    principal = struct.unpack_from("<QQ", config, 256 + slot * 16)
    if not all(principal):
        raise ValueError("unregistered principal")
    magic = b"CYXFCL02" if writable else b"CYXFCL01"
    grant = struct.pack("<8s16sIBBH4Q", magic, config[16:32], inode,
                        slot, 3, 3, inode_generation, acl_generation, *principal)
    message = (b"CYX/STARTUP-FILE-CLIENT/v1" + sha256(config).digest()
               + sha256(business).digest() + sha256(owner).digest() + grant)
    return grant, message


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("config", "business", "owner", "output"):
        parser.add_argument(f"--{label}", type=Path, required=True)
    for label in ("principal-slot", "inode", "inode-generation", "acl-generation"):
        parser.add_argument(f"--{label}", type=int, required=True)
    parser.add_argument("--writable", action="store_true")
    args = parser.parse_args()
    try:
        grant, message = prepare(
            args.config.read_bytes(), args.business.read_bytes(), args.owner.read_bytes(),
            args.principal_slot, args.inode, args.inode_generation, args.acl_generation,
            writable=args.writable,
        )
        args.output.mkdir()
        for name, body in (("file-client.bin", grant), ("file-client-to-sign.bin", message)):
            with (args.output / name).open("xb") as destination:
                destination.write(body)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
