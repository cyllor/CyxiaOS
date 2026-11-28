#!/usr/bin/env python3
"""Prepare an independently signed ABI3 FILE_SERVICE deployment grant."""

import argparse
from hashlib import sha256
from pathlib import Path
import struct


def prepare(config: bytes, package: bytes, budget_ns: int) -> tuple[bytes, bytes]:
    if not 576 <= len(config) <= 65856:
        raise ValueError("expected a bounded signed offline configuration")
    if not 64 <= len(package) <= 128 * 1024 or package[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a bounded little-endian ELF64 package")
    if not 2_000_000 <= budget_ns <= 88_000_000:
        raise ValueError("role12 and its CPU3 peer each need a full business dispatch credit")
    grant = struct.pack("<8s4HQ", b"CYXFSV01", 12, 3, 3, 0, budget_ns)
    message = b"CYX/STARTUP-FILE-OWNER/v1" + sha256(config).digest() + sha256(package).digest() + grant
    return grant, message


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--budget-ns", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        grant, message = prepare(args.config.read_bytes(), args.package.read_bytes(), args.budget_ns)
        args.output.mkdir()
        with (args.output / "file-owner.bin").open("xb") as out:
            out.write(grant)
        with (args.output / "file-owner-to-sign.bin").open("xb") as out:
            out.write(message)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
