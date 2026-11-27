"""Assemble v4 snapshot read fixtures using only the carried V18 wire fields."""

import argparse
from hashlib import sha256
from pathlib import Path
from struct import pack


FIXTURE = Path(__file__).parent / "fixtures" / "v020-snapshot-read-v4.tsv"


def frame(op, payload, version=4, context=0):
    return pack("<IHHHHIQQ", 0x43594651, version, 32, op, 0, len(payload),
                0x0102030405060708, context) + payload


def history(key, path, reserved=bytes(6), length=None):
    raw_path = path.encode("utf-8")
    fields = pack("<H6s", len(raw_path) if length is None else length, reserved)
    return frame(0x26, key + fields + raw_path)


def render():
    uuid = b"CYX-W11-STAGING!"
    snapshot = 0x5060708090A0B0C0
    generation = 0xFEDCBA9876543210
    key = pack("<16sQIIQ", uuid, snapshot, 7, 0, generation)
    prefix = "/团队".encode("utf-8")
    path = "/团队/报告.txt"
    digest = sha256(b"CyxiaOS:history-prefix:v1\0" + pack("<Q", len(prefix)) + prefix)
    cases = (
        ("query", "accept", frame(0x25, key)),
        ("history", "accept", history(key, path)),
        ("history-sibling", "scope", history(key, "/团队预览/报告.txt")),
        ("prefix-digest", "digest", digest.digest()),
        ("older-frame", "schema", frame(0x25, key, version=3)),
        ("caller-context", "format", frame(0x25, key, context=1)),
        ("slot-out-of-range", "format", frame(0x25, pack("<16sQIIQ", uuid, snapshot, 8, 0, generation))),
        ("reserved-key", "format", frame(0x25, pack("<16sQIIQ", uuid, snapshot, 7, 1, generation))),
        ("zero-generation", "format", history(pack("<16sQIIQ", uuid, snapshot, 7, 0, 0), path)),
        ("reserved-path", "format", history(key, path, reserved=b"\0\0\0\0\0\1")),
        ("character-count", "format", history(key, path, length=len(path))),
    )
    header = "# Existing v4 snapshot read staging wire and carried V18 key\n# case\tverdict\thex\n"
    return header + "".join(f"{name}\t{verdict}\t{raw.hex()}\n" for name, verdict, raw in cases)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true", help="print the canonical TSV")
    args = parser.parse_args()
    expected = render()
    if args.emit:
        print(expected, end="")
    elif FIXTURE.read_text(encoding="ascii") != expected:
        raise SystemExit(f"Snapshot read vectors differ from {FIXTURE}")
    else:
        print("11 independent snapshot read vectors match")
