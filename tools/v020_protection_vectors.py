"""Independent Python codec for the G1 D6 ProtectionStore candidate."""

import argparse
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import struct

if __package__:
    from .v020_snapshot_envelopes import BLOCK_BYTES, crc32c_zeroed
else:
    from v020_snapshot_envelopes import BLOCK_BYTES, crc32c_zeroed

VECTORS = Path(__file__).parent / "fixtures" / "v020-g1-protection.tsv"
ENVELOPE = struct.Struct("<IHH16sQII")
PAYLOAD = struct.Struct("<HHIQQQ8QBBB5s32s32s")
MAGIC = 0x43594450
USED = ENVELOPE.size + PAYLOAD.size
ZERO_DIGEST = bytes(32)


@dataclass(frozen=True)
class Protection:
    uuid: bytes
    generation: int
    protection_generation: int
    live_epoch: int
    online_age_ns: int
    deadlines: tuple[int, ...]
    gate: int
    phase: int
    reopen: bytes
    obligation: bytes
    cleanup_frozen: int = 0

    def validate(self):
        if (len(self.uuid) != 16 or not any(self.uuid)
                or min(self.generation, self.protection_generation, self.live_epoch) <= 0
                or len(self.deadlines) != 8 or self.gate not in (0, 1)
                or self.phase not in (0, 1, 2)
                or self.cleanup_frozen not in (0, 1)
                or len(self.reopen) != 32 or len(self.obligation) != 32
                or (self.phase == 0) != (self.obligation == ZERO_DIGEST)
                or (self.gate == 1) != (self.reopen != ZERO_DIGEST)
                or self.gate == 1 and self.phase != 0):
            raise ValueError("invalid ProtectionStore candidate state")


def seal(raw):
    struct.pack_into("<I", raw, 32, crc32c_zeroed(raw, 32))
    return bytes(raw)


def encode(record):
    record.validate()
    raw = bytearray(BLOCK_BYTES)
    ENVELOPE.pack_into(raw, 0, MAGIC, 1, ENVELOPE.size, record.uuid,
                       record.generation, 0, 0)
    PAYLOAD.pack_into(raw, ENVELOPE.size, 1, PAYLOAD.size, 0,
                      record.protection_generation, record.live_epoch, record.online_age_ns,
                      *record.deadlines, record.gate, record.phase, record.cleanup_frozen, bytes(5),
                      record.reopen, record.obligation)
    return seal(raw)


def decode(raw):
    if len(raw) != BLOCK_BYTES:
        raise ValueError("invalid ProtectionStore candidate block size")
    magic, version, header, uuid, generation, checksum, reserved = ENVELOPE.unpack_from(raw)
    if ((magic, version, header, reserved) != (MAGIC, 1, ENVELOPE.size, 0)
            or checksum != crc32c_zeroed(raw, 32)):
        raise ValueError("invalid ProtectionStore candidate envelope")
    (version, length, reserved, protection, live, age, *rest) = PAYLOAD.unpack_from(
        raw, ENVELOPE.size
    )
    *deadlines, gate, phase, cleanup_frozen, reserved2, reopen, obligation = rest
    if ((version, length, reserved, reserved2) != (1, PAYLOAD.size, 0, bytes(5))
            or any(raw[USED:])):
        raise ValueError("invalid ProtectionStore candidate payload")
    record = Protection(uuid, generation, protection, live, age, tuple(deadlines),
                        gate, phase, reopen, obligation, cleanup_frozen)
    record.validate()
    return record


def examples():
    frozen = Protection(b"CYX-G1-PROT-VEC!", 9, 7, 10, 500,
                        (0, 120, 220, 0, 560, 0, 820, 1040), 0, 0, ZERO_DIGEST, ZERO_DIGEST)
    prepared = replace(frozen, generation=10, phase=1, obligation=sha256(b"restore").digest())
    restored = replace(prepared, generation=11, live_epoch=11, phase=2)
    opened = replace(restored, generation=12, protection_generation=8, gate=1,
                     phase=0, reopen=sha256(b"independent admission").digest(),
                     obligation=ZERO_DIGEST)
    for name, record in (("closed", frozen), ("prepared", prepared),
                         ("restored", restored), ("opened", opened),
                         ("cleanup-frozen", replace(frozen, cleanup_frozen=1)),
                         ("open-and-cleanup-frozen", replace(opened, cleanup_frozen=1))):
        yield name, "accept", encode(record)

    def changed(record, offset, data):
        raw = bytearray(encode(record))
        raw[offset:offset + len(data)] = data
        return seal(raw)

    yield "empty-envelope", "reject", changed(frozen, 40, bytes(PAYLOAD.size))
    yield "open-without-proof", "reject", changed(opened, 144, ZERO_DIGEST)
    overlapping = bytearray(changed(opened, 137, b"\x02"))
    overlapping[176:208] = restored.obligation
    yield "open-while-restored", "reject", seal(overlapping)
    yield "invalid-cleanup-freeze", "reject", changed(frozen, 138, b"\x02")
    yield "reserved", "reject", changed(frozen, 139, b"\x01")
    yield "nonzero-tail", "reject", changed(frozen, USED, b"\x01")
    unsealed = bytearray(encode(frozen))
    unsealed[32] ^= 1
    yield "wrong-crc", "reject", bytes(unsealed)


def render():
    lines = ["# D6 candidate #1. Prefix hex expands to 4096 bytes with zero padding.",
             "# case\tverdict\tsha256_full_block\tprefix_hex"]
    for case, verdict, raw in examples():
        lines.append("\t".join((case, verdict, sha256(raw).hexdigest(), raw.rstrip(b"\0").hex())))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true", help="print deterministic fixture rows")
    args = parser.parse_args()
    if args.emit:
        print(render(), end="")
        return
    if VECTORS.read_text(encoding="ascii") != render():
        raise SystemExit("G1 ProtectionStore vectors differ from independent encoder")
    for case, verdict, raw in examples():
        try:
            result = decode(raw)
        except ValueError:
            if verdict != "reject":
                raise
        else:
            if verdict != "accept" or encode(result) != raw:
                raise SystemExit(f"unexpected G1 ProtectionStore result for {case}")
    print("G1 ProtectionStore candidate vectors verified")


if __name__ == "__main__":
    main()
