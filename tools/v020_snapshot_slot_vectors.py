"""Independent wire codec and vectors for the D7 populated slot candidate."""

import argparse
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import struct
import sys

if __package__:
    from .v020_snapshot_envelopes import (
        BLOCK_BYTES, BLOCK_COUNT, DATA_START, INODE_BYTES, crc32c_zeroed, encode_envelope,
    )
else:
    from v020_snapshot_envelopes import (
        BLOCK_BYTES, BLOCK_COUNT, DATA_START, INODE_BYTES, crc32c_zeroed, encode_envelope,
    )


FIXTURES = Path(__file__).parent / "fixtures"
MIRROR_VECTOR = FIXTURES / "v020-g1-slot-mirror.bin"
DESCRIPTOR_VECTORS = FIXTURES / "v020-g1-slot.tsv"
MIRROR_PAGES = 14
BUSINESS_INODES = 224
SLOT_START = 4132
SLOT_STRIDE = 15
SLOTS = 8
UUID = b"CYX-G1-SLOT-VEC!"
PREFIX_BYTES = 40
HEADER = struct.Struct("<IHH16sQI4x3Q3I4x32sQII")
ENVELOPE = struct.Struct("<IHH16sQII")
INODE = struct.Struct("<IHH3QHHIQ")
EXTENT = struct.Struct("<3I")


class SlotError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Identity:
    uuid: bytes
    snapshot_id: int
    slot: int
    generation: int
    live_epoch: int
    capture_lsn: int
    online_age_ns: int

    def block(self):
        if (len(self.uuid) != 16 or not any(self.uuid) or not 0 <= self.slot < SLOTS
                or min(self.snapshot_id, self.generation, self.live_epoch) <= 0):
            raise SlotError("invalid", "unusable capture identity")
        return SLOT_START + SLOT_STRIDE * self.slot


def seal(block, offset):
    struct.pack_into("<I", block, offset, crc32c_zeroed(block, offset))


def encode(identity, store_generation, digest):
    first = identity.block() + 1
    if len(digest) != 32 or ((identity.slot == 0) != (store_generation is not None)):
        raise SlotError("invalid", "wrong SlotStore envelope or digest length")
    body = bytearray(BLOCK_BYTES - PREFIX_BYTES)
    HEADER.pack_into(body, 0, 0x43595352, 3, HEADER.size, identity.uuid,
                     identity.snapshot_id, identity.slot, identity.generation, identity.live_epoch,
                     identity.capture_lsn, BUSINESS_INODES, MIRROR_PAGES, first, digest,
                     identity.online_age_ns, 0, 0)
    seal(body, 120)
    block = bytearray(BLOCK_BYTES)
    if identity.slot == 0:
        block[:PREFIX_BYTES] = encode_envelope("slot", identity.uuid, store_generation)[:PREFIX_BYTES]
    block[PREFIX_BYTES:] = body
    if identity.slot == 0:
        seal(block, 32)
    return bytes(block)


def decode(block, raw):
    if len(raw) != BLOCK_BYTES:
        raise SlotError("invalid", "descriptor page must occupy 4096 bytes")
    payload = raw[PREFIX_BYTES:]
    (magic, version, length, uuid, snap, slot, generation, epoch, lsn, inodes, pages,
     first, inode_digest, age, crc, _) = HEADER.unpack_from(payload)
    if ((magic, version, length, inodes, pages) != (0x43595352, 3, HEADER.size, 224, 14)
            or any(payload[36:40]) or any(payload[76:80]) or any(payload[124:])
            or crc != crc32c_zeroed(payload, 120)):
        raise SlotError("invalid", "broken slot header, CRC or reserved bytes")
    identity = Identity(uuid, snap, slot, generation, epoch, lsn, age)
    if (identity.block(), first) != (block, block + 1):
        raise SlotError("conflict", "slot identity belongs to another physical block")
    store_generation = None
    if slot == 0:
        magic, version, length, envelope_uuid, store_generation, crc, reserved = ENVELOPE.unpack_from(raw)
        if ((magic, version, length, reserved) != (0x43594C53, 1, 40, 0)
                or not any(envelope_uuid) or store_generation == 0 or crc != crc32c_zeroed(raw, 32)):
            raise SlotError("invalid", "broken SlotStore envelope")
        if envelope_uuid != uuid:
            raise SlotError("conflict", "slot and SlotStore UUIDs differ")
    elif any(raw[:PREFIX_BYTES]):
        raise SlotError("invalid", "only slot zero may have a store envelope")
    return identity, store_generation, inode_digest


def check_inode(raw, index):
    magic, kind, flags, gen, size, _, extents, reserved, parent, parent_gen = INODE.unpack_from(raw)
    crc, = struct.unpack_from("<I", raw, 252)
    if (magic != 0x4359494E or flags or reserved or any(raw[240:252])
            or crc != crc32c_zeroed(raw, 252)):
        raise SlotError("invalid", "broken inode header or CRC")
    if index == 0 and (kind, gen, parent, parent_gen) != (2, 1, 0, 1):
        raise SlotError("invalid", "mirror has no canonical root")
    if kind == 0:
        if any(raw[16:252]):
            raise SlotError("invalid", "free inode has live fields")
        return
    if (kind not in (1, 2) or gen == 0 or extents > 16 or parent >= BUSINESS_INODES
            or parent_gen == 0 or size > 8 * 1024 * 1024
            or kind == 2 and (size > 32768 or size % 128)):
        raise SlotError("invalid", "invalid business inode fields")
    covered = 0
    for index in range(16):
        logical, physical, count = EXTENT.unpack_from(raw, 48 + index * EXTENT.size)
        if index >= extents:
            if (logical, physical, count) != (0, 0, 0):
                raise SlotError("invalid", "unused extent contains bytes")
            continue
        if (logical != covered or count == 0
                or not DATA_START <= physical < physical + count <= BLOCK_COUNT):
            raise SlotError("invalid", "invalid extent")
        covered += count
    if covered != (size + BLOCK_BYTES - 1) // BLOCK_BYTES:
        raise SlotError("invalid", "extent coverage differs from inode size")


def verify_binding(expected, store_generation, proof, raw):
    if sha256(raw).digest() != proof:
        raise SlotError("conflict", "descriptor digest differs from catalog")
    identity, generation, digest = decode(expected.block(), raw)
    if (identity, generation) != (expected, store_generation):
        raise SlotError("conflict", "descriptor differs from the trusted capture identity")
    return digest


def verify_mirror(digest, mirror):
    if len(mirror) != MIRROR_PAGES * BLOCK_BYTES:
        raise SlotError("invalid", "incorrect business mirror size")
    for index, offset in enumerate(range(0, len(mirror), INODE_BYTES)):
        check_inode(mirror[offset:offset + INODE_BYTES], index)
    if sha256(mirror).digest() != digest:
        raise SlotError("conflict", "entire business mirror digest mismatch")


def verify(expected, store_generation, proof, raw, mirror):
    verify_mirror(verify_binding(expected, store_generation, proof, raw), mirror)


def inode(kind=0, generation=0, size=0, physical=0):
    result = bytearray(INODE_BYTES)
    live = int(kind != 0)
    INODE.pack_into(result, 0, 0x4359494E, kind, 0, generation, size, 0, live, 0, 0, live)
    EXTENT.pack_into(result, 48, 0, physical, live)
    seal(result, 252)
    return bytes(result)


def example_mirror():
    return inode(2, 1, 128, 4269) + inode() * 222 + inode(generation=17)


def example_identity(slot):
    return Identity(UUID, 0x1020304050607080 + slot, slot, 0xFEDCBA9876543210,
                    11, 0x0102030405060708, 36000000000)


def variants(mirror):
    free = mirror[INODE_BYTES:2 * INODE_BYTES]
    return {
        "original": mirror,
        "last-generation": mirror[:-INODE_BYTES] + free,
        "without-root": free + mirror[INODE_BYTES:],
    }


def examples():
    mirror = example_mirror()
    digest = sha256(mirror).digest()
    first, last = example_identity(0), example_identity(7)
    head, tail = encode(first, 9, digest), encode(last, None, digest)

    def changed(raw, offset, reseal=False):
        raw = bytearray(raw)
        raw[offset] ^= 1
        if reseal:
            payload = raw[PREFIX_BYTES:]
            seal(payload, 120)
            raw[PREFIX_BYTES:] = payload
        return bytes(raw)

    wrong_lsn = replace(last, capture_lsn=last.capture_lsn + 1)
    stale = replace(last, generation=last.generation - 1)
    foreign = replace(first, uuid=b"NOT-THE-SLOT-ID!")
    absent_root = sha256(variants(mirror)["without-root"]).digest()
    yield "slot-0", 0, "accept", "original", head, sha256(head).digest()
    yield "slot-7", 7, "accept", "original", tail, sha256(tail).digest()
    for name, slot, status, variant, raw in (
        ("wrong-location", 6, "conflict", "original", tail),
        ("wrong-uuid", 0, "conflict", "original", encode(foreign, 9, digest)),
        ("stale-store-generation", 0, "conflict", "original", encode(first, 8, digest)),
        ("stale-slot-generation", 7, "conflict", "original", encode(stale, None, digest)),
        ("wrong-capture-lsn", 7, "conflict", "original", encode(wrong_lsn, None, digest)),
        ("outer-crc", 0, "invalid", "original", changed(head, 32)),
        ("inner-crc", 7, "invalid", "original", changed(tail, 160)),
        ("nonzero-prefix", 7, "invalid", "original", changed(tail, 2)),
        ("sealed-reserved", 7, "invalid", "original", changed(tail, 168, reseal=True)),
        ("mirror-last-page", 7, "conflict", "last-generation", tail),
        ("mirror-without-root", 7, "invalid", "without-root", encode(last, None, absent_root)),
    ):
        yield name, slot, status, variant, raw, sha256(raw).digest()
    yield "wrong-catalog-proof", 7, "conflict", "original", tail, sha256(head).digest()


def render():
    header = "# D7 slot candidate. Descriptor prefix hex expands with zero padding to 4096 B.\n"
    header += "# case\tslot\tverdict\tmirror_variant\tcatalog_sha256\tdescriptor_prefix\n"
    zero = bytes(1)
    return header + "".join(
        f"{name}\t{slot}\t{status}\t{variant}\t{proof.hex()}\t{raw.rstrip(zero).hex()}\n"
        for name, slot, status, variant, raw, proof in examples()
    )


def check():
    mirror = MIRROR_VECTOR.read_bytes()
    if mirror != example_mirror() or DESCRIPTOR_VECTORS.read_text(encoding="ascii") != render():
        raise ValueError("slot fixtures differ from the independent encoder")
    images = variants(mirror)
    rows = 0
    for line in DESCRIPTOR_VECTORS.read_text(encoding="ascii").splitlines():
        if line.startswith("#"):
            continue
        name, slot, wanted, variant, proof, prefix = line.split("\t")
        capture = example_identity(int(slot))
        raw = bytes.fromhex(prefix).ljust(BLOCK_BYTES, b"\0")
        store_generation = 9 if capture.slot == 0 else None
        try:
            verify(capture, store_generation, bytes.fromhex(proof), raw, images[variant])
        except SlotError as failure:
            if failure.status != wanted:
                raise ValueError(f"{name}: expected {wanted}, found {failure.status}") from failure
        else:
            if wanted != "accept":
                raise ValueError(f"{name}: expected {wanted}, accepted")
        rows += 1
    print(f"{rows} independent D7 slot vectors match")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "descriptors", "mirror"), nargs="?", default="check")
    args = parser.parse_args()
    if args.mode == "mirror":
        sys.stdout.buffer.write(example_mirror())
    elif args.mode == "descriptors":
        print(render(), end="")
    else:
        check()
