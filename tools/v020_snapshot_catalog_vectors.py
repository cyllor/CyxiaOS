"""Independent wire codec and in-memory D7 CatalogStore binding vectors."""

import argparse
from dataclasses import dataclass, replace
from hashlib import sha256
import struct

if __package__:
    from . import v020_snapshot_slot_vectors as slot
    from .v020_snapshot_envelopes import BLOCK_BYTES, crc32c_zeroed, encode_envelope
else:
    import v020_snapshot_slot_vectors as slot
    from v020_snapshot_envelopes import BLOCK_BYTES, crc32c_zeroed, encode_envelope


CATALOG_BLOCK = 4131
CATALOG_VECTORS = slot.FIXTURES / "v020-g1-catalog.tsv"
HEADER = struct.Struct("<IHHHHIQ")
ENTRY = struct.Struct("<BBHI5QIIQ32s")
HEADER_OFFSET = slot.PREFIX_BYTES
ENTRIES_OFFSET = HEADER_OFFSET + HEADER.size
ENTRIES_END = ENTRIES_OFFSET + slot.SLOTS * ENTRY.size
NO_DIGEST = bytes(32)
OTHER_UUID = b"NOT-THE-SLOT-ID!"


class CatalogError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Entry:
    generation: int = 0
    capture: slot.Identity | None = None
    digest: bytes = NO_DIGEST
    root_drop_lsn: int | None = None


@dataclass(frozen=True)
class Catalog:
    uuid: bytes
    generation: int
    next_snapshot_id: int
    entries: tuple[Entry, ...]


@dataclass(frozen=True)
class Context:
    uuid: bytes
    catalog_generation: int
    slot_store_generation: int
    live_epoch: int
    committed_lsn: int
    online_age_ns: int


def slot_class(index):
    return 1 if index < 6 else 2


def validate(catalog):
    if len(catalog.entries) != 8 or not catalog.next_snapshot_id:
        raise CatalogError("invalid", "incorrect directory size or snapshot ID watermark")
    seen_ids = set()
    for index, row in enumerate(catalog.entries):
        capture = row.capture
        if capture is None:
            if row.digest != NO_DIGEST or row.root_drop_lsn is not None:
                raise CatalogError("invalid", "free slot has capture metadata")
            continue
        capture.block()
        if (capture.uuid, capture.slot) != (catalog.uuid, index):
            raise CatalogError("conflict", "capture belongs to a different volume or slot")
        if (capture.generation != row.generation or capture.snapshot_id in seen_ids
                or capture.snapshot_id >= catalog.next_snapshot_id or len(row.digest) != 32
                or row.digest == NO_DIGEST or row.root_drop_lsn is not None
                and row.root_drop_lsn <= capture.capture_lsn):
            raise CatalogError("invalid", "invalid capture generation, ID, digest or drop LSN")
        seen_ids.add(capture.snapshot_id)
    return len(seen_ids)


def encode(catalog):
    occupied = validate(catalog)
    raw = bytearray(encode_envelope("catalog", catalog.uuid, catalog.generation))
    HEADER.pack_into(raw, HEADER_OFFSET, 0x43594344, 1, HEADER.size, ENTRY.size,
                     slot.SLOTS, occupied, catalog.next_snapshot_id)
    for index, row in enumerate(catalog.entries):
        prefix = (slot_class(index), index, 0, row.generation)
        offset = ENTRIES_OFFSET + index * ENTRY.size
        if row.capture is None:
            ENTRY.pack_into(raw, offset, 0, *prefix, 0, 0, 0, 0, 0, 0, 0, NO_DIGEST)
            continue
        capture = row.capture
        block = capture.block()
        state = 1 if row.root_drop_lsn is None else 2
        ENTRY.pack_into(raw, offset, state, *prefix, capture.snapshot_id, capture.live_epoch,
                        capture.capture_lsn, capture.online_age_ns, block, block + 1,
                        row.root_drop_lsn or 0, row.digest)
    slot.seal(raw, 32)
    return bytes(raw)


def envelope_identity(raw, expected_magic):
    if len(raw) != BLOCK_BYTES:
        raise CatalogError("invalid", "store envelope needs exactly one block")
    magic, version, size, uuid, generation, crc, reserved = slot.ENVELOPE.unpack_from(raw)
    if ((magic, version, size, reserved) != (expected_magic, 1, 40, 0)
            or not any(uuid) or not generation or crc != crc32c_zeroed(raw, 32)):
        raise CatalogError("invalid", "broken store envelope")
    return uuid, generation


def decode(block, raw):
    if block != CATALOG_BLOCK:
        raise CatalogError("conflict", "CatalogStore belongs at its fixed block")
    uuid, generation = envelope_identity(raw, 0x43594143)
    tag, version, size, width, slots, occupied, next_id = HEADER.unpack_from(raw, HEADER_OFFSET)
    if ((tag, version, size, width, slots) != (0x43594344, 1, 24, 96, 8)
            or any(raw[ENTRIES_END:])):
        raise CatalogError("invalid", "invalid candidate directory header or tail")
    rows = []
    for index, row in enumerate(ENTRY.iter_unpack(raw[ENTRIES_OFFSET:ENTRIES_END])):
        state, kind, slot_number, reserved, gen, snap, epoch, lsn, age, descriptor, mirror, drop, digest = row
        if (kind, slot_number, reserved) != (slot_class(index), index, 0):
            raise CatalogError("invalid", "noncanonical slot directory row")
        if state == 0:
            if any((snap, epoch, lsn, age, descriptor, mirror, drop)) or digest != NO_DIGEST:
                raise CatalogError("invalid", "free slot has live fields")
            rows.append(Entry(gen))
            continue
        capture = slot.Identity(uuid, snap, index, gen, epoch, lsn, age)
        address = capture.block()
        if (descriptor, mirror) != (address, address + 1):
            raise CatalogError("conflict", "capture addresses belong to a different slot")
        if state not in (1, 2) or state == 1 and drop:
            raise CatalogError("invalid", "invalid slot state or unexpected root drop")
        rows.append(Entry(gen, capture, digest, drop if state == 2 else None))
    catalog = Catalog(uuid, generation, next_id, tuple(rows))
    if validate(catalog) != occupied:
        raise CatalogError("invalid", "occupied directory count disagrees with rows")
    return catalog


def verify(block, raw, context, read):
    catalog = decode(block, raw)
    if not context.slot_store_generation or not context.live_epoch:
        raise CatalogError("invalid", "missing selected volume state")
    if (catalog.uuid, catalog.generation) != (context.uuid, context.catalog_generation):
        raise CatalogError("conflict", "catalog belongs to a different volume or generation")
    occupied = [entry for entry in catalog.entries if entry.capture is not None]
    for entry in occupied:
        capture = entry.capture
        if (capture.live_epoch > context.live_epoch or capture.capture_lsn > context.committed_lsn
                or capture.online_age_ns > context.online_age_ns
                or (entry.root_drop_lsn or 0) > context.committed_lsn):
            raise CatalogError("conflict", "capture or root drop is ahead of the selected view")
    if catalog.entries[0].capture is None:
        identity = envelope_identity(read(slot.SLOT_START), 0x43594C53)
        if identity != (context.uuid, context.slot_store_generation):
            raise CatalogError("conflict", "slot-zero envelope is from a different store")
    for entry in occupied:
        capture = entry.capture
        address = capture.block()
        descriptor = read(address)
        digest = slot.verify_binding(capture, context.slot_store_generation if capture.slot == 0 else None,
                                     entry.digest, descriptor)
        mirror = b"".join(read(address + page + 1) for page in range(slot.MIRROR_PAGES))
        slot.verify_mirror(digest, mirror)
    return catalog


def selected_context(name):
    original = slot.example_identity(0)
    current = Context(original.uuid, 17, 9, original.live_epoch,
                      original.capture_lsn + 1, original.online_age_ns)
    contexts = {
        "current": current,
        "other-volume": replace(current, uuid=OTHER_UUID),
        "prior-catalog": replace(current, catalog_generation=16),
        "prior-slotstore": replace(current, slot_store_generation=8),
        "prior-epoch": replace(current, live_epoch=original.live_epoch - 1),
        "prior-lsn": replace(current, committed_lsn=original.capture_lsn - 1),
        "before-drop": replace(current, committed_lsn=original.capture_lsn),
        "prior-age": replace(current, online_age_ns=original.online_age_ns - 1),
    }
    return contexts[name]


def fixture_descriptor(index, source, mirror_sha256):
    capture = slot.example_identity(index)
    if index == 0 and source != "live-head":
        uuid = OTHER_UUID if source == "foreign-empty-head" else capture.uuid
        return encode_envelope("slot", uuid, 9)
    if index == 7:
        if source == "foreign-tail":
            capture = replace(capture, uuid=OTHER_UUID)
        if source == "stale-tail":
            capture = replace(capture, generation=capture.generation - 1)
        if source == "other-tail-capture":
            capture = replace(capture, capture_lsn=capture.capture_lsn + 1)
    return slot.encode(capture, 9 if index == 0 else None, mirror_sha256)


def examples(mirror):
    mirror_sha256 = sha256(mirror).digest()
    captures = tuple(slot.example_identity(index) for index in range(slot.SLOTS))
    all_entries = tuple(Entry(capture.generation, capture,
                              sha256(fixture_descriptor(capture.slot, "live-head", mirror_sha256)).digest())
                        for capture in captures)
    free = (Entry(),) * slot.SLOTS
    both = Catalog(slot.UUID, 17, captures[-1].snapshot_id + 1,
                   (all_entries[0], *free[1:-1], all_entries[-1]))
    last_only = replace(both, entries=(Entry(6), *both.entries[1:]))
    deleting = replace(both, entries=(*both.entries[:-1], replace(
        all_entries[-1], root_drop_lsn=captures[-1].capture_lsn + 1)))
    both_raw, last_raw, deleting_raw = map(encode, (both, last_only, deleting))
    both_reads = "4132:15,4237:15"
    yield "first-and-last", "accept", "current", "live-head", both_reads, CATALOG_BLOCK, both_raw
    yield "last-with-free-head", "accept", "current", "empty-head", "4132:1,4237:15", CATALOG_BLOCK, last_raw
    yield "deleting-capture", "accept", "current", "live-head", both_reads, CATALOG_BLOCK, deleting_raw
    yield "eight-slots", "accept", "current", "live-head", "4132:120", CATALOG_BLOCK, encode(
        replace(both, entries=all_entries))
    yield "post-collection-watermark", "accept", "current", "empty-head", "4132:1", CATALOG_BLOCK, encode(
        replace(both, entries=(Entry(6), *free[1:-1], Entry(captures[-1].generation))))

    for source in ("foreign-tail", "stale-tail", "other-tail-capture"):
        proof = sha256(fixture_descriptor(7, source, mirror_sha256)).digest()
        rebound = replace(last_only, entries=(*last_only.entries[:-1], replace(all_entries[-1], digest=proof)))
        yield source, "conflict", "current", source, "4132:1,4237:1", CATALOG_BLOCK, encode(rebound)
    yield "descriptor-digest", "conflict", "current", "foreign-tail", "4132:1,4237:1", CATALOG_BLOCK, last_raw
    yield "foreign-empty-head", "conflict", "current", "foreign-empty-head", "4132:1", CATALOG_BLOCK, last_raw
    retired_head = replace(last_only, entries=(Entry(captures[0].generation), *last_only.entries[1:]))
    yield "retired-head-bytes", "accept", "current", "live-head", "4132:1,4237:15", CATALOG_BLOCK, encode(retired_head)
    for context in ("other-volume", "prior-catalog", "prior-slotstore", "prior-epoch", "prior-lsn", "prior-age"):
        yield (context, "conflict", context, "live-head", "4132:1" if context == "prior-slotstore" else "-",
               CATALOG_BLOCK, both_raw)
    yield "uncommitted-drop", "conflict", "before-drop", "live-head", "-", CATALOG_BLOCK, deleting_raw
    yield "wrong-catalog-block", "conflict", "current", "live-head", "-", CATALOG_BLOCK - 1, both_raw
    yield "approved-empty-envelope", "invalid", "current", "empty-head", "-", CATALOG_BLOCK, encode_envelope(
        "catalog", slot.UUID, both.generation)

    def changed(raw, offset, fmt, value, reseal=True):
        page = bytearray(raw)
        struct.pack_into(fmt, page, offset, value)
        if reseal:
            slot.seal(page, 32)
        return bytes(page)

    tail_offset = ENTRIES_OFFSET + 7 * ENTRY.size
    for name, verdict, raw in (
        ("row-width", "invalid", changed(both_raw, 48, "<H", ENTRY.size + 1)),
        ("slot-count", "invalid", changed(both_raw, 50, "<H", slot.SLOTS + 1)),
        ("occupied-count", "invalid", changed(both_raw, 52, "<I", 1)),
        ("outer-crc", "invalid", changed(both_raw, 52, "<I", 1, reseal=False)),
        ("duplicate-slot", "invalid", changed(both_raw, tail_offset + 2, "<H", 0)),
        ("wrong-class", "invalid", changed(both_raw, tail_offset + 1, "<B", 1)),
        ("descriptor-address", "conflict", changed(both_raw, tail_offset + 48, "<I", slot.SLOT_START)),
        ("mirror-address", "conflict", changed(both_raw, tail_offset + 52, "<I", slot.SLOT_START + 1)),
        ("duplicate-id", "invalid", changed(both_raw, tail_offset + 16, "<Q", captures[0].snapshot_id)),
        ("zero-generation", "invalid", changed(both_raw, tail_offset + 8, "<Q", 0)),
        ("bad-watermark", "invalid", changed(both_raw, 56, "<Q", captures[-1].snapshot_id)),
        ("zero-watermark", "invalid", changed(last_raw, 56, "<Q", 0)),
        ("wrong-state", "invalid", changed(both_raw, tail_offset, "<B", 3)),
        ("active-drop", "invalid", changed(both_raw, tail_offset + 56, "<Q", captures[-1].capture_lsn + 1)),
        ("delete-at-capture", "invalid", changed(deleting_raw, tail_offset + 56, "<Q", captures[-1].capture_lsn)),
        ("free-with-snapshot-id", "invalid", changed(last_raw, ENTRIES_OFFSET + 16, "<Q", 1)),
        ("empty-digest", "invalid", changed(both_raw, tail_offset + 64, "32s", NO_DIGEST)),
        ("reserved-row", "invalid", changed(both_raw, tail_offset + 4, "<I", 1)),
        ("reserved-tail", "invalid", changed(both_raw, ENTRIES_END, "<B", 1)),
    ):
        yield name, verdict, "current", "live-head", "-", CATALOG_BLOCK, raw


def render(mirror):
    header = "# D7 catalog candidate. Expand prefix hex with zeros to 4096 B.\n"
    header += "# case\tverdict\tcontext\tslot_source\treads (block:count)\tcatalog_block\tcatalog_prefix\n"
    return header + "".join(
        f"{name}\t{wanted}\t{context}\t{source}\t{reads}\t{block}\t{raw.rstrip(bytes(1)).hex()}\n"
        for name, wanted, context, source, reads, block, raw in examples(mirror)
    )


def check(mirror):
    fixtures = CATALOG_VECTORS.read_text(encoding="ascii")
    if mirror != slot.example_mirror() or fixtures != render(mirror):
        raise ValueError("catalog fixtures differ from the independent encoder")
    mirror_sha256 = sha256(mirror).digest()
    cases = 0
    for line in fixtures.splitlines():
        if line.startswith("#"):
            continue
        name, wanted, context, source, expected_reads, block, prefix = line.split("\t")
        raw = bytes.fromhex(prefix).ljust(BLOCK_BYTES, b"\0")
        reads = []

        def read(address):
            reads.append(address)
            index, page = divmod(address - slot.SLOT_START, slot.SLOT_STRIDE)
            if not 0 <= index < slot.SLOTS:
                raise ValueError(f"{name}: attempted out-of-slot read")
            if page == 0:
                return fixture_descriptor(index, source, mirror_sha256)
            offset = (page - 1) * BLOCK_BYTES
            return mirror[offset:offset + BLOCK_BYTES]

        try:
            result = verify(int(block), raw, selected_context(context), read)
        except (CatalogError, slot.SlotError) as failure:
            actual = failure.status
        else:
            actual = "accept"
            if encode(result) != raw:
                raise ValueError(f"{name}: accepted page does not round-trip")
        if actual != wanted:
            raise ValueError(f"{name}: expected {wanted}, found {actual}")
        addresses = []
        if expected_reads != "-":
            for segment in expected_reads.split(","):
                start, count = map(int, segment.split(":"))
                addresses.extend(range(start, start + count))
        if reads != addresses:
            raise ValueError(f"{name}: unexpected read range: {reads}")
        cases += 1
    print(f"{cases} independent D7 catalog vectors match")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "emit"), nargs="?", default="check")
    args = parser.parse_args()
    image = slot.MIRROR_VECTOR.read_bytes()
    if args.mode == "emit":
        print(render(image), end="")
    else:
        check(image)
