"""Independent D1.5 codec and read-only verifier for V0.20 scratch media."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
from typing import BinaryIO


BLOCK_BYTES = 4096
STAGING_UUID = b"CYX-W11-STAGING!"
BLOCK_COUNT = 131072
BITMAP_START = 4098
INODE_START = 4102
INODE_BYTES = 256
DATA_START = 4118
STAGED_FILE_BLOCK = 4270
STAGED_FILE_NAME = b"readme.txt"
STAGED_FILE_DATA = b"CyxiaOS V0.20 signed scratch\n"

_INODE_COUNT = 256
_ACL_BYTES = 64
_DIR_SLOT_BYTES = 128
_FILE_READ = 1 << 8
_FILE_WRITE = 1 << 9
_SYSTEM_RIGHTS = _FILE_READ | _FILE_WRITE | (1 << 13)
_ROOT_OWNER_RIGHTS = 1 << 14
_INODE_PREFIX = struct.Struct("<4sHHQQQHHIQ")
_INODE_RUN = struct.Struct("<III")
_INODE_CRC_OFFSET = 252
_ACL_PREFIX = struct.Struct("<IIQQQIIQIII")
_ZERO_BLOCK = bytes(BLOCK_BYTES)
_ENVELOPE_PREFIX = struct.Struct("<IHH16sQ")
_ENVELOPE_BYTES = 40
_ENVELOPE_CRC_OFFSET = 32


class EnvelopeVerificationError(ValueError):
    """The bytes do not match the scratch envelope or its v1 geometry."""


@dataclass(frozen=True)
class _Extent:
    inode: int
    first_block: int
    blocks: int


@dataclass(frozen=True)
class _Layout(_Extent):
    magic: int


# D1.2 fixed positions and D1.5 magic values, in physical block order.
_LAYOUTS = {
    "catalog": _Layout(224, 4131, 1, 0x43594143),
    "slot": _Layout(226, 4132, 120, 0x43594C53),
    "request": _Layout(228, 4252, 16, 0x43595152),
    "protection": _Layout(227, 4268, 1, 0x43594450),
}
ENVELOPE_HEAD_BLOCKS = tuple(layout.first_block for layout in _LAYOUTS.values())
SLOT_TAIL_BLOCK = _LAYOUTS["slot"].first_block + _LAYOUTS["slot"].blocks - 1

# The unified scratch manifest selects the canonical D1.2 baseline positions.
_ACL = _Extent(230, 4126, 4)
_ROOT = _Extent(0, 4269, 1)
_STAGED_FILE = _Extent(1, STAGED_FILE_BLOCK, 1)
_SYSTEM_EXTENTS = {
    extent.inode: extent
    for extent in (
        _Extent(225, 4118, 1),  # BootEpochStore
        _Extent(229, 4119, 7),  # FileReceiptStore
        _ACL,
        _Extent(231, 4130, 1),  # SecurityStateStore
        *_LAYOUTS.values(),
    )
}


@dataclass(frozen=True)
class ObjectEnvelope:
    kind: str
    fs_uuid: bytes
    generation: int
    crc32c: int


def _layout_for(kind: str) -> _Layout:
    try:
        return _LAYOUTS[kind]
    except KeyError:
        raise EnvelopeVerificationError(f"unknown snapshot object kind {kind!r}") from None


def crc32c_zeroed(raw: bytes | bytearray, offset: int) -> int:
    """Compute CRC32C with the four-byte checksum field treated as zero."""
    checksum = 0xFFFFFFFF
    for byte in raw[:offset] + bytes(4) + raw[offset + 4:]:
        checksum ^= byte
        for _ in range(8):
            checksum = (checksum >> 1) ^ (0x82F63B78 if checksum & 1 else 0)
    return checksum ^ 0xFFFFFFFF


def _check_crc(raw: bytes, offset: int, record: str) -> int:
    (found,) = struct.unpack_from("<I", raw, offset)
    if found != crc32c_zeroed(raw, offset):
        raise EnvelopeVerificationError(f"{record} has an invalid CRC32C")
    return found


def encode_envelope(kind: str, fs_uuid: bytes, generation: int = 1) -> bytes:
    """Encode a 4 KiB D1.5 candidate block with an empty payload."""
    layout = _layout_for(kind)
    if len(fs_uuid) != 16 or fs_uuid == bytes(16):
        raise EnvelopeVerificationError("snapshot envelope requires a nonzero 16-byte UUID")
    if not 1 <= generation < 2**64:
        raise EnvelopeVerificationError("snapshot envelope requires a nonzero u64 generation")

    raw = bytearray(BLOCK_BYTES)
    _ENVELOPE_PREFIX.pack_into(raw, 0, layout.magic, 1, _ENVELOPE_BYTES, fs_uuid, generation)
    struct.pack_into("<I", raw, _ENVELOPE_CRC_OFFSET, crc32c_zeroed(raw, _ENVELOPE_CRC_OFFSET))
    return bytes(raw)


def decode_envelope(kind: str, raw: bytes) -> ObjectEnvelope:
    """Decode an exact D1.5 block for the expected kind."""
    layout = _layout_for(kind)
    record = f"snapshot {kind} envelope"
    if len(raw) != BLOCK_BYTES:
        raise EnvelopeVerificationError(f"{record} must occupy exactly one 4096-byte block")
    magic, version, header_bytes, fs_uuid, generation = _ENVELOPE_PREFIX.unpack_from(raw)
    if (magic, version, header_bytes) != (layout.magic, 1, _ENVELOPE_BYTES):
        raise EnvelopeVerificationError(f"{record} header has the wrong magic, version, or length")
    crc = _check_crc(raw, _ENVELOPE_CRC_OFFSET, record)
    if raw[36:40] != bytes(4):
        raise EnvelopeVerificationError(f"{record} has nonzero reserved bytes")
    if raw[_ENVELOPE_BYTES:] != _ZERO_BLOCK[_ENVELOPE_BYTES:]:
        raise EnvelopeVerificationError(f"{record} has a nonzero candidate payload")
    if fs_uuid == bytes(16) or generation == 0:
        raise EnvelopeVerificationError(f"{record} has a zero UUID or generation")
    return ObjectEnvelope(kind, fs_uuid, generation, crc)


@dataclass(frozen=True)
class _Checkpoint:
    fs_uuid: bytes
    generation: int
    lsn: int
    log_epoch: int


def _read_block(disk: BinaryIO, block: int) -> bytes:
    disk.seek(block * BLOCK_BYTES)
    raw = disk.read(BLOCK_BYTES)
    if len(raw) != BLOCK_BYTES:
        raise EnvelopeVerificationError(f"short read at scratch block {block}")
    return raw


def _read_superblock(disk: BinaryIO, index: int) -> _Checkpoint:
    raw = _read_block(disk, index)
    record = f"v1 superblock {index}"
    if (struct.unpack_from("<IHHII", raw) != (0x43594653, 1, 80, BLOCK_BYTES, BLOCK_COUNT)
            or struct.unpack_from("<5I", raw, 56) != (BITMAP_START, INODE_START, DATA_START, _INODE_COUNT, 0)):
        raise EnvelopeVerificationError(f"{record} has invalid v1 geometry")
    _check_crc(raw, 76, record)
    if raw[80:] != _ZERO_BLOCK[80:]:
        raise EnvelopeVerificationError(f"{record} has nonzero padding")
    fs_uuid = raw[16:32]
    generation, lsn, log_epoch = struct.unpack_from("<3Q", raw, 32)
    if fs_uuid != STAGING_UUID or generation == 0 or log_epoch == 0:
        raise EnvelopeVerificationError(f"{record} has an invalid scratch UUID, generation, or log epoch")
    return _Checkpoint(fs_uuid, generation, lsn, log_epoch)


def _read_checkpoint_pair(disk: BinaryIO) -> _Checkpoint:
    older, newer = sorted((_read_superblock(disk, 0), _read_superblock(disk, 1)),
                          key=lambda checkpoint: checkpoint.generation)
    if older == newer == _Checkpoint(STAGING_UUID, 1, 0, 1):
        return newer
    if (newer.generation != older.generation + 1
            or newer.log_epoch != older.log_epoch + 1 or newer.lsn < older.lsn):
        raise EnvelopeVerificationError("invalid v1 checkpoint pair")
    return newer


def _check_free_inode(raw: bytes, inode: int) -> None:
    if raw[:_INODE_CRC_OFFSET] != b"NIYC" + bytes(248):
        raise EnvelopeVerificationError(f"v1 inode {inode} must use the fresh free format")
    _check_crc(raw, _INODE_CRC_OFFSET, f"v1 inode {inode}")


def _check_live_extent(raw: bytes, expected: _Extent, *, size: int) -> range:
    record = f"v1 inode {expected.inode}"
    _check_crc(raw, _INODE_CRC_OFFSET, record)
    kind = 2 if expected.inode == 0 else 1
    if _INODE_PREFIX.unpack_from(raw) != (
        b"NIYC", kind, 0,  # magic, kind, reserved
        1, size, 0,  # generation, size, durable write sequence
        1, 0, 0, 1,  # extent count, reserved, parent, parent generation
    ):
        raise EnvelopeVerificationError(f"{record} has noncanonical live metadata")
    logical, physical, count = _INODE_RUN.unpack_from(raw, _INODE_PREFIX.size)
    if ((logical, physical, count) != (0, expected.first_block, expected.blocks)
            or any(raw[_INODE_PREFIX.size + _INODE_RUN.size:_INODE_CRC_OFFSET])):
        raise EnvelopeVerificationError(f"{record} has a noncanonical extent or reserved bytes")
    return range(physical, physical + count)


def _check_acl(raw: bytes, inode: int, hidden: bool, *, file_owner_rights: int | None) -> int:
    record = f"v1 ACL {inode}"
    _check_crc(raw, 60, record)
    staged_file = file_owner_rights is not None and inode == _STAGED_FILE.inode
    live = int(inode == 0 or hidden or staged_file)
    owner_rights = _ROOT_OWNER_RIGHTS if inode == 0 else 0
    if file_owner_rights is not None and inode == 0:
        owner_rights |= 1 << 12  # FILE_ENUM
    if staged_file:
        owner_rights = file_owner_rights
    system_rights = _SYSTEM_RIGHTS if hidden else 0
    found = _ACL_PREFIX.unpack_from(raw)
    if found != (
        inode, live, live,  # inode identifier, state, inode generation
        live, live,  # principal identifier and generation
        owner_rights, system_rights, live, 0, 0, 0,  # rights, ACL generation, parent, reserved
    ):
        raise EnvelopeVerificationError(f"{record} has noncanonical ownership, rights, or state")
    return found[5]


def _check_bitmap(disk: BinaryIO, owned: set[int]) -> None:
    expected = bytearray(BLOCK_COUNT // 8)
    for block in owned:
        expected[block // 8] |= 1 << (block % 8)
    bitmap = b"".join(_read_block(disk, block) for block in range(BITMAP_START, INODE_START))
    for index, (found, wanted) in enumerate(zip(bitmap, expected, strict=True)):
        if found != wanted:
            changed = found ^ wanted
            bit = next(bit for bit in range(8) if changed & (1 << bit))
            block = index * 8 + bit
            problem = "has an unexplained allocation at" if found & (1 << bit) else "is missing allocation for"
            raise EnvelopeVerificationError(f"v1 bitmap {problem} block {block}")


def _check_root(disk: BinaryIO, *, file_read: bool) -> dict:
    root = _read_block(disk, _ROOT.first_block)
    entry = struct.pack("<IHHQ", _STAGED_FILE.inode, len(STAGED_FILE_NAME), 0, 1) + STAGED_FILE_NAME
    entry = entry.ljust(124, b"\0")
    for slot, offset in enumerate(range(0, BLOCK_BYTES, _DIR_SLOT_BYTES)):
        raw = root[offset:offset + _DIR_SLOT_BYTES]
        record = f"v1 root directory slot {slot}"
        _check_crc(raw, 124, record)
        if slot == 0 and file_read:
            if raw[:124] != entry:
                raise EnvelopeVerificationError(f"{record} has the wrong staged file identity")
            continue
        if raw[:124] != b"\xff" * 4 + bytes(120):
            raise EnvelopeVerificationError(f"{record} must be empty")
    if not file_read:
        return {}
    data = _read_block(disk, STAGED_FILE_BLOCK)
    if data != STAGED_FILE_DATA.ljust(BLOCK_BYTES, b"\0"):
        raise EnvelopeVerificationError("staged file payload or zero padding differs")
    return {
        "file_read_bytes": len(STAGED_FILE_DATA),
        "file_read_sha256": hashlib.sha256(data[:len(STAGED_FILE_DATA)]).hexdigest(),
        "file_read_dirent_sha256": hashlib.sha256(root[:_DIR_SLOT_BYTES]).hexdigest(),
    }


def _verify_unified_metadata(disk: BinaryIO, *, file_owner_rights: int | None) -> dict:
    inodes = b"".join(_read_block(disk, block) for block in range(INODE_START, DATA_START))
    acls = b"".join(_read_block(disk, block) for block in range(_ACL.first_block, _ACL.first_block + _ACL.blocks))
    owned = set(range(DATA_START))
    system_inodes = system_blocks = 0
    file_read = file_owner_rights is not None
    file_evidence = {}
    for inode in range(_INODE_COUNT):
        inode_offset = inode * INODE_BYTES
        raw = inodes[inode_offset:inode_offset + INODE_BYTES]
        expected = _ROOT if inode == 0 else _SYSTEM_EXTENTS.get(inode)
        hidden = inode in _SYSTEM_EXTENTS
        size = _DIR_SLOT_BYTES if inode == 0 else BLOCK_BYTES * expected.blocks if hidden else 0
        staged_file = file_read and inode == _STAGED_FILE.inode
        if staged_file:
            expected, size = _STAGED_FILE, len(STAGED_FILE_DATA)
        if expected is None:
            # Reserved and unused business inodes use the fresh free format.
            _check_free_inode(raw, inode)
        else:
            blocks = _check_live_extent(raw, expected, size=size)
            if not owned.isdisjoint(blocks):
                raise EnvelopeVerificationError(f"v1 inode {inode} overlaps an allocated extent")
            owned.update(blocks)
            if hidden:
                system_inodes += 1
                system_blocks += len(blocks)
        acl_offset = inode * _ACL_BYTES
        rights = _check_acl(acls[acl_offset:acl_offset + _ACL_BYTES], inode, hidden,
                            file_owner_rights=file_owner_rights)
        if staged_file:
            file_evidence["file_owner_rights"] = rights
    _check_bitmap(disk, owned)
    return {
        "system_inodes": system_inodes,
        "system_blocks": system_blocks,
        "data_blocks": len(owned) - DATA_START,
        **file_evidence,
        **_check_root(disk, file_read=file_read),
    }


def verify_envelopes(path: Path, *, unified: bool = False, file_read: bool = False,
                     snapshot_read: bool = False, file_volatile_write: bool = False) -> dict:
    """Read both v1 superblocks and all 138 candidate blocks from a scratch image.

    Bind the heads to the scratch UUID and generation 1. Unified mode verifies
    the allocated eight-object scratch layout. By default the snapshot ranges
    and inode slots must be free. Snapshot read mode also hashes the entire
    SlotStore extent. Volatile write mode requires a staged file with an
    exact READ|WRITE owner ACL. Return JSON-compatible evidence.
    """
    if (file_read or file_volatile_write) and not unified:
        raise EnvelopeVerificationError("staged file requires the unified media layout")
    file_owner_rights = None
    if file_volatile_write:
        file_owner_rights = _FILE_READ | _FILE_WRITE
    elif file_read:
        file_owner_rights = _FILE_READ
    with path.open("rb") as disk:
        if disk.seek(0, os.SEEK_END) != BLOCK_BYTES * BLOCK_COUNT:
            raise EnvelopeVerificationError("scratch image must be exactly 512 MiB")
        checkpoint = _read_checkpoint_pair(disk)
        if unified:
            allocation = _verify_unified_metadata(disk, file_owner_rights=file_owner_rights)
        else:
            allocation = {}
            # The four ranges fit in the first bitmap page and the candidate
            # inode slots share the page starting at inode 224.
            bitmap = _read_block(disk, BITMAP_START)
            inode_page = _read_block(disk, INODE_START + 224 * INODE_BYTES // BLOCK_BYTES)
        objects = {}
        for kind, layout in _LAYOUTS.items():
            if not unified:
                offset = (layout.inode * INODE_BYTES) % BLOCK_BYTES
                _check_free_inode(inode_page[offset:offset + INODE_BYTES], layout.inode)
            raw = _read_block(disk, layout.first_block)
            envelope = decode_envelope(kind, raw)
            if envelope.fs_uuid != checkpoint.fs_uuid:
                raise EnvelopeVerificationError(f"snapshot {kind} envelope UUID differs from the superblocks")
            if envelope.generation != 1:
                raise EnvelopeVerificationError(f"snapshot {kind} envelope generation must be 1 on scratch media")
            digest = hashlib.sha256(raw) if snapshot_read and kind == "slot" else None
            for block in range(layout.first_block, layout.first_block + layout.blocks):
                if not unified and bitmap[block // 8] & (1 << (block % 8)):
                    raise EnvelopeVerificationError(f"snapshot {kind} block {block} is allocated in the v1 bitmap")
                if block == layout.first_block:
                    continue
                tail = _read_block(disk, block)
                if tail != _ZERO_BLOCK:
                    raise EnvelopeVerificationError(f"snapshot {kind} tail block {block} is nonzero")
                if digest is not None:
                    digest.update(tail)
            objects[kind] = {
                "first_block": layout.first_block,
                "blocks": layout.blocks,
                "inode": layout.inode,
                "generation": envelope.generation,
                "crc32c": envelope.crc32c,
                "envelope_sha256": hashlib.sha256(raw).hexdigest(),
                "zero_tail_blocks": layout.blocks - 1,
            }
            if digest is not None:
                objects[kind]["extent_sha256"] = digest.hexdigest()
    return {
        "golden_vector_pending": True,
        "fs_uuid": checkpoint.fs_uuid.hex(),
        "superblock_generation": checkpoint.generation,
        "snapshot_blocks": sum(layout.blocks for layout in _LAYOUTS.values()),
        "objects": objects,
        **allocation,
    }
