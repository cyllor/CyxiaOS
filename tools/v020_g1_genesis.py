"""Generate or verify the 512 MiB G1 genesis candidate for signed scratch."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
from tempfile import TemporaryDirectory

if __package__:
    from .v020_snapshot_envelopes import (
        BITMAP_START, BLOCK_BYTES, BLOCK_COUNT, DATA_START, INODE_BYTES, INODE_START,
        STAGING_UUID, crc32c_zeroed, encode_envelope,
    )
else:
    from v020_snapshot_envelopes import (
        BITMAP_START, BLOCK_BYTES, BLOCK_COUNT, DATA_START, INODE_BYTES, INODE_START,
        STAGING_UUID, crc32c_zeroed, encode_envelope,
    )


CAPACITY = BLOCK_BYTES * BLOCK_COUNT
ROOT = 4269
BOOT = 4118
INDEX = 4125
ACL = 4126
SECURITY = 4130
BLOCKS_PER_READ = 256
BUILTIN_CONFIG = (
    Path(__file__).resolve().parents[1] / "tests/fixtures/v020-signed-scratch/config.bin"
)
CONFIG_SHA256 = "ffff2c6b9fde3b5311c4df1c871ff6b3830817fd1d76e0a1fb4bc07aaa369bcf"
IMAGE_SHA256 = Path(__file__).parent / "fixtures/v020-g1-genesis.sha256"
SNAPSHOT_HEADS = {"catalog": 4131, "slot": 4132, "request": 4252, "protection": 4268}
SYSTEM_EXTENTS = {
    224: (4131, 1), 225: (BOOT, 1), 226: (4132, 120), 227: (4268, 1),
    228: (4252, 16), 229: (4119, 7), 230: (ACL, 4), 231: (SECURITY, 1),
}


def _seal(prefix, size, crc_offset):
    raw = bytearray(prefix.ljust(size, b"\0"))
    struct.pack_into("<I", raw, crc_offset, crc32c_zeroed(raw, crc_offset))
    return bytes(raw)


def _superblock():
    head = struct.pack("<IHHII16s3Q5I", 0x43594653, 1, 80, BLOCK_BYTES, BLOCK_COUNT,
                       STAGING_UUID, 1, 0, 1, BITMAP_START, INODE_START, DATA_START, 256, 0)
    return _seal(head, BLOCK_BYTES, 76)


def _inode(kind=0, size=0, first=0, blocks=0):
    live = int(kind != 0)
    head = struct.pack("<IHH3QHHIQ", 0x4359494E, kind, 0, live, size, 0, live, 0, 0, live)
    return _seal(head + struct.pack("<3I", 0, first, blocks), INODE_BYTES, 252)


def _acl(inode):
    live = int(inode == 0 or inode in SYSTEM_EXTENTS)
    owner_rights = (1 << 14) if inode == 0 else 0
    system_rights = 0x2300 if inode in SYSTEM_EXTENTS else 0
    head = struct.pack("<II3QIIQ", inode, live, live, live, live, owner_rights, system_rights, live)
    return _seal(head, 64, 60)


def _stream_index():
    head = struct.pack("<IHH16s2Q", 0x43595349, 4, 64, STAGING_UUID, 0, 1)
    groups = b"".join(struct.pack("<IIQQ", 0, 0, 0, principal) for principal in range(1, 17))
    return _seal(head.ljust(64, b"\0") + groups, BLOCK_BYTES, 4092)


def _security_state():
    config_hash = sha256(BUILTIN_CONFIG.read_bytes()).digest()
    if config_hash.hex() != CONFIG_SHA256:
        raise ValueError("signed scratch configuration differs from the pinned fixture")
    head = struct.pack("<IHH16s6Q8xQ32s16Q", 0x43595353, 2, 248, STAGING_UUID,
                       1, 1, 1, 1, 0, 0, 1, config_hash, *([1] * 16))
    return _seal(head, BLOCK_BYTES, 72)


def _genesis_blocks():
    bitmap = bytearray(BLOCK_COUNT // 8)
    extents = {0: (ROOT, 1), **SYSTEM_EXTENTS}
    allocated = set(range(DATA_START))
    for first, count in extents.values():
        allocated.update(range(first, first + count))
    for block in allocated:
        bitmap[block // 8] |= 1 << (block % 8)

    inodes = [_inode()] * 256
    inodes[0] = _inode(2, 128, ROOT, 1)
    for inode, (first, count) in SYSTEM_EXTENTS.items():
        inodes[inode] = _inode(1, count * BLOCK_BYTES, first, count)

    boot = struct.pack("<IHH16sQ", 0x43594245, 1, 40, STAGING_UUID, 0)
    areas = {
        0: _superblock() * 2,
        BITMAP_START: bytes(bitmap),
        INODE_START: b"".join(inodes),
        BOOT: _seal(boot, BLOCK_BYTES, 32),
        INDEX: _stream_index(),
        ACL: b"".join(_acl(inode) for inode in range(256)),
        SECURITY: _security_state(),
        ROOT: _seal(b"\xff" * 4, 128, 124) * (BLOCK_BYTES // 128),
    }
    for kind, first in SNAPSHOT_HEADS.items():
        areas[first] = encode_envelope(kind, STAGING_UUID)
    return {
        first + offset // BLOCK_BYTES: raw[offset:offset + BLOCK_BYTES]
        for first, raw in areas.items()
        for offset in range(0, len(raw), BLOCK_BYTES)
        if any(raw[offset:offset + BLOCK_BYTES])
    }


def verify_image(path):
    """Check every byte, including the zero journal, object tails, and free data."""
    blocks = _genesis_blocks()
    digest = sha256()
    chunk_bytes = BLOCKS_PER_READ * BLOCK_BYTES
    with path.open("rb") as image:
        if os.fstat(image.fileno()).st_size != CAPACITY:
            raise ValueError("genesis candidate must occupy exactly 512 MiB")
        for first in range(0, BLOCK_COUNT, BLOCKS_PER_READ):
            actual = image.read(chunk_bytes)
            expected = bytearray(chunk_bytes)
            for block in range(first, first + BLOCKS_PER_READ):
                if block in blocks:
                    offset = (block - first) * BLOCK_BYTES
                    expected[offset:offset + BLOCK_BYTES] = blocks[block]
            if actual != expected:
                for offset in range(0, len(expected), BLOCK_BYTES):
                    if actual[offset:offset + BLOCK_BYTES] != expected[offset:offset + BLOCK_BYTES]:
                        raise ValueError(
                            f"genesis candidate differs at block {first + offset // BLOCK_BYTES}"
                        )
            digest.update(actual)

    image_hash = digest.hexdigest()
    if image_hash != IMAGE_SHA256.read_text(encoding="ascii").strip():
        raise ValueError("genesis candidate SHA-256 differs from the pinned fixture")
    return {
        "candidate": "g1-v1-signed-scratch-genesis",
        "golden_vector_pending": True,
        "image_bytes": CAPACITY,
        "image_sha256": image_hash,
        "nonzero_blocks": len(blocks),
        "signed_config_sha256": CONFIG_SHA256,
    }


def generate_image(path):
    """Publish a new verified sparse candidate without overwriting an existing path."""
    with TemporaryDirectory(prefix=".cyx-g1-", dir=path.parent) as temporary:
        staged = Path(temporary) / "genesis.raw"
        with staged.open("xb") as image:
            image.truncate(CAPACITY)
            for block, raw in sorted(_genesis_blocks().items()):
                image.seek(block * BLOCK_BYTES)
                image.write(raw)
        report = verify_image(staged)
        os.link(staged, path)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "verify"))
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    try:
        report = generate_image(args.image) if args.action == "generate" else verify_image(args.image)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
