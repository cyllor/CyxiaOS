#!/usr/bin/env python3
"""Build disposable signed role12 file fixtures with the public test trust root."""

import argparse
from hashlib import sha256
import os
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory

from package_v020_file_client import prepare as client_grant
from package_v020_file_owner import prepare as owner_grant
from test_v020_signed_scratch_vector import sign_scratch_fixture
from v020_g1_genesis import ACL, ROOT as FILE_ROOT, SNAPSHOT_HEADS, _inode
from v020_snapshot_envelopes import BITMAP_START, BLOCK_BYTES, INODE_BYTES, INODE_START
from verify_smp import require
from verify_v020_sec_f import create_raw, nonempty_pages, seal, write_pages


PUBLIC_TEST_ROOT = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
ROOT = Path(__file__).resolve().parents[1]


def writable_pages(config):
    pages = nonempty_pages(config)
    first_snapshot = SNAPSHOT_HEADS["catalog"]
    for block in range(first_snapshot, FILE_ROOT):
        pages.pop(block, None)
    for block in (FILE_ROOT + 2, FILE_ROOT + 3):
        del pages[block]

    bitmap = bytearray(BLOCK_BYTES)
    for block in range(first_snapshot):
        bitmap[block // 8] |= 1 << (block % 8)
    for block in (FILE_ROOT, FILE_ROOT + 1):
        bitmap[block // 8] |= 1 << (block % 8)
    pages[BITMAP_START] = bytes(bitmap)

    system_home = INODE_START + (224 * INODE_BYTES) // BLOCK_BYTES
    system_inodes = bytearray(pages[system_home])
    system_acl = bytearray(pages[ACL + 3])
    for inode in (224, 226, 227, 228):
        offset = inode * INODE_BYTES % BLOCK_BYTES
        system_inodes[offset:offset + INODE_BYTES] = _inode()
        offset = inode * 64 % BLOCK_BYTES
        empty_acl = bytearray(struct.pack("<I", inode).ljust(64, b"\0"))
        system_acl[offset:offset + 64] = seal(empty_acl, 60)
    pages[system_home] = bytes(system_inodes)
    pages[ACL + 3] = bytes(system_acl)

    file_acl_page = bytearray(pages[ACL])
    file_acl = bytearray(file_acl_page[64:128])
    struct.pack_into("<I", file_acl, 32, (1 << 8) | (1 << 9) | (1 << 13))
    file_acl_page[64:128] = seal(file_acl, 60)
    pages[ACL] = bytes(file_acl_page)
    return pages


def build(source, output, *, writable=False):
    require((source / "offline-ed25519-pubkey.bin").read_bytes() == PUBLIC_TEST_ROOT,
            "the fixture builder only accepts the repository's public test trust root")
    output.mkdir()
    catalog = output / "catalog"
    catalog.mkdir()
    names = ("offline-ed25519-pubkey.bin", "offline-config.bin", "rule-profile.bin",
             "security-profile.bin", "key-manifest.bin", "key-generation.txt",
             "lifecycle-packages.sig")
    if not writable:
        names += ("file-volume.bin", "file-volume.sig")
    for name in names:
        shutil.copyfile(source / name, catalog / name)
    config = (catalog / "offline-config.bin").read_bytes()
    business_package = catalog / "business-package.elf"
    linker = ROOT / "user/v0199-control/linker.ld"
    subprocess.run([
        "rustc", str(ROOT / "user/v0199-control/file_owner_read_fixture.rs"), "--edition=2024",
        "--target", "aarch64-unknown-none-softfloat", "--crate-name", "cyxia_file_reader",
        "-C", "opt-level=2", "-C", "panic=abort", "-C", "relocation-model=pic",
        "-C", "overflow-checks=yes", "-C", "strip=debuginfo",
        "-C", "link-arg=-pie", "-C", "link-arg=--no-dynamic-linker", "-C", "link-arg=-Bsymbolic",
        "-C", "link-arg=--no-undefined", "-C", "link-arg=--build-id=none",
        "-C", "link-arg=-zmax-page-size=4096", "-C", "link-arg=-zcommon-page-size=4096",
        "-C", f"link-arg=-T{linker}", "-o", str(business_package),
        *(["--cfg", "cyxia_fixture_write"] if writable else []),
    ], check=True, env={**os.environ, "CYXIA_FIXTURE_FS_UUID_HEX": config[16:32].hex()})
    package = business_package.read_bytes()
    (catalog / "file-owner.elf").write_bytes(package)
    with TemporaryDirectory(prefix="cyx-file-read-scratch-signing-") as staged:
        def sign(wire):
            return sign_scratch_fixture(Path(staged), wire)

        (catalog / "business-package.sig").write_bytes(sign(
            b"CYX/STARTUP-BUSINESS-PACKAGE/v1" + sha256(config).digest() + sha256(package).digest()))
        for name, (grant, message) in (
            ("file-owner", owner_grant(config, package, 12_000_000)),
            ("file-client", client_grant(config, package, package, 0, 1, 1, 1, writable=writable)),
        ):
            (catalog / f"{name}.bin").write_bytes(grant)
            (catalog / f"{name}.sig").write_bytes(sign(message))
    with create_raw(output / "seed.raw") as seed:
        write_pages(seed, writable_pages(config) if writable else nonempty_pages(config))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--writable", action="store_true", help="package a writable baseline-v1 fixture")
    args = parser.parse_args()
    try:
        build(args.catalog, args.output, writable=args.writable)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"file fixture: {error}\n")


if __name__ == "__main__":
    main()
