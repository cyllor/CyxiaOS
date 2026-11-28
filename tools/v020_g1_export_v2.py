#!/usr/bin/env python3
"""Export a verified legacy v2 volume for offline G1 migration."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

import check_v2_filesystem as legacy
from verify_smp import require


def source_stamp(path):
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size == legacy.BLOCK * legacy.COUNT,
            "offline source must be a regular 512 MiB volume image")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def check_source(path):
    digest = sha256()
    with path.open("rb") as source:
        pages = [source.read(legacy.BLOCK) for _ in range(2)]
        try:
            old, new = sorted(map(legacy.superblock, pages), key=lambda row: row["generation"])
        except ValueError as error:
            raise ValueError(f"invalid v2 superblock pair ({error})") from error
        require(old["uuid"] == new["uuid"] and new["generation"] - old["generation"] <= 1,
                "v2 superblock pair has conflicting identities or discontinuous generations")
        digest.update(b"".join(pages))
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest(), pages


def logical_tree_digest(files, directories):
    digest = sha256(b"CYX/G1-MIGRATION-TREE/v1")
    for path in sorted(files.keys() | directories.keys(), key=lambda name: name.encode("utf-8")):
        encoded = path.encode("utf-8")
        node = files.get(path)
        digest.update(struct.pack("<BI", 1 if node is not None else 2, len(encoded)))
        digest.update(encoded)
        if node is not None:
            digest.update(struct.pack("<Q", node["size"]))
            digest.update(bytes.fromhex(node["sha256"]))
    return digest.hexdigest()


def export_tree(archive, current, view, written):
    files = view["files"]
    for node in files.values():
        expected = node["sha256"]
        if expected in written:
            continue
        digest, size = sha256(), 0
        with archive.open(f"objects/{expected}", "w") as out:
            for chunk in legacy.content(node, current):
                out.write(chunk)
                digest.update(chunk)
                size += len(chunk)
        require(size == node["size"] and digest.hexdigest() == expected,
                "business payload changed during export")
        written.add(expected)

    directories = {}
    for name, node in view["directories"].items():
        payload = b"".join(legacy.content(node, current))
        require(len(payload) == node["size"], "short exported directory")
        digest = sha256(payload).hexdigest()
        if digest not in written:
            archive.writestr(f"objects/{digest}", payload)
            written.add(digest)
        directories[name] = {**node, "sha256": digest}
    return {"files": files, "directories": directories,
            "logical_tree_sha256": logical_tree_digest(files, directories)}


def export_committed(archive, current, source, digest, superblocks):
    verified = legacy.inspect_committed(current, source)
    written = set()
    live = export_tree(archive, current, verified, written)
    snapshots = [{**row, **export_tree(archive, current, row, written)} for row in verified["snapshots"]]
    catalog = current(legacy.CATALOG_START)
    header = current(legacy.REQUEST_START)
    watermarks = [
        {"slot": slot, "generation": legacy.u64(header, 512 + 128 * slot + 16),
         "issued_hi": legacy.u64(header, 512 + 128 * slot + 24)}
        for slot in range(16)
    ]
    slots = [legacy.u64(catalog, 512 + 448 * slot + 16) for slot in range(8)]
    members = {}

    def store(name, payload):
        archive.writestr(name, payload)
        members[name] = {"bytes": len(payload), "sha256": sha256(payload).hexdigest()}

    store("legacy/superblocks.bin", b"".join(superblocks))
    for name, start, count in (
        ("bitmap", legacy.BITMAP_START, 4),
        ("inodes", legacy.INODE_START, 16),
        ("control", legacy.CONTROL_START, 1),
        ("catalog", legacy.CATALOG_START, 1),
        ("boot", legacy.DATA_START + 1, 1),
        ("requests", legacy.REQUEST_START, 16),
    ):
        store(f"legacy/{name}.bin", b"".join(current(start + page) for page in range(count)))
    for snapshot in snapshots:
        slot = snapshot["slot"]
        first = legacy.SNAPSHOT_START + slot * 15
        store(f"legacy/snapshots/{slot}.bin", b"".join(current(first + page) for page in range(15)))

    manifest = {
        "schema": "cyxia-g1-v2-export/v1",
        "source_sha256": digest,
        "volume": source,
        "boot_epoch": verified["boot_epoch"],
        "control": verified["control"],
        "slot_generations": slots,
        "request_watermarks": watermarks,
        "request_records": verified["request_records"],
        "live": live,
        "snapshots": snapshots,
        "legacy_members": members,
    }
    archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {"status": "EXPORTED", "source_sha256": digest, "fs_uuid": source["uuid"],
            "boot_epoch": verified["boot_epoch"], "snapshots": len(snapshots), "objects": len(written)}


def export_volume(source, destination):
    """Publish the archived committed view only after a complete read-only check."""
    if os.path.lexists(destination):
        raise FileExistsError(f"export path already exists: {destination}")
    before = source_stamp(source)
    digest, superblocks = check_source(source)
    with TemporaryDirectory(prefix=".cyx-g1-export-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "export.zip"
        with staged.open("xb") as out:
            with legacy.committed_volume(source) as (current, volume):
                with ZipFile(out, "w", compression=ZIP_DEFLATED, compresslevel=1) as archive:
                    report = export_committed(archive, current, volume, digest, superblocks)
            require(source_stamp(source) == before, "legacy source changed during export")
            out.flush()
            os.fsync(out.fileno())
        os.link(staged, destination)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        report = export_volume(args.source, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
