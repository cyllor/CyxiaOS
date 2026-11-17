#!/usr/bin/env python3
"""Prepare complete pinned Wayland Protocols data for an isolated SDK.

This copies authentic release data and the full source distribution; it runs no
scanner, compiler, Meson, target code or network operation. The resulting sysroot
overlay must be copied into a fresh SDK and checked with validate_installation.
It does not claim installation of generated convenience headers or runtime use.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile

VERSION = "1.41"
ARCHIVE_ROOT = "wayland-protocols-1.41"
ARCHIVE_SHA256 = "2786b6b1b79965e313f2c289c12075b9ed700d41844810c51afda10ee329576b"
ARCHIVE_BYTES = 120224
SOURCE_URL = "https://gitlab.freedesktop.org/wayland/wayland-protocols/-/releases/1.41/downloads/wayland-protocols-1.41.tar.xz"
HASH_SOURCE = "https://github.com/openembedded/openembedded-core/blob/walnascar/meta/recipes-graphics/wayland/wayland-protocols_1.41.bb"
HASH_SOURCE_BLOB = "e8ab9d84fcecc242d7309affe1afb703faa18103"
MESON_SHA256 = "565ab4d4b472187e333605bbb21d957f64024a6bad0459a89e1fea2b346b23e8"
PC_TEMPLATE_SHA256 = "94e445b0b2c2194378b08311f7da3c75b4773fbd6049e8a8bf01276415019c73"
COPYING_SHA256 = "f1a2b233e8a9a71c40f4aa885be08a0842ac85bb8588703c1dd7e6e6502e3124"
MAX_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 256
DATA_ROOT = "usr/share/wayland-protocols"
PC_PATH = "usr/share/pkgconfig/wayland-protocols.pc"
LICENSE_PATH = "usr/share/licenses/wayland-protocols/COPYING"
REQUIRED_XML = (
    "staging/fifo/fifo-v1.xml",
    "staging/commit-timing/commit-timing-v1.xml",
    "unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml",
    "stable/presentation-time/presentation-time.xml",
    "staging/tearing-control/tearing-control-v1.xml",
    "staging/linux-drm-syncobj/linux-drm-syncobj-v1.xml",
    "staging/color-management/color-management-v1.xml",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def plain(path):
    require(isinstance(path, (str, os.PathLike)), "Missing filesystem path")
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), "Linked input/output path: " + str(path))
    return path


def read(path, limit=MAX_BYTES):
    path = plain(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "Not a bounded regular file: " + str(path))
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    after = path.stat()
    keys = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns")
    require(len(raw) == before.st_size and len(raw) <= limit and all(getattr(before, k) == getattr(after, k) for k in keys),
            "Input changed while reading: " + str(path))
    return raw


def identity(raw, mode=0o644):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": format(mode, "04o")}


def archive_files(path):
    raw = read(path)
    require(len(raw) == ARCHIVE_BYTES and hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA256,
            "Archive differs from the independently pinned official release")
    files, seen, expanded = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
        for count, member in enumerate(archive, 1):
            name = PurePosixPath(member.name)
            require(count <= MAX_MEMBERS and not name.is_absolute() and ".." not in name.parts
                    and name.parts and name.parts[0] == ARCHIVE_ROOT and member.name not in seen
                    and (member.isdir() or member.isfile()) and not member.mode & ~0o777,
                    "Unsafe, duplicate or excessive archive member")
            seen.add(member.name)
            expanded += member.size
            require(expanded <= MAX_BYTES and member.size <= MAX_BYTES, "Expanded source exceeds bound")
            if member.isfile():
                key = str(name.relative_to(ARCHIVE_ROOT))
                payload = archive.extractfile(member).read(member.size + 1)
                require(len(payload) == member.size, "Truncated release member")
                files[key] = (payload, member.mode)
    require(len(seen) == 184 and len(files) == 125 and expanded == 879013, "Release member inventory changed")
    for name, expected in (("meson.build", MESON_SHA256), ("wayland-protocols.pc.in", PC_TEMPLATE_SHA256),
                           ("COPYING", COPYING_SHA256)):
        require(hashlib.sha256(files[name][0]).hexdigest() == expected, "Release metadata mismatch: " + name)
    return raw, files


def data_files(files):
    meson = files["meson.build"][0].decode()
    require(re.search(r"project\('wayland-protocols',\s+version: '1\.41',", meson), "Wrong actual upstream version")
    xml = []
    for state in ("stable", "staging", "unstable"):
        match = re.search(r"(?m)^" + state + r"_protocols = (\{.*?^\})", meson, re.S | re.M)
        require(match is not None, "Missing original protocol list")
        protocol_set = ast.literal_eval(match.group(1))
        require(isinstance(protocol_set, dict), "Invalid original protocol list")
        for name, versions in protocol_set.items():
            require(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]+", name)
                    and isinstance(versions, list), "Invalid original protocol entry")
            for version in versions:
                require(isinstance(version, str) and re.fullmatch(r"v[0-9]+|", version), "Invalid protocol version")
                suffix = ("-unstable" if state == "unstable" else "") + ("-" + version if version else "")
                relative = state + "/" + name + "/" + name + suffix + ".xml"
                require(relative in files and str(PurePosixPath(relative).parent / "README") in files,
                        "Incomplete original XML/README pair")
                xml.append(relative)
    actual_xml = {name for name in files if name.split("/")[0] in ("stable", "staging", "unstable") and name.endswith(".xml")}
    require(len(xml) == len(set(xml)) and set(xml) == actual_xml and set(REQUIRED_XML) <= actual_xml,
            "The complete upstream XML set, including every Mesa input, is required")
    selected = set(xml) | {str(PurePosixPath(name).parent / "README") for name in xml} | {"COPYING"}
    data = {DATA_ROOT + "/" + name: files[name][0] for name in sorted(selected)}
    template = files["wayland-protocols.pc.in"][0].decode()
    for key, value in {"prefix": "/usr", "datarootdir": "${prefix}/share", "PACKAGE": "wayland-protocols",
                       "WAYLAND_PROTOCOLS_VERSION": VERSION}.items():
        template = template.replace("@" + key + "@", value)
    require("@" not in template, "Unresolved upstream pkg-config template")
    data[PC_PATH] = template.encode()
    data[LICENSE_PATH] = files["COPYING"][0]
    return data, sorted(xml)


def actual_files(directory):
    directory = plain(directory)
    require(directory.is_dir(), "Missing plain directory")
    result, entries = set(), 0
    for parent, dirs, files in os.walk(directory, followlinks=False):
        entries += len(dirs) + len(files)
        require(entries <= 1024, "Unexpected oversized bundle directory inventory")
        for name in [*dirs, *files]:
            plain(Path(parent) / name)
        result.update(str((Path(parent) / name).relative_to(directory)) for name in files)
        require(len(result) <= 512, "Unexpected oversized bundle")
    return result


def prepare(archive, output):
    archive, output = plain(archive), plain(output)
    require(not output.exists() and output.parent.is_dir(), "Output must be a fresh directory with an existing parent")
    raw, source = archive_files(archive)
    data, xml = data_files(source)
    source_rows = {name: identity(payload, mode) for name, (payload, mode) in sorted(source.items())}
    rows = {name: identity(payload) for name, payload in sorted(data.items())}
    origin = {"schema_version": 1, "status": "PINNED_WAYLAND_PROTOCOLS_DATA_ONLY", "version": VERSION,
              "source_url": SOURCE_URL, "hash_source": HASH_SOURCE, "hash_source_git_blob": HASH_SOURCE_BLOB,
              "archive": identity(raw), "source_files": source_rows, "files": rows,
              "protocol_xml": xml, "mesa_required_xml": list(REQUIRED_XML),
              "producer_sha256": hashlib.sha256(read(__file__)).hexdigest(),
              "native_execution": False, "guest_execution": False,
              "scope": "Complete original XML/README/COPYING data; full release source retained; canonical pc template substitution. Generated convenience headers and runtime behavior are not claimed."}
    with tempfile.TemporaryDirectory(prefix=".wayland-protocols-", dir=output.parent) as temporary:
        staging = Path(temporary) / "bundle"
        staging.mkdir()
        (staging / "source.archive").write_bytes(raw)
        (staging / "source.archive").chmod(0o644)
        for name, (payload, mode) in source.items():
            path = staging / "source" / ARCHIVE_ROOT / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload); path.chmod(mode)
        for name, payload in data.items():
            path = staging / "sysroot" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload); path.chmod(0o644)
        (staging / "origin.json").write_text(json.dumps(origin, indent=2) + "\n")
        (staging / "origin.json").chmod(0o644)
        validate_bundle(staging)
        require(not output.exists(), "Output appeared during preparation")
        staging.rename(output)
    return validate_bundle(output)


def validate_bundle(bundle):
    bundle = plain(bundle)
    raw, source = archive_files(bundle / "source.archive")
    data, xml = data_files(source)
    origin_raw = read(bundle / "origin.json")
    origin = json.loads(origin_raw)
    source_rows = {name: identity(payload, mode) for name, (payload, mode) in sorted(source.items())}
    rows = {name: identity(payload) for name, payload in sorted(data.items())}
    require(origin["schema_version"] == 1 and origin["status"] == "PINNED_WAYLAND_PROTOCOLS_DATA_ONLY" and origin["version"] == VERSION
            and origin["source_url"] == SOURCE_URL and origin["archive"] == identity(raw)
            and origin["hash_source"] == HASH_SOURCE and origin["hash_source_git_blob"] == HASH_SOURCE_BLOB
            and origin["producer_sha256"] == hashlib.sha256(read(__file__)).hexdigest()
            and origin["source_files"] == source_rows and origin["files"] == rows
            and origin["protocol_xml"] == xml and origin["mesa_required_xml"] == list(REQUIRED_XML)
            and origin["native_execution"] is False and origin["guest_execution"] is False,
            "Data receipt differs from actual pinned release")
    expected = {"source.archive", "origin.json"} | {"source/" + ARCHIVE_ROOT + "/" + name for name in source} | {"sysroot/" + name for name in data}
    require(actual_files(bundle) == expected, "Bundle inventory changed")
    require(stat.S_IMODE((bundle / "source.archive").stat().st_mode) == 0o644
            and stat.S_IMODE((bundle / "origin.json").stat().st_mode) == 0o644,
            "Bundle archive/receipt mode changed")
    for name, expected_row in {**{"source/" + ARCHIVE_ROOT + "/" + n: r for n, r in source_rows.items()},
                               **{"sysroot/" + n: r for n, r in rows.items()}}.items():
        path = bundle / name
        require(identity(read(path), stat.S_IMODE(path.stat().st_mode)) == expected_row, "Bundle file changed: " + name)
    return {"status": "PINNED_PROTOCOL_DATA_VERIFIED_NOT_NATIVE_OR_GUEST_RUN", "bundle": str(bundle),
            "origin": identity(origin_raw), "archive": identity(raw), "version": VERSION,
            "protocol_xml_count": len(xml), "mesa_required_xml": {n: rows[DATA_ROOT + "/" + n] for n in REQUIRED_XML},
            "files": rows, "native_execution": False, "guest_execution": False}


def validate_installation(bundle, sysroot):
    result = validate_bundle(bundle)
    sysroot = plain(sysroot)
    rows = result["files"]
    expected_data = {str(PurePosixPath(n).relative_to(DATA_ROOT)) for n in rows if n.startswith(DATA_ROOT + "/")}
    require(actual_files(sysroot / DATA_ROOT) == expected_data, "Installed complete protocol data inventory changed")
    for name, row in rows.items():
        path = sysroot / name
        require(identity(read(path), stat.S_IMODE(path.stat().st_mode)) == row, "Installed protocol data changed: " + name)
    return {**result, "sysroot": str(sysroot), "installation_verified": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.archive, args.output)
    print(json.dumps({k: result[k] for k in ("status", "bundle", "version", "protocol_xml_count", "origin")}, indent=2))
