"""Check detached custody evidence for an offline v2 migration source."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
from subprocess import TimeoutExpired
from zipfile import BadZipFile, ZipFile

from check_v2_filesystem import BLOCK, SYSTEM_ROOT, checksum
from verify_unified_disk import signature
from verify_v0199_verdicts import strict_json
from verify_smp import require


DOMAIN = b"CYX/G1-MIGRATION/LEGACY-AUTHORITY/v1"
OFFLINE_DOMAIN = b"CYX/OFFLINE/v1"
CONFIG_HEADER = 256
CONFIG_PRINCIPALS = 16
CONFIG_MAX_PAYLOAD = 65_536
SIGNATURE_BYTES = 64
ACL_BYTES = 64
ACL_ROW_BYTES = 8 + ACL_BYTES
MAX_ACL_ROWS = 9 * SYSTEM_ROOT
FILE_RIGHTS = (1 << 8) | (1 << 9) | (1 << 13)
DIR_RIGHTS = (1 << 10) | (1 << 11) | (1 << 12) | (1 << 14)
CONFIG_MAX = CONFIG_HEADER + CONFIG_MAX_PAYLOAD + SIGNATURE_BYTES
AUTHORITY_LIMITS = {"offline-config.bin": CONFIG_MAX, "security-state.bin": BLOCK,
                    "file-acl-views.bin": MAX_ACL_ROWS * ACL_ROW_BYTES}
# A v2 node can list 16 inline and 338 indirect extents. The independent
# reader supports deep directories, including JSON escapes in each name.
MAX_ESCAPED_PATH = SYSTEM_ROOT * (1 + 6 * 63)
MANIFEST_MAX = MAX_ACL_ROWS * (1024 + (16 + 338) * 80 + MAX_ESCAPED_PATH) + 2 * 1024 * 1024


def read_bounded(path, bound):
    with path.open("rb") as source:
        data = source.read(bound + 1)
    require(len(data) <= bound, f"oversized authority input {path.name}")
    return data


def verify_signature(public, message, wire):
    try:
        signature(public, message, wire)
    except TimeoutExpired as error:
        raise ValueError("Ed25519 authority verification timed out") from error


def old_policy(wire, public, uuid):
    principal_bytes = CONFIG_PRINCIPALS * 16
    require(len(wire) >= CONFIG_HEADER + principal_bytes + SIGNATURE_BYTES,
            "short old OfflineConfigEnvelope")
    magic, version, header, total, length, fs_uuid = struct.unpack_from("<IHHII16s", wire)
    require((magic, version, header, total, fs_uuid) == (0x43594f46, 1, CONFIG_HEADER, len(wire), uuid)
            and principal_bytes <= length <= CONFIG_MAX_PAYLOAD
            and CONFIG_HEADER + length + SIGNATURE_BYTES == total,
            "old OfflineConfigEnvelope identity or length differs")
    generations = struct.unpack_from("<4Q", wire, 32)
    isolation, mode = struct.unpack_from("<QH", wire, 192)
    require(all(generations) and all(any(wire[at:at + 32]) for at in (64, 96, 128))
            and isolation <= 0xffff and mode <= 2 and not any(wire[202:CONFIG_HEADER]),
            "invalid old OfflineConfigEnvelope fields")
    payload = wire[CONFIG_HEADER:-SIGNATURE_BYTES]
    require(sha256(payload).digest() == wire[160:192], "old offline configuration payload digest differs")
    principals = tuple(struct.iter_unpack("<QQ", payload[:principal_bytes]))
    require(all(min(principal) > 0 for principal in principals)
            and len({principal[0] for principal in principals}) == CONFIG_PRINCIPALS,
            "invalid old configuration principal map")
    verify_signature(public, OFFLINE_DOMAIN + wire[:-SIGNATURE_BYTES], wire[-SIGNATURE_BYTES:])
    return generations, set(principals)


def check_old_security(raw, uuid, boot_epoch, config, generations):
    require(len(raw) == BLOCK, "short old SecurityStateStore v2")
    checksum(raw, 72)
    magic, version, header, fs_uuid = struct.unpack_from("<IHH16s", raw)
    require((magic, version, header, fs_uuid) == (0x43595353, 2, 248, uuid)
            and not any(raw[76:80]) and not any(raw[header:]),
            "invalid old SecurityStateStore v2 header or identity")
    state, rule_min, security_min, key, isolated, epoch = struct.unpack_from("<6Q", raw, 24)
    config_generation, = struct.unpack_from("<Q", raw, 80)
    signed_generation, signed_rule, signed_security, signed_key = generations
    require(state > 0 and epoch == boot_epoch and isolated <= 0xffff
            and config_generation == signed_generation and key == signed_key
            and rule_min <= signed_rule and security_min <= signed_security
            and raw[88:120] == sha256(config).digest(),
            "old SecurityStateStore differs from the committed BootEpoch or signed policy")


def check_acl_views(wire, manifest, principals):
    active = [(0, manifest["live"])]
    active.extend((row["slot"] + 1, row) for row in manifest["snapshots"] if row["state"] == 1)
    expected = sorted(((view, inode["inode"]), inode) for view, tree in active
                      for namespace in ("files", "directories") for inode in tree[namespace].values())
    require(len(wire) == len(expected) * ACL_ROW_BYTES, "old authority needs complete ACL coverage for active roots")
    for offset, ((view, inode_id), inode) in enumerate(expected):
        start = offset * ACL_ROW_BYTES
        supplied_view, reserved = struct.unpack_from("<II", wire, start)
        acl = wire[start + 8:start + ACL_ROW_BYTES]
        checksum(acl, 60)
        identity, state, generation, principal, principal_generation, owner, system, acl_generation, parent = (
            struct.unpack_from("<II3QIIQI", acl))
        allowed = FILE_RIGHTS if inode["kind"] == 1 else DIR_RIGHTS
        require((supplied_view, reserved, identity, state, generation, parent)
                == (view, 0, inode_id, 1, inode["generation"], inode["parent"])
                and acl_generation > 0 and (principal, principal_generation) in principals
                and (owner | system) & ~allowed == 0 and not any(acl[52:60]),
                "old ACL differs from the committed view or signed policy")
    return len(expected)


def prepare(directory, key_file, manifest, manifest_wire):
    """Validate source policy and coverage, then construct the message for its custodian."""
    public = trust_key(key_file)
    members = {name: read_bounded(directory / name, limit) for name, limit in AUTHORITY_LIMITS.items()}
    rows = validate_inputs(manifest, public, members)
    return public, signing_message(manifest_wire, members), rows, members


def trust_key(key_file):
    public = read_bounded(key_file, 32)
    require(len(public) == 32 and any(public), "invalid external old authority trust key")
    return public


def signing_message(manifest_wire, members):
    return DOMAIN + sha256(manifest_wire).digest() + b"".join(
        sha256(members[name]).digest() for name in AUTHORITY_LIMITS)


def validate_inputs(manifest, public, members):
    require(manifest["schema"] == "cyxia-g1-v2-export/v1" and is_digest(manifest["source_sha256"]),
            "unexpected legacy export schema or source digest")
    config = members["offline-config.bin"]
    uuid = bytes.fromhex(manifest["volume"]["uuid"])
    generations, principals = old_policy(config, public, uuid)
    check_old_security(members["security-state.bin"], uuid, manifest["boot_epoch"], config, generations)
    return check_acl_views(members["file-acl-views.bin"], manifest, principals)


def attach(archive, directory, public, message, rows, members):
    signed = read_bounded(directory / "legacy-authority.sig", SIGNATURE_BYTES)
    verify_signature(public, message, signed)
    for name, data in {**members, "legacy-authority.sig": signed}.items():
        archive.writestr(f"authority/{name}", data)
    return receipt(public, message, rows)


def receipt(public, message, rows):
    return {"trust_key_sha256": sha256(public).hexdigest(),
            "message_sha256": sha256(message).hexdigest(), "acl_rows": rows}


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def read_zip_member(archive, name, bound):
    info = archive.getinfo(name)
    require(info.file_size <= bound, f"oversized authority archive member {name}")
    with archive.open(info) as member:
        data = member.read(bound + 1)
    require(len(data) == info.file_size, f"wrong read size for {name}")
    return data


def verify_payloads(archive, manifest):
    layouts = {"superblocks": 2, "bitmap": 4, "inodes": 16, "control": 1,
               "catalog": 1, "boot": 1, "requests": 16}
    snapshots = manifest["snapshots"]
    slots = [entry["slot"] for entry in snapshots]
    require(all(type(slot) is int and 0 <= slot < 8 for slot in slots) and len(slots) == len(set(slots)),
            "invalid legacy slot inventory")
    layouts.update({f"snapshots/{slot}": 15 for slot in slots})
    sizes = {f"legacy/{name}.bin": blocks * BLOCK for name, blocks in layouts.items()}
    require(manifest["legacy_members"].keys() == sizes.keys(), "legacy metadata inventory differs")
    expected = {}
    for name, size in sizes.items():
        item = manifest["legacy_members"][name]
        require(item["bytes"] == size and is_digest(item["sha256"]), "invalid legacy metadata descriptor")
        expected[name] = (size, item["sha256"])
    for view in [manifest["live"], *snapshots]:
        for namespace in ("files", "directories"):
            cap = 8 * 1024 * 1024 if namespace == "files" else 32768
            for inode in view[namespace].values():
                size, digest = inode["size"], inode["sha256"]
                require(type(size) is int and 0 <= size <= cap and is_digest(digest), "invalid archive object descriptor")
                name = f"objects/{digest}"
                require(expected.setdefault(name, (size, digest)) == (size, digest), "conflicting object lengths")
    reserved = {"manifest.json", *(f"authority/{name}" for name in AUTHORITY_LIMITS), "authority/legacy-authority.sig"}
    require(set(archive.namelist()) == expected.keys() | reserved, "archive member inventory differs from signed manifest")
    for name, (size, digest) in expected.items():
        raw = read_zip_member(archive, name, size)
        require(len(raw) == size and sha256(raw).hexdigest() == digest, f"contents differ from signed manifest: {name}")


def verify_archive(path, key_file):
    public = trust_key(key_file)
    with ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) <= MAX_ACL_ROWS + 20 and len(names) == len(set(names)),
                "excess or duplicate authority archive members")
        manifest_wire = read_zip_member(archive, "manifest.json", MANIFEST_MAX)
        members = {name: read_zip_member(archive, f"authority/{name}", limit)
                   for name, limit in AUTHORITY_LIMITS.items()}
        signed = read_zip_member(archive, "authority/legacy-authority.sig", SIGNATURE_BYTES)
        message = signing_message(manifest_wire, members)
        verify_signature(public, message, signed)
        manifest = strict_json(manifest_wire)
        require((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode() == manifest_wire,
                "non-canonical signed export manifest")
        rows = validate_inputs(manifest, public, members)
        verify_payloads(archive, manifest)
        return {"status": "VERIFIED_SOURCE_AUTHORITY", "source_sha256": manifest["source_sha256"],
                "manifest_sha256": sha256(manifest_wire).hexdigest(), **receipt(public, message, rows)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--trusted-old-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_archive(args.archive, args.trusted_old_key)
    except (BadZipFile, KeyError, OSError, TypeError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
