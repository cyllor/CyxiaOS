#!/usr/bin/env python3
"""Verify signed snapshot protection settlement with the scratch trust anchor."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory

from build_v020_role_recovery_fixture import (
    CATALOG_FILES, TARGET, TEST_TRUST_ANCHOR, build_kernel, compile_roles,
)
from package_v020_snapshot_authority import prepare
from test_v020_signed_scratch_vector import sign_scratch_fixture
import v020_g1_snapshot_wire as wire
from v020_snapshot_envelopes import BITMAP_START
from verify_v020_sec_f import BLOCK_BYTES, append_redo, at, create_raw, nonempty_pages, seal, write_pages
from verify_v020_signed_resident import PMU_PATCH, RECOVERY_NS, boot, require, rows, sha


def build(output, source):
    output.mkdir()
    catalog, roles, target = (output / name for name in ("catalog", "roles", "target"))
    catalog.mkdir()
    roles.mkdir()
    for name in (*CATALOG_FILES, "file-volume.bin", "file-volume.sig"):
        shutil.copyfile(source / name, catalog / name)
    require((catalog / "offline-ed25519-pubkey.bin").read_bytes() == TEST_TRUST_ANCHOR,
            "expected the public scratch fixture trust anchor")
    config = (catalog / "offline-config.bin").read_bytes()
    volume = output / "volume-id.bin"
    volume.write_bytes(config[16:32])
    principal = output / "recovery-principal-generation.bin"
    principal.write_bytes(config[504:512])
    environment = os.environ.copy()
    for name in ("CYXIA_TLS_SIGNER_KEY_FILE", "CYXIA_PREDECESSOR_STARTUP_CATALOG_DIR"):
        environment.pop(name, None)
    environment.update(CYXIA_STARTUP_CATALOG_DIR=str(catalog),
                       CYXIA_STARTUP_ROLE_PACKAGES_DIR=str(roles), CARGO_TARGET_DIR=str(target),
                       CYX_SNAPSHOT_AUTHORITY_TEST_VOLUME=str(volume),
                       CYX_SNAPSHOT_AUTHORITY_TEST_PRINCIPAL_GENERATION=str(principal))
    compile_roles(roles, environment, lambda role: (
        "snapshot_authority_fixture.rs" if role == 11 else "main.rs", []))
    build_kernel(output / "prepare.log", environment, False)
    inputs = tuple((target / TARGET / "release/build").glob(
        "cyxia-kernel-*/out/startup-catalog/lifecycle-packages-to-sign.bin"))
    require(len(inputs) == 1, "expected the compiled protected lifecycle roster")
    roster = inputs[0].read_bytes()
    authority, message = prepare(config, (catalog / "file-volume.bin").read_bytes(), roster)
    with TemporaryDirectory(prefix="cyx-snapshot-authority-sign-") as directory:
        def sign(data):
            return sign_scratch_fixture(Path(directory), data)

        (catalog / "lifecycle-packages.sig").write_bytes(sign(roster))
        (catalog / "snapshot-authority.bin").write_bytes(authority)
        (catalog / "snapshot-authority.sig").write_bytes(sign(message))
    build_kernel(output / "build.log", environment, False)
    shutil.copyfile(target / TARGET / "release/cyxia-kernel", output / "kernel.elf")


def verify(args):
    require(sha(args.qemu) == args.qemu_sha256 and sha(PMU_PATCH) == args.patch_sha256,
            "expected the pinned per-vCPU PMU simulator and patch")
    config = (args.output / "catalog/offline-config.bin").read_bytes()
    pages = nonempty_pages(config)
    uuid = config[16:32]
    generation, = struct.unpack_from("<Q", config, 504)
    pages[4252] = wire.header({15: (generation, 0)}, uuid=uuid, generation=1)
    key = struct.pack("<16sIQQ", uuid, 15, generation, 1)
    request = wire.read_request(wire.frame(0x27, 1, struct.pack("<QII", 1, 1, 0), key), 1)
    pending = wire.record(request, state=1).ljust(BLOCK_BYTES, b"\0")
    terminal = wire.record(request, state=2, log=1, txid=3, lsn=12, payload=struct.pack("<QII", 2, 1, 1))
    settled = terminal.ljust(BLOCK_BYTES, b"\0")
    header = wire.header({15: (generation, 1)}, uuid=uuid, generation=2)
    protection = bytearray(pages[4268])
    struct.pack_into("<Q", protection, 24, 3)
    struct.pack_into("<Q", protection, 48, 2)
    protection[138] = 1
    protection = seal(protection, 32)
    redo = {}
    append_redo(redo, 8, 5, 2, ((4252, header), (4260, pending)), epoch=1)
    append_redo(redo, 14, 9, 3, ((4260, settled), (4268, protection)), epoch=1)
    disk = args.output / "scratch.raw"
    with create_raw(disk) as raw:
        write_pages(raw, pages)

    def verify_boot(name, epoch):
        output = args.output / name
        result = boot(str(args.qemu), args.output / "kernel.elf", output, args.timeout, disk, epoch,
                      expected_policy_envelope=config)
        require(result["status"] == "PASS", f"{name}: {result.get('error')}")
        lines = (output / "serial.txt").read_text().splitlines()
        require(rows(lines, "V020_G1_SNAPSHOT_PROTECTION_AUTH") == [(epoch, 1, 0x27)]
                and rows(lines, "V020_G1_SNAPSHOT_PROTECTION_TERMINAL") == [(epoch, 1, 12)]
                and not rows(lines, "V020_G1_SNAPSHOT_RUNTIME_REFUSED"),
                f"{name}: the Supervisor did not retrieve the exact terminal outcome")
        replay = [] if epoch == 1 else [(1, 12, 2)]
        require(rows(lines, "V020_SEC_F_SNAPSHOT_FREEZE_REPLAY") == replay,
                f"{name}: protection replay disagrees with the selected BootPair")
        budget = rows(lines, "V020_G1_SNAPSHOT_RUNTIME_BUDGET")
        require(len(budget) == 1 and all(0 < used <= batches * quota and quota == RECOVERY_NS
                                         for batches, used, quota in budget),
                f"{name}: the protection work did not settle within paid CPU0 batches")
        result["protection_budget"] = budget[0]
        return result

    result = verify_boot("qemu", 1)
    with disk.open("rb") as raw:
        require(all(at(raw, number) == block for number, block in redo.items())
                and at(raw, 20) == bytes(BLOCK_BYTES), "live protection redo differs from its exact two groups")
        expected = b"".join(pages.get(block, bytes(BLOCK_BYTES)) for block in range(4131, 4269))
        require(at(raw, 4131, len(expected)) == expected, "live protection modified an uncheckpointed home")

    cold = verify_boot("qemu-reopen", 2)
    pages.update({4252: header, 4260: settled, 4268: protection})
    expected = b"".join(pages.get(block, bytes(BLOCK_BYTES)) for block in range(4131, 4269))
    with disk.open("rb") as raw:
        checkpoint = max(struct.unpack_from("<3Q", at(raw, index), 32) for index in (0, 1))
        protected = at(raw, 4131, len(expected))
        require(checkpoint == (2, 12, 2) and protected == expected
                and at(raw, 8, 12 * BLOCK_BYTES) == bytes(12 * BLOCK_BYTES)
                and at(raw, BITMAP_START) == pages[BITMAP_START],
                "cold checkpoint or retained protection receipt differs")
    result.update(protected_homes_sha256=sha256(protected).hexdigest(), checkpoint=checkpoint,
                  reopened=cold,
                  qemu_sha256=args.qemu_sha256, patch_sha256=args.patch_sha256,
                  scope="signed FREEZE_SET, cold checkpoint and exact terminal replay")
    (args.output / "verification.json").write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, help="build with this signed scratch volume catalog")
    parser.add_argument("--qemu", type=Path, help="verify an already built fixture in this QEMU")
    parser.add_argument("--qemu-sha256")
    parser.add_argument("--patch-sha256")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if not args.catalog and not args.qemu:
        parser.error("supply --catalog to build or --qemu to verify")
    args.output = args.output.resolve()
    try:
        if args.catalog:
            build(args.output, args.catalog)
        if args.qemu:
            verify(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
