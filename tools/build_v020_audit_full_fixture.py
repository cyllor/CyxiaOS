#!/usr/bin/env python3
"""Build the signed full durable audit fixture using a public test trust anchor."""

import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory

from build_v020_role_recovery_fixture import (CATALOG_FILES, TARGET, TEST_TRUST_ANCHOR,
                                             build_kernel, compile_roles, provision_disk)
from package_v020_recovery_store import prepare as prepare_carrier
from package_v020_role_services import prepare as prepare_grants
from test_v020_signed_scratch_vector import sign_scratch_fixture
from v020_production_media import verify_signed_disk
from v020_snapshot_envelopes import BLOCK_BYTES
from verify_smp import require
from verify_v020_audit_full import audit_record, seed_pages


def build(args):
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir()
    catalog, roles, target = (output / name for name in ("catalog", "roles", "target"))
    catalog.mkdir()
    roles.mkdir()
    for name in CATALOG_FILES:
        shutil.copyfile(args.catalog / name, catalog / name)
    require((catalog / "offline-ed25519-pubkey.bin").read_bytes() == TEST_TRUST_ANCHOR,
            "expected the public scratch fixture trust anchor")
    envelope = (catalog / "offline-config.bin").read_bytes()
    verify_signed_disk(args.seed, 1, expected_policy_envelope=envelope)
    disk = output / "seed.raw"
    provision_disk(args.seed, args.carrier, disk, envelope)
    with disk.open("r+b") as raw:
        locator, message = prepare_carrier(envelope, raw, 1)
        block, = struct.unpack_from("<I", locator, 60)
        raw.seek(block * BLOCK_BYTES)
        require(raw.read(2 * BLOCK_BYTES) == bytes(2 * BLOCK_BYTES),
                "source carrier already holds evidence")
        pages, proofs = seed_pages(locator)
        raw.seek(block * BLOCK_BYTES)
        raw.write(b"".join(pages))
        raw.flush()
        os.fsync(raw.fileno())

    environment = {name: value for name, value in os.environ.items() if name not in (
        "CYXIA_TLS_SIGNER_KEY_FILE", "CYXIA_PREDECESSOR_STARTUP_CATALOG_DIR")}
    environment.update(CYXIA_STARTUP_CATALOG_DIR=str(catalog),
                       CYXIA_STARTUP_ROLE_PACKAGES_DIR=str(roles), CARGO_TARGET_DIR=str(target),
                       CYX_AUDIT_FIXTURE_FIRST_DIGEST=audit_record(1, proofs[0])[96:].hex())
    compile_roles(roles, environment,
                  lambda role: ("audit_full_fixture.rs", []) if role == 11
                  else ("main.rs", ["--cfg", "audit_full_idle"]))
    with TemporaryDirectory(prefix="cyx-audit-full-sign-") as directory:
        def sign(data):
            return sign_scratch_fixture(Path(directory), data)

        (catalog / "recovery-store.bin").write_bytes(locator)
        (catalog / "recovery-store.sig").write_bytes(sign(message))
        build_kernel(output / "kernel-prepare.log", environment, False)
        inputs = tuple((target / TARGET / "release/build").glob(
            "cyxia-kernel-*/out/startup-catalog/lifecycle-packages-to-sign.bin"))
        require(len(inputs) == 1, "unable to identify the exact signed role roster")
        roster = inputs[0].read_bytes()
        (catalog / "lifecycle-packages.sig").write_bytes(sign(roster))
        grants, message = prepare_grants(roster, ["11:0x42000"], [], [])
        (catalog / "role-services.bin").write_bytes(grants)
        (catalog / "role-services.sig").write_bytes(sign(message))
        build_kernel(output / "kernel-build.log", environment, False)
    shutil.copyfile(target / TARGET / "release/cyxia-kernel", output / "kernel.elf")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("catalog", "seed", "carrier", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
