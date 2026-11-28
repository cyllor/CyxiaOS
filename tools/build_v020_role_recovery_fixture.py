#!/usr/bin/env python3
"""Build signed SEC-P/S role-recovery fixtures with the public scratch test key."""

import argparse
from hashlib import sha256
import os
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory

from package_v020_recovery_store import prepare as prepare_carrier
from package_v020_role_services import ROLES, prepare as prepare_grants
from test_v020_signed_scratch_vector import sign_scratch_fixture
from v020_g1_genesis import ACL, ROOT
from v020_snapshot_envelopes import BITMAP_START, BLOCK_BYTES, INODE_START
from verify_smp import require


REPO = Path(__file__).resolve().parents[1]
TARGET = "aarch64-unknown-none-softfloat"
CATALOG_FILES = ("offline-config.bin", "offline-ed25519-pubkey.bin", "rule-profile.bin",
                 "security-profile.bin", "key-generation.txt", "key-manifest.bin")
TLS_FILES = ("tls-verifier.elf", "tls-signer.elf", "tls-ingress.elf")
TEST_TRUST_ANCHOR = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def provision_disk(seed: Path, carrier: Path, output: Path, envelope: bytes) -> None:
    with seed.open("rb") as initial, carrier.open("rb") as donor, output.open("xb") as disk:
        require(seed.stat().st_size == carrier.stat().st_size == 512 * (1 << 20),
                "expected disposable 512 MiB v1 fixture volumes")
        require(initial.read(32)[16:32] == donor.read(32)[16:32] == envelope[16:32],
                "the fixture's prepared carrier and seed volume use different file identities")
        initial.seek(0)
        disk.truncate(seed.stat().st_size)
        # Preserve the real seed boot pair. The donor supplies only the
        # independently prepared ordinary file carrier in this test volume.
        carrier_metadata = {BITMAP_START, INODE_START, ACL, ROOT}
        for first in range(0, seed.stat().st_size, 1 << 20):
            initial.seek(first)
            chunk = bytearray(initial.read(1 << 20))
            for block in carrier_metadata:
                offset = block * BLOCK_BYTES - first
                if 0 <= offset < len(chunk):
                    donor.seek(block * BLOCK_BYTES)
                    chunk[offset:offset + BLOCK_BYTES] = donor.read(BLOCK_BYTES)
            if chunk.count(0) != len(chunk):
                disk.seek(first)
                disk.write(chunk)
        disk.flush()


def provision_network(catalog: Path, source: Path, predecessor: Path, sign) -> bytes:
    predecessor.mkdir()
    for name in CATALOG_FILES:
        shutil.copyfile(catalog / name, predecessor / name)
    prior = (catalog / "offline-config.bin").read_bytes()
    manifest = bytearray((source / "key-manifest.bin").read_bytes())
    require(len(manifest) == 184 and manifest[:8] == b"CYXNET01" and manifest[73] == 1,
            "expected an active disposable TLS fixture")
    key, verifier, signer = struct.unpack_from("<3Q", manifest, 8)
    require(key == struct.unpack_from("<Q", prior, 56)[0] + 1,
            "the TLS key generation does not follow the seed policy")
    manifest[32:64] = sha256(prior).digest()
    packages = []
    for name in TLS_FILES:
        shutil.copyfile(source / name, catalog / name)
        packages.append(sha256((catalog / name).read_bytes()).digest())
    require(manifest[152:184] == packages[2], "TLS fixture ingress is not bound to its manifest")
    manifest_hash = sha256(manifest).digest()
    tls_signing = b"CYX/TLS-PACKAGES/v1" + struct.pack("<3Q", verifier, signer, key)
    (catalog / "tls-packages.sig").write_bytes(sign(tls_signing + manifest_hash + packages[0] + packages[1]))
    (catalog / "key-manifest.bin").write_bytes(manifest)
    (catalog / "key-generation.txt").write_text(f"{key}\n", encoding="ascii")
    current = bytearray(prior[:-64])
    struct.pack_into("<Q", current, 32, struct.unpack_from("<Q", prior, 32)[0] + 1)
    struct.pack_into("<Q", current, 56, key)
    current[128:160] = manifest_hash
    envelope = bytes(current) + sign(b"CYX/OFFLINE/v1" + current)
    (catalog / "offline-config.bin").write_bytes(envelope)
    return envelope


def compile_roles(roles: Path, environment: dict, source_for_role) -> None:
    sources = REPO / "user/v0199-control"
    options = ("-pie", "--no-dynamic-linker", "-Bsymbolic", "--no-undefined",
               "--build-id=none", "-zmax-page-size=4096", "-zcommon-page-size=4096",
               f"-T{sources / 'linker.ld'}")
    for role in ROLES:
        source, extra = source_for_role(role)
        argv = ["rustc", str(sources / source), "--edition=2024", "--target", TARGET,
                "--crate-name", "cyxia_native_control_role", "--cfg", f'control_role="{role}"',
                "-A", "dead_code", *extra, "-C", "opt-level=2", "-C", "panic=abort", "-C",
                "relocation-model=pic", "-C", "overflow-checks=yes", "-C", "strip=debuginfo"]
        for flag in options:
            argv += ["-C", f"link-arg={flag}"]
        subprocess.run([*argv, "-o", str(roles / f"v0199-role-{role}.elf")],
                       cwd=REPO, env=environment, check=True)


def build_roles(roles: Path, environment: dict) -> None:
    def source_for_role(role):
        if role in (6, 7, 11):
            return "sec_ps_recovery.rs", []
        if role in (2, 8):
            return "sec_s_control.rs", ["--cfg", "sec_ps_recovery"]
        return "main.rs", []

    compile_roles(roles, environment, source_for_role)


def build_kernel(output: Path, environment: dict, network: bool) -> None:
    argv = ["cargo", "build", "--locked", "--offline", "-p", "cyxia-kernel", "--release",
            "--target", TARGET, "--features", "prototype-memory"]
    if network:
        argv.extend(("--features", "v020-production-resident-net"))
    with output.open("wb") as log:
        result = subprocess.run(argv, cwd=REPO, env=environment, stdout=log, stderr=subprocess.STDOUT)
    require(result.returncode == 0, f"kernel fixture build failed, see {output}")


def build(args) -> None:
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir()
    catalog, roles, target = (output / name for name in ("catalog", "roles", "target"))
    catalog.mkdir()
    roles.mkdir()
    for name in CATALOG_FILES:
        shutil.copyfile(args.catalog / name, catalog / name)
    require((catalog / "offline-ed25519-pubkey.bin").read_bytes() == TEST_TRUST_ANCHOR,
            "the fixture must use the public RFC 8032 scratch test trust anchor")
    envelope = (catalog / "offline-config.bin").read_bytes()
    disk = output / "seed.raw"
    provision_disk(args.seed, args.carrier, disk, envelope)
    environment = {key: value for key, value in os.environ.items() if key not in (
        "CYXIA_TLS_SIGNER_KEY_FILE", "CYXIA_PREDECESSOR_STARTUP_CATALOG_DIR")}
    with TemporaryDirectory(prefix="cyx-ps-sign-") as work:
        def sign(message):
            return sign_scratch_fixture(Path(work), message)

        if args.network_catalog is not None:
            predecessor = output / "predecessor"
            envelope = provision_network(catalog, args.network_catalog, predecessor, sign)
            environment["CYXIA_PREDECESSOR_STARTUP_CATALOG_DIR"] = str(predecessor)
            environment["CYXIA_TLS_SIGNER_KEY_FILE"] = str(args.tls_test_key.resolve())
        with disk.open("rb") as raw:
            locator, signing = prepare_carrier(envelope, raw, 1)
        (catalog / "recovery-store.bin").write_bytes(locator)
        (catalog / "recovery-store.sig").write_bytes(sign(signing))
        shutil.copyfile(args.business_elf, catalog / "business-package.elf")
        config_hash = sha256(envelope).digest()
        business_hash = sha256(args.business_elf.read_bytes()).digest()
        (catalog / "business-package.sig").write_bytes(sign(
            b"CYX/STARTUP-BUSINESS-PACKAGE/v1" + config_hash + business_hash))
        environment.update(CYXIA_STARTUP_CATALOG_DIR=str(catalog),
                           CYXIA_STARTUP_ROLE_PACKAGES_DIR=str(roles), CARGO_TARGET_DIR=str(target),
                           CYX_CONTROL_CATALOG_DIGEST_HEX=config_hash.hex(),
                           CYX_CONTROL_RULE_HASH_HEX=sha256((catalog / "rule-profile.bin").read_bytes()).hexdigest())
        build_roles(roles, environment)
        features_net = args.network_catalog is not None
        build_kernel(output / "kernel-prepare.log", environment, features_net)
        inputs = sorted((target / TARGET / "release/build").glob(
            "cyxia-kernel-*/out/startup-catalog/lifecycle-packages-to-sign.bin"))
        require(len(inputs) == 1, "expected one trusted role signing message")
        roster = inputs[0].read_bytes()
        (catalog / "lifecycle-packages.sig").write_bytes(sign(roster))
        grants, message = prepare_grants(roster, ["6:1", "7:1", "2:0x11", "8:0x60", "11:0x42000"], [], [])
        (catalog / "role-services.bin").write_bytes(grants)
        (catalog / "role-services.sig").write_bytes(sign(message))
        build_kernel(output / "kernel-build.log", environment, features_net)
    shutil.copyfile(target / TARGET / "release/cyxia-kernel", output / "kernel.elf")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("catalog", "seed", "carrier", "business-elf", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--network-catalog", type=Path, help="disposable deployed TLS fixture assets")
    parser.add_argument("--tls-test-key", type=Path, help="private path for the disposable TLS fixture only")
    args = parser.parse_args()
    if (args.network_catalog is None) != (args.tls_test_key is None):
        parser.error("network fixture requires both the public catalog and its test signer key")
    try:
        build(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
