"""Independent frozen OfflineConfigEnvelope v1 scratch vector, using OpenSSL.

The seed is the public RFC 8032 section 7.1 test vector 1. Only the public
key and the resulting signed fixture are embedded in opted-in guest images.
"""
import hashlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/v020-signed-scratch/config.bin"
FSYNC_FIXTURE = FIXTURE.with_name("fsync-config.bin")
RECEIPT_QUERY_FIXTURE = FIXTURE.with_name("fsync-receipt-query.bin")
FSYNC_CLIENT_FIXTURE = FIXTURE.with_name("fsync-client.bin")
UUID = b"CYX-W11-STAGING!"
FSYNC_UUID = b"CYX-FSYNC-TEST!!"
FSYNC_POLICY = b"CYX-SCRATCH-FSYNC/v1:inode=1,principal=1"
LABEL = b"CYX/OFFLINE/v1"
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
# Three empty test-only lists. The guest accepts precisely these twelve bytes.
CATALOG = (b"scratch/test/rules/1", b"scratch/test/security/1", b"scratch/test/keys/1")
EXPECTED_SHA256 = "ffff2c6b9fde3b5311c4df1c871ff6b3830817fd1d76e0a1fb4bc07aaa369bcf"


def receipt_query_policy(fsync_wire):
    return (b"CYX-SCRATCH-FILE-RECEIPT-QUERY/v1:fsync="
            + hashlib.sha256(fsync_wire).hexdigest().encode("ascii")
            + b",principal=1,generation=1,holder_role=11,file_service=12,ipc_send=1")


def fsync_client_policy(fsync_wire):
    return (b"CYX-SCRATCH-FILE-FSYNC-CLIENT/v1:fsync="
            + hashlib.sha256(fsync_wire).hexdigest().encode("ascii")
            + b",principal=1,generation=1,holder_role=11,file_service=12,ipc_send=1,"
              b"inode=1,inode_generation=1,file_rights=0x2300")


def sha(data):
    return hashlib.sha256(data).digest()


def unsigned_bytes(uuid=UUID, lists=bytes(12)):
    payload = b"".join(struct.pack("<QQ", i, 1) for i in range(1, 17)) + lists
    header = struct.pack("<IHHII16s4Q", 0x43594F46, 1, 256, 320 + len(payload), len(payload),
                         uuid, 1, 1, 1, 1)
    header += b"".join(map(sha, CATALOG)) + sha(payload) + bytes(64)
    assert len(header) == 256
    return header + payload


def sign_scratch_fixture(path, contents):
    # PKCS#8 Ed25519 private key, RFC 8410. No production key material.
    key = path / "test-key.der"
    key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + SEED)
    message = path / "message"
    message.write_bytes(contents)
    return subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin",
                                    "-inkey", str(key), "-keyform", "DER",
                                    "-in", str(message)])


def signed_vector(path, uuid=UUID, lists=bytes(12)):
    unsigned = unsigned_bytes(uuid, lists)
    return unsigned + sign_scratch_fixture(path, LABEL + unsigned)


class SignedScratchVector(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for independent encoder")
    def test_wire_signature_and_committed_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            encoded = signed_vector(Path(directory))
            self.assertEqual(FIXTURE.read_bytes(), encoded)
            self.assertEqual(sha(encoded).hex(), EXPECTED_SHA256)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for independent encoder")
    def test_separate_fsync_fixture_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            encoded = signed_vector(Path(directory), FSYNC_UUID, FSYNC_POLICY)
            self.assertEqual(FSYNC_FIXTURE.read_bytes(), encoded)
            self.assertNotEqual(sha(encoded).hex(), EXPECTED_SHA256)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for independent encoder")
    def test_receipt_query_qualification_binds_the_existing_fsync_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            encoded = signed_vector(Path(directory), FSYNC_UUID,
                                    receipt_query_policy(FSYNC_FIXTURE.read_bytes()))
            self.assertEqual(RECEIPT_QUERY_FIXTURE.read_bytes(), encoded)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for independent encoder")
    def test_fsync_client_qualification_binds_the_existing_fsync_policy_and_acl(self):
        with tempfile.TemporaryDirectory() as directory:
            encoded = signed_vector(Path(directory), FSYNC_UUID,
                                    fsync_client_policy(FSYNC_FIXTURE.read_bytes()))
            self.assertEqual(FSYNC_CLIENT_FIXTURE.read_bytes(), encoded)


if __name__ == "__main__":
    unittest.main()
