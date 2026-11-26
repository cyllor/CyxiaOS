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
UUID = b"CYX-W11-STAGING!"
LABEL = b"CYX/OFFLINE/v1"
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
# Three empty test-only lists. The guest accepts precisely these twelve bytes.
CATALOG = (b"scratch/test/rules/1", b"scratch/test/security/1", b"scratch/test/keys/1")
EXPECTED_SHA256 = "ffff2c6b9fde3b5311c4df1c871ff6b3830817fd1d76e0a1fb4bc07aaa369bcf"


def sha(data):
    return hashlib.sha256(data).digest()


def unsigned_bytes():
    payload = b"".join(struct.pack("<QQ", i, 1) for i in range(1, 17)) + bytes(12)
    header = struct.pack("<IHHII16s4Q", 0x43594F46, 1, 256, 320 + len(payload), len(payload),
                         UUID, 1, 1, 1, 1)
    header += b"".join(map(sha, CATALOG)) + sha(payload) + bytes(64)
    assert len(header) == 256
    return header + payload


def signed_vector(path):
    # PKCS#8 Ed25519 private key, RFC 8410. No production key material.
    key = path / "test-key.der"
    key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + SEED)
    message = path / "message"
    message.write_bytes(LABEL + unsigned_bytes())
    signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin",
                                          "-inkey", str(key), "-keyform", "DER",
                                          "-in", str(message)])
    return unsigned_bytes() + signature


class SignedScratchVector(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for independent encoder")
    def test_wire_signature_and_committed_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            encoded = signed_vector(Path(directory))
            self.assertEqual(FIXTURE.read_bytes(), encoded)
            self.assertEqual(sha(encoded).hex(), EXPECTED_SHA256)


if __name__ == "__main__":
    unittest.main()
