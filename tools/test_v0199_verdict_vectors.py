"""Independent Verdict v4 reference bytes for G1 and archive regression tests."""

from hashlib import sha256
from pathlib import Path
import unittest

import verify_v0199_verdicts as archive


VECTORS = Path(__file__).with_name("fixtures") / "v0199-verdict-v4.tsv"
RUN = 0x0123456789ABCDEF
CHECKER_VERSION = 0x01020304
EPOCHS = tuple(int.from_bytes(bytes(range(i, i + 8)), "big") for i in range(16, 64, 8))
HASHES = tuple(bytes(range(i, i + 32)) for i in range(1, 162, 32))


def add_digest(prefix):
    return bytes(prefix) + sha256(b"CYX/VERDICT/v4" + prefix).digest()


def reference_record(case, proof, status, reason, count):
    """Encode the offsets in 安§0.9 using the reference fixture fields."""
    prefix = bytearray(288)
    fields = [
        (0, 4, 0x43595632), (4, 2, 4), (6, 2, 320), (8, 8, RUN),
        (16, 4, case), (20, 2, status), (22, 2, proof),
        (24, 4, (case & 0xFFFF0000) | 0x3412), (28, 4, CHECKER_VERSION),
        (32, 4, reason), (36, 4, count),
        *((40 + 8 * i, 8, value) for i, value in enumerate(EPOCHS)),
    ]
    for at, width, value in fields:
        prefix[at:at + width] = value.to_bytes(width, "little")
    for i, value in enumerate(HASHES[:5]):
        offset = 96 + i * 32
        prefix[offset:offset + 32] = value
    if count:
        prefix[256:288] = HASHES[5]
    return add_digest(prefix)


class VerdictVectors(unittest.TestCase):
    def test_frozen_bytes_cross_check_archive_parser(self):
        _, g5, _, _ = archive.inventory()
        reasons = set()
        proofs = set()
        for line in VECTORS.read_text(encoding="ascii").splitlines():
            if line.startswith("#"):
                continue
            name, case, proof, status, reason, count, hex_wire = line.split("\t")
            case = int(case, 16)
            proof, status, reason, count = map(int, (proof, status, reason, count))
            with self.subTest(name=name):
                raw = bytes.fromhex(hex_wire)
                self.assertIn((case, proof), g5)
                self.assertEqual(raw, reference_record(case, proof, status, reason, count))
                self.assertEqual(archive.parse(raw), {
                    "test_id": case, "proof_class": proof, "run_id": RUN,
                    "status": ("NOT_RUN", "PASS", "FAIL")[status],
                    "checker_id": (case & 0xFFFF0000) | 0x3412, "checker_version": CHECKER_VERSION,
                    "reason": reason, "evidence_count": count,
                    **dict(zip(("boot_epoch", "controller_epoch", "security_epoch",
                                "object_or_stream_generation", "seed", "fault_point_id"), EPOCHS, strict=True)),
                    **dict(zip(("design_hash", "binary_hash", "security_profile_hash", "input_hash", "rule_hash"),
                               (value.hex() for value in HASHES[:5]), strict=True)),
                    "evidence_digest": (HASHES[5] if count else bytes(32)).hex(),
                })
            reasons.add(reason)
            proofs.add(proof)
        self.assertEqual(reasons, set(range(10)))
        self.assertEqual(proofs, {1, 2, 3, 4})

    def test_all_required_g4_wire_keys_match_the_frozen_corpus_digest(self):
        g4, _, ids, _ = archive.inventory()
        lines = VECTORS.read_text(encoding="ascii").splitlines()
        golden = next(line.removeprefix("# g4-corpus-sha256: ")
                      for line in lines
                      if line.startswith("# g4-corpus-sha256: "))
        pairs = []
        for line in lines:
            if line.startswith("# g4-pairs: "):
                for token in line.removeprefix("# g4-pairs: ").split():
                    test, proof = token.split("-")
                    pairs.append((int(test, 16), int(proof)))
        self.assertEqual(pairs, sorted(g4))
        digest = sha256()
        seen = set()
        for test, proof in sorted(g4):
            raw = reference_record(test, proof, 0, 2, 0)
            digest.update(raw)
            decoded = archive.parse(raw)
            self.assertEqual((decoded["test_id"], decoded["proof_class"], decoded["status"], decoded["reason"]),
                             (test, proof, "NOT_RUN", 2))
            seen.add(test)
        self.assertEqual(seen, set(ids))
        self.assertEqual(len(g4), 262)
        self.assertEqual(digest.hexdigest(), golden)

    def test_rehashed_invalid_fields_and_truncated_records_are_rejected(self):
        raw = reference_record(0x00050008, 1, 1, 0, 2)
        mutations = (
            (0, 4, 0), (4, 2, 3), (6, 2, 319), (8, 8, 0),
            (16, 4, 0x0008000C), (20, 2, 3), (22, 2, 5),
            (24, 4, 0x00060001), (24, 4, 0x00050000), (28, 4, 0),
            (32, 4, 4), (36, 4, 0), (88, 8, 1), (256, 32, 0),
        )
        for offset, width, value in mutations:
            with self.subTest(offset=offset, value=value):
                prefix = bytearray(raw[:288])
                prefix[offset:offset + width] = value.to_bytes(width, "little")
                with self.assertRaises(ValueError):
                    archive.parse(add_digest(prefix))
        for damaged in (raw[:-1], raw + b"\0", raw[:-1] + bytes([raw[-1] ^ 1])):
            with self.assertRaises(ValueError):
                archive.parse(damaged)


if __name__ == "__main__":
    unittest.main()
