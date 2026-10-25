import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from build_unified import ROOT, audit_private_images, identity_metadata


class BillingProvisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.pair = Path(temporary.name) / "pair"
        subprocess.run([sys.executable, str(ROOT / "user/prototype-cluster/tools/provision.py"), str(self.pair)],
                       check=True, capture_output=True, timeout=20)

    def test_real_ed25519_billing_keys_are_distinct_mutually_pinned_and_private(self):
        nodes = [self.pair / name for name in ("a", "b")]
        metadata = [identity_metadata(node) for node in nodes]
        for i, node in enumerate(nodes):
            self.assertEqual(metadata[i]["billing_public_hex"], metadata[1-i]["peer_billing_public_hex"])
            for name in ("billing.seed", "billing.pub", "peer.billing.pub"):
                self.assertEqual((node / name).stat().st_mode & 0o777, 0o600)
            seed = (node / "billing.seed").read_bytes()
            self.assertTrue(seed != (nodes[1-i] / "billing.seed").read_bytes(), "independent kernel keys")
            self.assertTrue(seed not in (node / "key.der").read_bytes(), "TLS identity cannot sign billing evidence")
        # Test the exact production image gate with explicit byte containers;
        # these containers are not presented as compiled/native evidence.
        own, peer = [(node / "key.der").read_bytes() for node in nodes]
        local_bill, peer_bill = [(node / "billing.seed").read_bytes() for node in nodes]
        service = b"EL0-container" + own
        image = b"EL1-container" + own + local_bill
        audit_private_images(service, image, own, peer, local_bill, peer_bill)
        for bad_service, bad_image in [(service + local_bill, image), (service + peer_bill, image),
                                       (service, image + peer_bill), (service + peer, image),
                                       (service, image + peer), (service, own)]:
            with self.assertRaises(ValueError):
                audit_private_images(bad_service, bad_image, own, peer, local_bill, peer_bill)

    def test_partial_identity_is_not_completed_and_seed_public_mismatch_fails_before_build(self):
        spec = importlib.util.spec_from_file_location("provision_billing_tested", ROOT / "user/prototype-cluster/tools/provision_billing.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        files = {str(p.relative_to(self.pair)): p.read_bytes() for p in self.pair.glob("*/*")}
        with self.assertRaisesRegex(ValueError, "refusing to replace"):
            module.provision(self.pair)
        self.assertTrue(all((self.pair / p).read_bytes() == value for p, value in files.items()), "refusal must leave both identities unchanged")
        (self.pair / "a/billing.seed").write_bytes((self.pair / "b/billing.seed").read_bytes())
        with self.assertRaisesRegex(ValueError, "does not match"):
            identity_metadata(self.pair / "a")
        (self.pair / "a/billing.seed").write_bytes(files["a/billing.seed"])
        (self.pair / "a/billing.pub").unlink()
        with self.assertRaisesRegex(ValueError, "partial billing"):
            module.provision(self.pair)
        self.assertFalse((self.pair / "a/billing.pub").exists())


if __name__ == "__main__":
    unittest.main()
