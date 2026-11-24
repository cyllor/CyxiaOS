"""Negative golden vectors for single-node Cargo closure check."""
import unittest
from tools.verify_v0199_local_link_graph import inspect_tree

BASE = """cyxia-kernel v0.1.0 (/workspace/kernel)
cyxia-kernel-core v0.1.0 (/workspace/crates/kernel-core)
cyxia-prototype v0.1.0 (/workspace/crates/prototype)
cyxia-driver-virtio v0.1.0 (/workspace/crates/driver-virtio)
"""


class NativeLocalClosureTests(unittest.TestCase):
    def test_only_native_core_and_independent_network_pass(self):
        report = inspect_tree(BASE + "cyxia-net-transport v0.1.0 (/workspace/crates/net-transport)\n")
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["native_network_independent"])

    def test_cross_node_transport_and_peer_accounting_fail(self):
        for item in ("cyxia-cluster-transport", "cyxia-peer-billing"):
            with self.subTest(name=item):
                report = inspect_tree(BASE + f"{item} v0.1.0 (/workspace/crates/{item})\n")
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(item, report["prohibited_active"])

    def test_missing_kernel_or_prototype_not_interpreted_as_success(self):
        report = inspect_tree("cyxia-prototype v0.1.0 (/workspace/crates/prototype)\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("cyxia-kernel", report["required_missing"])
        self.assertIn("cyxia-kernel-core", report["required_missing"])

    def test_history_comments_are_not_active_package_entries(self):
        report = inspect_tree(BASE + "# historical cyxia-cluster-transport v0.1.0\n"
                                   + "/src/cyxia-peer-billing v0.1.0\n")
        self.assertEqual(report["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
