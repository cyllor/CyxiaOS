import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ServiceTlsExitDiagnosticsTests(unittest.TestCase):
    def test_diagnostic_is_one_shot_and_fault_profile_only(self):
        runtime = (ROOT / "user/prototype-cluster/src/runtime.rs").read_text()
        self.assertIn("broker::service_fault_enabled()", runtime)
        self.assertIn("unauthenticated_exit", runtime)
        self.assertIn("!reported_unauthenticated_exit", runtime)
        self.assertEqual(runtime.count("broker::trace(exit_reason.trace_event())"), 1)

    def test_reason_codes_are_non_authoritative_trace_events(self):
        source = (ROOT / "user/prototype-cluster/src/session_exit.rs").read_text()
        self.assertIn("pub const EVENT_BASE: u64 = 0x230", source)
        self.assertIn("why the EL0 service left one session", source)
        self.assertNotIn("authenticated_peer", source)
        self.assertNotIn("driver.connect", source)


if __name__ == "__main__":
    unittest.main()
