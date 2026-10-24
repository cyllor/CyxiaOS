import struct
import unittest

from verify_domains import ALL_FAMILIES, CONTROL_MAGIC, CONTROL_WORDS, IPI_MAGIC, UNIFIED_MAGIC, diagnostics, parse_control, parse_ipi, parse_tasks, parse_unified


def encode(values):
    return struct.pack(f"<{len(values)}Q", *values)


def control():
    values = [0] * CONTROL_WORDS
    values[:4] = [CONTROL_MAGIC, 1, 7, ALL_FAMILIES]
    values[12:14] = [64, 640]
    return values


class EvidenceParserTests(unittest.TestCase):
    def test_truncated_capture_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "size"):
            parse_control(encode(control())[:-8])

    def test_boot_identity_must_match(self):
        with self.assertRaisesRegex(ValueError, "BootEpoch"):
            parse_control(encode(control()), boot_epoch=8)

    def test_registered_families_are_not_execution(self):
        result = parse_control(encode(control()), boot_epoch=7)
        self.assertEqual(result["registered_families"], ALL_FAMILIES)
        self.assertEqual(result["applied_objects"], [])

    def test_applied_cannot_be_configuration_only(self):
        values = control()
        at = 512
        for index, value in {0: 1, 1: 1, 2: 4, 3: 1, 4: 22, 5: 7,
                             7: 7, 8: 1, 9: 2, 14: 2, 28: 3, 30: 1}.items():
            values[at + index] = value
        with self.assertRaisesRegex(ValueError, "published EL0 reply"):
            parse_control(encode(values))
        values[at + 639] = 1
        self.assertEqual(parse_control(encode(values))["applied_objects"], [])

    def test_fatal_and_nonzero_file_exit_never_pass(self):
        values = [0] * 512
        values[15] = 25
        with self.assertRaisesRegex(ValueError, "fatal code 25"):
            parse_unified(encode(values))
        values[0:2] = [UNIFIED_MAGIC, 7]
        values[15:21] = [0, 1, 4096, 4, 1, 16]
        with self.assertRaisesRegex(ValueError, "exit code 16"):
            parse_unified(encode(values))

    def test_disabled_file_probe_is_not_success(self):
        values = [0] * 512
        values[0:2] = [UNIFIED_MAGIC, 7]
        with self.assertRaisesRegex(ValueError, "enabled ordinary EL0 file probe"):
            parse_unified(encode(values))

    def test_business_core_quarantine_cannot_hide_behind_control_progress(self):
        values = [0] * 32
        values[0] = 0x43595441534B0001
        values[2] = 12
        values[3] = 2
        with self.assertRaisesRegex(ValueError, "overrun/quarantine"):
            parse_tasks(encode(values))

    def test_published_overrun_remains_a_real_receipt_but_fails_acceptance(self):
        values = control()
        at = 512
        for index, value in {0: 1, 1: 1, 7: 7, 12: 500_001,
                             13: 1, 14: 1, 18: 1, 30: 1}.items():
            values[at + index] = value
        with self.assertRaisesRegex(ValueError, "0.5 ms publication"):
            parse_control(encode(values))
        values[at + 12] = 500_000
        values[at + 18] = 0
        values[at + 10] = 1_900_000
        values[at + 11] = 100_000
        values[at + 29] = 1
        with self.assertRaisesRegex(ValueError, "encoding/inference/decoding"):
            parse_control(encode(values))

    def test_sticky_credit_failure_cannot_be_hidden_by_old_task_snapshot(self):
        task = [0] * 32
        task[0] = 0x43595441534B0001
        sticky = [0] * 32
        sticky[:2] = [0x43594F5652520001, 1]
        with self.assertRaisesRegex(ValueError, "sticky CPU credit overrun"):
            diagnostics({}, {
                "UNIFIED_EVIDENCE": encode([0] * 512),
                "DOMAIN_TASK_EVIDENCE": encode(task),
                "TASK_OVERRUN_EVIDENCE": encode(sticky),
            })

    def test_ipi_notification_is_not_a_completed_wake(self):
        values = [0] * 512
        values[:5] = [IPI_MAGIC, 1, 15, 1, 3]
        values[8] = 3
        self.assertFalse(parse_ipi(encode(values))["wake_verified"])
        values[5:7] = [1, 1]
        values[10] = 1
        self.assertFalse(parse_ipi(encode(values))["wake_verified"])
        values[5:7] = [2, 2]
        values[9] = 1
        self.assertTrue(parse_ipi(encode(values))["wake_verified"])

    def test_ipi_receipt_must_have_real_handler_and_consume(self):
        values = [0] * 512
        values[:5] = [IPI_MAGIC, 1, 15, 1, 3]
        values[8:10] = [3, 1]
        with self.assertRaisesRegex(ValueError, "real handler receipt"):
            parse_ipi(encode(values))
        values[5:7] = [1, 1]
        values[13] = 2
        with self.assertRaisesRegex(ValueError, "IPI receipt error 2"):
            parse_ipi(encode(values))


if __name__ == "__main__":
    unittest.main()
