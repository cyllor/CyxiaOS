"""Check that a refused writable mount requires corroborating device evidence."""

import copy
import unittest

import verify_v0199_d08_flush as check


class FlushGateTests(unittest.TestCase):
    def test_refusal_requires_observed_feature_drop_and_untouched_media(self):
        lines = ["SMP_BOOT_OK a=4 b=15 c=0", "V020_W11_MEDIA_ATTACH_ERROR a=3 b=0 c=0", check.STARTUP]
        snapshot = {
            "virtio": {
                "device-id": 2,
                "host-features": {"dev-features": [], "transports": [check.VERSION_1]},
                "status": {"statuses": [check.FAILED]},
            },
            "drive": {"ro": False, "drv": "raw", "image": {"virtual-size": check.SCRATCH_BYTES},
                      "cache": {"no-flush": False}},
            "operations": dict.fromkeys(check.COUNTERS, 0),
        }
        before = "11" * 32
        result = check.check_reopen(lines, snapshot, flush=False, before=before, after=before)
        self.assertEqual(result["attach_errors"], [(3, 0, 0)])

        for invalid in (
            {**snapshot, "operations": {**snapshot["operations"], "wr_operations": 1}},
            {**snapshot, "drive": {**snapshot["drive"], "ro": True}},
        ):
            with self.assertRaises(ValueError):
                check.check_reopen(lines, invalid, flush=False, before=before, after=before)
        advertised = copy.deepcopy(snapshot)
        advertised["virtio"]["host-features"]["dev-features"] = [check.FLUSH]
        with self.assertRaisesRegex(ValueError, "FLUSH support differs"):
            check.check_reopen(lines, advertised, flush=False, before=before, after=before)
        with self.assertRaisesRegex(ValueError, "changed the volume"):
            check.check_reopen(lines, snapshot, flush=False, before=before, after="22" * 32)
        with self.assertRaisesRegex(ValueError, "did not fence"):
            check.check_reopen(lines[:-1], snapshot, flush=False, before=before, after=before)


if __name__ == "__main__":
    unittest.main()
