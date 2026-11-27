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

        # Correct attachment error and zero I/O are not sufficient if another
        # trace contradicts the refusal. These mutations passed the old judge.
        for marker in (
            "V020_W11_MEDIA_IO_ERROR a=6 b=0 c=13",
            "V020_SEC_D_BLOCK_MMIO_UNKNOWN a=2 b=0 c=5",
            "V020_SIGNED_RESIDENT_PROGRESS a=1 b=65535 c=34680",
            "V020_SIGNED_RESIDENT_CPU a=1 b=1 c=0",
            "V020_W11_MEDIA_IO_ERROR malformed",
        ):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                check.check_reopen(lines + [marker], snapshot, flush=False,
                                   before=before, after=before)

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

    def test_writable_mount_requires_ordered_confirmation_and_no_io_error(self):
        step = "V020_W11_MEDIA_STEP a=4 b=1 c=2"
        boot = f"V020_SIGNED_RESIDENT_BOOT a=2 b={len(check.ROLES)} c=0"
        lines = ["SMP_BOOT_OK a=4 b=15 c=0", step, boot]
        snapshot = {
            "virtio": {
                "device-id": 2,
                "host-features": {"dev-features": [check.FLUSH], "transports": [check.VERSION_1]},
                "guest-features": {"dev-features": [check.FLUSH]},
                "status": {"statuses": [check.DRIVER_OK]},
            },
            "drive": {"ro": False, "drv": "raw", "image": {"virtual-size": check.SCRATCH_BYTES},
                      "cache": {"no-flush": False}},
            "operations": dict.fromkeys(check.COUNTERS, 1),
        }
        before, after = "11" * 32, "22" * 32
        check.check_reopen(lines, snapshot, flush=True, before=before, after=after)
        for invalid in (
            [lines[0], boot, step],
            lines + ["V020_W11_MEDIA_IO_ERROR a=6 b=0 c=13"],
            lines + ["V020_SEC_D_BLOCK_MMIO_UNKNOWN a=2 b=0 c=5"],
        ):
            with self.subTest(lines=invalid), self.assertRaises(ValueError):
                check.check_reopen(invalid, snapshot, flush=True, before=before, after=after)


if __name__ == "__main__":
    unittest.main()
