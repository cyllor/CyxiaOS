"""Check that a refused writable mount requires corroborating device evidence."""

import copy
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_v0199_d08_flush as check
import verify_v020_signed_resident as resident


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

    def test_qmp_replay_requires_ordered_responses_and_exact_serial(self):
        disk = Path("/scratch.raw")
        records = [{"direction": "receive", "message": {"QMP": {}}}]
        index = 0

        def exchange(command, response, args=None):
            nonlocal index
            index += 1
            request = {"execute": command, "id": index}
            if args is not None:
                request["arguments"] = args
            records.extend((
                {"direction": "send", "message": request},
                {"direction": "receive", "message": {"id": index, "return": response}},
            ))

        def snapshot(count):
            exchange("x-query-virtio", [{"path": "/d08"}])
            exchange("x-query-virtio-status", {"device-id": 2}, {"path": "/d08"})
            exchange("query-block", [{"device": "scratch", "qdev": "d08",
                                      "inserted": {"file": str(disk)}}])
            exchange("query-blockstats", [{"device": "scratch",
                                           "stats": dict.fromkeys(check.COUNTERS, count)}])

        exchange("qmp_capabilities", {})
        exchange("query-cpus-fast", [{"cpu-index": i, "qom-type": "cortex-a53-arm-cpu"}
                                     for i in range(4)])
        exchange("query-memory-size-summary", {"base-memory": 1024**3, "plugged-memory": 0})
        snapshot(0)
        exchange("cont", {})
        exchange("ringbuf-read", "YWJj", {"device": "cyxlog", "size": 65536, "format": "base64"})
        exchange("stop", {})
        snapshot(1)
        exchange("quit", {})
        initial, final = check.replay_reopen_qmp(records, b"abc", disk)
        self.assertEqual(initial["operations"], dict.fromkeys(check.COUNTERS, 0))
        self.assertEqual(final["operations"], dict.fromkeys(check.COUNTERS, 1))
        # An exit response can be absent after a clean disconnect; other replies cannot.
        self.assertEqual(check.replay_reopen_qmp(records[:-1], b"abc", disk), (initial, final))
        for changed in (records[:2] + records[3:], records[:3] + [records[2]] + records[3:]):
            with self.assertRaises(ValueError):
                check.replay_reopen_qmp(changed, b"abc", disk)
        altered = copy.deepcopy(records)
        next(row for row in altered if row["message"].get("execute") == "stop")["message"]["execute"] = "cont"
        with self.assertRaises(ValueError):
            check.replay_reopen_qmp(altered, b"abc", disk)
        with self.assertRaises(ValueError):
            check.replay_reopen_qmp(records, b"abd", disk)
        with self.assertRaises(ValueError):
            check.replay_reopen_qmp(records, b"abc", Path("/another.raw"))


    def test_preserved_disks_survive_next_writable_boot(self):
        with tempfile.TemporaryDirectory() as d, patch.object(check, "SCRATCH_BYTES", 16):
            root = Path(d)
            disk = root / "scratch.raw"
            disk.write_bytes(b"0123456789abcdef")
            expected = check.sha(disk)
            seed = root / "seed.raw"
            negative = root / "negative.raw"
            self.assertEqual(check.preserve_disk(disk, seed, expected), expected)
            self.assertEqual(check.preserve_disk(disk, negative, expected), expected)
            disk.write_bytes(b"fedcba9876543210")
            self.assertEqual(check.sha(seed), expected)
            self.assertEqual(check.sha(negative), expected)
            self.assertNotEqual(check.sha(disk), expected)
            with self.assertRaisesRegex(ValueError, "preserved disk differs"):
                check.preserve_disk(disk, root / "mismatch.raw", expected)
            with self.assertRaises(FileExistsError):
                check.preserve_disk(disk, seed, check.sha(disk))
            self.assertEqual(check.sha(seed), expected)
            disk.write_bytes(b"short")
            with self.assertRaisesRegex(ValueError, "unexpected scratch image size"):
                check.preserve_disk(disk, root / "short.raw", check.sha(disk))


    def test_decision_return_prefix(self):
        raw = bytearray(resident.DECISION_RETURN_BYTES)
        struct.pack_into("<Q", raw, 0, 2)
        row = resident.DECISION_RETURN_ROW
        row.pack_into(raw, 8, 100, 2, 9, 0, 0x10000, 4)
        row.pack_into(raw, 8 + row.size, 200, 3, 8, 0x15 << 26, 0x10004, 2)
        # Stopped mid-write: ignore an unpublished row, not a complete one.
        row.pack_into(raw, 8 + 2 * row.size, 300, 2, 8, 0, 0, 4)
        parsed = resident.decode_decision_returns(raw)
        self.assertEqual([item["kind"] for item in parsed], [9, 8])
        self.assertEqual([item["x8"] for item in parsed], [4, 2])
        for offset, value in ((0, 33), (16, 5), (24, 0), (8 + row.size, 99)):
            with self.subTest(offset=offset):
                malformed = bytearray(raw)
                struct.pack_into("<Q", malformed, offset, value)
                with self.assertRaises(ValueError):
                    resident.decode_decision_returns(malformed)
        with self.assertRaises(ValueError):
            resident.decode_decision_returns(raw[:-1])

    def test_failed_progress_trace_retains_raw_capture(self):
        for late_error in (False, True):
            with self.subTest(late_error=late_error), tempfile.TemporaryDirectory() as d:
                root = Path(d)

                def capture(socket_path, elf, output, deadline):
                    (output / resident.TRACE_FILE).write_bytes(b"raw trace fixture")
                    (output / "budget-qmp.jsonl").write_bytes(b"raw QMP fixture")
                    (output / "role-syscall-abi.bin").write_bytes(b"raw ABI fixture")
                    (output / resident.DECISION_RETURN_FILE).write_bytes(b"raw return fixture")
                    if late_error:
                        raise ValueError("ABI mismatch after pmemsave")
                    return {"budget_trace_sha256": check.sha(output / resident.TRACE_FILE)}

                with patch.object(resident, "capture_budget_trace", side_effect=capture) as qmp:
                    result = resident.retain_failed_progress_trace(
                        root / "socket", root / "elf", root, 123)
                    self.assertEqual(result["status"], "CAPTURE_ERROR" if late_error else "CAPTURED")
                    self.assertEqual(result["capture_sha256"], {
                        name: check.sha(root / "failed-progress" / name)
                        for name in (resident.TRACE_FILE, "budget-qmp.jsonl",
                                     "role-syscall-abi.bin", resident.DECISION_RETURN_FILE)
                    })
                    if late_error:
                        self.assertIn("ABI mismatch", result["error"])
                    repeated = resident.retain_failed_progress_trace(
                        root / "socket", root / "elf", root, 123)
                    self.assertEqual(repeated["status"], "CAPTURE_ERROR")
                    self.assertEqual(qmp.call_count, 1)

    def test_failed_seed_is_sealed_but_never_admitted(self):
        with tempfile.TemporaryDirectory() as d, patch.object(check, "SCRATCH_BYTES", 16):
            root = Path(d)
            for name in ("serial.bin", "serial.txt", "qemu-stderr.log"):
                (root / name).write_bytes(name.encode())
            disk = root / "disk.raw"
            disk.write_bytes(b"0123456789abcdef")
            (root / "cpu0-budget-trace.bin").write_bytes(b"trace")
            (root / "budget-qmp.jsonl").write_bytes(b"qmp")
            seed = {"status": "FAIL", "error": "incomplete role progress"}
            with self.assertRaisesRegex(ValueError, "incomplete role progress"):
                check.seal_seed_capture(seed, root, disk)
            self.assertEqual(seed["status"], "FAIL")
            self.assertEqual(seed["capture_sha256"], {
                name: check.sha(root / name)
                for name in ("serial.bin", "serial.txt", "qemu-stderr.log",
                             "cpu0-budget-trace.bin", "budget-qmp.jsonl")
            })
            self.assertEqual(seed["preserved_disk_sha256"], check.sha(disk))
            self.assertEqual(check.sha(root / "scratch-after.raw"), check.sha(disk))


if __name__ == "__main__":
    unittest.main()
