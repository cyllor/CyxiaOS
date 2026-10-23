"""Ensure the edge acceptance gate rejects incomplete or misleading evidence."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_edge as verify


def successful_log():
    rows = verify.MARKERS[:5] + [verify.EXITS[0]] + verify.MARKERS[5:] + [verify.EXITS[1]]
    return ("\r\n".join(rows) + "\r\n").encode()


class EdgeEvidenceTests(unittest.TestCase):
    def test_every_stage_and_exact_check_count_required(self):
        good = successful_log()
        self.assertEqual(verify.validate(good)["checks"], 168)
        for marker in verify.MARKERS:
            encoded = (marker + "\r\n").encode()
            for bad in (good.replace(encoded, b""), good.replace(encoded, encoded * 2),
                        good.replace(encoded, encoded.replace(b"PASS", b"FAIL"))):
                with self.subTest(marker=marker), self.assertRaises(AssertionError):
                    verify.validate(bad)
        for bad in (good.replace(b"checks=168", b"checks=169"),
                    good.replace(b"checks=168", b"checks=136"),
                    good.replace(b"COUNTERS", b"COUNT\r\nERS"),
                    good + b"noise EDGE_PROBE TIMERS PASS\r\n",
                    good.replace(b"COUNTERS", b"TEMP").replace(b"STREAMS", b"COUNTERS").replace(b"TEMP", b"STREAMS")):
            with self.assertRaises(AssertionError):
                verify.validate(bad)

    def test_exit_fault_order_and_cleanup_records_required(self):
        good = successful_log()
        for exit_record in verify.EXITS:
            encoded = exit_record.encode()
            for bad in (good.replace(encoded, b""), good.replace(encoded, encoded + b"\r\n" + encoded),
                        good.replace(encoded, encoded.replace(b"code=0", b"code=139")),
                        good.replace(encoded, encoded.replace(b"far=0x0", b"far=0x18")),
                        good.replace(encoded, encoded.replace(b"Exited", b"Fault"))):
                with self.subTest(exit_record=exit_record), self.assertRaises(AssertionError):
                    verify.validate(bad)
        child = (verify.EXITS[0] + "\r\n").encode()
        for bad in (child + good.replace(child, b""),
                    good.replace(b"free_pages=64", b"free_pages=63"),
                    good + b"EL0 pid=3 Exited code=0 free_pages=64 esr=0x0 far=0x0\r\n",
                    good + b"KERNEL_FAULT\r\n", good + b"panicked\r\n"):
            with self.assertRaises(AssertionError):
                verify.validate(bad)

    def test_retained_process_must_be_real_clean_ai_scheduled(self):
        row = dict(pid=1, parent_pid=0, state="Exited", code=0, exit_signal=0,
                   esr=0, far=0, free_pages=64, heap_pages=0, heap_free=4096,
                   heap_model=0, image_pages=0, image_free=4096, thread_count=0,
                   thread_peak=1, thread_admissions=0, thread_denials=0,
                   rank_model=12289, cpu_model=12290, guard_selections=0,
                   thread_guard_selections=0, syscalls=200, ai_selections=40, thread_ai_selections=40)
        verify.validate_processes({1: row}, 4096)
        child = dict(row, pid=2, parent_pid=1)
        verify.validate_processes({1: row, 2: child}, 4096)
        for key, value in dict(exit_signal=11, heap_pages=1, image_free=4095,
                               thread_count=1, ai_selections=0, rank_model=0).items():
            with self.subTest(key=key), self.assertRaises(AssertionError):
                verify.validate_processes({1: dict(row, **{key: value})}, 4096)
        with self.assertRaises(AssertionError):
            verify.validate_processes({2: child}, 4096)

    def test_unbalanced_ai_or_live_objects_rejected(self):
        before = {
            "ai": {},
            "OFD_OBJECTS": dict.fromkeys(("live", "references", "epolls", "watches", "fd_refs",
                                         "staged_refs", "inflight_refs", "staged_messages", "inflight_messages"), 0),
            "ANCILLARY_OBJECTS": dict.fromkeys(("messages", "references", "staged_messages",
                                               "inflight_messages", "staged_refs", "inflight_refs"), 0),
            "SHARED_OBJECTS": dict.fromkeys(("objects", "pages", "mappings", "description_refs",
                                           "mapping_refs", "grant_reserved", "grant_used"), 0),
        }
        before["SHARED_OBJECTS"].update(available="true", free_pages=4096, page_capacity=4096)
        after = copy.deepcopy(before)
        for domain in verify.DOMAINS:
            before["ai"][domain] = dict(requests=0, committed=0, denied=0, capacity=0,
                                       invalid=0, failed=0, ai=0, approved=0, proposals=0,
                                       grant_units=0, release_units=0)
            after["ai"][domain] = dict(requests=1, committed=1, denied=0, capacity=0,
                                      invalid=0, failed=0, ai=1, approved=1, proposals=1,
                                      grant_units=1, release_units=1)
        verify.validate_accounting(before, after)
        for name, field, value in (("OFD_OBJECTS", "watches", 1),
                                    ("ANCILLARY_OBJECTS", "references", 1),
                                    ("SHARED_OBJECTS", "pages", 1)):
            bad = copy.deepcopy(after)
            bad[name][field] = value
            with self.assertRaises(AssertionError):
                verify.validate_accounting(before, bad)
        for field in ("release_units", "requests", "ai"):
            bad = copy.deepcopy(after)
            bad["ai"]["unix"][field] += 1
            with self.assertRaises(AssertionError):
                verify.validate_accounting(before, bad)

    def test_existing_evidence_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            marker = output / "summary.json"
            marker.write_text("preserved failure\n")
            with self.assertRaises(FileExistsError):
                verify.verify(output / "missing-kernel.elf", output)
            self.assertEqual(marker.read_text(), "preserved failure\n")


if __name__ == "__main__":
    unittest.main()
