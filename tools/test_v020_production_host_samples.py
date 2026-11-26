"""Synthetic procfs and clock tests; not native timing evidence."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v020_production_host_samples import HostMediaSamples


class HostMediaSamplesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.now = 100
        self.sampler = HostMediaSamples(10, [{"cpu-index": 0, "thread-id": 11}],
                                        proc_root=self.root, clock=lambda: self.now)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def test_cadence_and_completed_poll_aggregate(self):
        self.write("pressure/io", "some total=42\n")
        self.write("10/task/11/schedstat", "10 20 30\n")
        self.sampler.observe(0, phase="start")
        self.now += 100
        self.sampler.observe(5, 400)
        self.now += 100
        self.sampler.observe(7, 800)
        self.assertEqual(len(self.sampler.samples), 1)
        self.now = 100 + self.sampler.INTERVAL_NS
        self.sampler.observe(9, 200)
        row = self.sampler.samples[-1]
        self.assertEqual(row["completed_ringbuf_reads"], 3)
        self.assertEqual(row["max_ringbuf_ns"], 800)
        self.assertEqual(row["elapsed_ns"], self.sampler.INTERVAL_NS)
        self.assertEqual(row["decoded_serial_bytes"], 9)
        self.assertEqual(row["host_io_psi"]["text"], "some total=42\n")
        self.assertEqual(row["vcpu_schedstat"]["0"]["text"], "10 20 30\n")
        self.assertEqual(self.sampler.evidence()["unsampled_completed_ringbuf_reads"], 0)

    def test_unavailable_does_not_forge_zeros(self):
        self.sampler.observe(0, phase="start")
        row = self.sampler.samples[0]
        self.assertEqual(row["host_cpu_psi"], {"unavailable": "FileNotFoundError"})
        self.assertEqual(row["vcpu_schedstat"]["1"], {"unavailable": "no QMP thread id"})

    def test_forced_completion_retains_pending_aggregate(self):
        self.sampler.observe(0, phase="start")
        self.now += 1
        self.sampler.observe(3, 900)
        self.sampler.observe(3, phase="completion")
        row = self.sampler.samples[-1]
        self.assertEqual(row["phase"], "completion")
        self.assertEqual(row["completed_ringbuf_reads"], 1)
        self.assertEqual(row["max_ringbuf_ns"], 900)

    def test_sample_bound_and_unsampled_tail(self):
        self.sampler.MAX_SAMPLES = 1
        self.sampler.observe(0, phase="start")
        self.sampler.observe(1, 17, phase="completion")
        evidence = self.sampler.evidence()
        self.assertTrue(evidence["limit_reached"])
        self.assertEqual(len(evidence["samples"]), 1)
        self.assertEqual(evidence["unsampled_completed_ringbuf_reads"], 1)
        self.assertEqual(evidence["unsampled_max_ringbuf_ns"], 17)

    def test_invalid_qmp_ids_remain_unavailable(self):
        sampler = HostMediaSamples(10, [None, {"cpu-index": True, "thread-id": 11},
                                        {"cpu-index": 0, "thread-id": -1}],
                                   proc_root=self.root, clock=lambda: self.now)
        sampler.observe(0, phase="start")
        self.assertEqual(sampler.vcpu_threads, {str(i): None for i in range(4)})
        self.assertEqual(sampler.samples[0]["vcpu_schedstat"]["0"],
                         {"unavailable": "no QMP thread id"})

    def test_read_bound_is_explicit(self):
        self.write("pressure/cpu", "x" * (self.sampler.READ_LIMIT + 1))
        self.sampler.observe(0, phase="start")
        row = self.sampler.samples[0]["host_cpu_psi"]
        self.assertEqual(len(row["text"]), self.sampler.READ_LIMIT)
        self.assertTrue(row["truncated"])


if __name__ == "__main__":
    unittest.main()
