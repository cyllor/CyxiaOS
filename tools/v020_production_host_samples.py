"""Bounded, diagnostic-only host observations for the scratch media lane.

Host monotonic time is not guest time. PSI is host-wide and schedstat covers
only the QEMU main/vCPU threads, not all workers. Neither implies a cause of
an individual guest timeout. No QMP commands, guest writes or admission inputs.
"""
from pathlib import Path
import time


class HostMediaSamples:
    INTERVAL_NS = 250_000_000
    # The verifier caps the run at 300s; leave room for forced boundary samples.
    MAX_SAMPLES = 1204
    READ_LIMIT = 4096

    def __init__(self, pid, cpus, *, proc_root=Path("/proc"), clock=time.monotonic_ns):
        self.pid = pid
        self.proc_root = proc_root
        self.clock = clock
        self.origin = clock()
        self.next_ns = self.origin
        self.vcpu_threads = {str(i): None for i in range(4)}
        records = cpus[:4] if isinstance(cpus, list) else []
        for cpu in records:
            if not isinstance(cpu, dict):
                continue
            index, tid = cpu.get("cpu-index"), cpu.get("thread-id")
            if type(index) is int and 0 <= index < 4 and type(tid) is int and tid > 0:
                self.vcpu_threads[str(index)] = tid
        self.samples = []
        self.limit_reached = False
        self.polls = 0
        self.max_ringbuf_ns = 0

    def _read(self, path):
        try:
            with path.open(encoding="utf-8") as stream:
                value = stream.read(self.READ_LIMIT + 1)
            return {"text": value[:self.READ_LIMIT], "truncated": len(value) > self.READ_LIMIT}
        except (OSError, UnicodeError) as error:
            return {"unavailable": type(error).__name__}

    def observe(self, serial_bytes, ringbuf_ns=None, *, phase="poll"):
        """Aggregate completed ringbuf reads; force only named run boundaries."""
        if ringbuf_ns is not None:
            self.polls += 1
            self.max_ringbuf_ns = max(self.max_ringbuf_ns, ringbuf_ns)
        now = self.clock()
        if phase == "poll" and now < self.next_ns:
            return
        if len(self.samples) >= self.MAX_SAMPLES:
            self.limit_reached = True
            return
        self.next_ns = now + self.INTERVAL_NS
        proc = self.proc_root / str(self.pid)
        row = {
            "phase": phase, "elapsed_ns": now - self.origin,
            "decoded_serial_bytes": serial_bytes,
            "completed_ringbuf_reads": self.polls,
            "max_ringbuf_ns": self.max_ringbuf_ns,
            "host_cpu_psi": self._read(self.proc_root / "pressure/cpu"),
            "host_io_psi": self._read(self.proc_root / "pressure/io"),
            "qemu_io": self._read(proc / "io"),
            "qemu_main_schedstat": self._read(proc / "task" / str(self.pid) / "schedstat"),
            "vcpu_schedstat": {
                index: self._read(proc / "task" / str(tid) / "schedstat")
                if tid is not None else {"unavailable": "no QMP thread id"}
                for index, tid in self.vcpu_threads.items()
            },
        }
        row["sample_cost_ns"] = self.clock() - now
        self.samples.append(row)
        self.polls = 0
        self.max_ringbuf_ns = 0

    def evidence(self):
        return {
            "scope": "diagnostic host monotonic time, not guest deadline proof",
            "interval_ns": self.INTERVAL_NS, "max_samples": self.MAX_SAMPLES,
            "limit_reached": self.limit_reached, "qemu_pid": self.pid,
            "vcpu_threads": self.vcpu_threads, "samples": self.samples,
            "unsampled_completed_ringbuf_reads": self.polls,
            "unsampled_max_ringbuf_ns": self.max_ringbuf_ns,
        }
