"""Local QEMU transport and peer helpers for the V0.20 verifier."""
import hashlib
from pathlib import Path
import socket
import subprocess
import threading
import time

import v020_tls_peer
import verify_smp


# Fixed 512-byte host-peer sample (same bytes Task 5 measured). It is NOT a TLS
# ClientHello: the guest's rustls rejects it and parks, so no echo is expected.
PEER_SAMPLE = bytes((i * 7 + 3) & 0xFF for i in range(512))
PEER_WAIT_SECONDS = 5.0
GA_RAM = "256M"
# The staging feature enables prototype-memory (RAM_MIB = 1024; task-6 ruling).
STAGING_RAM = "1024M"
SCRATCH_BYTES = 512 * 1024 * 1024
NATIVE_MAC = "52:54:00:12:34:56"



def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def qemu_args(binary: str, qmp_path: str, elf: Path, port: int,
              scratch: Path | None = None, nic: bool = True, rng: bool = False,
              qmp_stdio: bool = False) -> list:
    """Pinned G-A argv; `scratch` selects the media-staging lane (-m 1024M + blk)."""
    ram = STAGING_RAM if scratch is not None else GA_RAM
    args = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
            "-cpu", "cortex-a53", "-smp", "4", "-m", ram, "-accel", "tcg,thread=multi",
            "-display", "none", "-monitor", "none"]
    if nic:
        # `-nic user,model=virtio-net-device` is not created on virt, and the
        # driver accepts modern (version 2) virtio-mmio only (task-5 ruling).
        args += ["-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:7",
                 "-device", f"virtio-net-device,netdev=n0,mac={NATIVE_MAC}"]
    else:
        args += ["-nic", "none"]
    if nic or rng or scratch is not None:
        args += ["-global", "virtio-mmio.force-legacy=false"]
    if rng:
        args += ["-object", "rng-random,id=rng0,filename=/dev/urandom",
                 "-device", "virtio-rng-device,rng=rng0"]
    if scratch is not None:
        args += ["-drive", f"file={scratch},if=none,id=scratch,format=raw,cache=none",
                 "-device", "virtio-blk-device,drive=scratch"]
    return args + ["-chardev", "ringbuf,id=cyxlog,size=1048576", "-serial", "chardev:cyxlog",
                   "-qmp", "stdio" if qmp_stdio else f"unix:{qmp_path},server=on,wait=off",
                   "-kernel", str(elf),
                   "-no-reboot"]


class HostPeer(threading.Thread):
    """Connect through hostfwd after the guest has begun listening."""

    def __init__(self, port: int, authenticated: bool = False, orderly_close: bool = True) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.authenticated = authenticated
        self.orderly_close = orderly_close
        self.listening = threading.Event()
        self.stopping = threading.Event()
        self.result: dict = {"sent": 0, "received": 0}

    def run(self) -> None:
        while not self.listening.wait(0.05):
            if self.stopping.is_set():
                self.result["error"] = "guest never listened"
                return
        try:
            if self.authenticated:
                self.result = v020_tls_peer.exchange(
                    self.port, PEER_WAIT_SECONDS, orderly_close=self.orderly_close
                )
                return
            with socket.create_connection(("127.0.0.1", self.port),
                                          timeout=PEER_WAIT_SECONDS) as conn:
                conn.sendall(PEER_SAMPLE)
                self.result["sent"] = len(PEER_SAMPLE)
                self.result["closed_by_guest"] = self.drain(conn)
        except (OSError, EOFError, ValueError, RuntimeError) as error:
            self.result["error"] = type(error).__name__ + ": " + str(error)

    def drain(self, conn: socket.socket) -> bool:
        deadline = time.monotonic() + PEER_WAIT_SECONDS
        while not self.stopping.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            conn.settimeout(min(left, 0.25))
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return True
            self.result["received"] += len(chunk)
        return False


def create_scratch(path: Path) -> None:
    with path.open("xb") as handle:
        handle.truncate(SCRATCH_BYTES)


def scratch_summary(path: Path) -> dict:
    nonzero = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4096), b""):
            nonzero += any(block)
    return {"scratch_bytes": SCRATCH_BYTES, "scratch_after_sha256": sha(path),
            "scratch_after_nonzero_blocks": nonzero}


def shutdown(proc, qmp) -> None:
    if proc.poll() is None:
        try:
            if qmp:
                qmp.execute("quit")
        except (OSError, ValueError, RuntimeError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=2)


def connect_qmp(proc, path: str, end: float):
    require = verify_smp.require
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        require(proc.poll() is None, "QEMU exited before handshake")
        if time.monotonic() >= end:
            raise TimeoutError("QMP handshake deadline")
        try:
            sock.connect(path)
            return sock
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.01)
