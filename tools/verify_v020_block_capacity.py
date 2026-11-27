#!/usr/bin/env python3
"""Verify that a normal host capacity expansion fences the signed scratch owner."""

import argparse
import base64
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from qmp_stdio import PipeTransport
from run_qemu import Qmp
from transport import FrameDecoder
from v020_production_modes import Modes, rows
from v020_production_qemu import SCRATCH_BYTES, create_scratch, qemu_args, sha, shutdown
from verify_smp import require
from verify_v020_production import run


EXPANDED_BYTES = SCRATCH_BYTES + 8 * 1024 * 1024
GEOMETRY_ACCEPTED = b"V020_W11_MEDIA_STEP a=1 b=1 c=1\n"
COMPLETE = b"V020_PRODUCTION_SKELETON_PASS "


def disk_snapshot(qmp):
    drive, = (d["inserted"] for d in qmp.execute("query-block") if d["device"] == "scratch")
    stats, = (d["stats"] for d in qmp.execute("query-blockstats") if d.get("device") == "scratch")
    return {"size": drive["image"]["virtual-size"],
            **{key: stats[key] for key in ("rd_operations", "wr_operations", "flush_operations")}}


def original_prefix_sha(path):
    digest = sha256()
    chunk_bytes = 1024 * 1024
    with path.open("rb") as disk:
        for _ in range(SCRATCH_BYTES // chunk_bytes):
            data = disk.read(chunk_bytes)
            require(len(data) == chunk_bytes, "resize lost original volume bytes")
            digest.update(data)
    return digest.hexdigest()


def resize_during_reopen(binary, elf, output, disk, timeout):
    decoder = FrameDecoder()
    serial = bytearray()
    argv = qemu_args(binary, "", elf, 0, scratch=disk, nic=False, qmp_stdio=True)
    with (output / "resize-qemu-stderr.log").open("wb") as stderr:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=stderr, bufsize=0)
        pipe = PipeTransport(proc)
        qmp = Qmp(pipe)

        def collect():
            result = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 1048576, "format": "base64"})
            for frame in decoder.feed(base64.b64decode(result, validate=True)):
                serial.extend(frame)
            require(len(serial) <= 262144, "resize UART evidence exceeded its bound")

        def wait_for(mark):
            while mark not in serial and time.monotonic() < end:
                require(proc.poll() is None, "guest exited during the resize check")
                collect()
                time.sleep(0.001)
            require(mark in serial, f"missing guest observation {mark!r}")

        try:
            end = time.monotonic() + timeout
            require("QMP" in qmp.receive(end), "missing QMP greeting")
            qmp.execute("qmp_capabilities")
            require(len(qmp.execute("query-cpus-fast")) == 4, "expected four guest CPUs")
            wait_for(GEOMETRY_ACCEPTED)
            qmp.execute("stop")
            collect()
            require(b"V020_W11_MEDIA_STEP a=2 b=1" not in serial, "reopen crossed the mount boundary before resize")
            prior = disk_snapshot(qmp)
            require(prior["size"] == SCRATCH_BYTES and prior["rd_operations"] > 0
                    and prior["wr_operations"] == prior["flush_operations"] == 0,
                    "guest did not begin a read-only reopen of the admitted geometry")
            qmp.execute("block_resize", {"device": "scratch", "size": EXPANDED_BYTES})
            require(disk_snapshot(qmp)["size"] == EXPANDED_BYTES, "host capacity change did not take effect")
            qmp.execute("cont")
            wait_for(COMPLETE)
            qmp.execute("stop")
            collect()
            after = disk_snapshot(qmp)
            lines = serial.decode("ascii").splitlines()
            stopped = rows(lines, "V020_SEC_D_BLOCK_MMIO_STOPPED")
            io = rows(lines, "V020_W11_MEDIA_IO")
            custody = rows(lines, "V020_SEC_D_BLOCK_CUSTODY")
            require(len(stopped) == 1 and stopped[0][:2] == (2, 0) and stopped[0][2] > 0
                    and len(custody) == 1 and custody[0][2] == 1,
                    "block owner did not retain custody and observe a real reset")
            recovery = rows(lines, "V020_SEC_D_BLOCK_RECOVERY")
            handoff = rows(lines, "V020_SEC_D_BLOCK_HANDOFF")
            chains = rows(lines, "V020_SEC_D_BLOCK_RECOVERY_CHAIN")
            ops = rows(lines, "V020_SEC_D_BLOCK_RECOVERY_OP")
            require(len(handoff) == 1
                    and 0x0a000000 <= handoff[0][0] < 0x0a200000
                    and handoff[0][0] % 512 == 0 and handoff[0][1:] == (2, 0)
                    and rows(lines, "V020_W11_MEDIA_RECOVERY_REQUIRED") == [(0, 0, 0)]
                    and recovery == [(0, 1, stopped[0][2])]
                    and len(chains) == len(ops) == sum(custody[0][:2])
                    and len({slot for slot, _, _ in chains}) == len(chains)
                    and all(slot < 8 and generation > 0 and complete in (0, 1)
                            for slot, generation, complete in chains)
                    and sum(complete for _, _, complete in chains) == custody[0][1]
                    and [slot for slot, _, _ in chains] == [slot for slot, _, _ in ops]
                    and all(kind == 1 and sector < SCRATCH_BYTES // 512 for _, kind, sector in ops),
                    "block recovery readback lost the reset result or original read tokens")
            require(len(io) == 1 and io[0][1:] == (0, 0)
                    and after["wr_operations"] == after["flush_operations"] == 0,
                    "resize issued writes or FLUSH to the original volume")
            require("V020_W11_MEDIA_STAGING_INCOMPLETE step=2" in lines
                    and rows(lines, "V020_W12_MEDIA_EPOCH") == [(0, 0, 0)]
                    and not rows(lines, "V020_FSYNC_RECOVERED")
                    and not rows(lines, "V020_W11_NET_LISTEN"),
                    "resize granted authority before the volume was reconciled")
            require(decoder.loss == decoder.corrupt == 0, "resize UART capture was incomplete")
            return {"before": prior, "after": after, "guest_io": io[0], "retained_custody": custody[0],
                    "recovery_handoff": handoff[0],
                    "recovery_chains": chains, "recovery_operations": ops,
                    "mmio_reset": stopped[0], "boot_epoch_granted": False}
        finally:
            shutdown(proc, qmp)
            pipe.close()
            (output / "resize-serial.txt").write_bytes(serial)
            (output / "resize-qmp.jsonl").write_text("".join(json.dumps(row) + "\n" for row in qmp.transcript))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh-elf", type=Path, required=True, help="signed FSYNC scratch release image")
    parser.add_argument("--reopen-elf", type=Path, required=True, help="matching signed FSYNC scratch reopen image")
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    require(1 <= args.timeout <= 120, "invalid capacity check timeout")
    binary = shutil.which("qemu-system-aarch64")
    require(binary is not None and sha(Path(binary)) == args.qemu_sha256, "QEMU differs from its pin")
    args.output.mkdir(parents=True, exist_ok=False)
    modes = Modes(authenticated_net=True, live_control=True, fsync_scratch=True)
    with tempfile.TemporaryDirectory(prefix="cyx-sec-d-capacity-") as temp:
        disk = Path(temp) / "scratch.raw"
        create_scratch(disk)
        seed = run(args.fresh_elf, args.output / "healthy-prepared", args.timeout, staging=True,
                   modes=modes, boot_disk=disk, qmp_stdio=True)
        require(seed["status"] == "PASS", f"healthy signed volume preparation failed: {seed.get('error')}")
        before = sha(disk)
        reopened = resize_during_reopen(binary, args.reopen_elf.resolve(strict=True), args.output, disk, args.timeout)
        require(disk.stat().st_size == EXPANDED_BYTES and original_prefix_sha(disk) == before,
                "capacity change modified the existing volume prefix")
    summary = {"status": "PASS", "scope": "scratch-capacity-growth", "qemu_sha256": args.qemu_sha256,
               "fresh_elf_sha256": seed["elf_sha256"], "reopen_elf_sha256": sha(args.reopen_elf),
               "original_volume_bytes_unchanged": True, **reopened}
    result = json.dumps(summary, indent=2) + "\n"
    (args.output / "summary.json").write_text(result)
    print(result, end="")


if __name__ == "__main__":
    main()
