"""Independent healthy proofs for an occupied D7 single-file read fixture."""

import argparse
import base64
from hashlib import sha256
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

from v020_snapshot_catalog_vectors import CATALOG_BLOCK, Catalog, Context, Entry, encode, verify
import v020_snapshot_slot_vectors as slot
from qmp_stdio import PipeTransport
from run_qemu import Qmp
from transport import FrameDecoder
from v020_production_modes import rows
from v020_production_qemu import qemu_args, sha, shutdown
from verify_smp import require
from v020_snapshot_envelopes import BLOCK_BYTES, BLOCK_COUNT, DATA_START, crc32c_zeroed, encode_envelope

UUID = b"CYX-HISTORY-VEC!"
CATALOG_GENERATION = 3
SLOT_STORE_GENERATION = 2
LIVE_EPOCH = 9
CHECKPOINT = 42
ONLINE_AGE_NS = 190_000_000_000
QEMU_SHA256 = "e5be7d6a2383d7ba75553e22579f1717675ed37f82be259ac8a42235bf0877b7"
COMPLETE = b"V020_HISTORY_READONLY_FIXTURE_PASS\n"
CASES = ((0, b"Archived January report\n"), (7, bytes(i % 251 for i in range(BLOCK_BYTES))))


def sealed(prefix, size, crc_offset):
    raw = bytearray(prefix.ljust(size, b"\0"))
    struct.pack_into("<I", raw, crc_offset, crc32c_zeroed(raw, crc_offset))
    return bytes(raw)


def fixture(slot_id, content, *, readonly_image=None):
    """Make a known-good sparse block map for one captured root."""
    root = 4300 + slot_id * 2
    capture = slot.Identity(UUID, 10 + slot_id, slot_id, 4 + slot_id, 8, 33, 180_000_000_000)
    mirror = (slot.inode(2, 1, 128, root) + slot.inode(1, 1, len(content), root + 1)
              + slot.inode() * 222)
    descriptor_address = capture.block()
    descriptor = slot.encode(capture, SLOT_STORE_GENERATION if slot_id == 0 else None,
                             sha256(mirror).digest())
    entries = [Entry() for _ in range(slot.SLOTS)]
    entries[slot_id] = Entry(capture.generation, capture, sha256(descriptor).digest())
    catalog = Catalog(UUID, CATALOG_GENERATION, capture.snapshot_id + 1, tuple(entries))
    raw = encode(catalog)
    blocks = {descriptor_address: descriptor}
    if slot_id:
        blocks[slot.SLOT_START] = encode_envelope("slot", UUID, SLOT_STORE_GENERATION)
    for offset in range(slot.MIRROR_PAGES):
        blocks[descriptor_address + 1 + offset] = mirror[offset * BLOCK_BYTES:(offset + 1) * BLOCK_BYTES]
    selected = Context(UUID, CATALOG_GENERATION, SLOT_STORE_GENERATION,
                       LIVE_EPOCH, CHECKPOINT, ONLINE_AGE_NS)
    require(verify(CATALOG_BLOCK, raw, selected, blocks.__getitem__) == catalog,
            "independent catalogue readback differs")
    if readonly_image is not None:
        # A block-addressed historical export for the isolated EL1 reader.
        # These test identities do not authorize a native writable mount.
        boot = struct.pack("<IHH16sQ", 0x43594245, 1, 40, UUID, 2)
        acl = struct.pack("<II3QIIQI", 1, 1, 1, 1, 1, 1 << 8, 0, 3, 0)
        name = b"readme.txt"
        entry = struct.pack("<IHHQ", 1, len(name), 0, 1) + name
        empty = sealed(bytes([255]) * 4, 128, 124)
        blocks.update({
            DATA_START: sealed(boot, BLOCK_BYTES, 32),
            DATA_START + 8: (bytes(64) + sealed(acl, 64, 60)).ljust(BLOCK_BYTES, b"\0"),
            CATALOG_BLOCK: raw,
            root: sealed(entry, 128, 124) + empty * (BLOCK_BYTES // 128 - 1),
            root + 1: content.ljust(BLOCK_BYTES, b"\0"),
            4270: b"Present file differs.\n".ljust(BLOCK_BYTES, b"\0"),
        })
        with readonly_image.open("xb") as image:
            image.truncate(BLOCK_COUNT * BLOCK_BYTES)
            for block, body in sorted(blocks.items()):
                image.seek(block * BLOCK_BYTES)
                image.write(body)
    return {
        "slot": slot_id,
        "snapshot_id": capture.snapshot_id,
        "slot_generation": capture.generation,
        "root_block": root,
        "data_block": root + 1,
        "bytes": len(content),
        "catalog_sha256": sha256(raw).hexdigest(),
        "descriptor_sha256": sha256(descriptor).hexdigest(),
        "mirror_sha256": sha256(mirror).hexdigest(),
        "file_sha256": sha256(content).hexdigest(),
    }


def verify_qemu(elf, output):
    binary = shutil.which("qemu-system-aarch64")
    require(binary is not None and sha(Path(binary)) == QEMU_SHA256,
            "Cortex-A53 fixture requires the pinned QEMU binary")
    elf = elf.resolve(strict=True)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="cyx-readonly-history-") as temp:
        disk = Path(temp) / "history.raw"
        slot_id, payload = CASES[0]
        expected = fixture(slot_id, payload, readonly_image=disk)
        before = sha(disk)
        argv = qemu_args(binary, "", elf, 0, scratch=disk, nic=False, qmp_stdio=True)
        argv[argv.index("-drive") + 1] += ",readonly=on"
        qmp = None
        decoded = bytearray()
        raw = bytearray()
        decoder = FrameDecoder()
        with (output / "qemu-stderr.log").open("wb") as err:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=err, bufsize=0)
            sock = PipeTransport(proc)
            deadline = time.monotonic() + 45
            try:
                qmp = Qmp(sock)
                require("QMP" in qmp.receive(deadline), "invalid QMP greeting")
                qmp.execute("qmp_capabilities")
                require(len(qmp.execute("query-cpus-fast")) == 4, "four vCPUs required")
                while time.monotonic() < deadline:
                    value = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 1048576,
                                                        "format": "base64"})
                    chunk = base64.b64decode(value, validate=True)
                    raw.extend(chunk)
                    require(len(raw) < 1024 * 1024, "exceeded fixture serial bound")
                    for frame in decoder.feed(chunk):
                        decoded.extend(frame)
                    require(not any(marker in decoded for marker in (b"PANIC", b"SMP_ERROR", b"FAIL")),
                            "history fixture failed")
                    if COMPLETE in decoded:
                        break
                    require(proc.poll() is None, "QEMU exited before the read witness")
                    time.sleep(0.01)
                else:
                    raise ValueError("history read witness did not arrive")
                qmp.execute("stop")
                require(not (decoder.loss or decoder.corrupt or decoder.buffer),
                        "incomplete framed serial witness")
            finally:
                shutdown(proc, qmp)
                sock.close()
                (output / "serial.bin").write_bytes(raw)
                (output / "serial.txt").write_bytes(decoded)
                if qmp:
                    (output / "qmp.jsonl").write_text(
                        "".join(json.dumps(row) + "\n" for row in qmp.transcript))
        lines = decoded.decode().splitlines()
        require(rows(lines, "V020_HISTORY_CANDIDATE_READ") ==
                [(expected["snapshot_id"], expected["slot"], len(payload))],
                "wrong archived file identity or size")
        data_rows = rows(lines, "V020_HISTORY_CANDIDATE_BYTES")
        require(len(data_rows) == 1 and struct.pack("<QQQ", *data_rows[0]) == payload,
                "archived file bytes differ from independent fixture")
        require(rows(lines, "V020_HISTORY_CANDIDATE_IO") == [(20, 40, 40)],
                "unexpected physical history read or queue count")
        require(sha(disk) == before, "read-only export changed across the guest run")
    report = {"status": "PASS", "scope": "isolated-el1-readonly-candidate-export",
              "disk_unchanged": True, "readonly_device": True, "physical_block_reads": 20,
              "virtio_requests_completed": 40, "disk_sha256": before, "elf_sha256": sha(elf),
              "qemu_sha256": QEMU_SHA256, **expected}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readonly-image", type=Path,
                        help="create the known-good slot 0 archive for the isolated QEMU fixture")
    parser.add_argument("--elf", type=Path, help="isolated AArch64 history self-test ELF")
    parser.add_argument("--output", type=Path, help="new directory for QEMU proof")
    args = parser.parse_args()
    if bool(args.elf) != bool(args.output) or args.elf and args.readonly_image:
        parser.error("pass --elf with --output for QEMU verification")
    if args.elf:
        result = verify_qemu(args.elf, args.output)
    else:
        result = [fixture(slot_id, content, readonly_image=args.readonly_image if slot_id == 0 else None)
                  for slot_id, content in CASES]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
