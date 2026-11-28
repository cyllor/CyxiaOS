#!/usr/bin/env python3
"""Verify the ABI3 role12 deployment and FILE_AUTH transport in pinned QEMU."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import struct
import subprocess
from tempfile import TemporaryDirectory
import time

from check_elf import symbol
from run_qemu import Qmp
from transport import FrameDecoder
from v020_production_media import BLOCK_BYTES, REDO_HEADER_BYTES, SECURITY_REDO
from v020_production_modes import rows
from v020_production_qemu import connect_qmp, sha, shutdown
from v020_snapshot_envelopes import DATA_START, INODE_START, crc32c_zeroed
from verify_smp import require
from verify_v020_audit_full import parse_page
from verify_v020_g1_file_budget import verify_file_owner_budget
from verify_v020_role_recovery import dump, qemu_command
from verify_v020_sec_f import clone_raw
from verify_v020_signed_resident import ROLES, verify_disk

BUSINESS_PROOF = "V020_SEC_S_RECOVERY_BUSINESS_DURABLE"
READ_CASES = 6
WRITE_HOME = 4270
WRITTEN_BYTES = b"G1 writeckpoint bytes\n"


def verify_write_disk(disk: Path, epoch: int, catalog: Path) -> None:
    file_page = WRITTEN_BYTES.ljust(BLOCK_BYTES, b"\0")
    receipt_home = DATA_START + 1
    with disk.open("rb") as source:
        def page(block):
            source.seek(block * BLOCK_BYTES)
            raw = source.read(BLOCK_BYTES)
            require(len(raw) == BLOCK_BYTES, "short read from signed fixture")
            return raw

        if epoch == 1:
            require(page(WRITE_HOME).startswith(b"live checkpoint bytes\n"),
                    "live FSYNC overwrote the checkpoint before replay")
            at, transactions, after = 2, [], {}
            while any(begin := page(at)):
                magic, version, kind = struct.unpack_from("<IHH", begin)
                require((magic, version, kind) == (0x43594c47, 1, 1) and at < 42,
                        "unexpected signed FSYNC journal header")
                txid, lsn, log_epoch = struct.unpack_from("<3Q", begin, 16)
                count, = struct.unpack_from("<I", begin, 64)
                require(1 <= count <= 4, "unexpected signed FSYNC journal size")
                digest = sha256()
                for index in range(count):
                    entry = page(at + 1 + index * 2) + page(at + 2 + index * 2)
                    home = struct.unpack_from("<Q", entry, 40)[0]
                    require(struct.unpack_from("<IHH", entry) == (0x43594c47, 1, 2)
                            and struct.unpack_from("<3Q", entry, 16) == (txid, lsn + index + 1, log_epoch)
                            and struct.unpack_from("<2I", entry, 48) == (index, count),
                            "signed FSYNC REDO disagrees with BEGIN")
                    contents = entry[64:64 + BLOCK_BYTES]
                    digest.update(struct.pack("<Q", home) + contents)
                    after[home] = contents
                commit = page(at + 1 + count * 2)
                require(struct.unpack_from("<IHH", commit) == (0x43594c47, 1, 3)
                        and struct.unpack_from("<3Q", commit, 16) == (txid, lsn + count + 1, log_epoch)
                        and commit[96:128] == digest.digest(), "signed FSYNC COMMIT failed digest readback")
                transactions.append((txid, lsn + count + 1, log_epoch))
                at += 2 + 2 * count
            require(len(transactions) == 5, "expected BootEpoch, stream, ISSUE, BOUND and DONE")
            data, inode, receipt = (after[home] for home in (WRITE_HOME, INODE_START, receipt_home))
            txid, lsn, log_epoch = transactions[-1]
            require(struct.unpack_from("<3Q", receipt, 64) == (log_epoch, txid, lsn),
                    "terminal receipt does not identify its exact COMMIT")
        else:
            data, inode, receipt = (page(home) for home in (WRITE_HOME, INODE_START, receipt_home))
        raw = receipt[:192]
        require(data == file_page and struct.unpack_from("<2Q", inode, 256 + 16) == (len(WRITTEN_BYTES), 1)
                and raw[8:24] == (catalog / "offline-config.bin").read_bytes()[16:32]
                and struct.unpack_from("<Q", raw, 24) == (1,)
                and struct.unpack_from("<QHHII", raw, 88) == (1, 3, 0, 0, len(WRITTEN_BYTES))
                and raw[140:172] == sha256(file_page).digest()
                and struct.unpack_from("<I", raw, 188)[0] == crc32c_zeroed(raw, 188),
                "normalized terminal receipt, inode and data readback differ")


def verify_owner_generation(disk: Path, generation: int) -> None:
    slot = 12 - 1
    with disk.open("rb") as source:
        source.seek(SECURITY_REDO * BLOCK_BYTES + REDO_HEADER_BYTES)
        state = source.read(BLOCK_BYTES)
    require(len(state) == BLOCK_BYTES
            and struct.unpack_from("<I", state, 72)[0] == crc32c_zeroed(state, 72)
            and struct.unpack_from("<Q", state, 120 + slot * 8)[0] == generation
            and struct.unpack_from("<Q", state, 56)[0] & (1 << slot) == 0,
            "role12 identity does not match the confirmed SecurityState")


def verify_fault(disk: Path, catalog: Path, output: Path, epoch: int, generation: int) -> None:
    locator = (catalog / "recovery-store.bin").read_bytes()
    require(len(locator) == 104, "missing signed recovery carrier locator")
    first, = struct.unpack_from("<I", locator, 60)
    with disk.open("rb") as source:
        source.seek(first * BLOCK_BYTES)
        raw = tuple(source.read(BLOCK_BYTES) for _ in range(2))
    pages = [parse_page(page, locator, slot) for slot, page in enumerate(raw) if any(page)]
    require(pages, "no sealed audit page on disk")
    current = max(pages, key=lambda page: page.generation)
    require(len(current.proofs) == 1, "expected a single retained stopped-writer proof")
    proof = current.proofs[0]
    event = sha256(struct.pack("<QQIQQ", 0xf2000000, 0, 3, 12, generation)).digest()
    chain = sha256(b"CYX/RECOVERY/v2" + bytes(32) + event + struct.pack("<Q", 1)).digest()
    require(struct.unpack_from("<QII4QI", proof, 8) == (epoch, 3, 2, 2, 1, 1, 0, 0x3c)
            and struct.unpack_from("<2Q", proof, 80) == (12, generation)
            and proof[96:160] == event + chain, "durable fault proof differs from role12 BRK evidence")
    (output / "role12-recovery-proof.bin").write_bytes(proof)


def run(args, disk, sock):
    elf = args.elf.read_bytes()
    witness = symbol(elf, "V020_SIGNED_FILE_OWNER_EVIDENCE")
    copy_slot = symbol(elf, "__copy_secondary_l3")["pa"] + 2 * BLOCK_BYTES
    require(witness["size"] == 9 * 8, "unexpected file owner evidence size")
    data, lines = bytearray(), []
    decoder = FrameDecoder()
    deadline = time.monotonic() + args.timeout
    with (args.output / "qemu-stderr.log").open("wb") as stderr:
        argv, _ = qemu_command(args, disk, sock)
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr)
        conn = qmp = None
        try:
            conn = connect_qmp(proc, str(sock), deadline)
            qmp = Qmp(conn)
            require("QMP" in qmp.receive(deadline), "missing QMP greeting")
            qmp.execute("qmp_capabilities")
            readback = args.output / "owner-readback.bin"
            next_read = 0
            retired_at = None
            while time.monotonic() < deadline:
                if select.select([proc.stdout], [], [], 0.05)[0]:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    require(chunk and len(data) + len(chunk) <= 2 << 20, "guest left without bounded evidence")
                    data.extend(chunk)
                    lines.extend(frame.decode("ascii").rstrip("\n") for frame in decoder.feed(chunk))
                require(not any(line.startswith("V020_STARTUP state=SECURE_DEGRADED") for line in lines),
                        "signed resident fenced before file owner verification")
                roster = rows(lines, "V020_SIGNED_RESIDENT_ROLE")
                if len(roster) != len(ROLES) or time.monotonic() < next_read:
                    continue
                next_read = time.monotonic() + 0.20
                record = struct.unpack("<9Q", dump(qmp, readback, witness["pa"], witness["size"]))
                progress = rows(lines, "V020_SIGNED_BUSINESS_PROGRESS")
                if record[8] != 0:
                    if retired_at is None:
                        retired_at = progress[-1][2] if progress else 0
                    elif (progress and progress[-1][2] > retired_at
                          and (not args.fault or rows(lines, BUSINESS_PROOF))):
                        break
            else:
                raise ValueError("signed file owner did not complete and retire before timeout")
            qmp.execute("stop")
            record = struct.unpack("<9Q", dump(qmp, readback, witness["pa"], witness["size"]))
            epoch, role, generation, root, asid, admits, completes, exit_status, retired = record
            positive = args.positive_read or args.positive_write
            transport = (0, 0) if positive else (1, 1)
            require((epoch, role, generation, asid, admits, completes, exit_status, retired)
                    == (args.epoch, 12, args.generation, 0xb5, *transport, int(not args.fault), 1)
                    and root != 0 and root % 4096 == 0, f"file owner readback {record} differs")
            require(dump(qmp, args.output / "retired-root.bin", root, 4096) == bytes(4096),
                    "role12 still has a usable translation root")
            require(dump(qmp, args.output / "closed-copy-slot.bin", copy_slot, BLOCK_BYTES)
                    == bytes(BLOCK_BYTES), "CPU3 left an open PAN copy slot")
            require(decoder.loss == decoder.corrupt == 0, "lost or corrupt native serial frame")
            require(roster == [(i, role, 1) for i, role in enumerate(ROLES)]
                    and rows(lines, "V020_SIGNED_RESIDENT_BOOT") == [(epoch, 8, 0)]
                    and rows(lines, "V020_SIGNED_BUSINESS_READY") == [(epoch, 14, 0)],
                    "the fixed control roster or business CPU mask changed")
            verify_disk(disk, epoch, roster, expected_policy_envelope=(args.catalog / "offline-config.bin").read_bytes())
            verify_owner_generation(disk, generation)
            custody = None
            if positive:
                reports = {}
                for name, label in [("custody", "V020_SIGNED_FILE_READ_CUSTODY"),
                                    ("cpu_ns", "V020_SIGNED_FILE_READ_CPU_NS")]:
                    member = symbol(elf, label)
                    require(member["size"] == 32, f"unexpected {label} record length")
                    reports[name] = struct.unpack("<4Q", dump(qmp, args.output / f"read-{name}.bin",
                                                            member["pa"], member["size"]))
                custody = reports["custody"]
                expected = (READ_CASES,) * 4 if args.positive_read else (
                    (2, 2, 2, 1) if args.epoch == 1 else (1, 1, 1, 1))
                require(custody == expected, "FILE_AUTH custody counts differ")
                require(all(0 < value < 500_000 for value in reports["cpu_ns"]),
                        "file syscall did not fit the existing CPU3 exit margin")
                (args.output / "file-read.json").write_text(json.dumps(reports, indent=2) + "\n")
            if not args.fault:
                try:
                    symbol(elf, "V020_G1_FILE_OWNER_BUDGET")
                except ValueError as error:
                    if positive or str(error) != "missing symbol V020_G1_FILE_OWNER_BUDGET":
                        raise
                else:
                    verify_file_owner_budget(qmp, elf, args.output, epoch, generation, args.catalog,
                                             2 if args.positive_read else 0, custody)
            if args.positive_write:
                witness = symbol(elf, "V020_G1_FILE_RUNTIME_RECEIPTS")
                require(witness["size"] == 32, "unexpected durable ABI witness length")
                copies = struct.unpack("<4Q", dump(qmp, args.output / "receipt-copyouts.bin",
                                                   witness["pa"], witness["size"]))
                receipt_id = (1 << 56) | 1
                require(copies == ((receipt_id, receipt_id, receipt_id, 0) if epoch == 1
                                   else (0, 0, receipt_id, 0)), "exact durable reply was not copied out")
                verify_write_disk(disk, epoch, args.catalog)
            if args.fault:
                require(rows(lines, BUSINESS_PROOF) == [(epoch, 3, 2)],
                        "CPU0 did not commit CPU3's stopped-writer proof")
                verify_fault(disk, args.catalog, args.output, epoch, generation)
            return epoch, generation
        finally:
            shutdown(proc, qmp)
            if conn is not None:
                conn.close()
            (args.output / "serial.bin").write_bytes(data)
            (args.output / "serial.txt").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "elf", "seed", "catalog", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("--generation", default=1, type=int)
    parser.add_argument("--timeout", default=45, type=float)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--fault", action="store_true",
                       help="check the BRK fixture and the stopped CPU3 writer's durable proof")
    modes.add_argument("--positive-read", action="store_true",
                       help="check the signed client's protected mounted reads across aligned windows")
    modes.add_argument("--positive-write", action="store_true",
                       help="check signed WRITE, durable FSYNC and the cold retained receipt")
    args = parser.parse_args()
    args.tls_server = None
    try:
        require(sha(args.qemu) == args.qemu_sha256, "unexpected QEMU executable")
        args.output.mkdir()
        disk = args.output / "scratch.raw"
        clone_raw(args.seed, disk)
        with TemporaryDirectory(prefix="cyx-file-owner-") as transport:
            epoch, generation = run(args, disk, Path(transport) / "qmp.sock")
    except (EOFError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"signed file owner: {error}\n")
    case = ("fault proof" if args.fault else "mounted read" if args.positive_read
            else "durable FSYNC" if args.positive_write else "clean exit")
    print(f"signed FILE_SERVICE role12 {case} PASS, BootEpoch {epoch}, generation {generation}")


if __name__ == "__main__":
    main()
