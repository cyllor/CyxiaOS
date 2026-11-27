#!/usr/bin/env python3
"""Independently check native signed baseline-v1 FSYNC and cold replay."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import shutil
import struct
import tempfile

from verify_smp import require
from verify_v0199_epoch_disk import crc, inode, put, seal
from verify_v020_production import build, run
from v020_production_media import FSYNC_POLICY_SHA256, FSYNC_UUID, require_read_only_refusal
from v020_production_modes import Modes, rows
from v020_production_qemu import create_scratch

BLOCK = 4096
BOOT = 4118
RECEIPT = 4119
INDEX = RECEIPT + 6
ACL = 4126
SECURITY = 4130
INODE = 4102
ROOT = 4269
DATA = 4270
RECEIPT_AT = 21 * 192
REQUEST_ID = 0x0100_0000_0000_0001
FINAL_LSN = 21
LEGACY_FINAL_LSN = 19
BOUND_LSN = 14
FIRST = 2
LOG_END = 4098
INITIAL = b"CyxiaOS V0.20 signed scratch\n".ljust(BLOCK, b"\0")
FINAL = b"CyxiaOS V0.20 durable fsync!\n".ljust(BLOCK, b"\0")
ZERO = bytes(BLOCK)


def checkpoint(generation, lsn):
    raw = bytearray(BLOCK)
    put(raw, 0, 'IHHII16s3Q5I', 0x43594653, 1, 80, BLOCK, 131072, FSYNC_UUID,
        generation, lsn, generation, 4098, 4102, 4118, 256, 0)
    put(raw, 76, 'I', crc(raw))
    return bytes(raw)


def boot_home(epoch):
    raw = bytearray(BLOCK)
    put(raw, 0, 'IHH16sQ', 0x43594245, 1, 40, FSYNC_UUID, epoch)
    put(raw, 32, 'I', crc(raw))
    return bytes(raw)


def security_home(epoch):
    raw = bytearray(BLOCK)
    put(raw, 0, 'IHH16s6Q', 0x43595353, 2, 248, FSYNC_UUID,
        epoch + 1, 1, 1, 1, 0, epoch)
    put(raw, 80, 'Q32s16Q', 1, bytes.fromhex(FSYNC_POLICY_SHA256), *([1] * 16))
    put(raw, 72, 'I', crc(raw))
    return bytes(raw)


def index_page(issued):
    raw = bytearray(BLOCK)
    put(raw, 0, 'IHH16sQQ', 0x43595349, 4, 64, FSYNC_UUID, 0, 1 + issued)
    for group in range(16):
        active = int(issued and group == 0)
        put(raw, 64 + 24 * group, 'IIQQ', active, active, active, group + 1)
    if issued:
        put(raw, 448, 'IIQQ', 1, 1, 1, 0)
    put(raw, 4092, 'I', crc(raw))
    return bytes(raw)


def inode_page(done, size=29, write_seq=7):
    file = bytearray(inode(1, 1, size if done else 29, DATA, 1))
    if done:
        put(file, 24, 'Q', write_seq)
        put(file, 252, 'I', 0)
        put(file, 252, 'I', crc(file))
    return inode(2, 1, 128, ROOT, 1) + bytes(file) + inode() * 14


def operation_digest(contents=FINAL, size=29, write_seq=7):
    request = struct.pack('<IHHHHIQQQ', 0x43594651, 4, 32, 5, 0, 8, REQUEST_ID, 0, write_seq)
    frozen = contents if size == 29 else struct.pack('<Q', size) + contents
    proposal = struct.pack('<6Q', 1, 1, 1 << 13, 1, 1, 1) + sha256(frozen).digest()
    return sha256(b"CYX/FILE-ADMIT/v3" + struct.pack('<QQ', 1, 1)
                  + sha256(request).digest() + proposal).digest()


def receipts(status, final_lsn, contents=FINAL, size=29, write_seq=7):
    store = bytearray(6 * BLOCK)
    if status == 0:
        return bytes(store)
    bound_lsn = 13 if final_lsn == LEGACY_FINAL_LSN else 14
    binding = {1: (0, 0, 0, 0), 2: (1, 3, bound_lsn, write_seq),
               3: (1, 4, final_lsn, write_seq)}[status]
    raw = bytearray(192)
    put(raw, 0, 'IHH16sQII7Q', 0x43595243, 4, 192, FSYNC_UUID, 1, 0, 1, 0, 1, 1, *binding)
    put(raw, 96, 'HH i I', status, 0, 0, size if status == 3 else 0)
    if status >= 2:
        raw[108:140] = operation_digest(contents, size, write_seq)
    if status == 3:
        raw[140:172] = sha256(contents).digest()
    put(raw, 172, 'QQ', REQUEST_ID, 1)
    put(raw, 188, 'I', crc(raw))
    store[RECEIPT_AT:RECEIPT_AT + len(raw)] = raw
    return bytes(store)


def tx(txid, epoch, lsn, images):
    begin = bytearray(BLOCK)
    put(begin, 64, 'IIQ', len(images), 0, BLOCK * len(images))
    records = [seal(begin, 1, 80, txid, lsn, epoch)]
    ordered = sha256()
    for index, (home, data) in enumerate(images):
        redo = bytearray(2 * BLOCK)
        put(redo, 40, 'QII', home, index, len(images))
        redo[64:64 + BLOCK] = data
        ordered.update(struct.pack('<Q', home))
        ordered.update(data)
        records.append(seal(redo, 2, 4160, txid, lsn + 1 + index, epoch))
    commit = bytearray(BLOCK)
    put(commit, 64, 'QQQII', txid, lsn, lsn + len(images), len(images), 0)
    commit[96:128] = ordered.digest()
    records.append(seal(commit, 3, 128, txid, lsn + 1 + len(images), epoch))
    return b''.join(records)


def boot_tx(epoch, begin_lsn):
    return tx(epoch, epoch, begin_lsn, [(SECURITY, security_home(epoch)), (BOOT, boot_home(epoch))])


def receipt_blocks(status, final_lsn, contents, size, write_seq):
    store = receipts(status, final_lsn, contents, size, write_seq)
    return [(RECEIPT, store[:BLOCK]), (RECEIPT + 1, store[BLOCK:2 * BLOCK])]


def boot_one_log(final_lsn=FINAL_LSN, contents=FINAL, size=29, write_seq=7):
    legacy = final_lsn == LEGACY_FINAL_LSN
    index = [(INDEX, index_page(True))]
    segment_index = [] if legacy else index
    bound = b''.join((
        boot_tx(1, 1),
        tx(2, 1, 5, receipt_blocks(1, final_lsn, contents, size, write_seq) + index),
        tx(3, 1, 10, receipt_blocks(2, final_lsn, contents, size, write_seq) + segment_index),
    ))
    if final_lsn == BOUND_LSN:
        return bound
    return bound + tx(4, 1, 14 if legacy else 15, [(DATA, contents)]
                      + receipt_blocks(3, final_lsn, contents, size, write_seq)
                      + segment_index + [(INODE, inode_page(True, size, write_seq))])


def read(disk, block, size=BLOCK):
    disk.seek(block * BLOCK)
    raw = disk.read(size)
    require(len(raw) == size, f"short FSYNC image read at block {block}")
    return raw


def checkpoint_lsn(epoch, final_lsn):
    return 0 if epoch == 1 else final_lsn + 4 * (epoch - 2)


def verify_disk(path, reopened, final_lsn=FINAL_LSN, *, contents=FINAL, size=29, write_seq=7,
                boot_epoch=None):
    require(final_lsn in (FINAL_LSN, LEGACY_FINAL_LSN, BOUND_LSN), "unrecognized FSYNC redo closure")
    require(29 <= size <= BLOCK and len(contents) == BLOCK and not any(contents[size:])
            and write_seq > 0 and (final_lsn != LEGACY_FINAL_LSN or (size, write_seq) == (29, 7)),
            "expected caller content must fit one allocated file block")
    epoch = boot_epoch if boot_epoch is not None else 1 + reopened
    require(epoch >= 1 and reopened == (epoch > 1), "invalid FSYNC checkpoint epoch")
    expected = (boot_tx(epoch, checkpoint_lsn(epoch, final_lsn) + 1) if reopened else
                boot_one_log(final_lsn, contents, size, write_seq))
    done = reopened and final_lsn != BOUND_LSN
    status = (3 if done else 2) if reopened else 0
    prior_checkpoint = max(1, epoch - 1)
    first, second = (prior_checkpoint, epoch) if epoch % 2 == 0 else (epoch, prior_checkpoint)
    with path.open("rb") as disk:
        require(read(disk, 0) == checkpoint(first, checkpoint_lsn(first, final_lsn))
                and read(disk, 1) == checkpoint(second, checkpoint_lsn(second, final_lsn)),
                "FSYNC checkpoint pair differs from the independently expected state")
        log = read(disk, FIRST, (LOG_END - FIRST) * BLOCK)
        require(log.startswith(expected) and not any(log[len(expected):]),
                "FSYNC BEGIN/REDO/COMMIT sequence or log tail differs")
        require(read(disk, BOOT) == boot_home(epoch - 1)
                and read(disk, SECURITY) == security_home(epoch - 1),
                "FSYNC BootEpoch or signed policy homes differ")
        require(read(disk, INODE) == inode_page(done, size, write_seq)
                and read(disk, DATA) == (contents if done else INITIAL),
                "FSYNC inode size, write sequence or visible data differs")
        require(read(disk, RECEIPT, 6 * BLOCK)
                == receipts(status, final_lsn, contents, size, write_seq)
                and read(disk, INDEX) == index_page(reopened),
                "FSYNC receipt or stream index homes differ")
        acl = read(disk, ACL)[64:128]
        require(struct.unpack_from('<IIQQQIIQ', acl) == (1, 1, 1, 1, 1, 0x2300, 0, 1)
                and struct.unpack_from('<I', acl, 60)[0] == crc(acl[:60] + bytes(4)),
                "FSYNC diagnostic owner ACL differs")
    return sha256(expected).hexdigest()


def run_healthy_boots(fresh, reopen, output, timeout, qmp_stdio, boot_count, content=FINAL[:29],
                      *, bound_only=False):
    """Run repeated independent QEMU boots on the same healthy signed volume."""
    require(boot_count >= 2 and 29 <= len(content) <= BLOCK, "invalid FSYNC healthy boot fixture")
    output.mkdir(parents=True, exist_ok=False)
    fresh_modes = Modes(authenticated_net=True, fsync_scratch=True, fsync_bound=bound_only)
    reopen_modes = replace(fresh_modes, media_reopen=True)
    size = len(content)
    padded = content.ljust(BLOCK, b"\0")
    write_seq = max(7, (size + 83) // 84)
    receipt_lsn = BOUND_LSN if bound_only else FINAL_LSN
    retained_digest = sha256(receipts(2 if bound_only else 3, receipt_lsn, padded, size, write_seq)
                             + index_page(True)).hexdigest()
    boots = []
    with tempfile.TemporaryDirectory(prefix="cyx-fsync-healthy-") as tmp:
        disk = Path(tmp) / "scratch.raw"
        create_scratch(disk)
        for epoch in range(1, boot_count + 1):
            reopened = epoch > 1
            case = output / f"boot-{epoch}"
            result = run(reopen if reopened else fresh, case, timeout, staging=True,
                         modes=reopen_modes if reopened else fresh_modes, boot_disk=disk,
                         qmp_stdio=qmp_stdio, expected_fsync_epoch=epoch if reopened else None)
            require(result["status"] == "PASS", f"healthy FSYNC boot {epoch}: {result.get('error')}")
            if reopened:
                require(result["scratch_before_sha256"] == boots[-1]["disk_sha256"],
                        "healthy FSYNC reboot must use the same verified disk")
            observations = result["observations"]
            endpoint = "native_file_receipt_query" if reopened else "native_file_fsync"
            if reopened or not bound_only:
                require(observations.get(endpoint) == {
                            "boot_epoch": epoch, "actor": 11, "service_generation": 1,
                        }, "missing epoch-bound native file client")
            lines = (case / "serial.txt").read_text().splitlines()
            if reopened:
                event = "V020_FSYNC_UNKNOWN_RECOVERED" if bound_only else "V020_FSYNC_RECOVERED"
                require(rows(lines, event) == [(epoch, receipt_lsn, write_seq)]
                        and observations["signed_receipt_view_sha256"] == retained_digest,
                        "reboot changed the retained receipt or stream index")
            elif bound_only:
                require(rows(lines, "V020_FSYNC_BOUND") == [(receipt_lsn, write_seq, 0)],
                        "initial FSYNC binding differs from the frozen request")
            else:
                require(rows(lines, "V020_FSYNC_COMMITTED") == [(receipt_lsn, write_seq, size)],
                        "initial FSYNC receipt differs from the caller's write")
            _, writes, flushes = rows(lines, "V020_W11_MEDIA_IO")[0]
            boots.append({
                "boot_epoch": epoch,
                "checkpoint_lsn": checkpoint_lsn(epoch, receipt_lsn),
                "journal_sha256": verify_disk(disk, reopened, receipt_lsn, contents=padded,
                                               size=size, write_seq=write_seq, boot_epoch=epoch),
                "disk_sha256": result["scratch_disk"]["scratch_after_sha256"],
                "receipt_view_sha256": observations["signed_receipt_view_sha256"],
                "writes": writes,
                "flushes": flushes,
                "elf_sha256": result["elf_sha256"],
                "qemu_sha256": result["qemu_sha256"],
            })
    report = {"status": "PASS", "scope": "signed-baseline-v1-native-fsync-diagnostic",
              "receipt_status": "BOUND" if bound_only else "DONE",
              "receipt_commit_lsn": receipt_lsn, "boots": boots}
    if bound_only:
        report.update({"file_bytes": 29, "file_write_seq": 0,
                       "file_sha256": sha256(INITIAL[:29]).hexdigest(),
                       "frozen_request_bytes": size, "frozen_write_seq": write_seq,
                       "later_query_status": "UNKNOWN", "later_query_errno": -6})
    else:
        report.update({"file_bytes": size, "file_write_seq": write_seq,
                       "file_commit_lsn": receipt_lsn, "file_sha256": sha256(content).hexdigest()})
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def run_pair(fresh, reopen, output, timeout, qmp_stdio):
    output.mkdir(parents=True, exist_ok=False)
    fresh_modes = Modes(authenticated_net=True, fsync_scratch=True)
    reopen_modes = replace(fresh_modes, media_reopen=True)
    with tempfile.TemporaryDirectory(prefix="cyx-fsync-native-") as tmp:
        disk = Path(tmp) / "scratch.raw"
        create_scratch(disk)
        first = run(fresh, output / "boot-1", timeout, staging=True, modes=fresh_modes,
                    boot_disk=disk, qmp_stdio=qmp_stdio)
        require(first["status"] == "PASS", f"FSYNC execution failed: {first.get('error')}")
        first_rows = (output / "boot-1/serial.txt").read_text().splitlines()
        require(rows(first_rows, "V020_FSYNC_COMMITTED") == [(FINAL_LSN, 7, 29)]
                and rows(first_rows, "V020_W11_MEDIA_IO")[0][2] == 12,
                "expected exact native FSYNC terminal and ordered flush count")
        first_hash = verify_disk(disk, reopened=False)

        # Preserve the positive image. A missing final COMMIT is checked on
        # this same signed image, then its exact verified bytes are restored.
        commit_block = FIRST + len(boot_one_log()) // BLOCK - 1
        with disk.open("r+b") as raw:
            original = read(raw, commit_block)
            raw.seek(commit_block * BLOCK)
            raw.write(ZERO)
        try:
            case = output / "missing-commit"
            denied = run(reopen, case, timeout, staging=True, modes=reopen_modes,
                         boot_disk=disk, qmp_stdio=qmp_stdio)
            denied_rows = (case / "serial.txt").read_text().splitlines()
            require_read_only_refusal(denied, denied_rows, case, 2)
            require(not rows(denied_rows, "V020_FSYNC_RECOVERED"),
                    "incomplete FSYNC exposed a durable receipt")
        finally:
            with disk.open("r+b") as raw:
                raw.seek(commit_block * BLOCK)
                raw.write(original)

        second = run(reopen, output / "boot-2", timeout, staging=True, modes=reopen_modes,
                     boot_disk=disk, qmp_stdio=qmp_stdio)
        require(second["status"] == "PASS", f"FSYNC reopen failed: {second.get('error')}")
        require(first["scratch_disk"]["scratch_after_sha256"] == second["scratch_before_sha256"],
                "FSYNC reopen did not use the same independently inspected disk")
        second_rows = (output / "boot-2/serial.txt").read_text().splitlines()
        require(rows(second_rows, "V020_FSYNC_RECOVERED") == [(2, FINAL_LSN, 7)]
                and rows(second_rows, "V020_W11_MEDIA_IO")[0][2] == 5,
                "expected native reopened receipt and checkpoint flushes")
        second_hash = verify_disk(disk, reopened=True)
    result = {
        "status": "PASS",
        "scope": "signed-baseline-v1-native-fsync-diagnostic",
        "epochs": [1, 2],
        "issued_bound_done_verified": True,
        "cold_replay_verified": True,
        "missing_commit_refused_without_write": True,
        "file_write_seq": 7,
        "commit_lsn": FINAL_LSN,
        "file_bytes": 29,
        "file_block_sha256": sha256(FINAL).hexdigest(),
        "first_log_sha256": first_hash,
        "second_log_sha256": second_hash,
    }
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fresh-elf", type=Path)
    parser.add_argument("--reopen-elf", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--qmp-stdio", action="store_true")
    parser.add_argument("--healthy-boots", type=int, metavar="COUNT",
                        help="boot and repeatedly reopen one healthy volume")
    parser.add_argument("--contents", type=Path,
                        help="expected file payload of the prebuilt fresh ELF in a healthy run")
    parser.add_argument("--bound-only", action="store_true",
                        help="verify a complete BOUND transaction and later UNKNOWN queries")
    args = parser.parse_args()
    if bool(args.fresh_elf) != bool(args.reopen_elf):
        parser.error("pass both kernel ELFs, or let the verifier build both")
    if args.healthy_boots is not None and args.healthy_boots < 2:
        parser.error("--healthy-boots requires at least 2")
    if args.bound_only and args.healthy_boots is None:
        parser.error("--bound-only requires --healthy-boots")
    if args.contents is not None and (args.healthy_boots is None or args.fresh_elf is None):
        parser.error("--contents requires --healthy-boots and prebuilt ELFs")
    with tempfile.TemporaryDirectory(prefix="cyx-fsync-elf-") as scratch:
        fresh, reopen = args.fresh_elf, args.reopen_elf
        if fresh is None:
            modes = Modes(authenticated_net=True, fsync_scratch=True, fsync_bound=args.bound_only)
            fresh = Path(scratch) / "fresh.elf"
            shutil.copy2(build(True, modes), fresh)
            reopen = build(True, replace(modes, media_reopen=True))
        if args.healthy_boots is None:
            report = run_pair(fresh, reopen, args.output, args.timeout, args.qmp_stdio)
        else:
            content = args.contents.read_bytes() if args.contents else FINAL[:29]
            report = run_healthy_boots(fresh, reopen, args.output, args.timeout, args.qmp_stdio,
                                       args.healthy_boots, content, bound_only=args.bound_only)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
