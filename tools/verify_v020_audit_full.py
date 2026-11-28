#!/usr/bin/env python3
"""Verify full durable audit custody through signed role loss and cold reopen."""

import argparse
from dataclasses import dataclass
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
from v020_production_modes import rows
from v020_production_qemu import connect_qmp, sha, shutdown
from v020_snapshot_envelopes import BLOCK_BYTES
from verify_smp import require
from verify_v020_role_recovery import dump
from verify_v020_sec_f import clone_raw
from verify_v020_signed_resident import PMU_PATCH, ROLES, capture_role_syscall_abi, verify_disk


AUDIT_PAGE_DOMAIN = b"CYX/RECOVERY-PROOF-PAGE/v1"
PROOF_HEADER = (0x43595241, 2, 256)
PAGE_SEAL = BLOCK_BYTES - 32
AUDIT_SLOTS = 8
WRITER_START = 160 + AUDIT_SLOTS * 256
EXTENSION = WRITER_START + 4 * 56
SPILL_START = EXTENSION + 40
SPILL_SLOTS = 8
SPILL_BYTES = 168
PROBE_MAGIC = 0x435958415546554C
PROBE_OFFSET = (ROLES.index(11) * 24 + 15) * BLOCK_BYTES
PROBE_SIZE = 16 * 8 + (AUDIT_SLOTS + 1) * 128
FIRST_SELECTOR = 0xC007
REPLACEMENT_SELECTOR = 0xC008
DEGRADED = "V020_SEC_S_AUDIT_DEGRADED"
RESUMED = "V020_SEC_S_AUDIT_RESUMED"
DEFERRED = "V020_SEC_S_RECOVERY_PROOF_DEFERRED"
PROMOTED = "V020_SEC_S_RECOVERY_PROOF_PROMOTED"
ACKED = "V020_SEC_S_RECOVERY_ACK_DURABLE"
STOP = "V020_SIGNED_ROLE_STOP"
RESTART = "V020_SIGNED_ROLE_RESTART"
BOOT = "V020_SIGNED_RESIDENT_BOOT"
DELIVERED_RECORDS = AUDIT_SLOTS + 1


def carrier_id(locator):
    require(len(locator) == 104 and locator[:8] == b"CYXRPF01", "invalid signed carrier locator")
    return sha256(b"CYX/RECOVERY-CARRIER/v1" + locator[8:24] + locator[56:]).digest()


def audit_record(seq, proof):
    """Independent projection of the frozen AuditRecord v2 response."""
    require(len(proof) == 256 and struct.unpack_from("<IHH", proof) == PROOF_HEADER,
            "invalid RecoveryProof v2 bytes")
    boot, cpu, flags, writer = struct.unpack_from("<QIIQ", proof, 8)
    require(boot > 0 and cpu < 4 and flags in (2, 3) and writer > 0
            and not any(proof[60:64]) and not any(proof[160:]), "invalid RecoveryProof fields")
    body = struct.pack("<IHHQQ4H4Q32s", 0x43594155, 2, 128, boot, seq, 10, 1, 3, 65535,
                       0, writer, cpu, writer, sha256(proof).digest())
    return body + sha256(b"CYX/AUDIT/v2" + body).digest()


def seed_pages(locator):
    """Build the last two legal v1 pages of eight old pending Boot 1 records."""
    proofs, pages, chain, prior = [], [bytes(BLOCK_BYTES), bytes(BLOCK_BYTES)], bytes(32), bytes(32)
    for seq in range(1, AUDIT_SLOTS + 1):
        event = sha256(b"CYX/AUDIT-FULL-FIXTURE/v1" + struct.pack("<Q", seq)).digest()
        chain = sha256(b"CYX/RECOVERY/v2" + chain + event + struct.pack("<Q", seq)).digest()
        proof = bytearray(256)
        struct.pack_into("<IHHQIIQQQQIIQQQQ", proof, 0, *PROOF_HEADER, 1, 0, 2, 1,
                         seq, seq, 0, 0x24, 0, 0, seq, 6, 1)
        proof[96:128], proof[128:160] = event, chain
        proofs.append(bytes(proof))
        raw = bytearray(BLOCK_BYTES)
        raw[:8], raw[8:40] = b"CYXRPR01", carrier_id(locator)
        struct.pack_into("<5Q", raw, 40, seq, 1, 0, 0, 0)
        raw[112:144] = prior
        struct.pack_into("<H", raw, 144, seq)
        raw[160:160 + seq * 256] = b"".join(proofs)
        struct.pack_into("<3Q32s", raw, WRITER_START, 1, 1, seq, chain)
        prior = sha256(AUDIT_PAGE_DOMAIN + raw[:PAGE_SEAL]).digest()
        raw[PAGE_SEAL:] = prior
        pages[(seq - 1) % 2] = bytes(raw)
    return tuple(pages), tuple(proofs)


@dataclass(frozen=True)
class AuditPage:
    raw: bytes
    generation: int
    boot: int
    retired: int
    ack_boot: int
    ack_generation: int
    proofs: tuple[bytes, ...]
    spill: tuple[tuple[int, bytes], ...]
    saturated: int

    @property
    def seal(self):
        return self.raw[PAGE_SEAL:]


def parse_page(raw, locator, slot):
    magic = raw[:8]
    require(len(raw) == BLOCK_BYTES and magic in (b"CYXRPR01", b"CYXRPR02")
            and raw[8:40] == carrier_id(locator)
            and raw[PAGE_SEAL:] == sha256(AUDIT_PAGE_DOMAIN + raw[:PAGE_SEAL]).digest(),
            "carrier page identity or durable seal differs")
    generation, boot, retired, ack_boot, ack_generation = struct.unpack_from("<5Q", raw, 40)
    count, = struct.unpack_from("<H", raw, 144)
    require(generation > 0 and (generation - 1) % 2 == slot and boot > 0 and count <= AUDIT_SLOTS
            and not any(raw[146:160]) and not any(raw[160 + count * 256:WRITER_START]),
            "carrier FIFO range differs")
    if retired == 0:
        require((ack_boot, ack_generation) == (0, 0) and not any(raw[80:112]),
                "unconfirmed records have an ACK owner")
    else:
        require(0 < ack_boot <= boot and ack_generation > 0 and any(raw[80:112]),
                "missing durable ACK owner")
    proofs = tuple(raw[160 + i * 256:416 + i * 256] for i in range(count))
    for i, proof in enumerate(proofs, retired + 1):
        audit_record(i, proof)
        require(struct.unpack_from("<Q", proof, 8)[0] <= boot, "proof writer is from a future boot")
    spill = []
    saturated = 0
    if magic == b"CYXRPR01":
        require(not any(raw[EXTENSION:PAGE_SEAL]), "legacy carrier has nonzero overflow bytes")
        require(generation == retired * 2 + count, "unrecognized legacy page generation")
    else:
        operations, saturated, first_loss, last_loss, mask = struct.unpack_from("<4QI", raw, EXTENSION)
        require(operations > 0 and not any(raw[SPILL_START - 4:SPILL_START])
                and generation == retired * 2 + count + operations
                and ((0 < first_loss <= last_loss <= boot and 0 < mask < 16) if saturated
                     else (first_loss, last_loss, mask) == (0, 0, 0)),
                "malformed durable audit overflow state")
        for index in range(SPILL_SLOTS):
            start = SPILL_START + index * SPILL_BYTES
            row = raw[start:start + SPILL_BYTES]
            stamp, = struct.unpack_from("<Q", row)
            if stamp == 0:
                require(not any(row), "empty overflow cell has unbound bytes")
                continue
            proof = row[8:] + bytes(96)
            audit_record(1, proof)
            writer_boot, cpu = struct.unpack_from("<QI", proof, 8)
            require(stamp <= generation and writer_boot <= boot and cpu == index // 2,
                    "overflow cell has wrong writer or watermark")
            spill.append((stamp, proof))
        require(len({stamp for stamp, _ in spill}) == len(spill), "duplicate overflow order stamp")
    return AuditPage(raw, generation, boot, retired, ack_boot, ack_generation,
                     proofs, tuple(sorted(spill)), saturated)


def read_pages(image, locator):
    block, = struct.unpack_from("<I", locator, 60)
    with image.open("rb") as disk:
        disk.seek(block * BLOCK_BYTES)
        pages = tuple(parse_page(disk.read(BLOCK_BYTES), locator, slot) for slot in range(2))
    before, current = sorted(pages, key=lambda page: page.generation)
    require(current.generation == before.generation + 1 and current.raw[112:144] == before.seal,
            "alternating audit page chain is disconnected")
    return before, current


def qemu_command(args, disk, sock):
    return [str(args.qemu), "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
            "-cpu", "cortex-a53", "-smp", "4", "-m", "1024M", "-accel", "tcg,thread=multi",
            "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "stdio",
            "-kernel", str(args.elf), "-no-reboot", "-qmp", f"unix:{sock},server=on,wait=off",
            "-global", "virtio-mmio.force-legacy=false", "-drive",
            f"file={disk},if=none,id=audit,format=raw,cache=none", "-device", "virtio-blk-device,drive=audit"]


def probe(qmp, path, backing):
    return dump(qmp, path, backing["pa"] + PROBE_OFFSET, PROBE_SIZE)


def probe_fields(raw):
    return struct.unpack_from("<5QQ5q3QqQ", raw)


def exact_rows(lines, name):
    return [(index, *rows([line], name)[0]) for index, line in enumerate(lines)
            if line.startswith(name + " ")]


def verify_observations(lines, epoch):
    require(rows(lines, "SMP_BOOT_OK") == [(4, 15, 0)] and rows(lines, BOOT) == [(epoch, 8, 0)],
            f"cold boot {epoch} or four-core topology differs")
    degraded = exact_rows(lines, DEGRADED)
    require(all(boot == epoch and 0 < mask < 16 and 0 <= count <= AUDIT_SLOTS
                and bool(mask & 1) == (count == AUDIT_SLOTS) for _, boot, mask, count in degraded),
            "degraded flags do not agree with the durable FIFO occupancy")
    full = [index for index, boot, mask, count in degraded if (boot, count) == (epoch, AUDIT_SLOTS)
            and mask & 1]
    require(full, "full queue did not expose AUDIT_DEGRADED")
    promotions = exact_rows(lines, PROMOTED)
    acknowledgments = exact_rows(lines, ACKED)
    require([(boot, seq, tail) for _, boot, seq, tail in acknowledgments]
            == [(epoch, seq, 0) for seq in range(1, DELIVERED_RECORDS + 1)], "ordered durable ACK sequence differs")
    require([(boot, seq) for _, boot, seq, _ in promotions] == [(epoch, DELIVERED_RECORDS)]
            and full[0] < acknowledgments[0][0] < promotions[0][0] < acknowledgments[-1][0],
            "original records were not retained ahead of the deferred proof")
    resumed = exact_rows(lines, RESUMED)
    require(any(boot == epoch and retired > 0 and index > promotions[0][0]
                and count < AUDIT_SLOTS for index, boot, count, retired in resumed),
            "normal audit admission resumed before persisted backlog fell")
    if epoch == 2:
        (stopped,) = exact_rows(lines, STOP)
        (restarted,) = exact_rows(lines, RESTART)
        require(stopped[1:] == (11, 1, 2) and restarted[1:3] == (11, 2)
                and full[0] < stopped[0] < restarted[0] < acknowledgments[0][0],
                "Supervisor did not fault and replace in its own slot")
        require(any(stopped[0] < index < restarted[0] and mask == 7
                    for index, _, mask, _ in degraded), "lost consumer did not expose the persistent backlog")
        deferred = exact_rows(lines, DEFERRED)
        require(len(deferred) == 1, "expected one durable fault proof")
        (written, written_boot, cpu, count), = deferred
        require((written_boot, cpu, count) == (epoch, 0, 1) and stopped[0] < written < restarted[0],
                "new proof was not durable while the consumer was offline")
    else:
        require(degraded[0][2] == 5, "cold boot did not recover the full FIFO and persistent backlog")
        require(not rows(lines, STOP) and not rows(lines, RESTART) and not rows(lines, DEFERRED),
                "cold replacement created extra effects")
    require(rows(lines, "V020_SEC_S_RECOVERY_STORE") == [(epoch - 1, AUDIT_SLOTS, 0)],
            "boot did not recover all unconfirmed original records")
    debit = rows(lines, "V020_SEC_S_RECOVERY_BUDGET")
    require(debit and all(n > 0 and 0 < used <= n * limit and limit == 8_000_000
                          for n, used, limit in debit), "audit persistence escaped Recovery metering")
    return {"degraded": [list(item[1:]) for item in degraded],
            "resumed": [list(item[1:]) for item in resumed],
            "metered_persistence": debit}


def check_final_probe(raw, epoch, wanted):
    magic, boot, generation, cap, stage, start, rid, rgen, aid, agen, need_read, read, ack, _, status, err = probe_fields(raw)
    selector = REPLACEMENT_SELECTOR if epoch == 2 else FIRST_SELECTOR
    require((magic, boot, generation, cap, stage) == (PROBE_MAGIC, epoch, 2, (epoch << 16) | selector, 4)
            and start > 0 and (rid, rgen, aid, agen, need_read) == (-1, -4, -1, -4, -1)
            and (read, ack, status, err) == (DELIVERED_RECORDS, DELIVERED_RECORDS, 0, 0),
            f"unexpected consumer tuple {probe_fields(raw)}")
    actual = tuple(raw[128 + i * 128:256 + i * 128] for i in range(DELIVERED_RECORDS))
    require(actual == wanted, "Supervisor re-delivery differed from the independently reconstructed records")
    return [record[96:].hex() for record in actual]


def run_guest(args, disk, output, locator, originals, epoch, cold_disk=None, existing_proof=None):
    output.mkdir()
    image = args.elf.read_bytes()
    backing = symbol(image, "V020_SIGNED_ROLE_BACKING")
    deadline = time.monotonic() + args.timeout
    decoder = FrameDecoder()
    raw_serial, lines = bytearray(), []
    initial, parked, deferred = None, None, existing_proof
    with TemporaryDirectory(prefix="cyx-audit-qmp-") as directory, (output / "qemu-stderr.log").open("wb") as stderr:
        sock = Path(directory) / "q"
        proc = subprocess.Popen(qemu_command(args, disk, sock), stdout=subprocess.PIPE, stderr=stderr)
        conn = qmp = None
        try:
            conn = connect_qmp(proc, str(sock), deadline)
            qmp = Qmp(conn)
            require("QMP" in qmp.receive(deadline), "missing QMP greeting")
            qmp.execute("qmp_capabilities")
            capture_at = 0.0
            while time.monotonic() < deadline:
                if select.select([proc.stdout], [], [], 0.025)[0]:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    require(chunk and len(raw_serial) + len(chunk) < 2 * (1 << 20),
                            "guest quit or exceeded the audit evidence bound")
                    raw_serial.extend(chunk)
                    frames = [frame.decode("ascii").rstrip("\n") for frame in decoder.feed(chunk)]
                    lines.extend(frames)
                    for frame in frames:
                        require(not frame.startswith(("V020_SIGNED_ROLE_ISOLATED", "V020_SIGNED_RESIDENT_FAULT",
                                                      "V020_SIGNED_RESIDENT_OVERRUN", "V020_SIGNED_RESIDENT_DEADLINE",
                                                      "V020_SIGNED_RESIDENT_COORD_OVERRUN",
                                                      "V020_STARTUP state=SECURE_DEGRADED")), frame)
                if not rows(lines, BOOT) or time.monotonic() < capture_at:
                    continue
                capture_at = time.monotonic() + 0.25
                obs = probe(qmp, output / "latest-role.bin", backing)
                fields = probe_fields(obs)
                if fields[0] != PROBE_MAGIC:
                    continue
                require(fields[-1] == 0, f"fixture failed with tuple {fields}")
                stage = fields[4]
                if stage == 2 and initial is None:
                    initial = obs
                    (output / "old-reader.bin").write_bytes(obs)
                if (epoch == 2 and stage == 3 and parked is None and rows(lines, RESTART)
                        and rows(lines, DEFERRED)):
                    qmp.execute("stop")
                    require(qmp.execute("query-status")["status"] == "paused", "guest did not pause")
                    parked = probe(qmp, output / "parked-replacement.bin", backing)
                    require(probe_fields(parked)[4] == 3 and probe_fields(parked)[11:13] == (0, 0),
                            "replacement advanced before the stable cut")
                    past, current = read_pages(disk, locator)
                    require(current.boot == epoch and current.retired == 0 and current.proofs == originals
                            and len(current.spill) == 1 and current.saturated == 0,
                            "full durable carrier did not preserve all original records plus the new event")
                    deferred = current.spill[0][1]
                    require(struct.unpack_from("<QIIQ", deferred, 8) == (epoch, 0, 2, 1)
                            and struct.unpack_from("<Q", deferred, 40)[0] == 1
                            and struct.unpack_from("<2Q", deferred, 80) == (11, 1),
                            "deferred proof is not the physically observed stopped Supervisor")
                    (output / "old-page.bin").write_bytes(past.raw)
                    (output / "deferred-page.bin").write_bytes(current.raw)
                    clone_raw(disk, cold_disk)
                    qmp.execute("cont")
                if stage == 4 and len(rows(lines, ACKED)) == DELIVERED_RECORDS and rows(lines, RESUMED):
                    require(deferred is not None, "missing pre-ACK durable spill witness")
                    break
            else:
                raise TimeoutError(f"Boot {epoch} did not consume all recovered audit records")
            qmp.execute("stop")
            require(qmp.execute("query-status")["status"] == "paused", "failed to freeze final evidence")
            final = probe(qmp, output / "final-reader.bin", backing)
            wanted = tuple(audit_record(i, proof) for i, proof in enumerate((*originals, deferred), 1))
            if epoch == 2:
                require(initial is not None and parked is not None and initial[128:256] == wanted[0]
                        and probe_fields(initial)[:5] == (PROBE_MAGIC, 2, 1, (2 << 16) | FIRST_SELECTOR, 2),
                        "the earlier lost reader did not receive the exact old head")
            digests = check_final_probe(final, epoch, wanted)
            previous, confirmed = read_pages(disk, locator)
            require((previous.retired, previous.proofs, previous.spill) == (DELIVERED_RECORDS - 1, (deferred,), ())
                    and (confirmed.boot, confirmed.retired, confirmed.proofs, confirmed.spill,
                         confirmed.saturated, confirmed.ack_boot, confirmed.ack_generation)
                        == (epoch, DELIVERED_RECORDS, (), (), 0, epoch, 2)
                    and confirmed.raw[80:112] == wanted[-1][96:], "final ACK is not physically confirmed")
            (output / "promoted-page.bin").write_bytes(previous.raw)
            (output / "final-page.bin").write_bytes(confirmed.raw)
            require(decoder.loss == decoder.corrupt == 0, "serial loss obscured the custody transitions")
            result = verify_observations(lines, epoch)
            policy = (args.catalog / "offline-config.bin").read_bytes()
            roles = rows(lines, "V020_SIGNED_RESIDENT_ROLE")
            require(roles == [(index, role, 2 if role == 11 and epoch == 3 else 1)
                              for index, role in enumerate(ROLES)], "cold role generation did not persist")
            result.update(capture_role_syscall_abi(qmp, output, image))
            result.update(boot_epoch=epoch, record_digests=digests, durable_ack_generation=2,
                          policy_sha256=verify_disk(disk, epoch, roles, expected_policy_envelope=policy),
                          serial_frames=decoder.frames)
            return result, deferred
        finally:
            shutdown(proc, qmp)
            if conn is not None:
                conn.close()
            proc.stdout.close()
            (output / "serial.bin").write_bytes(raw_serial)
            (output / "serial.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            if qmp is not None:
                (output / "qmp.jsonl").write_text("".join(json.dumps(row) + "\n" for row in qmp.transcript),
                                                 encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "elf", "scratch-disk", "catalog", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--patch-sha256", required=True)
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()
    output = args.output.resolve()
    try:
        output.mkdir(mode=0o700)
    except OSError as error:
        parser.exit(1, f"{error}\n")
    result = {"status": "FAIL"}
    try:
        result.update(qemu_sha256=sha(args.qemu), pmu_patch_sha256=sha(PMU_PATCH), elf_sha256=sha(args.elf))
        require((result["qemu_sha256"], result["pmu_patch_sha256"]) == (args.qemu_sha256, args.patch_sha256),
                "pinned QEMU or PMU patch differs")
        locator = (args.catalog / "recovery-store.bin").read_bytes()
        policy = (args.catalog / "offline-config.bin").read_bytes()
        require(locator[8:24] == policy[16:32] and locator[24:56] == sha256(policy).digest(),
                "signed carrier policy identity differs")
        expected, originals = seed_pages(locator)
        before, source = read_pages(args.scratch_disk, locator)
        require((before.raw, source.raw) == expected and source.proofs == originals,
                "source disk is not the independent Boot 1 full queue")
        live_disk, cold_disk = output / "takeover.raw", output / "cold-cut.raw"
        clone_raw(args.scratch_disk, live_disk)
        result["same_boot_takeover"], deferred = run_guest(
            args, live_disk, output / "takeover", locator, originals, 2, cold_disk=cold_disk)
        reopen_disk = output / "cold-reopen.raw"
        clone_raw(cold_disk, reopen_disk)
        result["cold_reopen"], _ = run_guest(args, reopen_disk, output / "cold-reopen", locator, originals, 3,
                                             existing_proof=deferred)
        require(result["same_boot_takeover"]["record_digests"] == result["cold_reopen"]["record_digests"],
                "cold-reopened records differ from same-boot replacement")
        result["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, EOFError, struct.error, subprocess.CalledProcessError) as error:
        result["error"] = str(error)
    (output / "verification.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if result["status"] != "PASS":
        parser.exit(1, f"{result['error']}\n")
    print(f"Full durable audit acceptance PASS {output}")


if __name__ == "__main__":
    main()
