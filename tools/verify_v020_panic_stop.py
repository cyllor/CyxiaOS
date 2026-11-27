#!/usr/bin/env python3
"""Verify the explicit healthy four-CPU terminal-stop fixture on Cortex-A53."""
import argparse
import base64
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zlib

from check_elf import boot_profile, symbol
from run_qemu import Qmp
from transport import FrameDecoder
from v020_production_qemu import connect_qmp, sha, shutdown
from verify_smp import require

MAGIC = 0x43595853544F5001
DMA_MAGIC = 0x435958444D415301
DMA_DEVICES = ((1, 3), (2, 1), (4, 1))  # (VirtIO device ID, registered queue mask)
SGI = 15
ALL = 15
HEADER = 11
ROW = 6
UART = HEADER + ROW * 4
UART_STATUS = {1: "queued", 2: "fifo_full", 3: "unavailable", 4: "deadline", 5: "console_unconfirmed"}
SCRATCH_FATAL = 400
SOFTWARE_STOP_KIND = 16
PAGE = 4096
RAM_BASE = 0x40000000
READONLY_RAM_PAGE = 0x0060000000000783


def stopped_cpus(qmp, park):
    registers = qmp.execute("human-monitor-command", {"command-line": "info registers -a"})
    blocks = re.split(r"CPU#(\d+)\b", registers)
    rows = {}
    for index, block in zip(blocks[1::2], blocks[2::2]):
        pc = re.search(r"\bPC=([0-9a-fA-F]+)\b", block)
        pstate = re.search(r"\bPSTATE=([0-9a-fA-F]+)\b", block)
        require(pc is not None and pstate is not None, "could not read parked CPU architectural state")
        pc, pstate = int(pc[1], 16), int(pstate[1], 16)
        # The entry masks DAIF and then has a WFE/backward-branch pair.
        require(park["va"] + 4 <= pc <= park["va"] + 8, f"CPU{index} left its terminal wait")
        require(pstate & 0x3DF == 0x3C5, f"CPU{index} is not masked EL1h")
        rows[int(index)] = {"pc": f"{pc:#x}", "pstate": f"{pstate:#x}"}
    require(set(rows) == set(range(4)), "could not enumerate all four stop PCs")
    return rows


def validate_record(data, late_peer=False):
    require(len(data) == 4096, "incomplete protected stop record")
    words = struct.unpack_from("<" + "Q" * (HEADER + ROW * 4), data)
    magic, ready, token, expected, confirmed, unknown, result, began, ended, hz, sent = words[:HEADER]
    require((magic, ready) == (MAGIC, 1), "stop record was never armed after CPU registration")
    require(token == 0x101, "healthy CPU0 did not retain the first-owner generation")
    expected_result = (ALL, 7, 8, 2) if late_peer else (ALL, ALL, 0, 1)
    require((expected, confirmed, unknown, result) == expected_result,
            "terminal classification differs from the expected ACK set")
    require(hz >= 10 and 0 < began <= ended, "invalid monotonic stop timer")
    cutoff = began + hz // 10
    require(late_peer or ended <= cutoff, "healthy stop exceeded the 100 ms monotonic budget")
    rows = []
    for slot in range(4):
        index = HEADER + slot * ROW
        affinity, target, ack, observed, ticks, irq = words[index:index + ROW]
        require(0 < target <= 128 and target.bit_count() == 1, "invalid discovered GIC target bit")
        require(ack == token and affinity == observed, f"CPU{slot} acknowledgement has wrong custody")
        if late_peer and slot == 3:
            require(ticks > ended, "deferred peer acknowledged before the result was sealed")
        else:
            require(began <= ticks <= min(ended, cutoff), f"CPU{slot} ACK missed the deadline")
        rows.append({"slot": slot, "mpidr_affinity": affinity, "target_mask": target,
                     "owner_generation": ack >> 8, "ack_ticks": ticks, "irq_token": irq})
    require(len({row["target_mask"] for row in rows}) == 4
            and len({row["mpidr_affinity"] for row in rows}) == 4, "CPU target identities overlap")
    require(sent == sum(row["target_mask"] for row in rows[1:]), "hardware sends omitted a registered peer")
    require(rows[0]["irq_token"] == 1023, "healthy owner did not originate in its foreground path")
    source = rows[0]["target_mask"].bit_length() - 1
    require(all(row["irq_token"] & 0x3FF == SGI and row["irq_token"] >> 10 & 7 == source
                for row in rows[1:]), "remote ACKs lack the actual owner-sourced GIC SGI")
    return {"owner": 0, "generation": token >> 8, "expected_mask": expected,
            "confirmed_mask": confirmed, "unknown_mask": unknown, "frequency_hz": hz,
            "started_ticks": began, "finished_ticks": ended, "deadline_ticks": cutoff,
            "elapsed_ticks": ended - began, "late_peer": 3 if late_peer else None,
            "elapsed_ns": (ended - began) * 1_000_000_000 // hz,
            "sgi": SGI, "sent_hardware_targets": sent, "cpus": rows}


def validate_uart(data, wire, stop):
    began, ended, sequence, written, status = struct.unpack_from("<5Q", data, UART * 8)
    require(status in UART_STATUS and stop["finished_ticks"] <= began <= ended,
            "owner UART outcome was not sealed after the ACK outcome")
    elapsed = ended - began
    require(elapsed <= stop["frequency_hz"] // 100, "owner emergency UART exceeded 10 ms")
    expected = (f"PANIC_STOP g={stop['generation']:x} o={stop['owner']:x} "
                f"a={stop['confirmed_mask']:x} u={stop['unknown_mask']:x}\n").encode("ascii")
    frame_bytes = len(expected) + 28
    require(0 <= written <= frame_bytes and written <= len(wire), "invalid emergency UART byte count")
    require((status != 1 or written == frame_bytes) and (status != 2 or written < frame_bytes),
            "emergency UART outcome contradicts its write count")
    require((status not in (3, 5) or written == sequence == 0)
            and (status not in (1, 2) or sequence > 0), "invalid emergency UART sequence")
    if written:
        header = struct.pack("<4sBBHQQ", b"CYX1", 1, 0, len(expected), 1, sequence)
        frame = header + expected
        frame += struct.pack("<I", zlib.crc32(frame))
        require(wire[-written:] == frame[:written], "emergency UART bytes do not match the sealed owner result")
    ordinary = wire[:-written] if written else wire
    decoder = FrameDecoder()
    frames = decoder.feed(ordinary)
    require(not decoder.buffer and decoder.loss == decoder.corrupt == 0
            and b"SMP_BOOT_OK a=4 b=15 c=0\n" in frames
            and not any(frame.startswith(b"FAIL") for frame in frames),
            "healthy four-core startup lacked its original serial proof")
    require(sequence in (0, decoder.last + 1), "emergency UART reused an ordinary frame sequence")
    if status == 1:
        require(decoder.feed(wire[-written:]) == [expected], "complete emergency frame failed decoding")
        frames.append(expected)
    return {
        "status": UART_STATUS[status], "sequence": sequence, "written_bytes": written,
        "frame_bytes": frame_bytes, "started_ticks": began, "finished_ticks": ended,
        "elapsed_ns": elapsed * 1_000_000_000 // stop["frequency_hz"],
    }, b"".join(frames)


def validate_dma_record(data, stop, with_dma):
    require(len(data) == PAGE, "incomplete protected DMA stop record")
    magic, token, registered, confirmed, unknown, result, began, ended = struct.unpack_from("<8Q", data)
    require(magic == DMA_MAGIC and token == (stop["generation"] << 8) | (stop["owner"] + 1),
            "DMA stop is not bound to the CPU stop owner")
    requested = (1 << len(DMA_DEVICES)) - 1 if with_dma else 0
    all_cpus_stopped = stop["confirmed_mask"] == ALL
    expected = (requested, 0, 1) if all_cpus_stopped else (0, requested, 3)
    require(registered == requested and (confirmed, unknown, result) == expected,
            "DMA reset classification disagrees with device registration and CPU ACKs")
    hz = stop["frequency_hz"]
    require(stop["finished_ticks"] <= began <= ended <= stop["owner_uart"]["started_ticks"],
            "DMA stop was not sealed between CPU ACKs and emergency UART")
    rows = []
    previous = began
    for index, (device_id, queues) in enumerate(DMA_DEVICES):
        row = struct.unpack_from("<8Q", data, (8 + index * 8) * 8)
        if not with_dma:
            require(not any(row), "unregistered device has DMA stop evidence")
            continue
        address, actual_id, actual_queues, status, start, finish, observed, error = row
        require(0x0A00_0000 <= address < 0x0A20_0000 and address % 4 == 0
                and (actual_id, actual_queues) == (device_id, queues), "invalid registered DMA identity")
        if all_cpus_stopped:
            require(status == 1 and error == 0 and previous <= start <= finish <= ended,
                    "missing ordered reset observation")
            require(finish - start <= hz // 10 and start * 1_000_000_000 // hz <= observed
                    <= finish * 1_000_000_000 // hz, "device reset observation missed its 100 ms bound")
            previous = finish
        else:
            require((status, start, finish, observed, error) == (0, 0, 0, 0, 0),
                    "a device was reset while a CPU remained unconfirmed")
        rows.append({"mmio_pa": address, "device_id": device_id, "queues": queues,
                     "reset_observed_ns": observed or None,
                     "elapsed_ns": (finish - start) * 1_000_000_000 // hz})
    require(len({row["mmio_pa"] for row in rows}) == len(rows), "registered device MMIO identities overlap")
    return {"registered_mask": registered, "confirmed_mask": confirmed, "unknown_mask": unknown,
            "complete": result == 1, "start_ticks": began, "finish_ticks": ended, "devices": rows}


def validate_device_registers(qmp, stop, rows):
    def read(address):
        reply = qmp.execute("human-monitor-command", {"command-line": f"xp /1wx {address:#x}"})
        value = re.fullmatch(r"[0-9a-f]+:\s+0x([0-9a-f]{8})\s*", reply, re.IGNORECASE)
        require(value is not None, f"failed to observe device MMIO register at {address:#x}")
        return int(value[1], 16)

    stopped = stop["confirmed_mask"] == ALL
    for row in rows:
        address = row["mmio_pa"]
        device_id, status, ready = read(address + 0x08), read(address + 0x70), read(address + 0x44)
        require(device_id == row["device_id"] and (status, ready) == ((0, 0) if stopped else (15, 1)),
                "QEMU MMIO disagrees with the kernel's device cessation witness")
        row.update(device_status=status, last_selected_queue_ready=ready)


def check_empty_root(raw, qmp, dump):
    try:
        empty = symbol(raw, "empty_l1")["pa"]
    except ValueError as error:
        if str(error) == "missing symbol empty_l1":
            return None
        raise
    require(empty >= RAM_BASE and empty % PAGE == 0, "PAN root address is outside aligned RAM")
    qmp.execute("pmemsave", {"val": empty, "size": PAGE, "filename": str(dump)})
    require(dump.read_bytes() == bytes(PAGE), "live PAN L1 is not empty")
    leaf = symbol(raw, "ram_l3")["pa"] + (empty - RAM_BASE) // PAGE * 8
    qmp.execute("pmemsave", {"val": leaf, "size": 8, "filename": str(dump)})
    descriptor, = struct.unpack("<Q", dump.read_bytes())
    require(descriptor == (empty | READONLY_RAM_PAGE), "PAN root has a writable or executable RAM alias")
    return {"empty_root_pa": f"{empty:#x}", "root_bytes_zero": PAGE, "alias_leaf": f"{descriptor:#x}"}


def verify(elf, output, qemu_digest, timeout, late_peer=False, with_dma=False):
    require(1 <= timeout <= 120, "invalid test deadline")
    raw = elf.read_bytes()
    symbol(raw, "cyxia_request_quiescent_stop")
    symbol(raw, "cyxia_terminal_stop")
    scratch = symbol(raw, "__exception_scratch")
    page, park = symbol(raw, "CYXIA_STOP_EVIDENCE"), symbol(raw, "cyxia_stop_park")
    dma_page = symbol(raw, "CYXIA_DMA_STOP_EVIDENCE")
    admission = symbol(raw, "EXCEPTION_ADMISSION_CLOSED")
    require(page["size"] == 4096 and page["pa"] % 4096 == 0 and park["size"] >= 12,
            "wrong stop evidence or terminal park layout")
    require(dma_page["size"] == PAGE and dma_page["pa"] % PAGE == 0 and dma_page["pa"] != page["pa"],
            "DMA stop evidence page layout is not independent of the CPU record")
    binary = shutil.which("qemu-system-aarch64")
    require(binary and sha(Path(binary)) == qemu_digest, "incorrect QEMU executable")
    version = subprocess.check_output([binary, "--version"], text=True, timeout=10).splitlines()[0]
    require(version.startswith("QEMU emulator version 10.2.2"), "unsupported QEMU version")
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "FAIL", "scope": "terminal-cpu-and-virtio-dma-stop" if with_dma
              else "healthy-boot-terminal-four-cpu-ack-subcheck",
              "formal_verdict": False, "elf_sha256": sha(elf), "qemu_sha256": qemu_digest,
              "qemu_version": version, "proof_class": "RUNTIME_QEMU"}
    wire = bytearray()
    serial = b""
    with tempfile.TemporaryDirectory(prefix="cyx-stop-") as tmp, (output / "qemu-stderr.log").open("wb") as err:
        path, data = str(Path(tmp) / "q"), Path(tmp) / "evidence"
        argv = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
                "-cpu", "cortex-a53", "-smp", "4", "-m", f"{boot_profile(raw)['ram_mib']}M",
                "-accel", "tcg,thread=multi", "-display", "none", "-monitor", "none", "-nic", "none",
                "-chardev", "ringbuf,id=cyxlog,size=65536", "-serial", "chardev:cyxlog",
                "-qmp", f"unix:{path},server=on,wait=off", "-kernel", str(elf), "-no-reboot"]
        if with_dma:
            disk = Path(tmp) / "scratch.raw"
            with disk.open("wb") as scratch_file:
                scratch_file.truncate(512 * 1024 * 1024)
            argv += ["-global", "virtio-mmio.force-legacy=false",
                     "-drive", f"file={disk},if=none,id=scratch,format=raw,cache=none",
                     "-device", "virtio-blk-device,drive=scratch",
                     "-netdev", "hubport,id=stopnet,hubid=0",
                     "-device", "virtio-net-device,netdev=stopnet,mac=52:54:00:12:34:56",
                     "-object", "rng-random,id=stoprng,filename=/dev/urandom",
                     "-device", "virtio-rng-device,rng=stoprng"]
        report["argv"] = argv
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=err)
        qmp = None
        try:
            deadline = time.monotonic() + timeout
            with connect_qmp(proc, path, deadline) as sock:
                qmp = Qmp(sock)
                require("QMP" in qmp.receive(deadline), "QMP handshake failed")
                qmp.execute("qmp_capabilities")
                require(len(qmp.execute("query-cpus-fast")) == 4, "wrong vCPU count")

                def read_record():
                    qmp.execute("pmemsave", {"val": page["pa"], "size": page["size"], "filename": str(data)})
                    snapshot = data.read_bytes()
                    require(len(snapshot) == page["size"], "short QMP memory snapshot")
                    return snapshot

                def read_uart():
                    payload = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 65536,
                                                           "format": "base64"})
                    wire.extend(base64.b64decode(payload, validate=True))
                    require(len(wire) <= 65536, "oversized terminal trace")

                while True:
                    require(time.monotonic() < deadline, "terminal stop was not sealed")
                    read_uart()
                    record = read_record()
                    if struct.unpack_from("<Q", record, (UART + 4) * 8)[0] != 0:
                        break
                    time.sleep(0.01)
                # The first live dump may overlap the release seal. Read the
                # now-stable owner fields before accepting any result.
                record = read_record()
                if late_peer:
                    sealed = record[:HEADER * 8]
                    peer_ack = (HEADER + 3 * ROW + 2) * 8
                    while struct.unpack_from("<Q", record, peer_ack)[0] == 0:
                        require(time.monotonic() < deadline, "deferred healthy CPU did not acknowledge")
                        time.sleep(0.01)
                        record = read_record()
                    require(record[:HEADER * 8] == sealed, "late acknowledgement rewrote owner result")
                (output / "native-stop-evidence.bin").write_bytes(record)
                report.update(validate_record(record, late_peer))
                qmp.execute("pmemsave", {
                    "val": scratch["pa"] + report["owner"] * PAGE + SCRATCH_FATAL,
                    "size": 56, "filename": str(data),
                })
                state, kind, _, _, _, _, reason = struct.unpack("<7Q", data.read_bytes())
                require((state, kind, reason) == (2, SOFTWARE_STOP_KIND, 99 if late_peer else 0x5100),
                        "owner did not seal the expected software terminal origin")
                report["software_origin"] = {"kind": kind, "reason": reason,
                                               "entry": "rust_panic" if late_peer else "smp_fatal"}
                qmp.execute("pmemsave", {"val": admission["pa"], "size": 8, "filename": str(data)})
                require(data.read_bytes() == (1).to_bytes(8, "little"), "terminal admission latch is open")
                require(qmp.execute("query-status")["running"], "VM stopped before guest wait-state proof")
                # Read live guest state twice with no QMP pause or register edits.
                time.sleep(0.02)
                report["terminal_registers_first"] = stopped_cpus(qmp, park)
                time.sleep(0.02)
                report["terminal_registers_second"] = stopped_cpus(qmp, park)
                report["software_pan_root"] = check_empty_root(raw, qmp, data)
                read_uart()
                report["owner_uart"], serial = validate_uart(record, bytes(wire), report)
                qmp.execute("pmemsave", {"val": dma_page["pa"], "size": PAGE, "filename": str(data)})
                device_record = data.read_bytes()
                (output / "native-dma-stop-evidence.bin").write_bytes(device_record)
                report["dma"] = validate_dma_record(device_record, report, with_dma)
                if with_dma:
                    require(b"V020_SEC_D_STOP_FIXTURE a=1 b=1 c=1\n" in serial,
                            "the fixture never observed retained chains for all three devices")
                    validate_device_registers(qmp, report, report["dma"]["devices"])
                require(elf.read_bytes() == raw, "kernel ELF changed during the run")
                report["status"] = "PASS"
                shutdown(proc, qmp)
        except (OSError, TimeoutError, ValueError, RuntimeError) as error:
            report["error"] = str(error)
        finally:
            shutdown(proc, None)
    (output / "serial.txt").write_bytes(serial)
    (output / "serial-wire.bin").write_bytes(wire)
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--expect-late-peer", action="store_true")
    parser.add_argument("--with-dma", action="store_true")
    args = parser.parse_args()
    result = verify(args.elf, args.output, args.qemu_sha256, args.timeout, args.expect_late_peer,
                    args.with_dma)
    print(json.dumps(result, indent=2))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
