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

from check_elf import boot_profile, symbol
from run_qemu import Qmp
from transport import FrameDecoder
from v020_production_qemu import connect_qmp, sha, shutdown
from verify_smp import require

MAGIC = 0x43595853544F5001
SGI = 15
ALL = 15
HEADER = 11
ROW = 6


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


def verify(elf, output, qemu_digest, timeout, late_peer=False):
    require(1 <= timeout <= 120, "invalid test deadline")
    raw = elf.read_bytes()
    symbol(raw, "cyxia_request_quiescent_stop")
    page, park = symbol(raw, "CYXIA_STOP_EVIDENCE"), symbol(raw, "cyxia_stop_park")
    admission = symbol(raw, "EXCEPTION_ADMISSION_CLOSED")
    require(page["size"] == 4096 and page["pa"] % 4096 == 0 and park["size"] >= 12,
            "wrong stop evidence or terminal park layout")
    binary = shutil.which("qemu-system-aarch64")
    require(binary and sha(Path(binary)) == qemu_digest, "incorrect QEMU executable")
    version = subprocess.check_output([binary, "--version"], text=True, timeout=10).splitlines()[0]
    require(version.startswith("QEMU emulator version 10.2.2"), "unsupported QEMU version")
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "FAIL", "scope": "healthy-boot-terminal-four-cpu-ack-subcheck",
              "formal_verdict": False, "elf_sha256": sha(elf), "qemu_sha256": qemu_digest,
              "qemu_version": version, "proof_class": "RUNTIME_QEMU"}
    serial = bytearray()
    with tempfile.TemporaryDirectory(prefix="cyx-stop-") as tmp, (output / "qemu-stderr.log").open("wb") as err:
        path, data = str(Path(tmp) / "q"), Path(tmp) / "evidence"
        argv = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
                "-cpu", "cortex-a53", "-smp", "4", "-m", f"{boot_profile(raw)['ram_mib']}M",
                "-accel", "tcg,thread=multi", "-display", "none", "-monitor", "none", "-nic", "none",
                "-chardev", "ringbuf,id=cyxlog,size=65536", "-serial", "chardev:cyxlog",
                "-qmp", f"unix:{path},server=on,wait=off", "-kernel", str(elf), "-no-reboot"]
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
                decoder = FrameDecoder()

                def read_record():
                    qmp.execute("pmemsave", {"val": page["pa"], "size": page["size"], "filename": str(data)})
                    snapshot = data.read_bytes()
                    require(len(snapshot) == page["size"], "short QMP memory snapshot")
                    return snapshot

                while True:
                    require(time.monotonic() < deadline, "terminal stop was not sealed")
                    payload = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 65536,
                                                           "format": "base64"})
                    for frame in decoder.feed(base64.b64decode(payload, validate=True)):
                        serial.extend(frame)
                    require(len(serial) <= 65536, "oversized terminal trace")
                    record = read_record()
                    if struct.unpack_from("<Q", record, 6 * 8)[0] != 0:
                        break
                    time.sleep(0.01)
                if late_peer:
                    sealed = record[:HEADER * 8]
                    peer_ack = (HEADER + 3 * ROW + 2) * 8
                    while struct.unpack_from("<Q", record, peer_ack)[0] == 0:
                        require(time.monotonic() < deadline, "deferred healthy CPU did not acknowledge")
                        time.sleep(0.01)
                        record = read_record()
                    require(record[:HEADER * 8] == sealed, "late acknowledgement rewrote owner result")
                (output / "native-stop-evidence.bin").write_bytes(record)
                require(b"SMP_BOOT_OK a=4 b=15 c=0\n" in serial
                        and b"FAIL" not in serial and decoder.loss == decoder.corrupt == 0,
                        "healthy four-core startup lacked its original serial proof")
                report.update(validate_record(record, late_peer))
                qmp.execute("pmemsave", {"val": admission["pa"], "size": 8, "filename": str(data)})
                require(data.read_bytes() == (1).to_bytes(8, "little"), "terminal admission latch is open")
                require(qmp.execute("query-status")["running"], "VM stopped before guest wait-state proof")
                # Read live guest state twice with no QMP pause or register edits.
                time.sleep(0.02)
                report["terminal_registers_first"] = stopped_cpus(qmp, park)
                time.sleep(0.02)
                report["terminal_registers_second"] = stopped_cpus(qmp, park)
                require(elf.read_bytes() == raw, "kernel ELF changed during the run")
                report["status"] = "PASS"
                shutdown(proc, qmp)
        except (OSError, TimeoutError, ValueError, RuntimeError) as error:
            report["error"] = str(error)
        finally:
            shutdown(proc, None)
    (output / "serial.txt").write_bytes(serial)
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu-sha256", required=True)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--expect-late-peer", action="store_true")
    args = parser.parse_args()
    result = verify(args.elf, args.output, args.qemu_sha256, args.timeout, args.expect_late_peer)
    print(json.dumps(result, indent=2))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
