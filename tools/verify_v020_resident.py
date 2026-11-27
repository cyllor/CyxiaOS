#!/usr/bin/env python3
"""Probe the default V0.20 AArch64 resident SECURE_DEGRADED serial service."""

import argparse
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import time

from transport import FrameDecoder
from v020_production_qemu import GA_RAM, sha
from v020_production_modes import rows
from verify_smp import require


STARTUP_REASONS = ("missing_startup_authority", "catalog_verified_pending",
                   "catalog_rejected", "catalog_budget")
STARTUP_BANNERS = {
    f"V020_STARTUP state=SECURE_DEGRADED reason={reason} command=status": reason
    for reason in STARTUP_REASONS
}
RECOVERY_LIMIT_NS = 8_000_000


def verify(elf: Path, output: Path, timeout: float,
           startup_reason: str = STARTUP_REASONS[0]) -> dict:
    require(1 <= timeout <= 120, "invalid run timeout")
    require(startup_reason in STARTUP_REASONS, "invalid expected startup state")
    output.mkdir(parents=True, exist_ok=False)
    binary = shutil.which("qemu-system-aarch64")
    require(binary is not None, "qemu-system-aarch64 is missing")
    version = subprocess.check_output([binary, "--version"], timeout=10, text=True)
    require(version.splitlines()[0].startswith("QEMU emulator version 10.2.2"),
            "unverified QEMU version")
    report = {"scope": "native-v020-resident-secure-degraded", "status": "FAIL",
              "elf_sha256": sha(elf), "qemu_sha256": sha(Path(binary)),
              "qemu_version": version.splitlines()[0]}
    raw = bytearray()
    lines = []
    decoder = FrameDecoder()
    deadline = time.monotonic() + timeout
    argv = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
            "-cpu", "cortex-a53", "-smp", "4", "-m", GA_RAM, "-accel", "tcg,thread=multi",
            "-display", "none", "-monitor", "none", "-nic", "none", "-serial", "stdio",
            "-kernel", str(elf), "-no-reboot"]
    with (output / "qemu-stderr.log").open("wb") as stderr:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=stderr, bufsize=0)
        try:
            def read_until(end, predicate):
                while time.monotonic() < end and not predicate():
                    leftover = max(0, end - time.monotonic())
                    if not select.select([proc.stdout], [], [], leftover)[0]:
                        break
                    data = os.read(proc.stdout.fileno(), 65536)
                    require(data, "QEMU closed the resident serial channel")
                    raw.extend(data)
                    require(len(raw) <= 1024 * 1024, "resident serial evidence exceeded limit")
                    lines.extend(frame.decode("ascii").rstrip("\n") for frame in decoder.feed(data))

            def status():
                return rows(lines, "V020_RESIDENT_STATUS")

            read_until(deadline, lambda: any(line.startswith("V020_STARTUP ") for line in lines))
            banners = [line for line in lines if line.startswith("V020_STARTUP ")]
            require(len(banners) == 1 and banners[0] in STARTUP_BANNERS,
                    "missing or malformed resident startup admission state")
            observed_reason = STARTUP_BANNERS[banners[0]]
            report["observed_startup_reason"] = observed_reason
            require(rows(lines, "SMP_BOOT_OK") == [(4, 15, 0)], "incomplete SMP startup")
            for expected in range(1, 4):
                # An idle interval separates every host-initiated request. An
                # eager one-shot banner or a halted loop cannot supply a reply.
                proc.stdin.write(b"statusx\n")
                read_until(min(deadline, time.monotonic() + 0.1), lambda: False)
                require(len(status()) == expected - 1, "invalid command produced a reply")
                proc.stdin.write(b"status\n")
                read_until(deadline, lambda: len(status()) >= expected)
                require(len(status()) == expected, "resident status request did not get one reply")
            snapshots = status()
            require(all(online == 15 and unavailable == 0 for online, unavailable, _ in snapshots),
                    "business CPUs left their live EL1 startup state")
            counts = [interrupts for _, _, interrupts in snapshots]
            require(0 < counts[0] < counts[1] < counts[2], "CPU0 architectural timer stopped")
            require(decoder.loss == decoder.corrupt == 0, "corrupt or incomplete console stream")
            require(not any(line.startswith(("V020_PROD_", "V020_W11_NET_", "FAIL"))
                            for line in lines), "diagnostic fixture or hardware error in resident boot")
            require(proc.poll() is None, "QEMU exited after the last resident response")
            report.update(replies=len(snapshots), timer_irqs=counts)
            costs = rows(lines, "V020_STARTUP_CATALOG_COST")
            if observed_reason == STARTUP_REASONS[0]:
                require(not costs, "absent startup catalog performed verification work")
            else:
                require(len(costs) == 1, "missing or repeated startup catalog budget settlement")
                elapsed_ns, prepaid_ns, flags = costs[0]
                require(elapsed_ns > 0 and prepaid_ns == RECOVERY_LIMIT_NS and flags in (0, 1, 3),
                        "invalid startup catalog budget settlement")
                report["catalog_budget"] = {"elapsed_ns": elapsed_ns, "prepaid_ns": prepaid_ns,
                                            "overrun": bool(flags & 1), "crossed_window": bool(flags & 2)}
                require((observed_reason == "catalog_budget") == bool(flags)
                        and bool(flags) == (elapsed_ns > prepaid_ns),
                        "startup catalog outcome disagrees with its budget settlement")
            require([line for line in lines if line.startswith("V020_STARTUP ")] == banners,
                    "repeated resident startup admission state")
            require(observed_reason == startup_reason, "unexpected resident startup admission state")
            report.update(status="PASS", startup_reason=startup_reason)
        except (OSError, ValueError) as error:
            report["error"] = f"{type(error).__name__}: {error}"
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            proc.stdin.close()
            proc.stdout.close()
    (output / "serial.bin").write_bytes(raw)
    (output / "serial.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--expected-startup-reason", choices=STARTUP_REASONS,
                        default=STARTUP_REASONS[0])
    args = parser.parse_args()
    result = verify(args.elf, args.output, args.timeout, args.expected_startup_reason)
    print(json.dumps(result, indent=2))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
