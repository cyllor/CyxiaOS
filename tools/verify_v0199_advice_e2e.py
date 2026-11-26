#!/usr/bin/env python3
"""Independent pinned-QEMU check of the V0.19.9 advice-chain native E2E fixture.

Fixture scope ONLY. This verifies that a real CPU0 EL0 AdviceEnvelope v1 trap
(0x50), a real register trap (0x50) and a real publish trap (0x41) drive the
kernel-core SvcV3Bridge/gate chain to a unique publish, an executor ApplyReport
and a supervisor terminal with an adopted-different-fallback causal label, and
that the wrong-identity / illegal-domain / forged-cap / wrong-CPU / non-publisher
negatives are rejected. It does NOT certify production in-vector syscall wiring,
real control services, a real executor device, or any AI control budget.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time

import verify_smp
from run_qemu import Qmp
from transport import FrameDecoder


ROOT = Path(__file__).resolve().parents[1]
# Fixture-scoped source binding. The shared verify_smp.run() binds the ENTIRE
# working tree, which a concurrent remediation wave can transiently break by
# deleting tracked files in another agent's scope. This runner instead binds the
# fixture's own stable sources plus the ELF, and still requires framed serial +
# a stopped-VM evidence page. It never edits or depends on other agents' files.
FIXTURE_SOURCES = [
    "kernel/src/arch/aarch64/v0199_advice_e2e.rs",
    "kernel/src/arch/aarch64/v0199_advice_user.S",
    "kernel/src/arch/aarch64/smp.rs",
    "kernel/Cargo.toml",
    "tools/verify_v0199_advice_e2e.py",
]
MAGIC = 0x4359_4145_3139_3939
COMPLETION = b"V0199_ADVICE_E2E_FIXTURE_PASS cpus=4 chain=advice-disposition-plan-receipt\n"
SCOPE = ("V0199_ADVICE_E2E_SCOPE production_wiring=false real_services=false "
         "fixture_executor=true")
SVC64 = 0x5600_0000


class AdviceE2E:
    completion = COMPLETION

    def profile(self, elf: bytes) -> dict:
        return verify_smp.profile(elf)

    @staticmethod
    def metadata() -> dict:
        return {
            "scope": "native-v0199-advice-chain-e2e-fixture",
            "production_wiring": False,
            "real_control_services": False,
            "real_executor_device": False,
            "glue_advice_intake": True,
            "ai_control_budget_verified": False,
            "host_physical_isolation_verified": False,
        }

    @staticmethod
    def success() -> dict:
        return {
            "native_advice_chain_e2e_fixture_verified": True,
            "production_wiring": False,
            "real_control_services": False,
            "real_executor_device": False,
        }

    @staticmethod
    def validate(serial: bytes, page: bytes, cpu_count: int) -> dict:
        require = verify_smp.require
        require(cpu_count == 4, "QMP did not prove four real guest CPUs")
        require(len(page) == 4096, "short native-owned evidence page")
        words = struct.unpack("<512Q", page)
        # [MAGIC, version, completion, online, control, business, advice_seq,
        #  plan_seq, decision_seq, disp_state, selected, fallback, causal_label,
        #  accept_count, action_count, rejected_negatives]
        require(list(words[:16]) == [
            MAGIC, 1, 1, 15, 1, 14, 1, 1, 4, 1, 1, 0, 2, 1, 1, 5
        ], "incomplete advice-chain completion evidence")
        require(all(v == 0 for v in words[56:64]), "nonzero reserved evidence")
        require(all(v == 0 for v in words[76:]), "nonzero reserved evidence tail")
        require(b"SMP_ERROR" not in serial and b"FAIL" not in serial, "guest reported fault")
        lines = serial.decode("ascii").splitlines()
        require(lines.count(
            "V0199_ADVICE_E2E_FIXTURE_PASS cpus=4 chain=advice-disposition-plan-receipt"
        ) == 1, "missing/duplicate advice-chain completion marker")
        require(lines.count(SCOPE) == 1, "fixture scope must not claim production wiring")

        def rows(name: str):
            pattern = re.compile(re.escape(name) + r" a=(\d+) b=(\d+) c=(\d+)")
            matched = []
            for line in lines:
                if line.startswith(name + " "):
                    found = pattern.fullmatch(line)
                    require(found is not None, "malformed " + name)
                    matched.append(tuple(map(int, found.groups())))
            return matched

        require(rows("SMP_BOOT_OK") == [(4, 15, 0)], "invalid four-core boot marker")
        require(rows("SMP_CPU_ON") == [(1, 1, 0), (2, 2, 0), (3, 3, 0)], "CPU_ON proof missing")
        # Positive causal chain, serial vs independent memory cross-check.
        require(rows("V0199_ADVICE_SUBMIT") == [(6, SVC64, 1)], "advice submit not recorded")
        require(rows("V0199_ADVICE_REVIEW") == [(4, 1, 0)], "rule review did not adopt candidate 4")
        require(rows("V0199_ADVICE_REGISTER") == [(2, SVC64, 1)], "register not frozen via 0x50")
        require(rows("V0199_ADVICE_REGISTER_RETRY") == [(2, 2, 0)], "register retry not idempotent")
        require(rows("V0199_ADVICE_PUBLISH") == [(8, SVC64, 1)], "publish not accepted via 0x41")
        require(rows("V0199_ADVICE_PUBLISH_REPLAY") == [(8, 2, 1)], "publish replay re-accepted")
        require(rows("V0199_ADVICE_APPLY") == [(1, 180, 4)], "executor apply evidence wrong")
        require(rows("V0199_ADVICE_SETTLE") == [(1, 1, 2)], "terminal/causal label wrong")
        require(rows("V0199_ADVICE_CHAIN") == [(1, 1, 1)], "causal chain ids disagree")
        # Negatives.
        require(rows("V0199_ADVICE_NEG") == [(0, 0, 0)], "identity/domain/cap negatives not rejected")
        require(rows("V0199_ADVICE_WRONG_CPU") == [(1, 0, 0)], "wrong-CPU negative missing")
        require(rows("V0199_ADVICE_BAD_PUBLISH") == [(6, 0, 0)], "non-publisher not rejected")
        # Independent memory rows.
        submit = words[16:24]
        register = words[24:32]
        publish = words[32:40]
        settle = words[40:48]
        negatives = words[48:56]
        require(tuple(submit[:6]) == (6, SVC64, 0x50, 1, 1, 1), "submit memory row wrong")
        require(tuple(register[:6]) == (2, SVC64, 0x50, 1, 1, 4), "register memory row wrong")
        require(tuple(publish[:6]) == (8, SVC64, 0x41, 1, 1, 1), "publish memory row wrong")
        require(tuple(settle[:6]) == (1, 1, 1, 2, 0, 180), "settle memory row wrong")
        require(tuple(negatives) == (0, 0, 0, 1, 0, 2, 2, 1), "negative memory row wrong")
        require(submit[6] != 0 and register[6] != 0 and publish[6] != 0 and settle[6] != 0,
                "causal digests must be nonzero")
        # Business CPUs kept running, control never promoted.
        business = rows("V0199_ADVICE_BUSINESS")
        require(len(business) == 3, "missing business progress")
        progress_total = 0
        for slot in range(1, 4):
            affinity, progress, control_turns, irqs = words[64 + (slot - 1) * 4:68 + (slot - 1) * 4]
            require(affinity == slot and progress >= 2 and control_turns == 0 and irqs > 0,
                    "CPU1-3 did not keep business-only native progress")
            require(business[slot - 1] == (slot, progress, irqs), "business serial/memory mismatch")
            progress_total += progress
        return {
            "guest_cpus": 4,
            "fixed_control_cpu": 0,
            "business_cpu_mask": 14,
            "advice_seq": words[6],
            "plan_seq": words[7],
            "decision_seq": words[8],
            "disposition_state": words[9],
            "selected_index": words[10],
            "fallback_index": words[11],
            "causal_label": words[12],
            "unique_native_accept_count": words[13],
            "rejected_negatives": words[15],
            "business_progress_turns": progress_total,
            "production_wiring": False,
            "evidence_kind": "guest-EL0-advice-chain-fixture-only",
        }


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fixture_manifest() -> dict:
    names = {}
    for name in FIXTURE_SOURCES:
        p = ROOT / name
        verify_smp.require(p.is_file() and not p.is_symlink(), "missing fixture source " + name)
        names[name] = sha(p)
    return names


def run(elf: Path, output: Path, timeout: float = 45) -> dict:
    require = verify_smp.require
    require(1 <= timeout <= 60, "invalid execution budget")
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), "refuse to reuse evidence output")
    output.mkdir(parents=True)
    before = fixture_manifest()
    (output / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    acceptance = AdviceE2E()
    report = {
        "status": "FAIL", "scope": "native-v0199-advice-chain-e2e-fixture",
        "model_driven": False, "production_wiring": False,
        "elf_sha256": sha(elf),
        "source_manifest_sha256": sha(output / "source-manifest.json"),
        "source_binding": "fixture-scoped (concurrent-wave whole-tree binding skipped)",
    }
    report.update(acceptance.metadata())
    decoder = FrameDecoder(); raw = bytearray(); decoded = bytearray()
    proc = None; sock = None; qmp = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cyx-adv-") as td, (output / "qemu-stderr.log").open("wb") as err:
        try:
            location = acceptance.profile(elf.read_bytes())
            binary = shutil.which("qemu-system-aarch64")
            require(binary is not None, "qemu-system-aarch64 is missing")
            version = subprocess.check_output([binary, "--version"], timeout=10, text=True)
            require(version.splitlines()[0] in ("QEMU emulator version 10.2.2",
                    "QEMU emulator version 10.2.2 (v10.2.2)"), "unverified QEMU version")
            report["qemu_version"] = version
            report["qemu_sha256"] = sha(Path(binary))
            path = str(Path(td) / "q.sock")
            args = [binary, "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
                    "-cpu", "cortex-a53", "-smp", "4", "-m", "256M", "-accel", "tcg,thread=multi",
                    "-display", "none", "-monitor", "none", "-nic", "none",
                    "-chardev", "ringbuf,id=cyxlog,size=1048576", "-serial", "chardev:cyxlog",
                    "-qmp", f"unix:{path},server=on,wait=off", "-kernel", str(elf), "-no-reboot"]
            report["argv"] = args
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
            end = started + timeout
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None, "QEMU exited before handshake")
                if time.monotonic() >= end:
                    raise TimeoutError("QMP handshake deadline")
                try:
                    sock.connect(path); break
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(0.01)
            qmp = Qmp(sock)
            require("QMP" in qmp.receive(end), "invalid QMP greeting")
            qmp.execute("qmp_capabilities")
            actual_cpus = qmp.execute("query-cpus-fast")
            report["qmp_cpus"] = actual_cpus
            while time.monotonic() < end:
                require(proc.poll() is None, "QEMU exited before acceptance")
                value = qmp.execute("ringbuf-read", {"device": "cyxlog", "size": 1048576, "format": "base64"})
                data = base64.b64decode(value, validate=True)
                raw.extend(data)
                require(len(raw) <= 2 * 1024 * 1024, "serial budget exceeded")
                for frame in decoder.feed(data):
                    decoded.extend(frame)
                if b"FAIL" in decoded or b"SMP_ERROR" in decoded:
                    raise ValueError("guest failure")
                if acceptance.completion in decoded:
                    qmp.execute("stop")
                    qmp.execute("pmemsave", {"val": location["pa"], "size": 4096,
                                            "filename": str(output / "native-page.bin")})
                    require(decoder.loss == 0 and decoder.corrupt == 0 and not decoder.buffer,
                            "incomplete/corrupt framed UART transport")
                    page = (output / "native-page.bin").read_bytes()
                    report["observations"] = acceptance.validate(bytes(decoded), page, len(actual_cpus))
                    require(sha(elf) == report["elf_sha256"], "ELF changed during guest run")
                    require(before == fixture_manifest(), "fixture source changed during guest run")
                    report["status"] = "PASS"
                    report.update(acceptance.success())
                    break
                time.sleep(0.01)
            else:
                raise TimeoutError("native execution deadline")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if proc is not None:
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
                report["qemu_exit"] = proc.returncode
            if sock:
                sock.close()
            if qmp:
                (output / "qmp.jsonl").write_text("".join(json.dumps(m) + "\n" for m in qmp.transcript))
    (output / "serial.bin").write_bytes(raw)
    (output / "serial.txt").write_bytes(decoded)
    report["transport"] = dict(frames=decoder.frames, lost=decoder.loss, corrupt=decoder.corrupt)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["evidence_sha256"] = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    try:
        result = run(args.elf, args.output, args.timeout)
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=__import__("sys").stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
