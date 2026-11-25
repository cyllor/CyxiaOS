#!/usr/bin/env python3
"""Independent pinned-QEMU check of the V0.20 production boot + in-vector SVC
dispatch SKELETON (wave 10 T1, feature v020-production).

This verifies that, in the production profile, the eight ABI3 PIE role packages
load through the build catalog and execute, and that the advice causal chain
(AdviceEnvelope v1 -> 0x50 intake -> RuleProfile review -> 0x50 register ->
0x41 publish -> ApplyReport -> supervisor terminal) is serviced by REAL EL0
SVC64 traps dispatched IN THE EXCEPTION VECTOR (ESR=0x56000000), not a fixture
turn loop. It also checks the fail-closed negatives and that CPU1-3 keep
business-only progress.

HONEST SCOPE: this is a production SKELETON, not full production authority. The
boot epoch is staged (volatile), the executor is a bounded fixture target, no
real model is active, and the snapshot/audit backend stays fail-closed (EAGAIN).
The verifier requires the guest to advertise exactly that scope and refuses any
claim of full_authority / real_models.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
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
# Profile-scoped source binding (a concurrent remediation wave can transiently
# break a whole-tree binding by editing another agent's scope). Bind the
# production skeleton's own stable sources plus the ELF.
PRODUCTION_SOURCES = [
    "kernel/src/arch/aarch64/production.rs",
    "kernel/src/arch/aarch64/v0199_advice_user.S",
    "kernel/src/arch/aarch64/smp.rs",
    "kernel/src/arch/aarch64/boot.rs",
    "kernel/src/arch/aarch64/exceptions.rs",
    "kernel/Cargo.toml",
    "kernel/build/aarch64.rs",
    "kernel/build/v0199_roles.rs",
    "tools/verify_v020_production.py",
]
MAGIC = 0x4359_5052_4431_3030
COMPLETION = b"V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt\n"
SCOPE = "V020_PROD_SCOPE production_skeleton=true full_authority=false real_models=false"
SVC64 = 0x5600_0000


class Production:
    completion = COMPLETION

    def profile(self, elf: bytes) -> dict:
        return verify_smp.profile(elf)

    @staticmethod
    def metadata() -> dict:
        return {
            "scope": "native-v020-production-skeleton",
            "production_skeleton": True,
            "full_authority": False,
            "real_models": False,
            "in_vector_dispatch": True,
            "staged_boot_epoch": True,
            "fixture_executor": True,
            "real_control_services": False,
            "real_executor_device": False,
        }

    @staticmethod
    def success() -> dict:
        return {
            "native_v020_production_skeleton_verified": True,
            "production_skeleton": True,
            "full_authority": False,
            "real_models": False,
            "in_vector_dispatch": True,
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
        ], "incomplete production advice-chain completion evidence")
        require(all(v == 0 for v in words[56:64]), "nonzero reserved evidence")
        require(all(v == 0 for v in words[76:80]), "nonzero reserved evidence")
        require(all(v == 0 for v in words[128:]), "nonzero reserved evidence tail")
        require(b"SMP_ERROR" not in serial and b"FAIL" not in serial, "guest reported fault")
        lines = serial.decode("ascii").splitlines()
        require(lines.count(
            "V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt"
        ) == 1, "missing/duplicate production completion marker")
        require(lines.count(SCOPE) == 1, "production skeleton scope must be advertised exactly")
        require(sum(line.startswith("V020_PROD_SCOPE") for line in lines) == 1,
                "exactly one scope line")
        # The skeleton must NOT claim full authority or real models.
        require(b"full_authority=true" not in serial, "must not claim full authority")
        require(b"real_models=true" not in serial, "must not claim real models")

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
        # PIE role bootstrap: eight packages loaded, each clocked.
        pie_load = rows("V020_PROD_PIE_LOAD")
        require(len(pie_load) == 1 and pie_load[0][0] == 8, "eight PIE packages must load")
        pie_roles = rows("V020_PROD_PIE_ROLE")
        require(len(pie_roles) == 8, "eight PIE role evidence rows required")
        require(all(c >= 1 for (_, c, _) in pie_roles), "every PIE role must clock")
        # Positive in-vector causal chain (ESR must be a real SVC64 trap).
        require(rows("V020_PROD_SUBMIT") == [(6, SVC64, 1)], "in-vector advice submit not recorded")
        require(rows("V020_PROD_REVIEW") == [(4, 1, 0)], "rule review did not adopt candidate 4")
        require(rows("V020_PROD_REGISTER") == [(2, SVC64, 1)], "register not frozen via in-vector 0x50")
        require(rows("V020_PROD_REGISTER_RETRY") == [(2, 2, 0)], "register retry not idempotent")
        require(rows("V020_PROD_PUBLISH") == [(8, SVC64, 1)], "publish not accepted via in-vector 0x41")
        require(rows("V020_PROD_PUBLISH_REPLAY") == [(8, 2, 1)], "publish replay re-accepted")
        require(rows("V020_PROD_APPLY") == [(1, 180, 4)], "executor apply evidence wrong")
        require(rows("V020_PROD_SETTLE") == [(1, 1, 2)], "terminal/causal label wrong")
        require(rows("V020_PROD_CHAIN") == [(1, 1, 1)], "causal chain ids disagree")
        # Negatives.
        require(rows("V020_PROD_NEG") == [(0, 0, 0)], "identity/domain/cap negatives not rejected")
        require(rows("V020_PROD_WRONG_CPU") == [(1, 0, 0)], "wrong-CPU negative missing")
        require(rows("V020_PROD_BAD_PUBLISH") == [(6, 0, 0)], "non-publisher not rejected")
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
        # PIE evidence: eight distinct TTBR roots, each clocked; snapshot/audit
        # roles serviced an in-vector role call (EAGAIN), sleep roles yielded.
        roots = []
        for i in range(8):
            at = 80 + i * 6
            root, clocks, role_calls, yields, hash_lo, svc_out = words[at:at + 6]
            require(root != 0 and root % 4096 == 0, "PIE TTBR root must be a real page")
            require(clocks >= 1, "PIE role did not clock")
            require(role_calls >= 1 or yields >= 1, "PIE role made no progress")
            require(hash_lo != 0, "PIE image hash must be nonzero")
            roots.append(root)
        require(len(set(roots)) == 8, "eight PIE TTBR roots must be distinct")
        # Business CPUs kept running, control never promoted.
        business = rows("V020_PROD_BUSINESS")
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
            "pie_roles_loaded": 8,
            "pie_distinct_ttbr_roots": len(set(roots)),
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
            "in_vector_dispatch": True,
            "production_skeleton": True,
            "full_authority": False,
            "real_models": False,
            "evidence_kind": "guest-EL0-in-vector-production-skeleton",
        }


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def source_manifest() -> dict:
    names = {}
    for name in PRODUCTION_SOURCES:
        p = ROOT / name
        verify_smp.require(p.is_file() and not p.is_symlink(), "missing production source " + name)
        names[name] = sha(p)
    return names


def run(elf: Path, output: Path, timeout: float = 60) -> dict:
    require = verify_smp.require
    require(1 <= timeout <= 120, "invalid execution budget")
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), "refuse to reuse evidence output")
    output.mkdir(parents=True)
    before = source_manifest()
    (output / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    acceptance = Production()
    report = {
        "status": "FAIL", "scope": "native-v020-production-skeleton",
        "model_driven": False, "production_skeleton": True, "full_authority": False,
        "elf_sha256": sha(elf),
        "source_manifest_sha256": sha(output / "source-manifest.json"),
        "source_binding": "production-scoped (concurrent-wave whole-tree binding skipped)",
    }
    report.update(acceptance.metadata())
    decoder = FrameDecoder(); raw = bytearray(); decoded = bytearray()
    proc = None; sock = None; qmp = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cyx-prod-") as td, (output / "qemu-stderr.log").open("wb") as err:
        try:
            location = acceptance.profile(elf.read_bytes())
            binary = shutil.which("qemu-system-aarch64")
            require(binary is not None, "qemu-system-aarch64 is missing")
            version = subprocess.check_output([binary, "--version"], timeout=10, text=True)
            # Prefix match accepts both stock 10.2.2 and the repo's pinned
            # per-vCPU-PMU-patched 10.2.2 build (mirrors verify_v0199_eight_packages).
            require(version.splitlines()[0].startswith("QEMU emulator version 10.2.2"),
                    "unverified QEMU version")
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
                    require(before == source_manifest(), "production source changed during guest run")
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
    parser.add_argument("--timeout", type=float, default=60)
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
