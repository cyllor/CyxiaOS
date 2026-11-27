#!/usr/bin/env python3
"""Independent pinned-QEMU check of the V0.19.9 SEC-N native Echo DEPLOYMENT fixture.

Fixture scope ONLY. This verifies that the real cross-compiled user/local-echo EL0
image is loaded into its own private TTBR0/identity on CPU0 and that its restricted
SVC 0x43 broker is serviced from a bounded kernel-owned trait-level mock Port, and
that the guest's REAL Admission ledger + rustls TLS session fail closed on:
  * a wrong kernel-local node pin (identity mismatch, never polls a connection);
  * a stalled peer exhausting the bounded 8192-turn handshake budget (real
    begin_ns lease created then rejected, begin_restart + park);
  * a stale connection generation mid-handshake;
  * finish-without-quiescence (the device boundary refuses to certify TX quiescence).

It does NOT certify a real VirtIO-net device, a real pinned TLS peer, the positive
authenticated Echo turn, or finish_session credit retirement. Those remain the open
device gap (real_device_wiring=false, tls_echo_turn_verified=false,
finish_retirement_verified=false, production_deployment=false). The socket side is a
bounded mock Port, never a real NIC; no completion witness is fabricated.

Build order (the kernel feature embeds the guest ELF via include_bytes!):
  1. provision the fixed test identity (a-test cert/key + b-test node pin);
  2. cargo build --release -p cyxia-local-echo --features guest --target aarch64-unknown-none;
  3. cargo build -p cyxia-kernel --target aarch64-unknown-none-softfloat
       --features smp-selftest,v0199-sec-n-selftest;
  4. this runner boots the kernel ELF in stock QEMU 10.2.2 and reads the evidence.
Pass --build to perform steps 1-3 automatically before the run.
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
from test_v020_signed_scratch_vector import CATALOG, sign_scratch_fixture


ROOT = Path(__file__).resolve().parents[1]
# Fixture-scoped source binding (a concurrent remediation wave can transiently
# break the whole-tree binding). Bind the fixture's own stable sources, the guest
# identity material and the embedded guest ELF, plus the kernel ELF.
FIXTURE_SOURCES = [
    "kernel/src/arch/aarch64/v0199_sec_n_fixture.rs",
    "kernel/src/arch/aarch64/smp.rs",
    "kernel/Cargo.toml",
    "tools/verify_v0199_sec_n.py",
    "crates/net-transport/tests/fixtures/a-test-cert.der",
    "crates/net-transport/tests/fixtures/a-test-key.der",
    "crates/net-transport/tests/fixtures/b-test-cert.der",
    "user/local-echo/src/runtime.rs",
    "user/local-echo/src/broker.rs",
    "user/local-echo/src/abi.rs",
]
GUEST_ELF = "target/aarch64-unknown-none/release/cyxia-local-echo"
MAGIC = 0x4359_5853_4543_4E31  # "CYXSECN1"
# Framed UART payloads are bounded to 96 bytes (cyxia_contracts::transport::encode);
# both markers must stay within that bound or the kernel silently drops them.
COMPLETION = b"V0199_SEC_N_FIXTURE_PASS cpus=4 deploy=el0-echo negatives=identity,budget,stale,quiescence\n"
SCOPE = "V0199_SEC_N_SCOPE production=false device=false echo_turn=false finish=false mock_port=true"
# node_id(b-test-cert.der) and node_id(a-test-cert.der): SHA256 of the Ed25519 SPKI key.
# The guest is the passive SERVER => it must own the LARGER node (b); peer.pin is a.
LOCAL_NODE = bytes.fromhex("ffffae142863c32aa1a210c541a2685f3f590e109e15d25e0dfcd5ad6d69b0dd")
PEER_NODE = bytes.fromhex("c04afa5ee908e77e049a4bbfde032ff097eb54caf3bc14776acdee22074b06c7")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def node_id(cert: bytes) -> bytes:
    i = cert.find(SPKI_PREFIX)
    if i < 0:
        raise ValueError("no Ed25519 SPKI in certificate")
    return hashlib.sha256(cert[i + 12:i + 44]).digest()


class SecNDeployment:
    completion = COMPLETION

    def profile(self, elf: bytes) -> dict:
        return verify_smp.profile(elf)

    @staticmethod
    def metadata() -> dict:
        return {
            "scope": "native-v0199-sec-n-echo-deployment-fixture",
            "production_deployment": False,
            "real_device_wiring": False,
            "tls_echo_turn_verified": False,
            "finish_retirement_verified": False,
            "mock_port": True,
            "real_admission_ledger_in_guest": True,
            "real_rustls_session_in_guest": True,
        }

    @staticmethod
    def success() -> dict:
        return {
            "native_sec_n_deployment_fixture_verified": True,
            "production_deployment": False,
            "real_device_wiring": False,
            "tls_echo_turn_verified": False,
            "finish_retirement_verified": False,
        }

    @staticmethod
    def validate(serial: bytes, page: bytes, cpu_count: int) -> dict:
        require = verify_smp.require
        require(cpu_count == 4, "QMP did not prove four real guest CPUs")
        require(len(page) == 4096, "short native-owned evidence page")
        words = struct.unpack("<512Q", page)
        # summary: [MAGIC, ver, completion, online, control, business, elf_len,
        #           entry, used_frames, lo(image_digest), d1, d2, d3,
        #           quiescence_refused, negatives, tls_echo_turn_verified]
        require(words[0] == MAGIC and words[1] == 1 and words[2] == 1,
                "incomplete SEC-N deployment completion evidence")
        require(words[3] == 15 and words[4] == 1 and words[5] == 14,
                "wrong four-core online/control/business masks")
        require(words[7] == 0x01000000, "guest entry must be the fixed 0x01000000")
        require(0 < words[8] <= 3072, "guest frame count out of fixture bounds")
        require(words[9] != 0, "guest image digest must be nonzero")
        require(words[13] >= 3, "every CLOSE must refuse TX quiescence")
        require(words[14] == 4, "expected four fail-closed negatives")
        require(words[15] == 0, "must NOT claim a verified TLS echo turn")
        require(all(v == 0 for v in words[60:]), "nonzero reserved evidence tail")
        require(b"SMP_ERROR" not in serial and b"FAIL" not in serial, "guest reported fault")
        lines = serial.decode("ascii").splitlines()
        require(lines.count(COMPLETION.decode().rstrip("\n")) == 1,
                "missing/duplicate SEC-N completion marker")
        require(lines.count(SCOPE) == 1, "fixture scope must not claim production deployment")

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
        # Load binds the embedded guest ELF entry/frame-count/digest.
        load = rows("V0199_SEC_N_LOAD")
        require(len(load) == 1 and load[0][0] == 0x01000000 and load[0][1] == words[8]
                and load[0][2] == words[9], "guest load evidence disagrees with memory")
        # Negatives: serial vs independent memory cross-check.
        identity = rows("V0199_SEC_N_NEG_IDENTITY")
        budget = rows("V0199_SEC_N_NEG_BUDGET")
        stale = rows("V0199_SEC_N_NEG_STALE")
        finish = rows("V0199_SEC_N_NEG_FINISH")
        require(len(identity) == len(budget) == len(stale) == len(finish) == 1,
                "missing negative report lines")
        row0, row1, row2 = words[16:24], words[24:32], words[32:40]
        # (1) identity mismatch: never polls a connection, never reaches TLS.
        require(row0[1] == 0 and row0[2] == 0, "identity mismatch must not poll or use entropy")
        require(row0[3] >= 1, "identity mismatch must CLOSE (park)")
        require(identity[0] == (row0[0], row0[3], row0[1]), "identity serial/memory mismatch")
        # (2) budget exhaustion: real lease + TLS entropy, bounded 8192 turns, no egress.
        require(row1[1] >= 8192, "handshake must spend the bounded turn budget")
        require(row1[2] > 0, "a real TLS session must request entropy")
        require(row1[5] == 0, "passive server sends nothing before ClientHello")
        require(row1[3] >= 1, "budget exhaustion must CLOSE (park)")
        require(budget[0] == (row1[0], row1[1], row1[2]), "budget serial/memory mismatch")
        # (3) stale generation: aborts mid-handshake, epoch advanced.
        require(200 <= row2[1] < 8192, "stale generation must abort before the budget")
        require(row2[6] == 2, "stale generation must advance the connection epoch")
        require(row2[3] >= 1, "stale generation must CLOSE (park)")
        require(stale[0] == (row2[0], row2[1], row2[6]), "stale serial/memory mismatch")
        # (4) finish without quiescence: refused at every CLOSE, no fabricated retirement.
        require(finish[0][0] == words[13] and finish[0][0] >= 3,
                "finish/quiescence refusal evidence wrong")
        # Business CPUs kept running, control never promoted.
        business = rows("V0199_SEC_N_BUSINESS")
        require(len(business) == 3, "missing business progress")
        progress_total = 0
        for slot in range(1, 4):
            affinity, progress, control_turns, irqs = words[48 + (slot - 1) * 4:52 + (slot - 1) * 4]
            require(affinity == slot and progress >= 2 and control_turns == 0 and irqs > 0,
                    "CPU1-3 did not keep business-only native progress")
            require(business[slot - 1] == (slot, progress, irqs), "business serial/memory mismatch")
            progress_total += progress
        return {
            "guest_cpus": 4,
            "fixed_control_cpu": 0,
            "business_cpu_mask": 14,
            "guest_elf_bytes": words[6],
            "guest_entry": words[7],
            "guest_frames": words[8],
            "identity_negative_dispatches": words[10],
            "budget_negative_dispatches": words[11],
            "stale_negative_dispatches": words[12],
            "quiescence_refusals": words[13],
            "rejected_negatives": words[14],
            "tls_echo_turn_verified": False,
            "business_progress_turns": progress_total,
            "production_deployment": False,
            "evidence_kind": "guest-EL0-sec-n-deployment-fixture-only",
        }


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fixture_manifest() -> dict:
    names = {}
    for name in FIXTURE_SOURCES + [GUEST_ELF]:
        p = ROOT / name
        verify_smp.require(p.is_file() and not p.is_symlink(), "missing fixture source " + name)
        names[name] = sha(p)
    # Bind the provisioned identity to the fixture's hardcoded node pins.
    cert = (ROOT / "crates/net-transport/tests/fixtures/b-test-cert.der").read_bytes()
    peer_cert = (ROOT / "crates/net-transport/tests/fixtures/a-test-cert.der").read_bytes()
    verify_smp.require(node_id(cert) == LOCAL_NODE, "b-test cert node_id != fixture LOCAL_NODE")
    verify_smp.require(node_id(peer_cert) == PEER_NODE, "a-test cert node_id != fixture PEER_NODE")
    verify_smp.require(LOCAL_NODE > PEER_NODE, "guest server node must be larger than the peer")
    return names


def cargo_prefix() -> str:
    cargo_env = Path.home() / ".cargo" / "env"
    return f'. "{cargo_env}" && ' if cargo_env.is_file() else ""


def build_guest(isolated_signer: bool = False) -> None:
    """Provision the fixed test identity and build the release local-echo guest.

    Shared with tools/verify_v020_production.py: the production kernel
    include_bytes!-embeds this exact fixture-identity guest ELF.
    """
    env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="cyx-sec-n-ident-") as temporary:
        ident = Path(temporary)
        fixtures = ROOT / "crates/net-transport/tests/fixtures"
        shutil.copy(fixtures / "b-test-cert.der", ident / "cert.der")
        if isolated_signer:
            shutil.copy(fixtures / "b-test-key.der", ident / "key.der")
        (ident / "peer.pin").write_bytes(PEER_NODE)
        guest_env = dict(env)
        guest_env.update({
            "CC_aarch64_unknown_none": "clang",
            "CFLAGS_aarch64_unknown_none":
                "--target=aarch64-none-elf -ffreestanding -fno-stack-protector "
                "-mno-outline-atomics -DRING_CORE_NOSTDLIBINC",
            "RUSTFLAGS": "-C relocation-model=static -C code-model=large -C strip=debuginfo",
            "CYXIA_LOCAL_ECHO_IDENTITY": str(ident),
        })
        feature = "guest-signer" if isolated_signer else "guest"
        subprocess.run(
            cargo_prefix() + "cargo build --release --locked --offline -p cyxia-local-echo "
            f"--features {feature} --target aarch64-unknown-none",
            shell=True, cwd=ROOT, env=guest_env, check=True, executable="/bin/bash")
        if isolated_signer:
            release = ROOT / GUEST_ELF
            signer = release.with_name("cyxia-echo-signer")
            message = (b"CYX/TLS-PACKAGES/v1" + struct.pack("<QQQ", 1, 1, 1)
                       + hashlib.sha256(CATALOG[2]).digest()
                       + hashlib.sha256(release.read_bytes()).digest()
                       + hashlib.sha256(signer.read_bytes()).digest())
            signature = sign_scratch_fixture(ident, message)
            verify_smp.require(len(signature) == 64, "invalid TLS fixture qualification")
            release.with_name("cyxia-tls-packages.sig").write_bytes(signature)


def build() -> Path:
    """Provision the fixed test identity and build the guest then the kernel feature."""
    build_guest()
    # The kernel must NOT inherit the guest RUSTFLAGS (different target/ABI).
    kernel_env = dict(os.environ)
    kernel_env.pop("RUSTFLAGS", None)
    subprocess.run(
        cargo_prefix() + "cargo build -p cyxia-kernel --target aarch64-unknown-none-softfloat "
        "--features smp-selftest,v0199-sec-n-selftest",
        shell=True, cwd=ROOT, env=kernel_env, check=True, executable="/bin/bash")
    return ROOT / "target/aarch64-unknown-none-softfloat/debug/cyxia-kernel"


def run(elf: Path, output: Path, timeout: float = 240) -> dict:
    require = verify_smp.require
    # The real guest's bounded 8192-turn handshake-budget phase is ~33k EL0 SVC
    # traps under TCG; the whole fixture needs ~2-3 minutes of guest wall time.
    require(1 <= timeout <= 300, "invalid execution budget")
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), "refuse to reuse evidence output")
    output.mkdir(parents=True)
    before = fixture_manifest()
    (output / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    acceptance = SecNDeployment()
    report = {
        "status": "FAIL", "scope": "native-v0199-sec-n-echo-deployment-fixture",
        "model_driven": False, "production_deployment": False,
        "elf_sha256": sha(elf),
        "source_manifest_sha256": sha(output / "source-manifest.json"),
        "source_binding": "fixture-scoped (concurrent-wave whole-tree binding skipped)",
    }
    report.update(acceptance.metadata())
    decoder = FrameDecoder(); raw = bytearray(); decoded = bytearray()
    proc = None; sock = None; qmp = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cyx-secn-") as td, (output / "qemu-stderr.log").open("wb") as err:
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
            # Mock port: no real NIC. The guest broker is serviced entirely in-kernel.
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
    parser.add_argument("--elf", type=Path, help="kernel ELF (omit with --build)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--build", action="store_true", help="build guest+kernel first")
    args = parser.parse_args()
    try:
        elf = build() if args.build else args.elf
        if elf is None:
            raise ValueError("--elf is required unless --build is given")
        result = run(elf, args.output, args.timeout)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=__import__("sys").stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
