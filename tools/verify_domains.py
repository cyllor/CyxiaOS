#!/usr/bin/env python3
"""Native domain functional probe and exact host replay of captured EL0 inputs.

This runner does not replace verify_unified.py or certify physical real-time
deadlines, a trained model, or two effective policies for all eighteen families.
Every PASS requires the real EL0 file probe and a captured publication whose
executor later reported APPLIED; the host verifier checks the original input,
hashes, candidate set, model evaluation and Plan reply.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import time

try:
    from .check_elf import boot_profile, inspect_elf, symbol
    from .doctor import ROOT
    from .run_qemu import Qmp
    from .transport import FrameDecoder
except ImportError:
    from check_elf import boot_profile, inspect_elf, symbol
    from doctor import ROOT
    from run_qemu import Qmp
    from transport import FrameDecoder

CONTROL_MAGIC = 0x435958444F4D3031
UNIFIED_MAGIC = 0x435958554E493031
IPI_MAGIC = 0x4359495049000001
CONTROL_WORDS = 512 + 64 * 640
ALL_FAMILIES = (1 << 18) - 1
REQUIRED = {
    "UNIFIED_EVIDENCE": 4096,
    "DOMAIN_CONTROL_EVIDENCE": CONTROL_WORDS * 8,
    "RUNTIME_V13_EVIDENCE": 8192,
    "STORAGE_V13_EVIDENCE": 4096,
    "DOMAIN_TASK_EVIDENCE": 256,
    "TASK_OVERRUN_EVIDENCE": 256,
    "IPI_EVIDENCE": 4096,
}
OPTIONAL = {"DYNAMIC_V13_EVIDENCE": 4096, "PANIC_EVIDENCE": 64,
            "TASK_SLICE_EVIDENCE": 1024}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def words(data, count):
    require(len(data) == count * 8, "incorrect evidence size")
    return struct.unpack(f"<{count}Q", data)


def parse_unified(data):
    u = words(data, 512)
    require(u[15] == 0, f"native fatal code {u[15]}")
    if u[0] == 0:
        return None
    require(u[0] == UNIFIED_MAGIC and u[1] > 0, "invalid unified header")
    require(u[6] <= 200, "unified event trace overflow")
    require(u[16] == 1 and u[17] > 0 and u[18] > 0,
            "image does not contain an enabled ordinary EL0 file probe")
    require(u[19] in (0, 1), "invalid probe completion flag")
    if u[19]:
        require(u[20] == 0, f"ordinary EL0 file probe exit code {u[20]}")
    return {
        "boot_epoch": u[1], "el0_returns": u[2],
        "sent_bytes": u[4], "received_bytes": u[5],
        "events": list(u[32:32 + 2 * u[6]:2]),
        "probe_object": [u[17], u[18]], "probe_completed": bool(u[19]),
        "probe_exit_code": u[20],
    }


def parse_control(data, boot_epoch=None):
    w = words(data, CONTROL_WORDS)
    if w[0] == 0:
        return None
    require(w[0] == CONTROL_MAGIC and w[1] == 1 and w[2] > 0,
            "invalid domain control header")
    require(w[12:14] == (64, 640), "unsupported domain evidence layout")
    require(w[25] == 0, f"native resource confirmation error {w[25]} in domain {w[26]}")
    if boot_epoch is not None:
        require(w[2] == boot_epoch, "domain/unified BootEpoch mismatch")
    require(w[3] & ~ALL_FAMILIES == 0, "unknown registered family")
    complete = []
    for slot in range(64):
        r = w[512 + slot * 640:512 + (slot + 1) * 640]
        # A stopped vCPU may be inside a record update. Such a record is never
        # evidence of completion; the host verifier also skips odd seqlocks.
        if r[639] & 1 or r[0] == 0 or r[30] == 0:
            continue
        require(r[0] == r[1] and r[7] == w[2], "record identity mismatch")
        require(1 <= r[14] <= 4, "invalid executor state")
        if r[13] > 0:
            require(r[12] <= 500_000 and r[18] == 0,
                    "published policy exceeded 0.5 ms publication budget")
            require(r[10] + r[11] + r[29] <= 2_000_000,
                    "published inference exceeded encoding/inference/decoding budget")
        if r[14] == 2:
            require(r[13] > 0 and r[19] == 1 and r[15] == 0,
                    "APPLIED without a published EL0 reply")
            require(r[28] >= r[9] >= r[8], "executor completion time ordering")
            complete.append((r[2], r[3], r[4], r[5]))
    return {
        "boot_epoch": w[2], "registered_families": w[3],
        "jobs": w[4], "published": w[5], "rejected": w[6],
        "applied": w[7], "failed": w[8], "unknown": w[9],
        "aborted": w[10], "applied_objects": complete,
        "family_jobs": list(w[32:50]), "family_applied": list(w[64:82]),
    }


def parse_tasks(data):
    w = words(data, 32)
    if w[0] == 0:
        return None
    require(w[0] == 0x43595441534B0001, "invalid task evidence header")
    require(w[2] == 0 and w[3] == 0,
            f"native task credit overrun/quarantine: mask={w[2]} overruns={w[3]}")
    return {
        "now_ns": w[1], "quarantine_mask": w[2], "overruns": w[3],
        "cpu_spent_ns": [w[4], w[5], w[6]], "threads": w[7],
        "service_admitted": bool(w[8]), "probe_object": [w[9], w[10]],
        "probe_life": w[11], "probe_entered": bool(w[12]),
        "probe_exit_code": w[13], "probe_cpu_ns": w[14],
        "stopped_pc": w[15], "stopped_kind": w[16],
        "stopped_esr": w[17], "stopped_far": w[18],
        "file_pending": w[21], "file_busy": w[22], "file_done": w[23],
        "cpu3_active_task": w[26], "cpu3_reserved_ns": w[27],
        "stopped_x0": w[29], "stopped_x8": w[30], "runnable": w[31],
    }


def parse_ipi(data):
    w = words(data, 512)
    require(w[13] == 0, f"native IPI receipt error {w[13]}")
    if w[0] == 0:
        return None
    require(w[0] == IPI_MAGIC and w[1] == 1, "invalid IPI evidence header")
    require(w[9] + w[10] <= w[6] <= w[5] and w[9] + w[10] <= w[8],
            "IPI completion without a consumed real handler receipt")
    return {
        "registered_cpus": w[2], "core_generation": w[3],
        "hardware_notifications": w[4], "handler_entries": w[5],
        "consumed_receipts": w[6], "probe_requests": w[8],
        "observed_receipts": w[9], "stale_receipts": w[10],
        "wake_verified": bool(w[2] & (1 << 3) and w[4] > 0 and w[9] > 0),
    }


def diagnostics(guest, bundle):
    guest["unified_words"] = list(words(bundle["UNIFIED_EVIDENCE"], 512)[:32])
    for symbol_name, key, count in (("DOMAIN_TASK_EVIDENCE", "task_evidence", 32),
                                    ("TASK_OVERRUN_EVIDENCE", "overrun_evidence", 32),
                                    ("TASK_SLICE_EVIDENCE", "slice_evidence", 128),
                                    ("IPI_EVIDENCE", "ipi_evidence", 512),
                                    ("PANIC_EVIDENCE", "panic_evidence", 8)):
        if symbol_name in bundle:
            guest[key] = list(words(bundle[symbol_name], count))
    if "DOMAIN_TASK_EVIDENCE" in bundle:
        guest["tasks"] = parse_tasks(bundle["DOMAIN_TASK_EVIDENCE"])
    if "IPI_EVIDENCE" in bundle:
        guest["ipi"] = parse_ipi(bundle["IPI_EVIDENCE"])
    # A synchronous file operation may retain its caller while waiting for a
    # new credit. Its periodic task snapshot can then be older than the actual
    # completion fault; the independent sticky record must still fail the run.
    require(not guest.get("overrun_evidence", [0])[0],
            "native sticky CPU credit overrun evidence is present")
    require(not guest.get("panic_evidence", [0])[0], "kernel panic evidence is present")


def profile(path):
    data = path.read_bytes()
    inspect_elf(data)
    require(boot_profile(data)["ram_mib"] == 1024, "domain image requires 1 GiB")
    locations = {}
    for name, size in REQUIRED.items():
        locations[name] = symbol(data, name)
        require(locations[name]["size"] == size, f"bad {name} size")
    for name, size in OPTIONAL.items():
        try:
            location = symbol(data, name)
        except ValueError as error:
            if str(error) != "missing symbol " + name:
                raise
        else:
            require(location["size"] == size, f"bad {name} size")
            locations[name] = location
    return data, locations


def drain(guest):
    encoded = guest["qmp"].execute("ringbuf-read", {
        "device": "cyxlog", "size": 1048576, "format": "base64"})
    data = base64.b64decode(encoded, validate=True)
    guest["raw"].extend(data)
    require(len(guest["raw"]) <= 4 * 1024 * 1024, "serial evidence budget exceeded")
    for frame in guest["decoder"].feed(data):
        guest["serial"].extend(frame)
    (guest["folder"] / "serial.txt").write_bytes(guest["serial"])
    require(not any(marker in guest["serial"] for marker in
                    (b"FAIL", b"PANIC", b"SMP_ERROR")), "guest reported failure")


def capture(guests, *, resume):
    """Stop all owned guests before reading evidence; never infer RT from this."""
    stopped = []
    bundles = []
    try:
        for guest in guests:
            guest["qmp"].execute("stop")
            stopped.append(guest)
        for guest in guests:
            bundle = {}
            for name, location in guest["locations"].items():
                path = guest["folder"] / (name + ".bin")
                guest["qmp"].execute("pmemsave", {
                    "val": location["pa"], "size": location["size"],
                    "filename": str(path)})
                bundle[name] = path.read_bytes()
            bundles.append(bundle)
    finally:
        if resume:
            for guest in stopped:
                guest["qmp"].execute("cont")
    return bundles


def archive(guest, data, control, force=False):
    if control is None or control["registered_families"] != ALL_FAMILIES:
        return
    objects = set(control["applied_objects"])
    if not objects or not (force or objects - guest["seen_objects"]):
        return
    require(len(guest["captures"]) < 256, "bounded evidence archive exhausted")
    path = guest["folder"] / f"control-{len(guest['captures']):03d}.bin"
    path.write_bytes(data)
    guest["captures"].append(path)
    guest["seen_objects"].update(objects)


def replay(verifier, capture_path, model):
    command = [str(verifier), str(capture_path)]
    if model is not None:
        command.append(str(model))
    result = subprocess.run(command, capture_output=True, timeout=30)
    capture_path.with_suffix(".verifier.stdout").write_bytes(result.stdout)
    capture_path.with_suffix(".verifier.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "host replay rejected " + capture_path.name +
            ": " + result.stderr.decode(errors="replace")[-2000:])
    proof = json.loads(result.stdout)
    require(proof.get("status") == "PASS" and proof.get("replayed", 0) > 0
            and proof.get("accepted", 0) > 0 and proof.get("applied", 0) > 0,
            "host verifier did not prove a real publication and APPLIED receipt")
    require(proof.get("physical_realtime_verified") is False,
            "functional replay cannot claim physical real-time verification")
    return proof


def run(args):
    require(1 <= args.timeout <= 600 and 0 <= args.hold <= 60,
            "invalid functional observation deadline")
    require(50 <= args.sample_ms <= 2000, "sample interval must be 50..2000 ms")
    require(args.single != (args.peer_elf is not None),
            "choose --single or provide --peer-elf")
    images = [args.elf.resolve(strict=True)]
    if not args.single:
        images.append(args.peer_elf.resolve(strict=True))
    verifier = args.verifier.resolve(strict=True)
    formatter = args.formatter.resolve(strict=True)
    model = args.model.resolve(strict=True) if args.model else None
    binary = Path(args.qemu or shutil.which("qemu-system-aarch64") or "")
    require(binary.is_file(), "qemu-system-aarch64 is missing")
    binary = binary.resolve(strict=True)
    output = args.output.resolve()
    require(not output.exists(), "refuse to reuse a test output directory")
    output.mkdir(parents=True, mode=0o700)
    report = {
        "schema_version": 1, "status": "FAIL", "scope": "native-domain-functional",
        "nodes": len(images), "physical_realtime_verified": False,
        "all_eighteen_families_two_effective_policies_verified": False,
        "release_acceptance_verified": False, "source_build_attested": False,
        "clock_profile": args.clock_profile, "sampling": "stopped guest snapshots",
        "elf_sha256": [sha(image) for image in images],
        "verifier_sha256": sha(verifier), "formatter_sha256": sha(formatter),
        "qemu_sha256": sha(binary), "output": str(output),
        "model_sha256": sha(model) if model else None,
    }
    guests = []
    started = time.monotonic()
    end = started + args.timeout
    ready_at = None
    last_progress = 0.0
    previous_umask = os.umask(0o077)
    print(json.dumps({"output": str(output), "nodes": len(images)}), flush=True)
    try:
        report["qemu_version"] = subprocess.check_output(
            [str(binary), "--version"], text=True, timeout=10).splitlines()[0]
        with tempfile.TemporaryDirectory(prefix="cyx-domains-") as temporary, ExitStack() as files:
            port = None
            if len(images) == 2:
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    port = listener.getsockname()[1]
            try:
                for ordinal, image in enumerate(images, 1):
                    folder = output / f"node-{ordinal}"
                    folder.mkdir(mode=0o700)
                    disk = folder / "disk.raw"
                    formatted = subprocess.run([str(formatter), str(disk), secrets.token_hex(16)],
                                               capture_output=True, check=True, timeout=30)
                    (folder / "format.log").write_bytes(formatted.stdout + formatted.stderr)
                    require(disk.stat().st_size == 512 * 1024 * 1024, "test disk must be 512 MiB")
                    blob, locations = profile(image)
                    qmp_path = str(Path(temporary) / f"q{ordinal}.sock")
                    network = ("hubport,id=net0,hubid=0" if port is None else
                               f"socket,id=net0,{'listen' if ordinal == 1 else 'connect'}=127.0.0.1:{port}")
                    command = [str(binary), "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
                               "-cpu", "cortex-a53", "-smp", "4", "-m", "1024M",
                               "-accel", "tcg,thread=single", "-S", "-display", "none", "-monitor", "none",
                               "-global", "virtio-mmio.force-legacy=false",
                               "-drive", f"if=none,id=disk0,format=raw,file={disk},cache=writeback",
                               "-device", "virtio-blk-device,drive=disk0", "-netdev", network,
                               "-device", f"virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:0{ordinal}",
                               "-object", f"filter-dump,id=capture,netdev=net0,file={folder / 'ethernet.pcap'}",
                               "-object", "rng-random,id=rng0,filename=/dev/urandom",
                               "-device", "virtio-rng-device,rng=rng0",
                               "-chardev", "ringbuf,id=cyxlog,size=1048576", "-serial", "chardev:cyxlog",
                               "-qmp", f"unix:{qmp_path},server=on,wait=off", "-kernel", str(image), "-no-reboot"]
                    if args.clock_profile == "icount":
                        command += ["-icount", "shift=0,align=on,sleep=on", "-rtc", "clock=vm"]
                    guest = {"folder": folder, "blob": blob, "locations": locations,
                             "argv": command, "raw": bytearray(), "serial": bytearray(),
                             "decoder": FrameDecoder(), "proc": None, "sock": None, "qmp": None,
                             "captures": [], "seen_objects": set()}
                    guests.append(guest)
                    error_log = files.enter_context((folder / "qemu-stderr.log").open("wb"))
                    guest["proc"] = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=error_log)
                    guest["sock"] = socket.socket(socket.AF_UNIX)
                    while True:
                        require(guest["proc"].poll() is None, "QEMU exited before QMP handshake")
                        if time.monotonic() >= end:
                            raise TimeoutError("QMP handshake deadline")
                        try:
                            guest["sock"].connect(qmp_path)
                            break
                        except (FileNotFoundError, ConnectionRefusedError):
                            time.sleep(0.01)
                    guest["qmp"] = Qmp(guest["sock"])
                    require("QMP" in guest["qmp"].receive(end), "invalid QMP greeting")
                    guest["qmp"].execute("qmp_capabilities")
                    require(len(guest["qmp"].execute("query-cpus-fast")) == 4, "four native CPUs required")
                    memory = guest["qmp"].execute("query-memory-size-summary")
                    require(memory["base-memory"] == 1024 ** 3, "wrong QEMU RAM size")
                for guest in guests:
                    guest["qmp"].execute("cont")
                while time.monotonic() < end:
                    if (output / "stop.request").exists():
                        raise RuntimeError("operator stopped this functional run")
                    for guest in guests:
                        require(guest["proc"].poll() is None, "QEMU exited during observation")
                        drain(guest)
                    bundles = capture(guests, resume=True)
                    ready = True
                    progress = []
                    for guest, bundle in zip(guests, bundles):
                        diagnostics(guest, bundle)
                        unified = parse_unified(bundle["UNIFIED_EVIDENCE"])
                        control = parse_control(bundle["DOMAIN_CONTROL_EVIDENCE"],
                                                unified["boot_epoch"] if unified else None)
                        guest["unified"], guest["control"] = unified, control
                        archive(guest, bundle["DOMAIN_CONTROL_EVIDENCE"], control)
                        observed = (unified is not None and control is not None and
                                    unified["probe_completed"] and unified["el0_returns"] > 0 and
                                    guest.get("ipi") is not None and guest["ipi"]["wake_verified"] and
                                    control["registered_families"] == ALL_FAMILIES and
                                    control["published"] > 0 and bool(guest["captures"]))
                        if len(guests) == 2 and unified:
                            observed = observed and unified["received_bytes"] > 0 and unified["sent_bytes"] > 0 and 3 in unified["events"]
                        ready = ready and observed
                        progress.append({"probe_done": bool(unified and unified["probe_completed"]),
                                         "jobs": control["jobs"] if control else 0,
                                         "applied": control["applied"] if control else 0})
                    now = time.monotonic()
                    if now - last_progress >= 2:
                        print(json.dumps({"wall_seconds": round(now - started, 2), "progress": progress}), flush=True)
                        last_progress = now
                    if ready:
                        ready_at = ready_at or now
                        if now - ready_at >= args.hold:
                            report["functional_conditions_observed"] = True
                            break
                    else:
                        ready_at = None
                    time.sleep(args.sample_ms / 1000)
                else:
                    raise TimeoutError("native file/control functional observation deadline")
            finally:
                if guests and all(g["qmp"] and g["proc"].poll() is None for g in guests):
                    try:
                        final = capture(guests, resume=False)
                        for guest, bundle in zip(guests, final):
                            try:
                                diagnostics(guest, bundle)
                                unified = parse_unified(bundle["UNIFIED_EVIDENCE"])
                                control = parse_control(bundle["DOMAIN_CONTROL_EVIDENCE"],
                                                        unified["boot_epoch"] if unified else None)
                                guest["unified"], guest["control"] = unified, control
                                archive(guest, bundle["DOMAIN_CONTROL_EVIDENCE"], control, force=True)
                            except ValueError as error:
                                guest["final_parse_error"] = str(error)
                            guest["registers"] = guest["qmp"].execute("human-monitor-command", {"command-line": "info registers -a"})
                            try:
                                bottom = symbol(guest["blob"], "__stack_bottom")["pa"]
                                top = symbol(guest["blob"], "__stack_top")["pa"]
                                guest["qmp"].execute("pmemsave", {"val": bottom, "size": top - bottom,
                                                       "filename": str(guest["folder"] / "cpu0-stack.bin")})
                                guest["stack_pa"] = bottom
                            except (ValueError, RuntimeError, OSError):
                                pass
                    except (ValueError, RuntimeError, OSError) as error:
                        report["final_capture_error"] = str(error)
                for guest in guests:
                    process = guest["proc"]
                    if process is not None and process.poll() is None:
                        try:
                            if guest["qmp"]:
                                guest["qmp"].execute("quit")
                        except (ValueError, RuntimeError, OSError):
                            pass
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            try:
                                process.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=2)
                    if guest["sock"]:
                        guest["sock"].close()
                    (guest["folder"] / "serial.raw").write_bytes(guest["raw"])
                    (guest["folder"] / "serial.txt").write_bytes(guest["serial"])
                    if guest["qmp"]:
                        (guest["folder"] / "qmp.json").write_text(json.dumps(guest["qmp"].transcript, indent=2))
        require(not report.get("final_capture_error"), report.get("final_capture_error", ""))
        proofs = []
        for guest in guests:
            require(not guest.get("final_parse_error"), guest.get("final_parse_error", ""))
            require(guest["decoder"].loss == guest["decoder"].corrupt == 0, "corrupt or lost serial frames")
            require(guest["captures"], "no captured APPLIED input for host replay")
            checked = [replay(verifier, path, model) for path in guest["captures"]]
            proofs.append({"captures": len(checked), "replays": checked,
                           "applied_domains": sorted({d for proof in checked for d in proof["applied_domains"]})})
        require([sha(image) for image in images] == report["elf_sha256"], "ELF changed during native run")
        require(sha(verifier) == report["verifier_sha256"], "host verifier changed during native run")
        report.update(status="PASS", host_replay=proofs)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    except KeyboardInterrupt:
        report["error"] = "interrupted by operator"
    finally:
        report["wall_seconds"] = time.monotonic() - started
        report["observations"] = [{key: guest.get(key) for key in
                                  ("argv", "unified", "unified_words", "control", "tasks", "ipi", "task_evidence", "overrun_evidence", "panic_evidence",
                                   "ipi_evidence", "slice_evidence",
                                   "registers", "stack_pa", "final_parse_error")}
                                 for guest in guests]
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        os.umask(previous_umask)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--peer-elf", type=Path)
    mode.add_argument("--single", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--formatter", type=Path, default=ROOT / "target/debug/examples/prototype-disk")
    parser.add_argument("--verifier", type=Path, default=ROOT / "target/debug/examples/verify-domain-evidence")
    parser.add_argument("--model", type=Path, help="raw model package used by the native controller")
    parser.add_argument("--qemu", help="path to qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=150)
    parser.add_argument("--hold", type=float, default=2, help="wall seconds after all functional conditions hold")
    parser.add_argument("--sample-ms", type=int, default=250)
    parser.add_argument("--clock-profile", choices=("icount", "wallclock"), default="icount")
    args = parser.parse_args()
    try:
        result = run(args)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps({key: result.get(key) for key in ("status", "scope", "output", "error", "wall_seconds")}), flush=True)
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
