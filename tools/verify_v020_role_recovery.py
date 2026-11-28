#!/usr/bin/env python3
"""Run the signed CPU0 local-recovery acceptance in pinned four-vCPU QEMU."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
from tempfile import TemporaryDirectory
import time

from check_elf import symbol
from check_v13_disk import crc32c
from run_qemu import Qmp
from transport import FrameDecoder
from v020_production_modes import rows
from v020_production_qemu import connect_qmp, sha, shutdown
from v020_g1_genesis import BOOT, SECURITY
from v020_snapshot_envelopes import BLOCK_BYTES, crc32c_zeroed
from v020_task_vm_fixture import toolchain_bin
from v020_tls_peer import exchange
from verify_smp import require
from verify_v020_sec_s import recovery_pages
from verify_v020_signed_resident import (PMU_PATCH, ROLES, capture_role_syscall_abi,
                                         verify_disk, verify_role_mappings)


WINDOW_NS = 100_000_000
RESTARTS = ((6, 2), (7, 1), (11, 1))
ROLE_BYTES = 24 * BLOCK_BYTES
PROBE_OFFSET = 15 * BLOCK_BYTES
PROBE_MAGIC = 0x4359585245435600
DECISION_MAGIC = 0x43595853434F4E00
STOP = "V020_SIGNED_ROLE_STOP"
RESTART = "V020_SIGNED_ROLE_RESTART"
PROGRESS = "V020_SIGNED_RESIDENT_PROGRESS"
BUSINESS = "V020_SIGNED_BUSINESS_PROGRESS"
RECOVERY = "V020_SEC_S_RECOVERY_BUDGET"
NET_READY = "V020_SIGNED_NET_READY"


def qemu_command(args, disk, path):
    argv = [str(args.qemu), "-machine", "virt-10.2,gic-version=2,secure=off,virtualization=off",
            "-cpu", "cortex-a53", "-smp", "4", "-m", "1024M", "-accel", "tcg,thread=multi",
            "-display", "none", "-monitor", "none", "-serial", "stdio", "-kernel", str(args.elf),
            "-no-reboot", "-qmp", f"unix:{path},server=on,wait=off",
            "-global", "virtio-mmio.force-legacy=false",
            "-drive", f"file={disk},if=none,id=scratch,format=raw,cache=none",
            "-device", "virtio-blk-device,drive=scratch", "-object", "rng-random,id=seed,filename=/dev/urandom",
            "-device", "virtio-rng-device,rng=seed"]
    port = None
    if args.tls_server is None:
        argv += ["-nic", "none"]
    else:
        manifest = (args.catalog / "key-manifest.bin").read_bytes()
        require(len(manifest) == 184 and manifest[:8] == b"CYXNET01"
                and manifest[64:72] == bytes((10, 0, 2, 15, 10, 0, 2, 2)),
                "expected the disposable QEMU IPv4 Echo fixture")
        guest, service = IPv4Address(manifest[64:68]), struct.unpack_from("<H", manifest, 74)[0]
        mac = manifest[76:82].hex(":")
        with socket.socket(socket.AF_INET) as loopback:
            loopback.bind(("127.0.0.1", 0))
            port = loopback.getsockname()[1]
        argv += ["-netdev", f"user,id=peer,restrict=on,hostfwd=tcp:127.0.0.1:{port}-{guest}:{service}",
                 "-device", f"virtio-net-device,netdev=peer,mac={mac}"]
    return argv, port


def dump(qmp, path, address, size):
    qmp.execute("pmemsave", {"val": address, "size": size, "filename": str(path)})
    raw = path.read_bytes()
    require(len(raw) == size, f"partial stopped-guest readback of {path.name}")
    return raw


def role_rows(qmp, output: Path, backing):
    raw = dump(qmp, output / "role-backing.bin", backing["pa"], backing["size"])
    require(len(raw) == len(ROLES) * ROLE_BYTES, "unexpected signed role backing size")
    return {role: struct.unpack_from("<16Q", raw, index * ROLE_BYTES + PROBE_OFFSET)
            for index, role in enumerate(ROLES)}


def plan_receipts(elf, image, qmp, output, epoch, probes):
    names = subprocess.check_output([toolchain_bin() / "llvm-nm", "-P", "--defined-only", elf],
                                    text=True).splitlines()
    owners = [line.split()[0] for line in names if "native6NATIVE" in line]
    require(len(owners) == 1, "missing the real D01 terminal owner")
    owner = symbol(image, owners[0])
    control = dump(qmp, output / "control-owner.bin", owner["pa"], owner["size"])
    plans = probes[8][8:12]
    require(plans == probes[2][8:12] and 0 < plans[0] < plans[1] < plans[2] < plans[3]
            and probes[2][:2] == (DECISION_MAGIC | 2, 31)
            and probes[8][:2] == (DECISION_MAGIC | 8, 63) and probes[8][3:5] == (4, 4)
            and all(probes[role][2] == epoch and probes[role][7] == 0 for role in (2, 8)),
            f"same-boot controller/publisher evidence differs: {probes[2]} {probes[8]}")
    results = []
    for version, plan in enumerate(plans, 1):
        header = struct.pack("<3Q4H4QiI", epoch, 1, plan, 0, 1, 1, 0, 0x100, epoch, epoch, version, 0, 2)
        offset = control.find(header)
        require(offset >= 0 and control.find(header, offset + 1) == -1,
                f"missing or duplicate scheduler APPLIED record for plan {plan}")
        raw = control[offset:offset + 98]
        require(raw[80:96] == bytes(16) and raw[96:] == b"\x02\0", "different actual scheduler action")
        completed = struct.unpack_from("<Q", raw, 72)[0]
        require(completed >= plan * WINDOW_NS, "receipt predates the real plan snapshot")
        (output / f"d01-applied-{version}.bin").write_bytes(raw)
        results.append({"seq": plan, "version": version, "completed_ns": completed, "weight": 2})
    return results


def check_transitions(lines, epoch, initial, final, receipts):
    roles = rows(lines, "V020_SIGNED_RESIDENT_ROLE")
    require(roles == [(index, role, 1) for index, role in enumerate(ROLES)]
            and rows(lines, "V020_SIGNED_RESIDENT_BOOT") == [(epoch, 8, 0)]
            and rows(lines, "SMP_BOOT_OK") == [(4, 15, 0)]
            and rows(lines, "V020_SIGNED_BUSINESS_READY") == [(epoch, 14, 0)],
            "the native CPU0/CPU1-3 topology or boot identity changed")
    require(not any(line.startswith(("V020_STARTUP state=SECURE_DEGRADED", "V020_SIGNED_ROLE_ISOLATED",
                                     "V020_SIGNED_RECOVERY_REPORT_LOSS")) for line in lines),
            "the local fault path fenced, isolated, or lost its recovery trace")
    events = [line for line in lines if line.startswith((STOP + " ", RESTART + " "))]
    require(len(events) == 2 * len(RESTARTS), "wrong number of scoped retirements or replacements")
    prior_stop, asid_seen = -1, set(range(0xA0, 0xA0 + len(ROLES)))
    for i, (role, reason) in enumerate(RESTARTS):
        stop, restart = (lines.index(events[2 * i + offset]) for offset in (0, 1))
        (new_role, generation, asid), = rows([lines[restart]], RESTART)
        require(rows([lines[stop]], STOP) == [(role, 1, reason)] and prior_stop < stop < restart
                and new_role == role and generation == 2 and 0 < asid < 256 and asid not in asid_seen,
                f"the stopped role {role} did not advance in its own CPU0 slot")
        asid_seen.add(asid)
        prior_stop = restart
        other = 255 ^ (1 << ROLES.index(role))
        during = lines[stop + 1:restart]
        progress = rows(during, PROGRESS)
        require(any((yield_mask >> 8) & 255 == other for _, yield_mask, _ in progress),
                f"unaffected CPU0 slots did not make progress while role {role} was stopped")
        business = rows(during, BUSINESS)
        require(len(business) >= 2 and all(a < b for a, b in zip(business[0], business[-1], strict=True)),
                f"business cores did not advance during role {role} recovery")
        a, b = initial[role], final[role]
        require(a[:4] == (PROBE_MAGIC | role, epoch, 1, (epoch << 16) | (0xC000 + ROLES.index(role)))
                and b[:3] == (PROBE_MAGIC | role, epoch, 2) and b[3] != a[3]
                and a[15] == b[15] == 0 and 0 < a[6] < b[6],
                f"role {role} did not obtain fresh signed private state and a new selector")
        if role != 11:
            require(b[4] == 3 and b[5] > 0 and b[13] in (2**64 - 1, 2**64 - 4),
                    f"role {role} did not reject the retired snapshot selector and read its new view")
            require(progress and (progress[0][0] + 1) * WINDOW_NS <= receipts[i + 1]["completed_ns"] < b[6],
                    f"missing native D01 scheduler completion during role {role} outage")
    old, new = initial[11], final[11]
    require(old[4] == 2 and new[4] == 4 and 0 < old[7] < new[7]
            and old[8:13] == new[8:13] and new[8] > 0
            and new[13:15] == (2**64 - 1, 2**64 - 1),
            "Supervisor takeover did not redeliver the exact unconfirmed audit record and revoke old READ/ACK")
    require(receipts[0]["completed_ns"] < final[6][6] and receipts[3]["completed_ns"] > new[6],
            "missing real controller work across the takeover")
    pmu = rows(lines, "V020_SIGNED_RESIDENT_CPU")
    debit = rows(lines, RECOVERY)
    require(len(pmu) >= 8 and all(0 < idle < measured == charged for measured, charged, idle in pmu)
            and all(a[0] < b[0] for a, b in zip(pmu, pmu[1:])), "CPU0 PMU and ledger differ")
    require(len(debit) >= 3 and all(count > 0 and 0 < used <= count * limit and limit == 8_000_000
                                   for count, used, limit in debit), "incomplete metered role retirement")
    return roles, {"transitions": events, "pmu_samples": pmu, "recovery_debits": debit}


def verify_generation_suffix(disk, roles, epoch):
    # The verified cold BootPair uses the two-image transaction in blocks
    # 2..7. Each subsequent same-boot restart has its own one-image transaction.
    generations = [generation for _, _, generation in roles]
    with disk.open("rb") as source:
        source.seek(3 * BLOCK_BYTES + 64)
        state = source.read(BLOCK_BYTES)
        source.seek(7 * BLOCK_BYTES)
        boot_commit = source.read(BLOCK_BYTES)
        prior_txid, prior_lsn, journal_epoch = struct.unpack_from("<3Q", boot_commit, 16)
        require(struct.unpack_from("<IHHI", boot_commit) == (0x43594C47, 1, 3, 128)
                and struct.unpack_from("<I", boot_commit, 56)[0] == crc32c_zeroed(boot_commit[:64], 56)
                and struct.unpack_from("<I", boot_commit, 12)[0] == crc32c(boot_commit[64:128]),
                "same-boot service recovery does not follow the durable BootPair")
        for i, (role, _) in enumerate(RESTARTS):
            source.seek((8 + i * 4) * BLOCK_BYTES)
            begin, redo, commit = source.read(BLOCK_BYTES), source.read(2 * BLOCK_BYTES), source.read(BLOCK_BYTES)
            records = []
            for kind, length, raw in ((1, 80, begin), (2, 4160, redo), (3, 128, commit)):
                magic, ver, observed_kind, size, payload_crc, txid, lsn, log_epoch = struct.unpack_from("<IHHII3Q", raw)
                require((magic, ver, observed_kind, size) == (0x43594C47, 1, kind, length)
                        and struct.unpack_from("<I", raw, 56)[0] == crc32c_zeroed(raw[:64], 56)
                        and payload_crc == crc32c(raw[64:length]) and not any(raw[length:]),
                        f"bad durable role {role} redo record")
                records.append((txid, lsn, log_epoch))
            txid, begin_lsn, log_epoch = records[0]
            require(txid == prior_txid + 1 and begin_lsn == prior_lsn + 1 and log_epoch == journal_epoch
                    and records == [(txid, begin_lsn + offset, log_epoch) for offset in range(3)]
                    and struct.unpack_from("<2Q", begin, 64) == (1, BLOCK_BYTES)
                    and struct.unpack_from("<4Q", commit, 64) == (txid, begin_lsn, begin_lsn + 1, 1),
                    "discontinuous same-boot redo")
            prior_txid, prior_lsn = txid, begin_lsn + 2
            image = redo[64:4160]
            require(struct.unpack_from("<Q", redo, 40)[0] == SECURITY
                    and commit[96:128] == sha256(redo[40:48] + image).digest()
                    and struct.unpack_from("<Q", image, 64)[0] == epoch,
                    "the role redo record changed the cold BootEpoch")
            expected = bytearray(state)
            struct.pack_into("<Q", expected, 24, struct.unpack_from("<Q", expected, 24)[0] + 1)
            index = ROLES.index(role)
            generations[index] += 1
            struct.pack_into("<Q", expected, 120 + 8 * index, generations[index])
            struct.pack_into("<I", expected, 72, crc32c_zeroed(expected, 72))
            require(image == expected, f"role {role} restart changed another protected identity or generation")
            state = image
    return generations


def verify_boot_policy(disk, epoch, roles, policy, lines):
    if not rows(lines, "V020_SEC_N_POLICY_COMMITTED"):
        return verify_disk(disk, epoch, roles, expected_policy_envelope=policy)
    # First TLS activation installs both homes without discarding the
    # original BootPair log. The restart suffix must preserve that policy.
    with disk.open("rb") as source:
        source.seek(SECURITY * BLOCK_BYTES)
        state = source.read(BLOCK_BYTES)
        source.seek(BOOT * BLOCK_BYTES)
        home = source.read(BLOCK_BYTES)
        source.seek(3 * BLOCK_BYTES + 64)
        redo = source.read(BLOCK_BYTES)
        source.seek(5 * BLOCK_BYTES + 64)
        boot_redo = source.read(BLOCK_BYTES)
    digest = sha256(policy).digest()
    configuration, rules, security, keys = struct.unpack_from("<4Q", policy, 32)
    require(rows(lines, "V020_SEC_N_POLICY_COMMITTED") == [(configuration, keys, 1)],
            "unexpected signed TLS policy transition")
    require(state == redo and state[:8] == b"SSYC\x02\x00\xf8\x00" and state[8:24] == policy[16:32]
            and struct.unpack_from("<I", state, 72)[0] == crc32c_zeroed(state, 72)
            and struct.unpack_from("<Q", state, 64)[0] == epoch and state[88:120] == digest
            and struct.unpack_from("<3Q", state, 32) == (rules, security, keys)
            and struct.unpack_from("<Q", state, 80)[0] == configuration
            and struct.unpack_from("<8Q", state, 120) == tuple(gen for _, _, gen in roles),
            "the checkpointed TLS policy and signed boot-pair evidence differ")
    require(home == boot_redo and home[:8] == b"EBYC\x01\x00\x28\x00" and home[8:24] == policy[16:32]
            and struct.unpack_from("<Q", home, 24)[0] == epoch
            and struct.unpack_from("<I", home, 32)[0] == crc32c_zeroed(home, 32),
            "TLS activation did not durably install the same BootEpoch")
    return digest.hex()


def verify_audit(disk, output, locator, policy, epoch, supervisor, lines):
    require(len(locator) == 104 and locator[:8] == b"CYXRPF01" and locator[24:56] == sha256(policy).digest(),
            "wrong audit carrier identity")
    pages = recovery_pages(disk, struct.unpack_from("<I", locator, 60)[0])
    original, acknowledged = sorted(pages, key=lambda page: struct.unpack_from("<Q", page, 40)[0])
    seq = supervisor[8]
    digest = struct.pack("<4Q", *supervisor[9:13])
    proof = original[160:416]
    proof_boot, cpu, flags, cpu_generation = struct.unpack_from("<QIIQ", proof, 8)
    record = struct.pack("<IHHQQ4H4Q32s", 0x43594155, 2, 128, proof_boot, seq, 10, 1, 3, 65535,
                         0, cpu_generation, cpu, cpu_generation, sha256(proof).digest())
    require(struct.unpack_from("<IHH", proof) == (0x43595241, 2, 256)
            and (proof_boot, cpu, flags) == (epoch, 0, 2)
            and struct.unpack_from("<2Q", proof, 80) == (6, 1)
            and original[144:146] == b"\x01\x00"
            and sha256(b"CYX/AUDIT/v2" + record).digest() == digest,
            "delivered audit digest differs from the durable attributed Ops proof")
    require(struct.unpack_from("<5Q", original, 40) == (1, epoch, 0, 0, 0)
            and struct.unpack_from("<5Q", acknowledged, 40) == (2, epoch, seq, epoch, 2)
            and acknowledged[80:112] == digest and acknowledged[112:144] == original[-32:]
            and not any(acknowledged[144:146]),
            "the replacement Supervisor did not durably retire the originally unconfirmed record")
    require(rows(lines, "V020_SEC_S_RECOVERY_PROOF_DURABLE") == [(epoch, 1, 1)]
            and rows(lines, "V020_SEC_S_RECOVERY_ACK_DURABLE") == [(epoch, seq, 0)],
            "unexpected durable proof and ACK sequence")
    (output / "original-audit-page.bin").write_bytes(original)
    (output / "ack-audit-page.bin").write_bytes(acknowledged)
    return {"seq": seq, "record_digest": digest.hex(), "ack_generation": 2}


def echo_sample(port, timeout, server, peer):
    started = time.monotonic_ns()
    result = exchange(port, timeout, orderly_close=True, server_identity=server, peer_identity=peer)
    return {"started_ns": started, "completed_ns": time.monotonic_ns(), **result}


def watch_echo(lines, observed, stop, restart):
    for line in lines:
        if line.startswith(STOP + " "):
            stop.append(observed)
        if line.startswith(RESTART + " "):
            restart.append(observed)


def check_echo_timing(samples, stop, restart):
    require(len(samples) == 5 and len(stop) == len(restart) == len(RESTARTS), "missing TLS continuity samples")
    require(samples[0]["completed_ns"] < stop[0] and restart[-1] <= samples[-1]["started_ns"],
            "missing authenticated Echo before and after local recovery")
    for sample, before, after, (role, _) in zip(samples[1:-1], stop, restart, RESTARTS, strict=True):
        require(before <= sample["started_ns"] < sample["completed_ns"] < after,
                f"TLS Echo did not complete inside the role {role} recovery interval")
        sample["stopped_role"] = role
        sample["stop_observed_ns"] = before
        sample["restart_observed_ns"] = after


def run(args, disk, output, proof):
    image = args.elf.read_bytes()
    backing = symbol(image, "V020_SIGNED_ROLE_BACKING")
    deadline = time.monotonic() + args.timeout
    initial, lines, raw_serial = {}, [], bytearray()
    decoder = FrameDecoder()
    net_samples, stop_observed, restart_observed = [], [], []
    with (TemporaryDirectory(prefix="cyx-ps-qmp-") as directory,
          (output / "qemu-stderr.log").open("wb") as stderr,
          ThreadPoolExecutor(max_workers=1) as peer):
        qmp_path = Path(directory) / "q"
        argv, port = qemu_command(args, disk, qmp_path)
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr)
        conn = qmp = None
        try:
            conn = connect_qmp(proc, str(qmp_path), deadline)
            qmp = Qmp(conn)
            require("QMP" in qmp.receive(deadline), "missing QMP greeting")
            qmp.execute("qmp_capabilities")
            net = symbol(image, "V020_RESIDENT_NET_EVIDENCE") if port is not None else None
            net_complete = net is None
            capture_at = 0.0
            while time.monotonic() < deadline:
                if select.select([proc.stdout], [], [], 0.05)[0]:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    require(chunk, "guest closed serial before local recovery completed")
                    raw_serial.extend(chunk)
                    require(len(raw_serial) <= 2 * (1 << 20), "local recovery exceeded its evidence bound")
                    decoded = [frame.decode("ascii").rstrip("\n") for frame in decoder.feed(chunk)]
                    lines.extend(decoded)
                    if net is not None:
                        watch_echo(decoded, time.monotonic_ns(), stop_observed, restart_observed)
                    require(not any(line.startswith(("V020_STARTUP state=SECURE_DEGRADED", "V020_SIGNED_ROLE_ISOLATED"))
                                    for line in decoded), "guest fenced or isolated a role before local recovery completed")
                generations = rows(lines, RESTART)
                if net is not None and rows(lines, NET_READY):
                    expected = 1 + len(stop_observed) + (len(restart_observed) == len(RESTARTS))
                    if len(net_samples) < expected:
                        net_samples.append(peer.submit(echo_sample, port, min(8, args.timeout),
                                                       args.tls_server, args.tls_peer))
                if not rows(lines, PROGRESS) or time.monotonic() < capture_at:
                    continue
                capture_at = time.monotonic() + 0.20
                final = role_rows(qmp, output, backing)
                for role, _ in RESTARTS:
                    row = final[role]
                    if row[0] == PROBE_MAGIC | role and row[2] == 1 and row[4] > 0:
                        initial[role] = row
                        (output / f"role-{role}-initial.bin").write_bytes(struct.pack("<16Q", *row))
                if net is not None and len(net_samples) == 5 and all(f.done() for f in net_samples):
                    proof["tls_echo"] = [future.result() for future in net_samples]
                    raw = dump(qmp, output / "net-evidence.bin", net["pa"], net["size"])
                    proof["net_owner"] = struct.unpack("<11Q", raw)
                    net_complete = proof["net_owner"][5] == 5
                if (len(generations) == 3 and final[11][4] == 4 and final[2][11] > 0 and final[8][11] > 0
                        and net_complete):
                    break
            else:
                raise TimeoutError("the three signed replacements and four deterministic receipts did not complete")
            qmp.execute("stop")
            require(qmp.execute("query-status")["status"] == "paused", "failed to freeze final QEMU evidence")
            final = role_rows(qmp, output, backing)
            proof["transport"] = dict(frames=decoder.frames, lost=decoder.loss, corrupt=decoder.corrupt)
            require(decoder.loss == decoder.corrupt == 0, "corrupt local recovery serial stream")
            require(set(initial) == {role for role, _ in RESTARTS}, "missing first-generation live readbacks")
            proof["initial_probes"], proof["replacement_probes"] = initial, final
            proof.update(verify_role_mappings(qmp, output, image, backing))
            proof.update(capture_role_syscall_abi(qmp, output, image))
            require(proof.get("role_syscall_abi") == dict.fromkeys(ROLES, 3),
                    "the restored CPU0 role lost its registered ABI3 identity")
            receipts = plan_receipts(args.elf, image, qmp, output, args.epoch, final)
            roles, result = check_transitions(lines, args.epoch, initial, final, receipts)
            proof.update(result, decision_receipts=receipts)
            if net is not None:
                manifest = (args.catalog / "key-manifest.bin").read_bytes()
                key = struct.unpack_from("<Q", manifest, 8)[0]
                port_inside = struct.unpack_from("<H", manifest, 74)[0]
                evidence = proof["net_owner"]
                require(rows(lines, NET_READY) == [(args.epoch, key, port_inside)]
                        and evidence[:6] == (args.epoch, key, 2, 5, 5, 5) and evidence[7:9] == (0, 0),
                        "signed TLS did not preserve the same live listener and retire all five sessions")
                check_echo_timing(proof["tls_echo"], stop_observed, restart_observed)
            policy = (args.catalog / "offline-config.bin").read_bytes()
            proof["signed_policy_sha256"] = verify_boot_policy(disk, args.epoch, roles, policy, lines)
            proof["durable_service_generations"] = verify_generation_suffix(disk, roles, args.epoch)
            proof["audit_takeover"] = verify_audit(disk, output, (args.catalog / "recovery-store.bin").read_bytes(),
                                                    policy, args.epoch, final[11], lines)
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
    parser.add_argument("--tls-server", type=Path)
    parser.add_argument("--tls-peer", type=Path)
    parser.add_argument("--epoch", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=100)
    args = parser.parse_args()
    if (args.tls_server is None) != (args.tls_peer is None):
        parser.error("set both loopback TLS fixture identities")
    output = args.output.resolve()
    proof = {"status": "FAIL", "boot_epoch": args.epoch}
    try:
        output.mkdir(mode=0o700)
    except OSError as error:
        parser.exit(1, f"{error}\n")
    try:
        proof.update(elf_sha256=sha(args.elf), qemu_sha256=sha(args.qemu), pmu_patch_sha256=sha(PMU_PATCH))
        require((proof["qemu_sha256"], proof["pmu_patch_sha256"]) == (args.qemu_sha256, args.patch_sha256),
                "pinned QEMU or PMU patch differs")
        disk = output / "recovery.raw"
        shutil.copyfile(args.scratch_disk, disk)
        run(args, disk, output, proof)
        require((sha(args.elf), sha(args.qemu)) == (proof["elf_sha256"], proof["qemu_sha256"]),
                "acceptance inputs changed during execution")
        proof["status"] = "PASS"
    except (OSError, EOFError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        proof["error"] = str(error)
        (output / "verification.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
        parser.exit(1, f"{error}\n")
    (output / "verification.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    print(f"SEC-P/S local recovery verification PASS {output}")


if __name__ == "__main__":
    main()
