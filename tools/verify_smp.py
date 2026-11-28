#!/usr/bin/env python3
"""Run the pinned four-vCPU native execution fixture, never certify full isolation.

The default V0.20 contract is the fixed CPU0 topology (C={CPU0}, B={CPU1-3})
from kernel/src/arch/aarch64/smp.rs::fixed_cpu0_fixture. The retired dynamic
CoreSet transition contract (CPU1 control) stays reachable via --legacy-coreset
for kernels built with --features smp-selftest,legacy-coreset. The CPU roles are
scripted test inputs, not model output. Both framed serial records and a
stopped-VM evidence page are required. No network or downloads.
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

from check_elf import inspect_elf, symbol
from run_qemu import Qmp
from qmp_stdio import PipeTransport
from transport import FrameDecoder
from build_sources import working_tree_names

ROOT = Path(__file__).resolve().parents[1]
MAGIC = 0x435958534D503031


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def overrun_diagnostic(serial: bytes) -> dict:
    """Failure-only extraction from framed UART; never a native PASS."""
    def row(tag):
        hits = re.findall(rb'^' + tag + rb' a=(\d+) b=(\d+) c=(\d+)\n', serial, re.M)
        require(len(hits) == 1, 'missing/duplicate complete ' + tag.decode() + ' record')
        values = tuple(map(int, hits[0]))
        require(all(v < 2**64 for v in values), 'oversized diagnostic field')
        return values

    role, actual, reserved = row(b'V0199_BOOTSTRAP_OVERRUN')
    require(reserved > 0, 'zero reserved CPU quota')
    result = dict(role=role, actual_ns=actual, reserved_ns=reserved,
                  cpu_excess_ns=max(0, actual-reserved))
    phases = b'V0199_DECISION_OVERRUN_PHASES'
    trap = b'V0199_DECISION_OVERRUN_TRAP'
    if phases in serial or trap in serial:
        before, after, dispatched = row(phases)
        kind, esr, syscall = row(trap)
        require(role in (2, 8) and before <= actual
                and (after == 0 or before <= after <= actual)
                and (dispatched == 0 or after != 0 and after <= dispatched <= actual),
                'inconsistent decision overrun phases')
        require(serial.index(phases) < serial.index(trap)
                < serial.index(b'V0199_BOOTSTRAP_OVERRUN'),
                'out-of-order overrun diagnostics')
        result.update(before_enter_ns=before, after_exit_ns=after,
                      after_dispatch_ns=dispatched, trap_kind=kind,
                      trap_esr=esr, syscall_x8=syscall)
    recovery = b'V0199_RECOVERY_OVERRUN_PHASE'
    if recovery in serial:
        phase, checkpoint, charged = row(recovery)
        stages = {1:"retire_asid",2:"retire_tables",3:"unseal_break",
                  4:"unseal_make",5:"retire_scrub",10:"package_copy",
                  11:"package_verify",12:"private_stage",13:"stack",
                  14:"scratch_or_code_sync",15:"seal_break",16:"seal_make",
                  17:"map_leaves",18:"publish_asid",19:"replacement_inventory"}
        require(phase in stages and checkpoint > 0 and charged == actual
                and reserved == 2_000_000 and role in (2,3,6,7,8,9,10,11)
                and phases not in serial and trap not in serial
                and serial.index(recovery) < serial.index(b'V0199_BOOTSTRAP_OVERRUN'),
                'inconsistent recovery overrun checkpoint')
        result.update(recovery_stage=stages[phase], recovery_checkpoint=checkpoint,
                      recovery_phase_id=phase)
    return result


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def manifest() -> dict[str, str]:
    # Bind the entire checked-out tree (including new tracked/untracked source),
    # excluding only Git-ignored outputs. Never infer source identity from HEAD
    # while accepting edited files alongside it.
    names = working_tree_names(ROOT)
    require({'kernel/src/arch/aarch64/smp.rs', 'crates/arch-aarch64/src/user.rs', 'Cargo.lock'} <= set(names),
            'incomplete source checkout')
    files = [ROOT / name for name in names]
    require(all(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(ROOT) for p in files),
            'source must be regular non-escaping files')
    return {name: sha(path) for name, path in zip(names, files)}


def profile(elf: bytes) -> dict:
    layout = inspect_elf(elf)
    marker = symbol(elf, 'CYXIA_SMP_PROFILE')
    require(marker['size'] == 48, 'wrong native SMP profile size')
    for seg in layout['loads']:
        delta = marker['pa'] - seg['pa']
        if 0 <= delta and delta + 48 <= seg['size']:
            values = struct.unpack_from('<6Q', elf, seg['offset'] + delta)
            require(values == (1, 4, 8, 1, 0, 0), 'not the bounded native execution fixture')
            evidence = symbol(elf, 'SMP_EVIDENCE')
            require(evidence['pa'] % 4096 == 0 and evidence['size'] == 4096,
                    'invalid native evidence page')
            return evidence
    raise ValueError('profile not backed by loaded ELF bytes')


def _rows(lines: list[str], label: str) -> list[tuple[int, int, int]]:
    result = []
    for line in lines:
        if line.startswith(label + ' '):
            match = re.fullmatch(re.escape(label) + r' a=(\d+) b=(\d+) c=(\d+)', line)
            require(match is not None, 'malformed ' + label)
            result.append(tuple(int(v) for v in match.groups()))
    return result


def validate(serial: bytes, page: bytes, cpu_count: int) -> dict:
    """Default V0.20 contract: fixed C={CPU0}, B={CPU1,CPU2,CPU3}.

    Derived from smp.rs::fixed_cpu0_fixture and the shared business worker:
    CPU0 never enters EL0 (its whole evidence row stays zero), CPU1-3 run only
    business dispatches (one probe pass of exactly 5 permission faults each,
    every completed turn ended by a private timer IRQ), and ownership.fault(0)
    quarantines exactly CPU0 fail-closed: control mask empties, no business core
    is promoted, and in-flight business keeps running until deterministic close.
    """
    require(cpu_count == 4, 'QMP must observe exactly four vCPUs')
    require(len(page) == 4096, 'incomplete evidence page')
    words = struct.unpack('<512Q', page)
    # [MAGIC, version, completion, online, stopped, initial control/business,
    #  reserved, final quarantined/control/business, reserved x5]
    require(list(words[:16]) == [MAGIC, 1, 1, 15, 14, 1, 14, 0, 1, 0, 14, 0, 0, 0, 0, 0],
            'incomplete fixed CPU0 topology/quarantine evidence')
    require(all(v == 0 for v in words[48:]), 'nonzero evidence reserved fields')
    require(b'FAIL' not in serial and b'SMP_ERROR' not in serial, 'guest reported failure')
    lines = serial.decode('ascii').splitlines()
    require(lines.count('SMP_SELFTEST_PASS cpus=4') == 1, 'missing/duplicate completion')
    scope = 'SMP_SCOPE model=fixed_cpu0 production_isolation=false physical_isolation=false'
    require(lines.count(scope) == 1 and sum(line.startswith('SMP_SCOPE') for line in lines) == 1,
            'fixture scope must not claim production/model/hardware certification')
    require(not any(line.startswith(('SMP_SCALE_FIXTURE ', 'SMP_SCALE_MODEL ', 'SMP_ROLE_PROGRESS '))
                    for line in lines), 'retired dynamic CoreSet evidence in fixed CPU0 fixture')
    def rows(label):
        return _rows(lines, label)
    require(rows('SMP_BOOT_OK') == [(4, 15, 0)], 'missing boot handshake')
    require(rows('SMP_CPU_ON') == [(1, 1, 0), (2, 2, 0), (3, 3, 0)], 'CPU_ON failed')
    require(rows('SMP_FIXED_CPU0') == [(words[5], words[6], 1)],
            'wrong fixed CPU0 topology/generation or serial/page disagreement')
    require(rows('SMP_CONTROL_STALL') == [(words[8], words[9], words[10])],
            'serial and live fail-closed quarantine evidence disagree')
    cpus = [words[16 + i * 8:24 + i * 8] for i in range(4)]
    require(tuple(cpus[0]) == (0,) * 8, 'CPU0 ran user workload or took fixture interrupts')
    require([r[0] for r in cpus] == [0, 1, 2, 3], 'affinity mismatch')
    require(rows('SMP_CPU_EVIDENCE') == [(i, cpus[i][3], cpus[i][1]) for i in range(1, 4)],
            'serial and live CPU evidence disagree')
    for i in range(1, 4):
        row = cpus[i]
        require(row[1] >= 4, 'business CPU did not reach bounded progress before quarantine')
        require(row[2] == 0 and row[7] == 0, 'business CPU ran control work')
        require(row[3] > 0 and row[3] >= row[1] + row[2], 'timer preemption evidence missing')
        require(row[4] == 5 and row[5] == 0, 'permission probe/failure accounting wrong')
        require(row[6] > 0, 'EL0 never wrote its private business page')
    def first(label):
        return next(i for i, line in enumerate(lines) if line.startswith(label + ' '))
    require(max(i for i, line in enumerate(lines) if line.startswith('SMP_CPU_ON '))
            < first('SMP_BOOT_OK') < first('SMP_FIXED_CPU0') < first('SMP_CONTROL_STALL')
            < min(i for i, line in enumerate(lines) if line.startswith('SMP_CPU_EVIDENCE '))
            < first('SMP_SCOPE') < lines.index('SMP_SELFTEST_PASS cpus=4'),
            'evidence published out of fixture order')
    return {'cpus': 4, 'secondary_cpus': 3,
            'permission_fault_probes': sum(r[4] for r in cpus),
            'timer_preemptions': sum(r[3] for r in cpus),
            'initial_control': words[5], 'initial_business': words[6],
            'quarantined': words[8], 'final_control': words[9], 'final_business': words[10],
            'business_progress': [cpus[i][1] for i in range(1, 4)],
            'control_progress': [cpus[i][2] for i in range(1, 4)]}


def validate_legacy(serial: bytes, page: bytes, cpu_count: int) -> dict:
    """Retired dynamic CoreSet transition contract (CPU1 control). Only valid
    for kernels built with the opt-in legacy-coreset feature; never the default
    V0.20 fixed-CPU0 profile."""
    require(cpu_count == 4, 'QMP must observe exactly four vCPUs')
    require(len(page) == 4096, 'incomplete evidence page')
    words = struct.unpack('<512Q', page)
    require(list(words[:16]) == [MAGIC, 1, 1, 15, 14, 2, 6, 2, 2, 0, 13, 0, 0, 0, 0, 0],
            'incomplete native transition/quarantine evidence')
    require(all(v == 0 for v in words[48:]), 'nonzero evidence reserved fields')
    require(b'FAIL' not in serial and b'SMP_ERROR' not in serial, 'guest reported failure')
    lines = serial.decode('ascii').splitlines()
    require(lines.count('SMP_SELFTEST_PASS cpus=4') == 1, 'missing/duplicate completion')
    require(lines.count('SMP_SCOPE model=fixture production_isolation=false physical_isolation=false') == 1,
            'fixture scope must not claim production/model/hardware certification')
    def rows(label):
        return _rows(lines, label)
    require(rows('SMP_BOOT_OK') == [(4, 15, 0)], 'missing boot handshake')
    require(rows('SMP_CPU_ON') == [(1, 1, 0), (2, 2, 0), (3, 3, 0)], 'CPU_ON failed')
    require(rows('SMP_SCALE_FIXTURE') == [(6, 9, 3), (2, 13, 5)], 'wrong ownership transition sequence')
    stall = rows('SMP_CONTROL_STALL')
    require(len(stall) == 1 and stall[0][0] >= 4 and stall[0][2] >= stall[0][1] + 8,
            'business did not progress during controller stop')
    cpus = [words[16 + i * 8:24 + i * 8] for i in range(4)]
    require(tuple(cpus[0]) == (0,) * 8, 'unexpected CPU0 user workload')
    require([r[0] for r in cpus] == [0, 1, 2, 3], 'affinity mismatch')
    require(rows('SMP_CPU_EVIDENCE') == [(i, cpus[i][3], cpus[i][4]) for i in range(1, 4)],
            'serial and live CPU evidence disagree')
    require(rows('SMP_ROLE_PROGRESS') == [(i, cpus[i][1], cpus[i][2]) for i in range(1, 4)],
            'serial and live dispatch accounting disagree')
    require(cpus[1][1] == 0 and cpus[1][2] == stall[0][0] and cpus[1][6] == 0,
            'control-only CPU ran business work or resumed after close')
    require(cpus[2][1] >= 8 and cpus[2][2] >= 4, 'migrating CPU did not run both isolated contexts')
    require(cpus[3][1] >= stall[0][2] and cpus[3][2] == 0 and cpus[3][7] == 0,
            'business-only CPU ran control work')
    for i, expected_probes in [(1, 5), (2, 10), (3, 5)]:
        row = cpus[i]
        require(row[3] >= row[1] + row[2] and row[4] == expected_probes and row[5] == 0,
                'timer preemption/address-space probe failed')
        for count, data_count in [(row[1], row[6]), (row[2], row[7])]:
            require(count == 0 or data_count > 0, 'EL0 never wrote its private page')
    return {'cpus': 4, 'secondary_cpus': 3, 'permission_fault_probes': 20,
            'control_sets': [2, 6, 2], 'timer_preemptions': sum(r[3] for r in cpus),
            'business_progress_during_control_stop': stall[0][2] - stall[0][1]}


def boot_ram_mib(elf: bytes) -> int:
    """Read the actual linked boot profile; never trust a user-provided RAM label."""
    layout = inspect_elf(elf)
    marker = symbol(elf, 'CYXIA_BOOT_PROFILE')
    require(marker['size'] == 24, 'wrong boot profile size')
    for seg in layout['loads']:
        delta = marker['pa'] - seg['pa']
        if 0 <= delta and delta + 24 <= seg['size']:
            version, ram_mib, _pages = struct.unpack_from('<3Q', elf, seg['offset'] + delta)
            require(version == 1 and ram_mib in (256, 512, 1024), 'invalid linked RAM profile')
            return ram_mib
    raise ValueError('boot profile not backed by loaded ELF bytes')


def run(elf: Path, output: Path, timeout: float = 20, cpus: int = 4, *, acceptance=None, ram_mib: int = 256, scratch_disk: Path | None = None, legacy: bool = False, qmp_stdio: bool = False) -> dict:
    require(1 <= timeout <= 60 and cpus in (1, 4) and ram_mib in (256, 1024),
            'invalid execution budget/configuration')
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), 'refuse to reuse evidence output')
    output.mkdir(parents=True)
    before = manifest()
    (output / 'source-manifest.json').write_text(json.dumps(before, indent=2) + '\n')
    report = {'status': 'FAIL', 'scope': 'native-execution-fixture', 'model_driven': False,
              'native_smp_mechanism_verified': False, 'runtime_truth_attested': False,
              'production_isolation_verified': False, 'host_physical_isolation_verified': False,
              'native_cluster_verified': False, 'full_cosmic_port': False,
              'elf_sha256': sha(elf), 'source_manifest_sha256': sha(output / 'source-manifest.json')}
    if acceptance is None:
        report['fixture_contract'] = 'legacy-coreset' if legacy else 'fixed-cpu0'
    decoder = FrameDecoder(); raw = bytearray(); decoded = bytearray()
    proc = None; sock = None; qmp = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='cyx-smp-') as td, (output / 'qemu-stderr.log').open('wb') as err:
        try:
            location = profile(elf.read_bytes()) if acceptance is None else acceptance.profile(elf.read_bytes())
            if acceptance is not None:
                report.update(acceptance.metadata())
            if acceptance is not None:
                require(boot_ram_mib(elf.read_bytes()) == ram_mib, 'ELF/QEMU RAM profile mismatch')
            binary = shutil.which('qemu-system-aarch64')
            require(binary is not None, 'qemu-system-aarch64 is missing')
            version = subprocess.check_output([binary, '--version'], timeout=10, text=True)
            # The ordinary SMP fixtures keep their exact upstream version
            # gate. A specialized accounting verifier additionally requires
            # exact immutable patched-binary and source-patch SHA evidence.
            qemu_check = getattr(acceptance, 'verify_qemu', None)
            if qemu_check is not None:
                qemu_check(Path(binary), version)
            else:
                require(version.splitlines()[0] in ('QEMU emulator version 10.2.2',
                        'QEMU emulator version 10.2.2 (v10.2.2)'), 'unverified QEMU version')
            report['qemu_version'] = version
            report['qemu_sha256'] = sha(Path(binary))
            path = str(Path(td) / 'q.sock')
            args = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                    '-cpu', 'cortex-a53', '-smp', str(cpus), '-m', f'{ram_mib}M', '-accel', 'tcg,thread=multi',
                    '-display', 'none', '-monitor', 'none', '-nic', 'none',
                    '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                    '-qmp', 'stdio' if qmp_stdio else f'unix:{path},server=on,wait=off',
                    '-kernel', str(elf), '-no-reboot']
            if scratch_disk is not None:
                require(getattr(acceptance, 'scratch_epoch_disk', False) and ram_mib == 1024,
                        'disk restricted to explicit native epoch scratch fixture')
                require(not scratch_disk.is_symlink(), 'scratch disk must not be a symlink')
                scratch_disk = scratch_disk.resolve(strict=True)
                require(scratch_disk.is_file() and scratch_disk.stat().st_size == 512*1024*1024
                        and ',' not in str(scratch_disk), 'invalid scratch image')
                report['scratch_disk_before_sha256'] = sha(scratch_disk)
                args += ['-global', 'virtio-mmio.force-legacy=false',
                         '-drive', f'file={scratch_disk},if=none,id=epoch,format=raw,cache=none',
                         '-device', 'virtio-blk-device,drive=epoch']
            if getattr(acceptance, 'dedicated_d11_rng', False):
                require(scratch_disk is not None, 'dedicated D11 RNG requires the epoch disk fixture')
                args += ['-object', 'rng-builtin,id=d11-rng',
                         '-device', 'virtio-rng-device,rng=d11-rng']
            report['argv'] = args
            report['qmp_transport'] = 'stdio' if qmp_stdio else 'unix'
            proc = subprocess.Popen(args, stdin=subprocess.PIPE if qmp_stdio else None,
                                    stdout=subprocess.PIPE if qmp_stdio else subprocess.DEVNULL,
                                    stderr=err, bufsize=0)
            end = started + timeout
            if qmp_stdio:
                sock = PipeTransport(proc)
            else:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                while True:
                    require(proc.poll() is None, 'QEMU exited before handshake')
                    if time.monotonic() >= end: raise TimeoutError('QMP handshake deadline')
                    try: sock.connect(path); break
                    except (FileNotFoundError, ConnectionRefusedError): time.sleep(.01)
            qmp = Qmp(sock); greeting = qmp.receive(end)
            require('QMP' in greeting, 'invalid QMP greeting')
            qmp.execute('qmp_capabilities')
            actual_cpus = qmp.execute('query-cpus-fast')
            report['qmp_cpus'] = actual_cpus
            if acceptance is not None:
                memory = qmp.execute('query-memory-size-summary')
                report['qmp_memory'] = memory
                require(memory['base-memory'] == ram_mib * 1024 * 1024 and memory.get('plugged-memory', 0) == 0,
                        'QMP RAM topology disagrees with linked boot profile')
                report['guest_ram_mib'] = ram_mib
            while time.monotonic() < end:
                require(proc.poll() is None, 'QEMU exited before acceptance')
                value = qmp.execute('ringbuf-read', {'device': 'cyxlog', 'size': 1048576, 'format': 'base64'})
                data = base64.b64decode(value, validate=True)
                raw.extend(data)
                require(len(raw) <= 2 * 1024 * 1024, 'serial budget exceeded')
                for frame in decoder.feed(data): decoded.extend(frame)
                if b'V0199_BOOTSTRAP_OVERRUN' in decoded:
                    report['cpu0_overrun'] = overrun_diagnostic(bytes(decoded))
                    capture = getattr(acceptance, 'capture_overrun', None)
                    if capture is not None:
                        try:
                            qmp.execute('stop')
                            report['cpu0_overrun_capture'] = capture(qmp, output)
                        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                            report['cpu0_overrun_capture_error'] = type(error).__name__ + ': ' + str(error)
                    raise ValueError('native CPU0 execution overrun (see framed UART)')
                if b'FAIL' in decoded or b'SMP_ERROR' in decoded:
                    capture = getattr(acceptance, 'capture_panic', None)
                    if capture is not None and b'FAIL panic\n' in decoded:
                        try:
                            qmp.execute('stop')
                            detail = capture(qmp, output)
                            if detail is not None:
                                report['guest_panic'] = detail
                        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                            report['guest_panic_capture_error'] = type(error).__name__ + ': ' + str(error)
                    raise ValueError('guest failure')
                completion = b'SMP_SELFTEST_PASS cpus=4\n' if acceptance is None else acceptance.completion
                if completion in decoded:
                    qmp.execute('stop')
                    qmp.execute('pmemsave', {'val': location['pa'], 'size': 4096,
                                            'filename': str(output / 'native-page.bin')})
                    if getattr(acceptance, 'post_uart_seal', False):
                        # The final UART frame is itself inside the metered
                        # interval. Resume an incompletely sealed memory row;
                        # no unsealed prefix can pass the independent checker.
                        page = (output / 'native-page.bin').read_bytes()
                        require(len(page) == 4096, 'incomplete seal page')
                        if struct.unpack_from('<Q', page, 16)[0] != 1:
                            qmp.execute('cont')
                            time.sleep(.001)
                            continue
                    require(decoder.loss == 0 and decoder.corrupt == 0 and not decoder.buffer,
                            'incomplete/corrupt framed UART transport')
                    validator = (validate_legacy if legacy else validate) if acceptance is None else acceptance.validate
                    report['observations'] = validator(bytes(decoded), (output / 'native-page.bin').read_bytes(), len(actual_cpus))
                    # Optional independent extra physical memory proof, while
                    # every guest CPU is still stopped. Only the explicit
                    # acceptance profile may request bounded known spans.
                    if acceptance is not None and hasattr(acceptance, 'capture_extra'):
                        extra = acceptance.capture_extra(qmp, output, (output / 'native-page.bin').read_bytes())
                        report['observations'].update(extra)
                    require(sha(elf) == report['elf_sha256'], 'ELF changed during guest run')
                    require(before == manifest(), 'source changed during guest run')
                    if scratch_disk is not None:
                        # Force a new QEMU process, not guest reset or graceful
                        # device shutdown that could hide a missing guest FLUSH.
                        proc.kill()
                        proc.wait(timeout=5)
                        require(proc.returncode == -9, 'scratch VM not forcibly stopped')
                        report['forced_process_stop'] = True
                        report['scratch_disk_after_sha256'] = sha(scratch_disk)
                    report['status'] = 'PASS'
                    report['native_smp_mechanism_verified'] = True
                    if acceptance is not None:
                        report.update(acceptance.success())
                    break
                time.sleep(.01)
            else: raise TimeoutError('native execution deadline')
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        if qmp: qmp.execute('quit')
                    except (OSError, ValueError, RuntimeError): pass
                    try: proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        try: proc.wait(timeout=2)
                        except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)
                report['qemu_exit'] = proc.returncode
            if sock: sock.close()
            if qmp:
                (output / 'qmp.jsonl').write_text(''.join(json.dumps(m) + '\n' for m in qmp.transcript))
    (output / 'serial.bin').write_bytes(raw)
    (output / 'serial.txt').write_bytes(decoded)
    report['transport'] = dict(frames=decoder.frames, lost=decoder.loss, corrupt=decoder.corrupt)
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['evidence_sha256'] = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=20)
    parser.add_argument('--qmp-stdio', action='store_true', help='use owned pipes instead of a Unix socket')
    parser.add_argument('--cpus', type=int, choices=(1, 4), default=4,
                        help='1 is a negative admission test; it must not pass')
    parser.add_argument('--legacy-coreset', action='store_true',
                        help='validate the retired dynamic CoreSet fixture; requires a kernel '
                             'built with --features smp-selftest,legacy-coreset')
    args = parser.parse_args()
    try: report = run(args.elf, args.output, args.timeout, args.cpus, legacy=args.legacy_coreset,
                     qmp_stdio=args.qmp_stdio)
    except (OSError, ValueError) as error:
        print(str(error), file=__import__('sys').stderr); return 1
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
