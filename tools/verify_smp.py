#!/usr/bin/env python3
"""Run the pinned four-vCPU native execution fixture, never certify full isolation.

The CPU roles are scripted test inputs, not model output. Both framed serial
records and a stopped-VM evidence page are required. No network or downloads.
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
from transport import FrameDecoder

ROOT = Path(__file__).resolve().parents[1]
MAGIC = 0x435958534D503031


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


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
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                            cwd=ROOT, capture_output=True, check=True, timeout=10)
    names = sorted({os.fsdecode(n) for n in result.stdout.split(b'\0') if n})
    require({'kernel/src/smp.rs', 'crates/arch-aarch64/src/user.rs', 'Cargo.lock'} <= set(names),
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


def validate(serial: bytes, page: bytes, cpu_count: int) -> dict:
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
        result = []
        for line in lines:
            if line.startswith(label + ' '):
                match = re.fullmatch(re.escape(label) + r' a=(\d+) b=(\d+) c=(\d+)', line)
                require(match is not None, 'malformed ' + label)
                result.append(tuple(int(v) for v in match.groups()))
        return result
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


def run(elf: Path, output: Path, timeout: float = 20, cpus: int = 4, *, acceptance=None) -> dict:
    require(1 <= timeout <= 60 and cpus in (1, 4), 'invalid execution budget/configuration')
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
    decoder = FrameDecoder(); raw = bytearray(); decoded = bytearray()
    proc = None; sock = None; qmp = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='cyx-smp-') as td, (output / 'qemu-stderr.log').open('wb') as err:
        try:
            location = profile(elf.read_bytes()) if acceptance is None else acceptance.profile(elf.read_bytes())
            if acceptance is not None:
                report.update(acceptance.metadata())
            binary = shutil.which('qemu-system-aarch64')
            require(binary is not None, 'qemu-system-aarch64 is missing')
            version = subprocess.check_output([binary, '--version'], timeout=10, text=True)
            require(version.splitlines()[0] in ('QEMU emulator version 10.2.2',
                    'QEMU emulator version 10.2.2 (v10.2.2)'), 'unverified QEMU version')
            report['qemu_version'] = version
            report['qemu_sha256'] = sha(Path(binary))
            path = str(Path(td) / 'q.sock')
            args = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                    '-cpu', 'cortex-a53', '-smp', str(cpus), '-m', '256M', '-accel', 'tcg,thread=multi',
                    '-display', 'none', '-monitor', 'none', '-nic', 'none',
                    '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                    '-qmp', f'unix:{path},server=on,wait=off', '-kernel', str(elf), '-no-reboot']
            report['argv'] = args
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
            end = started + timeout
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
            while time.monotonic() < end:
                require(proc.poll() is None, 'QEMU exited before acceptance')
                value = qmp.execute('ringbuf-read', {'device': 'cyxlog', 'size': 1048576, 'format': 'base64'})
                data = base64.b64decode(value, validate=True)
                raw.extend(data)
                require(len(raw) <= 2 * 1024 * 1024, 'serial budget exceeded')
                for frame in decoder.feed(data): decoded.extend(frame)
                if b'FAIL' in decoded or b'SMP_ERROR' in decoded: raise ValueError('guest failure')
                completion = b'SMP_SELFTEST_PASS cpus=4\n' if acceptance is None else acceptance.completion
                if completion in decoded:
                    qmp.execute('stop')
                    qmp.execute('pmemsave', {'val': location['pa'], 'size': 4096,
                                            'filename': str(output / 'native-page.bin')})
                    require(decoder.loss == 0 and decoder.corrupt == 0 and not decoder.buffer,
                            'incomplete/corrupt framed UART transport')
                    validator = validate if acceptance is None else acceptance.validate
                    report['observations'] = validator(bytes(decoded), (output / 'native-page.bin').read_bytes(), len(actual_cpus))
                    require(sha(elf) == report['elf_sha256'], 'ELF changed during guest run')
                    require(before == manifest(), 'source changed during guest run')
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
    parser.add_argument('--cpus', type=int, choices=(1, 4), default=4,
                        help='1 is a negative admission test; it must not pass')
    args = parser.parse_args()
    try: report = run(args.elf, args.output, args.timeout, args.cpus)
    except (OSError, ValueError) as error:
        print(str(error), file=__import__('sys').stderr); return 1
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
