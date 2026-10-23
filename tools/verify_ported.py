"""Run a supplied kernel's embedded static-musl probe; never build or download.

This verifies a Linux-AArch64 syscall subset, not a desktop or general Linux
compatibility. IRQ counts are per process; they do not locate an interrupt
inside the floating-point calculation. Dedicated FP/TLS tests cover that path.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import time

from check_elf import inspect_elf
from doctor import ROOT
from shell import Guest


FATAL = (b'CHECK_FAILED', b'SERVICE_PANIC', b'FAIL panic',
         b'FAIL unexpected exception', b'PORTED_PROBE FAIL', b'EL0 start failed:')
LAUNCH = re.compile(rb'ELF pid=(\d+) started; ABI=Linux-AArch64-subset '
                    rb'image AI_DIRECT model=8195 pages=(\d+)')
STAGES = [b'PORTED_PROBE START argc=1 argv0=/bin/probe',
          b'PORTED_PROBE TLS_ERRNO PASS',
          b'PORTED_PROBE MALLOC_FREE PASS bytes=262144 cycles=3',
          b'PORTED_PROBE FILE_IO PASS',
          b'PORTED_PROBE FLOAT PASS value=3.625', b'PORTED_PROBE PASS']


def check_console(data):
    if any(marker in data for marker in FATAL):
        raise AssertionError(f'Guest failure: {bytes(data[-2000:])!r}')


def parse_processes(data):
    rows = {}
    for fields in re.findall(rb'UserStatus \{ ([^}]+) \}', data):
        row = dict(item.decode().split(': ', 1) for item in fields.split(b', '))
        row = {key: value if key == 'state' else int(value) for key, value in row.items()}
        if row['pid'] in rows:
            raise AssertionError(f'Duplicate PID in process snapshot: {row["pid"]}')
        rows[row['pid']] = row
    if not rows:
        raise AssertionError('Missing process snapshot')
    return rows


def validate_probe(data, rows, expected_pages, require_image=False):
    """Validate one isolated launch-to-exit transcript and its final snapshot."""
    check_console(data)
    lines = data.splitlines()
    launches = [match for line in lines if (match := LAUNCH.fullmatch(line))]
    if len(launches) != 1 or sum(b'ELF pid=' in line for line in lines) != 1:
        raise AssertionError('Expected exactly one authentic ELF launch record')
    pid, pages = map(int, launches[0].groups())
    if pid <= 0 or pages != expected_pages:
        raise AssertionError(f'Unexpected process/image grant: pid={pid}, pages={pages}')
    stages = [line for line in lines if line.startswith(b'PORTED_PROBE')]
    if len(stages) != 7 or stages[:5] + stages[6:] != STAGES:
        raise AssertionError(f'Incomplete, duplicated or reordered probe stages: {stages!r}')
    duration = re.fullmatch(rb'PORTED_PROBE FP_IRQ PASS elapsed_ns=(\d+)', stages[5])
    if duration is None or int(duration[1]) < 50_000_000:
        raise AssertionError(f'Missing bounded FP-loop evidence lasting at least 50 ms: {stages[5]!r}')
    terminal = f'EL0 pid={pid} Exited code=0 free_pages=64 esr=0x0 far=0x0'.encode()
    endings = [line for line in lines if re.match(rb'EL0 pid=\d+ (Exited|Fault|Killed)', line)]
    if endings != [terminal]:
        raise AssertionError(f'Unexpected terminal evidence: {endings!r}')
    if not (lines.index(launches[0][0]) < lines.index(STAGES[0])
            < lines.index(STAGES[-1]) < lines.index(terminal)):
        raise AssertionError('Probe stages must occur between launch and clean exit')
    row = rows.get(pid)
    expected = dict(pid=pid, state='Exited', code=0, esr=0, far=0,
                    free_pages=64, heap_pages=0, heap_free=2048,
                    heap_model=8194, rank_model=12289, cpu_model=12290)
    if row is None or any(row.get(key) != value for key, value in expected.items()):
        raise AssertionError(f'Unexpected final process state or unreclaimed pages: {row}')
    if any(row.get(key, 0) <= 0 for key in ('syscalls', 'ai_selections', 'preemptions')):
        raise AssertionError(f'Missing real syscall, local AI selection or IRQ evidence: {row}')
    image_observed = 'image_pages' in row and 'image_free' in row
    if image_observed:
        if row['image_pages'] != 0 or row['image_free'] != 4096:
            raise AssertionError(f'Executable image grant was not fully reclaimed: {row}')
    elif require_image or 'image_pages' in row or 'image_free' in row:
        raise AssertionError('Executable image page accounting is missing/incomplete')
    return dict(row, admitted_image_pages=pages,
                fp_irq_elapsed_ns=int(duration[1]),
                image_reclamation_observed=image_observed)


def validate_absent_rng(data, pwd):
    check_console(data)
    if (b'ENTROPY_UNAVAILABLE MECHANISM' not in data
            or data.splitlines().count(b'ELF start failed: Nodev') != 1):
        raise AssertionError('Missing explicit no-entropy startup denial')
    if b'ELF pid=' in data or b'PORTED_PROBE' in data:
        raise AssertionError('A program ran despite missing entropy')
    if b'/\r\n' not in pwd or b'cyxia:/> ' not in pwd:
        raise AssertionError('Shell failed to respond after missing-entropy denial')


def image_pages(probe):
    """Count mapped PT_LOAD pages plus the loader's 64-page initial stack."""
    if len(probe) < 64:
        raise ValueError('Truncated probe ELF')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', probe)
    if header[0][:7] != b'\x7fELF\x02\x01\x01' or header[1:4] != (2, 183, 1):
        raise ValueError('Probe must be static AArch64 ELF64 ET_EXEC')
    phoff, phsize, phnum = header[5], header[9], header[10]
    if phsize != 56 or not 0 < phnum <= 64 or phoff + phsize * phnum > len(probe):
        raise ValueError('Invalid probe program headers')
    pages = set()
    for index in range(phnum):
        kind, flags, offset, address, _, size, memory, _ = struct.unpack_from(
            '<IIQQQQQQ', probe, phoff + index * phsize)
        if kind in (2, 3):
            raise ValueError('Dynamic or interpreted probe is outside this acceptance scope')
        if kind != 1:
            continue
        if (not memory or size > memory or offset + size > len(probe)
                or not 0x01000000 <= address < address + memory <= 0x02000000
                or flags not in (4, 5, 6)):
            raise ValueError('Invalid probe load segment')
        for page in range(address // 4096, (address + memory + 4095) // 4096):
            if page in pages:
                raise ValueError('Probe has overlapping PT_LOAD pages')
            pages.add(page)
    if not pages or len(pages) + 64 > 4096:
        raise ValueError('Probe exceeds executable memory budget')
    return len(pages) + 64


def verify(elf, output, probe, require_image=False):
    elf, output, probe = map(lambda p: Path(p).resolve(), (elf, output, probe))
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status='FAIL', elf=str(elf), probe=str(probe),
                  scope='Embedded static musl on the Linux-AArch64 syscall subset; no desktop acceptance',
                  image_accounting_required=require_image, processes=[], checks=[], commands=[],
                  limitations=['Per-process IRQ counts do not identify the interrupted FP instruction.'],
                  artifacts={name: {key: f'{name}/{filename}' for key, filename in
                             [('console', 'console.txt'), ('serial', 'serial.bin'),
                              ('qemu', 'qemu-command.json'), ('state', 'state.json'),
                              ('qmp', 'qmp.jsonl')]} for name in ('rng', 'no-rng')})
    guests = []
    try:
        binary = elf.read_bytes()
        report['elf_sha256'] = hashlib.sha256(binary).hexdigest()
        info = inspect_elf(binary)
        payload = probe.read_bytes()
        report['probe_sha256'] = hashlib.sha256(payload).hexdigest()
        expected_pages = image_pages(payload)
        report['expected_image_pages'] = expected_pages
        if not any(payload in binary[seg['offset']:seg['offset'] + seg['size']]
                   for seg in info['loads'] if not seg['flags'] & 2):
            raise AssertionError('Supplied probe bytes are not embedded in a read-only kernel PT_LOAD')
        report['checks'].append('probe hash identifies exact bytes embedded in a read-only kernel load segment')

        def wait_from(guest, start, predicate, timeout=10):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                guest.poll()
                data = bytes(guest.text[start:])
                check_console(data)
                if predicate(data):
                    return data
                time.sleep(.01)
            raise TimeoutError(f'Guest condition timed out: {bytes(guest.text[start:])[-2000:]!r}')

        def command(guest, name, text):
            report['commands'].append(dict(session=name, command=text))
            data = guest.command(text)
            check_console(data)
            return data

        guest = Guest(elf, output / 'rng', rng=True)
        guests.append(guest)
        with guest:
            boot = guest.until(b'cyxia:/> ')
            check_console(boot)
            for marker in (b'ENTROPY_READY VIRTIO MECHANISM',
                           b'EXEC_MEMORY_RESERVED 128MiB BOOTSTRAP',
                           b'USER_HEAP_RESERVED 64MiB BOOTSTRAP'):
                if marker not in boot:
                    raise AssertionError(f'Missing boot prerequisite: {marker!r}')
            previous_pid = None
            for attempt in range(2):
                start = len(guest.text)
                command(guest, 'rng', 'posix exec probe')
                data = wait_from(guest, start, lambda d: LAUNCH.search(d))
                pid = int(LAUNCH.search(data)[1])
                wait_from(guest, start, lambda d: re.search(
                    rb'EL0 pid=' + str(pid).encode() + rb' (Exited|Fault|Killed) code=\d+[^\n]*\n', d))
                transcript = bytes(guest.text[start:])
                snapshot = command(guest, 'rng', 'posix list')
                rows = parse_processes(snapshot)
                row = validate_probe(transcript, rows, expected_pages, require_image)
                if previous_pid is not None and (pid == previous_pid or previous_pid in rows):
                    raise AssertionError('Second probe did not reuse the inactive first slot with a new PID')
                previous_pid = pid
                report['processes'].append(dict(attempt=attempt + 1, **row))
            contents = command(guest, 'rng', 'cat /musl-probe.txt')
            if b'CyxiaOS musl file IO' not in contents.splitlines():
                raise AssertionError('Guest shell could not read the file written by musl')
            report['checks'].append('two distinct PIDs reuse the first inactive slot and pass all seven real musl stages, including at least 50 ms of FP-loop execution')
            report['checks'].append('both executions observe syscalls, local AI selection, IRQ preemption and full heap/fixed-grant reclamation')
            report['checks'].append('guest shell reads back the file written by the static musl probe')
            if all(row['image_reclamation_observed'] for row in report['processes']):
                report['checks'].append('both executable image/stack grants return to zero used and 4096 free pages')
            else:
                report['limitations'].append('This kernel exposes no image_pages/image_free counters; image-pool reclamation was not directly observed.')
            report['rng_frames'] = guest.decoder.frames

        guest = Guest(elf, output / 'no-rng', rng=False)
        guests.append(guest)
        with guest:
            guest.until(b'cyxia:/> ')
            start = len(guest.text)
            command(guest, 'no-rng', 'posix exec probe')
            wait_from(guest, start, lambda d: b'ELF start failed: Nodev' in d)
            pwd = command(guest, 'no-rng', 'pwd')
            validate_absent_rng(bytes(guest.text), pwd)
            report['no_rng_frames'] = guest.decoder.frames
            report['checks'].append('without VirtIO RNG exec fails with Nodev before launch; shell remains responsive')
        for path, key in [(elf, 'elf_sha256'), (probe, 'probe_sha256')]:
            if hashlib.sha256(path.read_bytes()).hexdigest() != report[key]:
                raise AssertionError(f'Input changed during verification: {path}')
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    finally:
        for guest in guests:
            if guest.qmp is not None:
                (guest.output / 'qmp.jsonl').write_text(''.join(
                    json.dumps(row) + '\n' for row in guest.qmp.transcript))
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/ported')
    parser.add_argument('--probe', type=Path,
                        default=ROOT / 'artifacts/sysroot/aarch64-musl/probe.elf')
    parser.add_argument('--require-image-accounting', action='store_true',
                        help='fail unless UserStatus exposes reclaimed image_pages/image_free')
    args = parser.parse_args()
    result = verify(args.elf, args.output, args.probe, args.require_image_accounting)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
