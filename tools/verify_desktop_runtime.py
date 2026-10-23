"""Exercise real EL0 FP/TLS isolation and anonymous memory, not desktop acceptance.

The supplied kernel is used as-is; this tool never builds or downloads anything.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import inspect_elf, boot_profile
from doctor import ROOT
from shell import Guest


FATAL_MARKERS = (b'CHECK_FAILED', b'SERVICE_PANIC', b'FAIL panic',
                 b'FAIL unexpected exception', b'EL0 start failed:')
ACTIVE_STATES = ('Running', 'Waiting')


def check_console(data):
    if any(marker in data for marker in FATAL_MARKERS):
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
        raise AssertionError(f'Missing process snapshot: {data!r}')
    return rows


def verify(elf, output):
    elf, output = Path(elf).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status='FAIL', elf=str(elf),
                  scope='EL0 FP/TLS and anonymous-memory runtime; no X11/LXDE acceptance',
                  checks=[], processes=[], snapshots=[], commands=[],
                  artifacts=dict(console='session/console.txt', serial='session/serial.bin',
                                 qemu='session/qemu-command.json', state='session/state.json',
                                 qmp='qmp.jsonl'))
    guest = None
    try:
        binary = elf.read_bytes()
        report['elf_sha256'] = hashlib.sha256(binary).hexdigest()
        inspect_elf(binary)
        profile = boot_profile(binary)
        with Guest(elf, output / 'session') as guest:
            boot = guest.until(b'cyxia:/> ')
            check_console(boot)
            if f"USER_HEAP_RESERVED {profile['heap_pages']*8//256}MiB BOOTSTRAP".encode() not in boot:
                raise AssertionError('Anonymous-memory backing was not reserved at boot')
            report['checks'].append('provided kernel boots without graphics devices and reserves private heap RAM')

            def wait_from(start, predicate, timeout=10):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    guest.poll()
                    data = bytes(guest.text[start:])
                    check_console(data)
                    if predicate(data):
                        return data
                    time.sleep(.01)
                raise TimeoutError(f'Guest condition timed out: {bytes(guest.text[start:])[-2000:]!r}')

            def command(text):
                report['commands'].append(text)
                data = guest.command(text)
                check_console(data)
                return data

            def snapshot(label):
                rows = parse_processes(command('posix list'))
                report['snapshots'].append(dict(label=label, processes=rows))
                return rows

            seen_pids = set()

            def spawn(mode):
                start = len(guest.text)
                command('posix spawn ' + mode)
                data = wait_from(start, lambda data: re.search(rb'EL0 pid=(\d+) started;', data))
                pid = int(re.search(rb'EL0 pid=(\d+) started;', data)[1])
                if pid in seen_pids:
                    raise AssertionError(f'Process identity reused: {pid}')
                seen_pids.add(pid)
                return pid, start

            def terminal(pid, start, state='Exited', code=0):
                marker = f'EL0 pid={pid} {state} code={code}'.encode()
                wait_from(start, lambda data: marker in data)

            def clean_status(pid, rows, state='Exited', code=0):
                row = rows.get(pid)
                if not row or row['state'] != state or row['code'] != code:
                    raise AssertionError(f'Unexpected terminal state for PID {pid}: {row}')
                if row['heap_pages'] != 0 or row['heap_free'] != profile['heap_pages']:
                    raise AssertionError(f'Anonymous-memory leak in PID {pid}: {row}')
                if row['free_pages'] != 64:
                    raise AssertionError(f'Image page-grant leak: {row}')
                if row['rank_model'] != 12289 or row['ai_selections'] <= 0:
                    raise AssertionError(f'Local AI did not select PID {pid}: {row}')
                return row

            first, first_start = spawn('fpu')
            second, _ = spawn('fpu')
            rows = snapshot('two FP processes executing concurrently')
            if first == second or any(rows.get(pid, {}).get('state') not in ACTIVE_STATES
                                      for pid in (first, second)):
                raise AssertionError(f'Two live FP processes were not observed together: {rows}')
            if any(rows[pid]['ai_selections'] <= 0 for pid in (first, second)):
                raise AssertionError(f'Both concurrent FP processes must have run: {rows}')
            terminal(first, first_start)
            terminal(second, first_start)
            transcript = bytes(guest.text[first_start:])
            if transcript.count(b'NATIVE_FP_TLS_PASS\r\n') != 2:
                raise AssertionError(f'Expected two complete FP/TLS passes: {transcript[-2000:]!r}')
            rows = snapshot('concurrent FP processes completed')
            if sum(rows[pid]['preemptions'] for pid in (first, second)) <= 0:
                raise AssertionError(f'No IRQ preemption observed in the concurrent FP group: {rows}')
            for pid in (first, second):
                row = clean_status(pid, rows)
                if row['cpu_model'] != 12290:
                    raise AssertionError(f'AI slice model missing: {row}')
                report['processes'].append(dict(mode='fpu-concurrent', **row))
            report['checks'].append('two distinct concurrent PIDs preserve Q registers, FPCR/FPSR and TLS across syscalls under AI scheduling; the group also observes IRQ preemption')

            third, start = spawn('fpu')
            terminal(third, start)
            if bytes(guest.text[start:]).count(b'NATIVE_FP_TLS_PASS\r\n') != 1:
                raise AssertionError('Reused process slot did not pass initial-zero FP/TLS checks')
            rows = snapshot('fresh FP context in reused process slot')
            if first in rows or second not in rows:
                raise AssertionError(f'Expected the first inactive process slot to be reused: {rows}')
            row = clean_status(third, rows)
            report['processes'].append(dict(mode='fpu-reused-slot', **row))
            report['checks'].append('third FP process reuses an inactive slot and observes zero initial SIMD, FP control/status and TLS state')

            first_heap, heap_start = spawn('heap')
            second_heap, _ = spawn('heap')
            deadline = time.monotonic() + 3
            while True:
                rows = snapshot('waiting to observe two private 128-page heaps concurrently')
                concurrent = [rows.get(pid) for pid in (first_heap, second_heap)]
                if any(not row or row['state'] not in ACTIVE_STATES for row in concurrent):
                    raise AssertionError(f'Two independently admitted, active 128-page heaps were not observed together: {rows}')
                if all(row['heap_pages'] == 128 and row['heap_free'] == profile['heap_pages'] - 128
                       and row['heap_model'] == 8194 and row['ai_selections'] > 0
                       for row in concurrent):
                    report['concurrent_heap_snapshot'] = rows
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError(f'Concurrent heap allocations did not become ready: {rows}')
                time.sleep(.01)
            terminal(first_heap, heap_start)
            terminal(second_heap, heap_start)
            transcript = bytes(guest.text[heap_start:])
            if (transcript.count(b'NATIVE_HEAP_PASS\r\n') != 2
                    or transcript.count(b'NATIVE_HEAP_BUFFER_PASS\r\n') != 2):
                raise AssertionError(f'Expected two complete concurrent heap passes: {transcript[-2000:]!r}')
            rows = snapshot('both concurrent heap processes completed')
            for pid in (first_heap, second_heap):
                row = clean_status(pid, rows)
                if row['heap_model'] != 8194:
                    raise AssertionError(f'Concurrent heap lost its admission provenance: {row}')
                report['processes'].append(dict(mode='heap-concurrent', **row))
            report['checks'].append('two live AI-admitted 128-page heaps coexist; both retain PID-specific data, pass cross-page copies and reclaim all memory independently')

            def heap_case(mode, state='Exited', code=0, exception_class=None):
                pid, start = spawn(mode)
                terminal(pid, start, state, code)
                transcript = bytes(guest.text[start:])
                if state == 'Exited' and (b'NATIVE_HEAP_PASS\r\n' not in transcript
                                          or b'NATIVE_HEAP_BUFFER_PASS\r\n' not in transcript):
                    raise AssertionError(f'Heap checks did not finish for {pid}: {transcript[-2000:]!r}')
                row = clean_status(pid, snapshot(mode + ' completed'), state, code)
                if row['heap_model'] != 8194:
                    raise AssertionError(f'Anonymous memory was not admitted by its local model: {row}')
                if exception_class is not None:
                    heap_base = 0x04000000 if profile['heap_pages'] == 4096 else 0x200000
                    if row['esr'] >> 26 != exception_class or row['far'] != heap_base:
                        raise AssertionError(f'Unexpected heap protection fault: {row}')
                report['processes'].append(dict(mode=mode, **row))

            heap_case('heap')
            report['checks'].append('AI-admitted anonymous memory is zeroed, writable, safely copied across pages, reused zeroed and fully reclaimed at exit')
            heap_case('heapfault', 'Fault', 139, 0x24)
            report['checks'].append('read after unmap faults at the boot-profile heap base with data-abort EC 0x24 and reclaims outstanding heap grants')
            heap_case('heapexec', 'Fault', 139, 0x20)
            report['checks'].append('executing writable anonymous memory faults at the boot-profile heap base with instruction-abort EC 0x20 and reclaims heap grants')
            heap_case('heap')
            report['checks'].append('fresh heap program passes after both protection faults')
            if b'/\r\n' not in command('pwd'):
                raise AssertionError('Shell stopped responding after protection tests')
            check_console(guest.text)
            if hashlib.sha256(elf.read_bytes()).hexdigest() != report['elf_sha256']:
                raise AssertionError('Kernel ELF changed during verification; result identity is ambiguous')
            report['frames'] = guest.decoder.frames
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    finally:
        if guest is not None and guest.qmp is not None:
            (output / 'qmp.jsonl').write_text(''.join(json.dumps(row) + '\n'
                                                   for row in guest.qmp.transcript))
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/desktop-runtime')
    args = parser.parse_args()
    result = verify(args.elf, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
