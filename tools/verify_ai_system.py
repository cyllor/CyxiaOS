"""Check genuine guest-wide AI receipts while the lightweight desktop is running.

The host only launches, observes and asserts; all policy and counters run in EL1.
This gate never reports an overall AI coverage percentage or performance benefit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import boot_profile
from desktop_session import embedded_programs, wait_window
from doctor import ROOT
from shell import Guest
from verify_panel import launch
from verify_x11 import pump, wait

REQUIRED = {
    'el1_memory', 'el1_cpu', 'uart_timer', 'fs_admission', 'fs_cache',
    'cpu_process', 'cpu_thread', 'cpu_quantum', 'process', 'thread',
    'anonymous', 'elf', 'spawn_receipt', 'unix', 'pipe', 'pty',
    'storage', 'display', 'input', 'security',
}


def parse_snapshot(data):
    start = data.find(b'AI_SYSTEM schema=1 ')
    end = data.find(b'AI_SYSTEM_END\r\n', start)
    if start < 0 or end < start:
        raise AssertionError('Incomplete AI system snapshot')
    data = data[start:end]
    if b'full_contract=false' not in data or b'AI_GAPS ' not in data:
        raise AssertionError('Snapshot conceals implementation gaps')
    rows = {}
    for raw in re.findall(rb'AI_DOMAIN ([^\r\n]+)', data):
        fields = dict(piece.decode().split('=', 1) for piece in raw.split() if b'=' in piece)
        name = fields.pop('name')
        if name in rows:
            raise AssertionError('Duplicate domain: '+name)
        rows[name] = {key: int(value) if value.isdecimal() else value for key, value in fields.items()}
    missing = REQUIRED - rows.keys()
    if missing:
        raise AssertionError('Missing domains: '+str(sorted(missing)))
    return rows


def snapshot(guest):
    start = len(guest.text)
    guest.command('ai system')
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        guest.poll()
        data = bytes(guest.text[start:])
        if b'AI_SYSTEM_END\r\n' in data:
            return parse_snapshot(data)
        time.sleep(.01)
    raise TimeoutError('AI system response did not complete')


def check_receipts(rows):
    for name in ('process', 'thread', 'anonymous', 'elf', 'spawn_receipt', 'unix', 'pipe', 'pty'):
        r = rows[name]
        assert r['requests'] == sum(r[k] for k in ('committed', 'denied', 'capacity', 'invalid', 'failed')), (name, r)
        assert r['committed'] == r['ai'], (name, r)
        assert r['committed'] <= r['approved'] <= r['proposals'] <= r['requests'], (name, r)
        assert r['release_units'] <= r['grant_units'], (name, r)
    process, quantum, thread = (rows[k] for k in ('cpu_process', 'cpu_quantum', 'cpu_thread'))
    assert process['committed'] == process['ai'] + process['guard'], process
    assert quantum['committed'] == process['committed'], (process, quantum)
    assert quantum['enters'] == quantum['returns'] >= quantum['committed'], quantum
    assert thread['committed'] == thread['ai'] + thread['guard'], thread
    display = rows['display']
    assert display['model'] == 24577 and display['available'] == 'true', display
    assert display['admitted'] == display['ai_admitted'] + display['guard_admitted'], display
    assert display['completed'] <= display['submitted'] <= display['admitted'] <= display['proposals'], display
    assert display['planned_wait_ms'] <= (display['completed'] // 8), display
    assert display['failed'] == 0, display


def verify(elf, output):
    elf, output = Path(elf).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {'status': 'FAIL', 'scope': 'guest per-domain policy/receipt integration; not full AI OS acceptance',
              'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest(), 'checks': [], 'snapshots': {}}
    try:
        report['profile'] = boot_profile(elf.read_bytes())
        report['programs'] = embedded_programs(elf, ('Xcyxia', 'openbox', 'pcmanfm', 'lxpanel', 'x11-inspect'))
        with Guest(elf, output/'session', graphics=True, rng=True) as guest:
            guest.until(b'cyxia:/> ')
            before = snapshot(guest)
            report['snapshots']['boot'] = before
            assert before['process']['committed'] == 0, before['process']
            assert before['display']['admitted'] == 0, before['display']
            # Real memory-model rejection, then the explicitly requested release.
            ids = []
            for _ in range(3):
                answer = guest.command('mem alloc 8')
                ids.append(int(re.search(rb'allocated id=(\d+)', answer)[1]))
            assert b'AiDenied' in guest.command('mem alloc 8')
            for identifier in ids:
                guest.command(f'mem free {identifier}')
            # More files than cache slots create a real ranking decision opportunity.
            for index in range(6):
                guest.command(f'write /ai-check-{index} exact-{index}')
            for index in range(6):
                assert re.search(rb'(?m)^exact-' + str(index).encode() + rb'\r?$', guest.command(f'cat /ai-check-{index}'))
            assert b'NeedSamples' in guest.command('ai train')
            processes = []
            processes.append(launch(guest, 'xorg'))
            wait(guest, 0, b'CYXIA_XORG_READY')
            processes.append(launch(guest, 'openbox'))
            wait_window(guest)
            processes.append(launch(guest, 'lxpanel'))
            wait_window(guest, 'Lxpanel', 45)
            processes.append(launch(guest, 'pcmanfm'))
            wait_window(guest, 'Pcmanfm', 45)
            pump(guest, 2)
            active = snapshot(guest)
            check_receipts(active)
            report['snapshots']['desktop'] = active
            assert active['el1_memory']['denied'] > before['el1_memory']['denied']
            assert active['el1_memory']['free_pages'] == 32
            assert active['fs_cache']['ai_selected'] > 0, active['fs_cache']
            for name in ('process', 'thread', 'anonymous', 'elf', 'unix'):
                assert active[name]['committed'] > 0, (name, active[name])
            assert active['display']['completed'] >= 48, active['display']
            guest.qmp.execute('screendump', {'filename': str(output/'desktop.ppm')})
            report['checks'].append('four real desktop processes exercise local CPU, thread, memory, IPC and display policies')
            report['checks'].append('model denial and cache contention are visible independently of mechanism and safety counts')
            for pid in reversed(processes):
                start = len(guest.text)
                guest.command(f'posix kill {pid}')
                wait(guest, start, f'EL0 pid={pid} killed; pages reclaimed'.encode())
            pump(guest, .1)
            after = snapshot(guest)
            check_receipts(after)
            report['snapshots']['reaped'] = after
            for name in ('process', 'thread', 'anonymous', 'elf', 'spawn_receipt'):
                assert after[name]['grant_units'] == after[name]['release_units'], (name, after[name])
                assert after[name]['committed'] >= active[name]['committed'], (name, after[name])
            assert after['display']['phase'] == 'Idle', after['display']
            assert after['display']['admitted'] == after['display']['completed'], after['display']
            assert re.search(rb'(?m)^exact-0\r?$', guest.command('cat /ai-check-0'))
            assert re.search(rb'(?m)^/ai-check-0 File bytes=7 reads=\d+ cached=(true|false)\r?$', guest.command('stat /ai-check-0'))
            report['checks'].append('tracked memory/context/exit-receipt grants are reclaimed, cumulative counts survive exit, exact file data remains intact')
            (output/'qmp.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in guest.qmp.transcript))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report['elf_sha256'], 'kernel changed during gate'
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf', required=True)
    parser.add_argument('--output', default=str(ROOT/'artifacts/ai-system-verification'))
    args = parser.parse_args()
    result = verify(args.elf, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
