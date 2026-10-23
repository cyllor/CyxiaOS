"""Real EL0 multiprocess/IPC checks for the desktop foundation, not LXDE acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from shell import Guest
from check_elf import inspect_elf, boot_profile
from doctor import ROOT

POOL_PAGES = 64
ADMITTED_PROCESSES = 7


def verify(elf, output):
    elf, output = Path(elf).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status='FAIL', scope='D2 native process and IPC foundation; no X11/LXDE',
                  elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest(), checks=[])
    try:
        inspect_elf(elf.read_bytes())
        profile = boot_profile(elf.read_bytes())
        with Guest(elf, output / 'session') as guest:
            boot = guest.until(b'cyxia:/> ')
            assert f"USER_HEAP_RESERVED {profile['heap_pages']*8//256}MiB BOOTSTRAP".encode() in boot, boot
            assert b'EXEC_MEMORY_UNAVAILABLE' not in boot, boot

            def wait_from(start, predicate, timeout=10):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    guest.poll()
                    data = bytes(guest.text[start:])
                    if b'CHECK_FAILED' in data or b'SERVICE_PANIC' in data or b'FAIL panic' in data:
                        raise AssertionError(data[-2000:])
                    if predicate(data):
                        return data
                    time.sleep(.01)
                raise TimeoutError(bytes(guest.text[start:])[-2000:])

            def command(text, marker=None):
                start = len(guest.text)
                guest.command(text)
                if marker:
                    wait_from(start, lambda data: marker in data)
                return start

            def spawn(mode):
                start = command('posix spawn ' + mode)
                data = wait_from(start, lambda data: re.search(rb'EL0 pid=(\d+) started;', data))
                return int(re.search(rb'EL0 pid=(\d+) started;', data)[1]), start

            def pair():
                start = command('posix pair')
                data = wait_from(start, lambda data: b'EL0 IPC pair' in data)
                match = re.search(rb'EL0 IPC pair server=(\d+) client=(\d+)', data)
                return (int(match[1]), int(match[2])), start

            def snapshot():
                raw = guest.command('posix list')
                processes = {}
                for fields in re.findall(rb'UserStatus \{ ([^}]+) \}', raw):
                    row = dict(item.decode().split(': ', 1) for item in fields.split(b', '))
                    row = {key: value if key == 'state' else int(value) for key, value in row.items()}
                    processes[row['pid']] = row
                assert processes, raw
                return processes

            def kill(pid):
                command(f'posix kill {pid}', f'EL0 pid={pid} killed;'.encode())

            def complete_pair(pids, start):
                wait_from(start, lambda data: all(f'EL0 pid={pid} Exited code=0'.encode() in data for pid in pids))
                data = bytes(guest.text[start:])
                assert b'NATIVE_IPC_SERVER_PASS' in data and b'NATIVE_IPC_CLIENT_PASS' in data
                rows = snapshot()
                for pid in pids:
                    row = rows[pid]
                    assert row['state'] == 'Exited' and row['code'] == 0, row
                    assert row['ipc_sent'] == row['ipc_received'] == 16384, row
                    assert row['rank_model'] == 12289 and row['ai_selections'] > 0, row
                    assert row['waits'] > 0 and row['wakeups'] > 0, row
                return rows

            capacity_start = len(guest.text)
            live = [spawn('spin')[0]] + [spawn('idle')[0] for _ in range(ADMITTED_PROCESSES - 1)]
            command('posix spawn idle', b'EL0 start failed: Nomem')
            wait_from(capacity_start, lambda data: data.count(b'NATIVE_SERVICE_ALIVE private-memory=PASS') == ADMITTED_PROCESSES - 1)
            rows = snapshot()
            active = {pid for pid, row in rows.items() if row['state'] in ('Running', 'Waiting')}
            assert active == set(live), rows
            assert all(rows[pid]['free_pages'] == 8 and rows[pid]['rank_model'] == 12289
                       and rows[pid]['ai_selections'] > 0 for pid in live), rows
            assert rows[live[0]]['preemptions'] > 0, rows
            report['capacity_processes'] = rows
            old = live[3]
            kill(old)
            replacement, _ = spawn('idle')
            assert replacement > max(live)
            live[3] = replacement
            rows = snapshot()
            assert old not in rows and all(rows[pid]['free_pages'] == 8 for pid in live), rows
            command('posix spawn idle', b'EL0 start failed: Nomem')
            for pid in live:
                kill(pid)
            assert all(row['free_pages'] == POOL_PAGES for row in snapshot().values())
            report['checks'].append('seven isolated processes run under the original local AI models; eighth admission is denied with eight pages preserved; a freed slot is reused with a fresh PID')

            hog, _ = spawn('spin')
            pids, start = pair()
            rows = complete_pair(pids, start)
            assert rows[hog]['state'] == 'Running' and rows[hog]['preemptions'] > 0, rows
            assert rows[hog]['free_pages'] == POOL_PAGES - 8, rows
            report['checks'].append('two isolated Rust EL0 processes exchange 16 KiB each while a third is IRQ-preempted')
            report['concurrent_processes'] = rows
            kill(hog)
            assert all(row['free_pages'] == POOL_PAGES for row in snapshot().values())

            idle, start = spawn('idle')
            faulty, fault_start = spawn('fault')
            wait_from(start, lambda data: b'NATIVE_SERVICE_ALIVE private-memory=PASS' in data)
            wait_from(fault_start, lambda data: f'EL0 pid={faulty} Fault code=139'.encode() in data)
            rows = snapshot()
            assert rows[idle]['state'] in ('Running', 'Waiting'), rows
            assert rows[faulty]['esr'] >> 26 == 0x24 and rows[faulty]['far'] == 0xffffffc040200000, rows
            assert rows[idle]['free_pages'] == POOL_PAGES - 8, rows
            assert b'/\r\n' in guest.command('pwd')
            kill(idle)
            report['checks'].append('services survive 500 ms; kernel-memory fault kills only offending process; shell stays responsive')

            pids, start = pair()
            rows = snapshot()
            assert rows[pids[1]]['state'] == 'Waiting' and rows[pids[1]]['waits'] > 0, rows
            kill(pids[0])
            wait_from(start, lambda data: b'NATIVE_IPC_PEER_CLOSED' in data and f'EL0 pid={pids[1]} Exited code=0'.encode() in data)
            assert all(row['free_pages'] == POOL_PAGES for row in snapshot().values())
            report['checks'].append('peer exit becomes EOF/EPIPE; both page grants reclaimed')

            residents = [spawn('idle')[0] for _ in range(ADMITTED_PROCESSES - 1)]
            command('posix pair', b'EL0 pair failed: Nomem')
            rows = snapshot()
            assert all(rows[pid]['state'] in ('Running', 'Waiting') for pid in residents), rows
            assert all(row['free_pages'] == 16 for row in rows.values()), rows
            high_slot, heap_start = spawn('heap')
            wait_from(heap_start, lambda data: b'NATIVE_HEAP_PASS' in data and f'EL0 pid={high_slot} Exited code=0'.encode() in data)
            rows = snapshot()
            assert rows[high_slot]['heap_pages'] == 0 and rows[high_slot]['heap_free'] == profile['heap_pages'], rows
            assert rows[high_slot]['heap_model'] == 8194 and rows[high_slot]['free_pages'] == 16, rows
            assert all(rows[pid]['state'] in ('Running', 'Waiting') for pid in residents), rows
            report['high_slot_heap'] = rows[high_slot]
            for pid in residents:
                kill(pid)
            report['checks'].append('partial pair launch rolls back without terminating unrelated services or leaking grants')
            report['checks'].append('seventh slot reads, writes, revokes and reuses its real private heap backing while six neighbors remain alive')

            for _ in range(3):
                pids, start = pair()
                rows = complete_pair(pids, start)
                assert all(row['free_pages'] == POOL_PAGES for row in rows.values()), rows
            report['checks'].append('three restart cycles: clean private memory, fresh endpoint identities, complete capacity reclamation')
            assert b'posix run' in guest.command('help')
            report['frames'] = guest.decoder.frames
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report['elf_sha256']
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True)
    parser.add_argument('--output', default=str(ROOT / 'artifacts/native-services'))
    args = parser.parse_args()
    result = verify(args.elf, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
