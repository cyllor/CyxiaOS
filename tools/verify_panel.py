"""Verify real LXPanel controls against PCManFM on CyxiaOS's guest X server."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import inspect_elf, boot_profile
from desktop_session import embedded_programs, wait_window, windows
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import button, move, pump, wait


def click(guest, x, y):
    move(guest, -10000, -10000)
    move(guest, x, y)
    pump(guest, .5)
    button(guest, True)
    button(guest, False)
    pump(guest, .75)


def visible(guest, identifier, expected, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clients = windows(guest)
        if clients is not None and any(w['id'] == identifier for w in clients) == expected:
            return clients
        pump(guest, .25)
    raise AssertionError(f'X window {identifier} viewable did not become {expected}')


def launch(guest, name):
    start = len(guest.text)
    data = guest.command('posix exec ' + name)
    if b'ELF pid=' not in data:
        data = wait(guest, start, b'ELF pid=')
    match = re.search(rb'ELF pid=(\d+) started', data)
    if match is None:
        raise AssertionError(data[-1000:])
    return int(match[1])


def assert_reclaimed(rows, profile):
    """Both usage and grant ledgers must return to the profile's capacity."""
    expected = dict(free_pages=64, heap_pages=0, heap_free=profile['heap_pages'],
                    image_pages=0, image_free=4096, thread_count=0)
    assert rows and all(
        row['state'] in ('Exited', 'Killed') and
        all(row.get(key) == value for key, value in expected.items())
        for row in rows.values()), rows


def verify(elf, output):
    output.mkdir(parents=True, exist_ok=True)
    image = elf.read_bytes()
    inspect_elf(image)
    report = {'status': 'FAIL', 'scope': 'Real LXPanel taskbar/show-desktop and PCManFM window integration',
              'kernel_sha256': hashlib.sha256(image).hexdigest(),
              'profile': boot_profile(image), 'checks': []}
    try:
        report['programs'] = embedded_programs(elf, ('Xcyxia', 'openbox', 'pcmanfm', 'lxpanel', 'x11-inspect'))
        with Guest(elf, output/'session', graphics=True, rng=True) as guest:
            processes = []
            try:
                guest.until(b'cyxia:/> ')
                processes.append(launch(guest, 'xorg'))
                wait(guest, 0, b'CYXIA_XORG_READY')
                processes.append(launch(guest, 'openbox'))
                wait_window(guest)
                processes.append(launch(guest, 'lxpanel'))
                panel = wait_window(guest, 'Lxpanel', 45)[0]
                assert panel['width'] == 1024 and panel['height'] == 32, panel
                assert panel['x'] == 0 and panel['y'] == 736, panel
                processes.append(launch(guest, 'pcmanfm'))
                file_window = wait_window(guest, 'Pcmanfm', 45)[0]
                report['panel'] = panel
                report['file_window'] = file_window
                report['checks'].append('real upstream LXPanel mapped a bottom dock alongside Openbox and PCManFM')
                pump(guest, 2)
                # The pinned one-workspace profile has an icon-only menu,
                # show-desktop button and compact pager before the first task.
                task_point = (panel['x'] + 140, panel['y'] + panel['height']//2)
                click(guest, *task_point)
                visible(guest, file_window['id'], False)
                click(guest, *task_point)
                visible(guest, file_window['id'], True)
                report['checks'].append('physical mouse on LXPanel taskbar minimized and restored the same PCManFM X window')
                # Actual pinned icon buttons occupy x=0..21 and x=22..43;
                # the pager begins at x=44. Click the show-desktop icon center.
                desktop_point = (panel['x'] + 33, task_point[1])
                click(guest, *desktop_point)
                visible(guest, file_window['id'], False)
                click(guest, *desktop_point)
                visible(guest, file_window['id'], True)
                report['checks'].append('physical show-desktop button hid and restored the existing PCManFM window')
                rows = parse_processes(guest.command('posix list'))
                active = {pid: rows[pid] for pid in processes}
                assert all(r['state'] in ('Running', 'Waiting') and r['ai_selections'] > 0 and
                           r['heap_model'] == 8194 and r['cpu_model'] == 12290 for r in active.values()), active
                report['active_processes'] = active
                capture = output/'desktop.ppm'
                guest.qmp.execute('screendump', {'filename': str(capture)})
                report['screenshot_sha256'] = hashlib.sha256(capture.read_bytes()).hexdigest()
                for pid in reversed(processes):
                    start = len(guest.text)
                    guest.command(f'posix kill {pid}')
                    wait(guest, start, f'EL0 pid={pid} killed; pages reclaimed'.encode())
                rows = parse_processes(guest.command('posix list'))
                assert_reclaimed(rows, report['profile'])
                report['final_processes'] = rows
                report['checks'].append('all four process groups released heap/image grants; serial shell remained responsive')
            finally:
                if not (output/'desktop.ppm').exists():
                    guest.qmp.execute('screendump', {'filename': str(output/'desktop.ppm')})
                (output/'qmp.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in guest.qmp.transcript))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report['kernel_sha256'], 'kernel changed during gate'
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/panel-verified')
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
