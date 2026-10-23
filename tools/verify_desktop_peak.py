"""Keep six desktop/PTY processes alive while a seventh performs a durable save."""
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
from storage import create_disk
from verify_desktop_menu import capture, durable_save, spawned_child, storage_status
from verify_panel import assert_reclaimed, launch
from verify_ported import parse_processes
from verify_terminal import launch as terminal_launch, click, chord, type_text, read_file
from verify_x11 import pump, wait


VALUE = b'peak-seven-value\n'


def saved_file(guest):
    content = read_file(guest, '/peak-seven.txt', VALUE.replace(b'\n', b'\r\n'))
    status = guest.command('stat /peak-seven.txt')
    assert re.search(rb'(?m)^/peak-seven\.txt File bytes=17 reads=\d+ cached=(true|false)\r?$', status), status
    return {'content': content, 'stat': status.decode(errors='replace')}


def save_close_point(guest, output):
    """Locate the painted save canvas in the actual framebuffer, without EL0 helpers.

    The save window is 500x180 white pixels. The terminal interior and desktop
    are dark; terminal borders and the bottom panel cannot satisfy this area.
    Tolerate the few white frame pixels around the canvas when clicking its
    80x30 Close button, whose center is at client (430,140).
    """
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        capture(guest, output, 'seven-processes-saved')
        with (output / 'seven-processes-saved.ppm').open('rb') as stream:
            assert stream.readline() == b'P6\n'
            width, height = map(int, stream.readline().split())
            assert stream.readline() == b'255\n'
            pixels = stream.read()
        assert len(pixels) == width * height * 3
        for y in range(height - 180):
            row = pixels[y * width * 3:(y + 1) * width * 3]
            for run in re.finditer(rb'\xff{1440,1650}', row):
                if run.end() < len(row) and row[run.end()] == 255:
                    continue
                x = run.start() // 3
                if x + 490 >= width:
                    continue
                samples = [pixels[((y + dy) * width + x + dx) * 3:((y + dy) * width + x + dx) * 3 + 3]
                           for dy in (10, 40, 100, 170) for dx in (20, 250, 470)]
                if sum(p == b'\xff\xff\xff' for p in samples) >= 11:
                    return x + 430, y + 140
        pump(guest, .25)
    raise TimeoutError('The seven-process save window did not paint its 500x180 canvas')


def verify(elf, output):
    output.mkdir(parents=True, exist_ok=True)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = {'status': 'FAIL', 'kernel_sha256': digest(elf),
              'profile': boot_profile(elf.read_bytes()), 'checks': []}
    try:
        report['programs'] = embedded_programs(elf, (
            'Xcyxia', 'openbox', 'pcmanfm', 'lxpanel', 'cyxia-terminal', 'cyxia-sh', 'cyxia-save', 'x11-inspect'))
        disk = create_disk(output / 'cyxia-peak.raw')
        with Guest(elf, output / 'session', graphics=True, rng=True, disk=disk) as guest:
            try:
                boot = guest.until(b'cyxia:/> ', timeout=30)
                assert b'STORAGE_EMPTY' in boot
                resident = [launch(guest, 'xorg')]
                wait(guest, 0, b'CYXIA_XORG_READY')
                resident.append(launch(guest, 'openbox'))
                wait_window(guest)
                resident.append(launch(guest, 'pcmanfm-desktop'))
                wait_window(guest, 'Pcmanfm', 45)
                panel = launch(guest, 'lxpanel')
                resident.append(panel)
                wait_window(guest, 'Lxpanel', 45)
                pump(guest, 1)
                window, terminal, shell = terminal_launch(guest, output)
                type_text(guest, 'write /peak-seven.txt peak-seven-value\n')
                report['file_before_save'] = saved_file(guest)
                rows = parse_processes(guest.command('posix list'))
                six = set(resident + [terminal, shell])
                active = {pid for pid, row in rows.items() if row['state'] in ('Running', 'Waiting')}
                assert active == six and len(six) == 6, (active, six)
                report['checks'].append('the actual panel launched the Xlib terminal and PTY shell, which wrote the guest file through physical keyboard input')
                before = storage_status(guest)
                start = len(guest.text)
                click(guest, 16, 752)
                pump(guest, .6)
                chord(guest, 'end')
                chord(guest, 'ret')
                wait(guest, start, b'CYXIA_SAVE DURABLE generation=1', 30)
                save = spawned_child(bytes(guest.text[start:]), panel)
                after = storage_status(guest)
                durable_save(bytes(guest.text[start:]), before, after)
                # Do not create x11-inspect while all seven process grants are
                # live: verification must not require an eighth process.
                rows = parse_processes(guest.command('posix list'))
                active = {pid: row for pid, row in rows.items() if row['state'] in ('Running', 'Waiting')}
                assert set(active) == six | {save} and len(active) == 7, active
                assert all(row['free_pages'] == 8 and row['ai_selections'] > 0 for row in active.values()), active
                assert all(row['cpu_model'] == 12290 for row in active.values()), active
                # The small shell can complete entirely on its initial stack;
                # a process with no heap grant has no heap allocation decision.
                assert all(row['heap_model'] == 8194 for row in active.values() if row['heap_pages'] > 0), active
                report['active_processes'] = active
                report['storage_before'] = before
                report['storage_after'] = after
                report['file_at_peak'] = saved_file(guest)
                close_point = save_close_point(guest, output)
                report['save_close_point'] = close_point
                report['screenshot_sha256'] = digest(output / 'seven-processes-saved.ppm')
                report['checks'].append('seven real process groups stayed live with eight floor pages free while Save Files completed two actual VirtIO flushes and returned all staging grants')
                start = len(guest.text)
                click(guest, *close_point)
                wait(guest, start, f'EL0 pid={save} Exited code=0'.encode(), 15)
                start = len(guest.text)
                click(guest, window['x'] + 40, window['y'] + 60)
                type_text(guest, 'exit\n')
                wait(guest, start, f'EL0 pid={terminal} Exited code=0'.encode(), 20)
                for pid in reversed(resident):
                    start = len(guest.text)
                    guest.command(f'posix kill {pid}')
                    wait(guest, start, f'EL0 pid={pid} killed; pages reclaimed'.encode())
                report['final_processes'] = parse_processes(guest.command('posix list'))
                assert_reclaimed(report['final_processes'], report['profile'])
                report['checks'].append('closing the save and terminal reclaimed their children; all seven groups returned thread, heap, image and floor grants')
            finally:
                if not (output / 'seven-processes-saved.ppm').exists():
                    capture(guest, output, 'failure')
                (output / 'qmp.jsonl').write_text(''.join(json.dumps(v) + '\n' for v in guest.qmp.transcript))
        with Guest(elf, output / 'reboot', disk=disk) as guest:
            boot = guest.until(b'cyxia:/> ', timeout=30)
            assert b'STORAGE_RECOVERED generation=1' in boot
            report['recovered_file'] = saved_file(guest)
        assert digest(elf) == report['kernel_sha256']
        report['disk_sha256'] = digest(disk)
        report['checks'].append('a fresh VM recovered the exact 17-byte file written through the terminal before the seven-process save')
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/desktop-peak')
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
