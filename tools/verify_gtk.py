"""Exercise actual GTK3 widgets and Openbox on the supplied CyxiaOS ARM image.

This gate does not claim LXDE, a file manager, PTY or persistent storage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import FATAL, button, key, move, pump, wait


def gtk_wait(guest, start, marker, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        guest.poll()
        data = bytes(guest.text[start:])
        if marker in data:
            return data
        if (any(value in data for value in FATAL)
                or b'GTK_PROBE INIT_FAILED' in data
                or b'EL0 pid=3 Exited' in data or b'EL0 pid=3 Faulted' in data
                or b'EL0 start failed:' in data):
            raise AssertionError(data[-2500:])
        time.sleep(.01)
    raise TimeoutError(f'Missing {marker!r}: {data[-2000:]!r}')


def point(guest, bounds):
    x, y, width, height = bounds
    move(guest, -10000, -10000)
    move(guest, x+width//2, y+height//2)
    pump(guest, .5)


def verify(elf, output):
    output.mkdir(parents=True, exist_ok=True)
    image = elf.read_bytes()
    inspect_elf(image)
    result = dict(status='FAIL', scope='GTK3/Openbox widget integration, not full LXDE',
                  kernel_sha256=hashlib.sha256(image).hexdigest(), checks=[], programs={})
    try:
        for name in ('Xcyxia', 'openbox', 'gtk-probe'):
            binary = (ROOT/'artifacts/sysroot/aarch64-musl'/(name+'.elf')).read_bytes()
            assert image.count(binary) == 1, f'{name} exact target ELF missing'
            result['programs'][name] = hashlib.sha256(binary).hexdigest()
        with Guest(elf, output/'session', graphics=True, rng=True) as guest:
            try:
                guest.until(b'cyxia:/> ')
                guest.command('posix exec xorg')
                wait(guest, 0, b'CYXIA_XORG_READY')
                guest.command('posix exec openbox')
                pump(guest, 3)
                start = len(guest.text)
                guest.command('posix exec gtk-probe')
                gtk_wait(guest, start, b'GTK_PROBE DRAW')
                data = gtk_wait(guest, start, b'GTK_PROBE BUTTON')
                bounds = {}
                for widget in ('WINDOW', 'ENTRY', 'BUTTON'):
                    match = re.search(fr'GTK_PROBE {widget} x=(-?\d+) y=(-?\d+) width=(\d+) height=(\d+)'.encode(), data)
                    assert match is not None, (widget, data[-2000:])
                    bounds[widget] = list(map(int, match.groups()))
                result['bounds'] = bounds
                result['checks'].append('real GTK3 mapped and drew its window, entry and button')
                rows = parse_processes(guest.command('posix list'))
                assert len(rows) == 3 and all(r['state'] in ('Running', 'Waiting') for r in rows.values()), rows
                assert all(r['ai_selections'] > 0 and r['heap_model'] == 8194 and r['cpu_model'] == 12290 for r in rows.values()), rows
                result['active_processes'] = rows
                point(guest, bounds['BUTTON'])
                button(guest, True); button(guest, False)
                gtk_wait(guest, start, b'GTK_PROBE CLICK count=1')
                point(guest, bounds['ENTRY'])
                button(guest, True); button(guest, False)
                key(guest, 'a', True); key(guest, 'a', False)
                key(guest, 'shift', True)
                key(guest, 'a', True); key(guest, 'a', False)
                key(guest, 'shift', False)
                gtk_wait(guest, start, b'GTK_PROBE TEXT text=aA')
                result['checks'].append('physical mouse clicked GTK button and XKB keyboard edited GTK entry to aA')
                pump(guest, 1)
                capture = output/'desktop.ppm'
                guest.qmp.execute('screendump', {'filename': str(capture)})
                result['screenshot_sha256'] = hashlib.sha256(capture.read_bytes()).hexdigest()
                key(guest, 'alt', True)
                key(guest, 'f4', True); key(guest, 'f4', False)
                key(guest, 'alt', False)
                wait(guest, start, b'EL0 pid=3 Exited code=0', 15)
                assert b'GTK_PROBE EXIT' in guest.text[start:]
                result['checks'].append('Openbox Alt+F4 closed GTK window and GTK main loop exited cleanly')
                for pid in (2, 1):
                    marker = len(guest.text)
                    guest.command(f'posix kill {pid}')
                    wait(guest, marker, f'EL0 pid={pid} killed; pages reclaimed'.encode())
                rows = parse_processes(guest.command('posix list'))
                assert all(r['free_pages'] == 64 and r['heap_pages'] == 0 and r['image_pages'] == 0 for r in rows.values()), rows
                result['final_processes'] = rows
                result['checks'].append('all image and heap grants reclaimed; serial shell responsive')
            finally:
                if not (output/'desktop.ppm').exists():
                    guest.qmp.execute('screendump', {'filename': str(output/'desktop.ppm')})
                (output/'qmp.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in guest.qmp.transcript))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == result['kernel_sha256'], 'kernel changed during verification'
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = repr(error)
    (output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/gtk-verified')
    args = parser.parse_args()
    report = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)
