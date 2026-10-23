"""Verify real upstream X.Org + a window manager + Xlib on the CyxiaOS ARM kernel.

No host rendering or host X server is used. This integration gate is not LXDE
acceptance: panel, file manager, terminal and persistence remain separate.
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
from verify_ported import parse_processes

FATAL = (b'CHECK_FAILED', b'SERVICE_PANIC', b'FAIL panic', b'FAIL unexpected exception',
         b'GRAPHICS_GPU_ERROR', b'X11_PROBE FAIL', b'X11_PROBE ERROR', b'Fatal server error')


def wait(guest, start, marker, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        guest.poll()
        data = bytes(guest.text[start:])
        if any(value in data for value in FATAL):
            raise AssertionError(data[-2000:])
        if marker in data:
            return data
        time.sleep(.01)
    raise TimeoutError(f'Missing {marker!r}: {data[-1500:]!r}')


def pump(guest, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        guest.poll()
        time.sleep(.01)


def event(guest, events):
    guest.qmp.execute('input-send-event', {'events': events})
    pump(guest, .12)


def move(guest, x, y):
    event(guest, [{'type': 'rel', 'data': {'axis': 'x', 'value': x}},
                  {'type': 'rel', 'data': {'axis': 'y', 'value': y}}])


def button(guest, down):
    event(guest, [{'type': 'btn', 'data': {'button': 'left', 'down': down}}])


def key(guest, code, down):
    event(guest, [{'type': 'key', 'data': {'key': {'type': 'qcode', 'data': code}, 'down': down}}])


def white_rectangle(path, x, y):
    with path.open('rb') as stream:
        assert stream.readline() == b'P6\n'
        assert stream.readline() == b'1024 768\n'
        assert stream.readline() == b'255\n'
        pixels = stream.read()
    assert len(pixels) == 1024 * 768 * 3
    assert 0 <= x < x+80 <= 1024 and 0 <= y < y+60 <= 768
    for row in range(y, y+60):
        assert pixels[(row*1024+x)*3:(row*1024+x+80)*3] == b'\xff' * (80*3)
    return hashlib.sha256(pixels).hexdigest()


def verify(elf, output, wm='twm'):
    output.mkdir(parents=True, exist_ok=True)
    image = elf.read_bytes()
    inspect_elf(image)
    result = {'status': 'FAIL', 'scope': f'X.Org/{wm} integration; not LXDE desktop completion',
              'kernel_sha256': hashlib.sha256(image).hexdigest(), 'checks': []}
    try:
        programs = {}
        for name, filename in [('xorg','Xcyxia.elf'),(wm,wm+'.elf'),('x11-probe','x11-probe.elf')]:
            data = (ROOT/'artifacts/sysroot/aarch64-musl'/filename).read_bytes()
            assert image.count(data) == 1, f'{name} is not the exact embedded target image'
            programs[name] = hashlib.sha256(data).hexdigest()
        result['programs'] = programs
        with Guest(elf, output/'session', graphics=True, rng=True) as guest:
            guest.until(b'cyxia:/> ')
            start = len(guest.text)
            guest.command('posix exec xorg')
            wait(guest, start, b'CYXIA_XORG_READY 1024x768 input=keyboard,mouse')
            guest.command('posix exec '+wm)
            pump(guest, 2 if wm == 'openbox' else .8)
            start = len(guest.text)
            guest.command('posix exec x11-interactive')
            data = wait(guest, start, b'X11_PROBE WINDOW')
            data = wait(guest, start, b'height=180')
            assert b'X11_PROBE DRAW PASS' in data
            assert b'X11_PROBE REPARENTED PASS' in data
            x, y = map(int, re.search(rb'WINDOW x=(\d+) y=(\d+)', data).groups())
            result['checks'].append(f'X11 protocol, server pixel readback, real {wm} reparenting')
            rows = parse_processes(guest.command('posix list'))
            assert len(rows) == 3 and all(row['state'] in ('Running','Waiting') for row in rows.values())
            assert all(row['ai_selections'] > 0 and row['cpu_model'] == 12290 and row['heap_model'] == 8194 for row in rows.values())
            result['active_processes'] = rows
            # The Openbox theme has an inner border below its title label.
            # Hit the label itself, not that non-draggable border.
            title_offset = 20 if wm == 'openbox' else 10
            move(guest, -10000, -10000)
            move(guest, x+100, y-title_offset)
            # Let X.Org process EnterNotify and Openbox install its passive
            # grabs before pressing. TCG full-frame software updates can take
            # longer than the inter-event pacing used for ordinary input.
            pump(guest, .5)
            button(guest, True)
            # Openbox starts its drag on the first motion past the threshold;
            # a second motion exercises the active grab, as a real drag does.
            move(guest, 40, 30)
            pump(guest, .5)
            move(guest, 40, 30)
            button(guest, False)
            expected = f'X11_PROBE GEOMETRY x={x+80} y={y+60} width=320 height=180'.encode()
            wait(guest, start, expected)
            result['checks'].append('pointer-driven title-bar drag changed real window geometry')
            x += 80; y += 60
            capture = output/'desktop.ppm'
            deadline = time.monotonic()+3
            while True:
                guest.qmp.execute('screendump', {'filename': str(capture.resolve())})
                try:
                    result['pixels_sha256'] = white_rectangle(capture, x+20, y+20)
                    break
                except AssertionError:
                    if time.monotonic() >= deadline: raise
                    pump(guest, .05)
            move(guest, 0, 100+title_offset)
            button(guest, True); button(guest, False)
            key(guest, 'a', True); key(guest, 'a', False)
            key(guest, 'shift', True)
            key(guest, 'a', True); key(guest, 'a', False)
            key(guest, 'shift', False)
            data = wait(guest, start, b'keysym=65 text=A')
            assert b'keysym=97 text=a' in data and b'X11_PROBE BUTTON code=1 x=100 y=100' in data
            result['checks'].append('real mouse click and XKB lowercase/Shift keyboard delivery')
            wait(guest, start, b'EL0 pid=3 Exited code=0', 20)
            rows = parse_processes(guest.command('posix list'))
            assert rows[3]['heap_pages'] == 0 and rows[3]['heap_free'] == boot_profile(image)['heap_pages']
            assert rows[3]['image_pages'] == 0 and rows[3]['image_free'] == 4096
            assert rows[1]['state'] in ('Running','Waiting') and rows[2]['state'] in ('Running','Waiting')
            result['checks'].append('client clean exit reclaimed heap/image while server and WM survived')
            for pid in (2, 1):
                marker = len(guest.text)
                guest.command(f'posix kill {pid}')
                wait(guest, marker, f'EL0 pid={pid} killed; pages reclaimed'.encode())
            rows = parse_processes(guest.command('posix list'))
            assert all(row['free_pages'] == 64 and row['heap_pages'] == 0 and row['image_pages'] == 0 for row in rows.values())
            result['final_processes'] = rows
            result['checks'].append('all three process allocations reclaimed; serial shell remains responsive')
            (output/'qmp.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in guest.qmp.transcript))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == result['kernel_sha256'], 'kernel changed during verification'
        result['status'] = 'PASS'
        return result
    except Exception as error:
        result['error'] = repr(error)
        raise
    finally:
        (output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/x11-verified')
    parser.add_argument('--wm', choices=['twm','openbox'], default='twm')
    args = parser.parse_args()
    print(json.dumps(verify(args.elf.resolve(), args.output.resolve(), args.wm), indent=2))
