"""Verify real EL0 rectangle updates in ARM QEMU; this is not desktop acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import inspect_elf
from doctor import ROOT
from shell import Guest
from verify_graphics import COLORS


WIDTH, HEIGHT = 1024, 768
RECTANGLE = (17, 23, 32, 16)
FIRST_COLOR = (0x12, 0x34, 0x56)
SECOND_COLOR = (0xA1, 0xB2, 0xC3)
FATAL_MARKERS = (b'CHECK_FAILED', b'SERVICE_PANIC', b'FAIL panic',
                 b'FAIL unexpected exception', b'GRAPHICS_GPU_ERROR',
                 b'GRAPHICS_UPDATES_STOPPED')


def expected_pixels(color=None):
    row = b''.join(bytes(entry) * 128 for entry in COLORS)
    pixels = bytearray(row * HEIGHT)
    if color is not None:
        x, y, width, height = RECTANGLE
        update = bytes(color) * width
        for line in range(y, y + height):
            start = (line * WIDTH + x) * 3
            pixels[start:start + len(update)] = update
    return bytes(pixels)


def validate_pixels(path, expected):
    with path.open('rb') as stream:
        if (stream.readline() != b'P6\n'
                or stream.readline() != b'1024 768\n'
                or stream.readline() != b'255\n'):
            raise AssertionError('Unexpected QEMU image dimensions/format')
        pixels = stream.read()
    if len(pixels) != len(expected):
        raise AssertionError(f'Unexpected image byte count: {len(pixels)}')
    if pixels != expected:
        mismatch = next(i for i, pair in enumerate(zip(pixels, expected)) if pair[0] != pair[1])
        pixel = mismatch // 3
        raise AssertionError(f'Unexpected guest pixel at x={pixel % WIDTH}, y={pixel // WIDTH}')
    return hashlib.sha256(pixels).hexdigest()


def check_console(data):
    if any(marker in data for marker in FATAL_MARKERS):
        raise AssertionError(bytes(data[-2000:]))


def wait_marker(guest, start, marker, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        guest.poll()
        data = bytes(guest.text[start:])
        check_console(data)
        if marker in data:
            return data
        time.sleep(.01)
    raise TimeoutError(f'Missing {marker!r}; tail={bytes(guest.text[start:])[-2000:]!r}')


def capture(guest, path, expected, timeout=3):
    # A fenced RESOURCE_FLUSH finishes before QEMU's host display refresh.
    # Poll the real scanout until it matches; never replace or paint its pixels.
    deadline = time.monotonic() + timeout
    while True:
        guest.qmp.execute('screendump', {'filename': str(path.resolve())})
        try:
            return validate_pixels(path, expected)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            guest.poll()
            check_console(guest.text)
            time.sleep(.01)


def spawn_paint(guest):
    start = len(guest.text)
    guest.command('posix spawn paint')
    data = wait_marker(guest, start, b' started;')
    match = re.search(rb'EL0 pid=(\d+) started;', data)
    if not match:
        raise AssertionError(data)
    return int(match[1]), start


def expect_clean_exit(guest, pid, start):
    wait_marker(guest, start, f'EL0 pid={pid} Exited code=0'.encode())
    status = guest.command('posix list')
    rows = re.findall(rb'UserStatus \{ ([^}]+) \}', status)
    for fields in rows:
        row = dict(field.decode().split(': ', 1) for field in fields.split(b', '))
        if row.get('pid') == str(pid):
            if row.get('state') != 'Exited' or row.get('code') != '0' or row.get('free_pages') != '64':
                raise AssertionError(row)
            return row
    raise AssertionError(f'Missing process status for {pid}: {status!r}')


def save_qmp(guest, path):
    path.write_text(''.join(json.dumps(row) + '\n' for row in guest.qmp.transcript))


def verify(elf, output):
    elf, output = Path(elf).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status='FAIL', scope='EL0 graphics blit mechanism; no X11/LXDE desktop',
                  elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest(), checks=[], snapshots={})
    try:
        inspect_elf(elf.read_bytes())
        with Guest(elf, output / 'devices', graphics=True) as guest:
            boot = guest.until(b'cyxia:/> ')
            check_console(boot)
            if b'GRAPHICS_FRAME_OK 1024x768 BOOTSTRAP' not in boot:
                raise AssertionError(boot)
            report['snapshots']['boot'] = capture(guest, output / 'boot.ppm', expected_pixels())
            report['checks'].append('initial scanout contains all eight exact boot colour bars')

            pid, start = spawn_paint(guest)
            wait_marker(guest, start, b'NATIVE_PAINT_FIRST_PASS')
            # The native client emits FIRST only after asserting EFAULT for a
            # kernel source pointer and EINVAL for an off-screen/empty rectangle.
            report['checks'].append('EL0 rejects kernel pointer, off-screen rectangle and zero dimensions before further drawing')
            # The native program sleeps 1000 ms between frames. Capture FIRST
            # immediately, without sending an intervening console command.
            report['snapshots']['first'] = capture(
                guest, output / 'first.ppm', expected_pixels(FIRST_COLOR), timeout=.75)
            report['checks'].append('first EL0 blit: 32x16 at (17,23), RGB 123456; all other pixels unchanged')

            wait_marker(guest, start, b'NATIVE_PAINT_SECOND_PASS')
            report['snapshots']['second'] = capture(
                guest, output / 'second.ppm', expected_pixels(SECOND_COLOR))
            report['checks'].append('second EL0 blit: same backing updated to RGB a1b2c3; all other pixels unchanged')
            report['process'] = expect_clean_exit(guest, pid, start)
            if b'posix run' not in guest.command('help'):
                raise AssertionError('Shell did not respond after frame updates')
            check_console(guest.text)
            report['checks'].append('paint process exits zero, releases page grant and leaves shell responsive')
            save_qmp(guest, output / 'devices-qmp.jsonl')

        with Guest(elf, output / 'no-devices') as guest:
            boot = guest.until(b'cyxia:/> ')
            check_console(boot)
            if b'GRAPHICS_NO_GPU BOOTSTRAP' not in boot or b'GRAPHICS_FRAME_OK' in boot:
                raise AssertionError(boot)
            pid, start = spawn_paint(guest)
            wait_marker(guest, start, b'NATIVE_PAINT_NO_DEVICE')
            report['no_device_process'] = expect_clean_exit(guest, pid, start)
            if b'NATIVE_PAINT_FIRST_PASS' in guest.text or b'NATIVE_PAINT_SECOND_PASS' in guest.text:
                raise AssertionError('Paint incorrectly succeeded without a GPU')
            if b'posix run' not in guest.command('help'):
                raise AssertionError('Shell did not respond after missing-device error')
            check_console(guest.text)
            report['checks'].append('missing graphics device returns an error to EL0 without a kernel panic')
            save_qmp(guest, output / 'no-devices-qmp.jsonl')
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/graphics-updates')
    args = parser.parse_args()
    result = verify(args.elf, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
