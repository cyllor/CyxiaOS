"""Real ARM VirtIO bring-up verification; the host never draws guest pixels."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
from doctor import ROOT, RUST_BIN, TARGET, env, inspect
from check_elf import inspect_elf
from shell import Guest

COLORS = [(255,255,255),(255,255,0),(0,255,255),(0,255,0),
          (255,0,255),(255,0,0),(0,0,255),(0,0,0)]

def build(profile):
    if not inspect()['ready']:
        raise RuntimeError('Pinned environment mismatch; run tools/doctor.py')
    args = [str(RUST_BIN / 'cargo'), 'build', '-p', 'cyxia-kernel',
            '--target', TARGET, '--features', 'graphics']
    if profile == 'release':
        args.append('--release')
    subprocess.run(args, cwd=ROOT, env=dict(env(), CARGO_INCREMENTAL='0'), check=True, timeout=180)
    elf = ROOT / 'target' / TARGET / ('release' if profile == 'release' else 'debug') / 'cyxia-kernel'
    inspect_elf(elf.read_bytes())
    return elf


def check_pixels(path):
    with path.open('rb') as stream:
        if stream.readline() != b'P6\n' or stream.readline() != b'1024 768\n' or stream.readline() != b'255\n':
            raise AssertionError('Unexpected QEMU image dimensions/format')
        pixels = stream.read()
    row = b''.join(bytes(color) * 128 for color in COLORS)
    if pixels != row * 768:
        raise AssertionError('Guest framebuffer differs from expected colour bars')
    return hashlib.sha256(pixels).hexdigest()


def verify(elf, output):
    output.mkdir(parents=True, exist_ok=True)
    result = {'status': 'FAIL', 'scope': 'D1 graphics device bring-up, not a desktop',
              'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest(), 'checks': []}
    try:
        with Guest(elf, output / 'devices', graphics=True) as guest:
            boot = guest.until(b'cyxia:/> ')
            assert b'GRAPHICS_FRAME_OK 1024x768 BOOTSTRAP' in boot
            assert boot.count(b'GRAPHICS_INPUT_READY') == 2
            assert b'ERROR' not in boot and b'FAIL' not in boot
            result['checks'].append('frame-and-two-input-devices')
            # QEMU display refresh may occur after the guest's fenced resource flush.
            screenshot = output / 'frame.ppm'
            deadline = time.monotonic() + 3
            while True:
                guest.qmp.execute('screendump', {'filename': str(screenshot.resolve())})
                try:
                    result['pixel_sha256'] = check_pixels(screenshot)
                    break
                except AssertionError:
                    if time.monotonic() >= deadline:
                        raise
                    guest.poll()
                    time.sleep(.02)
            result['checks'].append('all-786432-guest-pixels')
            for down, marker in [(True, b'0001001e00000001'), (False, b'0001001e00000000')]:
                guest.qmp.execute('input-send-event', {'events': [
                    {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': 'a'}}}]})
                guest.until(marker)
            guest.qmp.execute('input-send-event', {'events': [
                {'type': 'rel', 'data': {'axis': 'x', 'value': 12}}]})
            guest.until(b'000200000000000c')
            result['checks'].append('keyboard-down-up-and-mouse')
            assert b'posix run' in guest.command('help')
            assert b'ERROR' not in guest.text and b'STOPPED' not in guest.text
            result['checks'].append('serial-shell-still-responsive')
            (output / 'qmp.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in guest.qmp.transcript))
        with Guest(elf, output / 'no-devices') as guest:
            boot = guest.until(b'cyxia:/> ')
            assert b'GRAPHICS_NO_GPU BOOTSTRAP' in boot
            assert b'GRAPHICS_FRAME_OK' not in boot
            assert b'posix run' in guest.command('help')
            result['checks'].append('missing-graphics-falls-back-to-shell')
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', choices=['dev', 'release'], default='dev')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / 'artifacts' / ('graphics-' + args.profile)
    print(json.dumps(verify(build(args.profile), output), indent=2))
