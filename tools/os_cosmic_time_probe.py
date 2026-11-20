#!/usr/bin/env python3
"""Observe the genuine clock and drive its calendar through actual guest input.

The original startup capture and 45-second verdict remain separate. Bright
pixels are candidate glyph evidence, combined with the actual sole panel child;
the saved screenshots require visual verification before claiming rendered time.
"""
import json
from pathlib import Path
import re
import sys
import time

import os_cosmic_startup_probe as startup
import os_x86
import x86_64 as pc


def ink(raw, bounds):
    parts = raw.split(b'\n', 3)
    pc.require(parts[:3] == [b'P6', b'1024 768', b'255'] and len(parts[3]) == 1024 * 768 * 3,
               'Unexpected real clock scanout')
    x1, y1, x2, y2 = bounds
    data = parts[3]
    return sum(min(data[3 * (y * 1024 + x):3 * (y * 1024 + x) + 3]) > 140
               for y in range(y1, y2) for x in range(x1, x2))


def shared_state(console):
    at = console.command('ai system')
    console.until(rb'AI_SYSTEM_END\r?\n', at)
    rows = re.findall(rb'^SHARED_OBJECTS ([^\r\n]+)', console.raw[at:], re.MULTILINE)
    pc.require(len(rows) == 1, 'Missing actual live shared-object receipt')
    return {key.decode(): int(value) for key, value in re.findall(rb'(\w+)=(\d+)', rows[0])}


def interaction(console, qmp, output):
    result = dict(status='FAIL', scope='eventual_calendar_pixels_two_cycles_and_original_process_liveness',
                  clock_rendered_verified=False,
                  semantic_frame_verified=False, cosmic_session_verified=False, full_os_verified=False)
    before = output / 'clock.ppm'
    qmp.execute('screendump', {'filename': str(before.resolve())})
    result['clock_glyph_candidate_pixels'] = ink(before.read_bytes(), (400, 0, 624, 64))
    result['clock_scanout_sha256'] = pc.sha(before)
    at = console.command('posix list')
    statuses = re.findall(rb'EL0 UserStatus \{ pid: (\d+), parent_pid: (\d+),[^\r\n]*?state: (Running|Waiting), code: 0,', console.raw[at:])
    active = {int(p) for p, _, _ in statuses}
    children = [int(p) for p, parent, _ in statuses if int(parent) == 6]
    result.update(core_children_alive={2, 3, 4, 5, 6} <= active, panel_children=children,
                  glyph_candidate=result['clock_glyph_candidate_pixels'] >= 100)
    if not (result['core_children_alive'] and len(children) == 1 and result['glyph_candidate']):
        return result
    result['shared_before_input'] = shared_state(console)
    input_start = len(console.raw)
    # The only installed applet is the unchanged upstream center clock. Mouse
    # input travels through QEMU's actual input device and guest compositor.
    qmp.execute('input-send-event', {'events': [
        {'type': 'rel', 'data': {'axis': 'x', 'value': 512}},
        {'type': 'rel', 'data': {'axis': 'y', 'value': 18}}]})

    def pump(seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            console.pump()
            time.sleep(.01)

    def click():
        qmp.execute('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
        pump(.15)
        qmp.execute('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': False}}]})

    def capture_until(name, predicate, observe_seconds=120, require_grid=False):
        path = output / name
        started = time.monotonic()
        matched = False
        while time.monotonic() - started < observe_seconds:
            pump(.5)
            qmp.execute('screendump', {'filename': str(path.resolve())})
            raw = path.read_bytes()
            pixels = ink(raw, (300, 64, 724, 600))
            header = ink(raw, (348, 55, 676, 110))
            lower_grid = ink(raw, (348, 290, 676, 410))
            footer = ink(raw, (348, 430, 676, 480))
            if predicate(pixels) and (not require_grid or
                    (header >= 300 and lower_grid >= 150 and footer >= 200)):
                matched = True
                break
        elapsed = round(time.monotonic() - started, 3)
        return dict(matched=matched, foreground_pixels=pixels, sha256=pc.sha(path),
                    header_pixels=header, lower_grid_pixels=lower_grid, footer_pixels=footer,
                    elapsed_seconds=elapsed, deadline_seconds=15,
                    within_deadline=matched and elapsed <= 15,
                    observation_limit_seconds=observe_seconds)

    pump(.5)
    click()
    # A later diagnostic can establish eventual rendering without making the
    # original 15-second interaction check pass. The boot gate is also unchanged.
    result['calendar_open'] = capture_until('calendar-open.ppm', lambda pixels: pixels >= 500, 120, True)
    if result['calendar_open']['matched']:
        result['shared_calendar_open'] = shared_state(console)
        click()
        result['calendar_closed'] = capture_until('calendar-closed.ppm', lambda pixels: pixels < 100)
        if result['calendar_closed']['matched']:
            result['shared_calendar_closed'] = shared_state(console)
            click()
            result['calendar_reopened'] = capture_until('calendar-reopened.ppm', lambda pixels: pixels >= 500, 120, True)
            if result['calendar_reopened']['matched']:
                click()
                result['calendar_closed_again'] = capture_until('calendar-closed-again.ppm', lambda pixels: pixels < 100)
                result['shared_after_second_close'] = shared_state(console)
    result['shared_after_input'] = shared_state(console)
    result['all_interactions_within_15_seconds'] = all(
        result.get(name, {}).get('within_deadline', False)
        for name in ('calendar_open', 'calendar_closed', 'calendar_reopened', 'calendar_closed_again'))
    result['abnormal_exits_after_input'] = [dict(pid=int(pid), code=int(code))
        for pid, code in re.findall(rb'USER pid=(\d+) (?:Exited|Fault) code=(\d+)\b', console.raw[input_start:])
        if int(code) != 0]
    after = console.command('posix list')
    still_alive = {int(pid) for pid in re.findall(
        rb'EL0 UserStatus \{ pid: (\d+),[^\r\n]*?state: (?:Running|Waiting), code: 0,', console.raw[after:])}
    result['original_child_alive_after_input'] = set(children) <= still_alive
    result['status'] = 'PASS' if (result['calendar_open']['matched']
        and result.get('calendar_closed', {}).get('matched')
        and result.get('calendar_reopened', {}).get('matched')
        and result.get('calendar_closed_again', {}).get('matched')
        and result['original_child_alive_after_input']
        and not result['abnormal_exits_after_input']) else 'FAIL'
    pc.write_json(output / 'time-qmp.json', qmp.transcript)
    return result


def main():
    startup.main(after_observation=interaction)
    # Reuse the original argument parser and capture, including its fixed gate.
    output = Path(sys.argv[sys.argv.index('--output') + 1])
    capture = pc.read_json(output / 'result.json')
    result = dict(capture.get('applet_diagnostic', {'status': 'FAIL'}),
        startup_status=capture['status'], first_frame_seconds=capture['first_frame_seconds'],
        first_frame_passed=capture.get('boot_scanout_replaced', False),
        image_sha256=capture['image_sha256'], serial_sha256=capture['serial_sha256'],
        producers=os_x86.producer_sources(__file__))
    pc.write_json(output / 'time-result.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'producers'}, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
