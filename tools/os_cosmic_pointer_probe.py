#!/usr/bin/env python3
"""Measure real guest pointer motion with actual input and scanout pixels.

Uses the clock-enabled normal session on an otherwise empty background.
No compositor, cursor, timing, or input-queue implementation is substituted.
"""
import json
from pathlib import Path
import sys
import time

import os_cosmic_startup_probe as startup
import os_x86
import x86_64 as pc

WIDTH, HEIGHT = 1024, 768
DEADLINE_SECONDS = .5
OBSERVE_SECONDS = 15
# The pinned native cursor has 140 white pixels away from a screen edge. A
# partially scanned cursor (71 pixels in a baseline capture) is not completion.
COMPLETE_CURSOR_PIXELS = 140
BRIGHT = bytes(int(i >= 200) for i in range(256))


def pixels(path):
    parts = path.read_bytes().split(b'\n', 3)
    pc.require(parts[:3] == [b'P6', b'1024 768', b'255']
               and len(parts[3]) == WIDTH * HEIGHT * 3, 'unexpected pointer scanout')
    return parts[3]


def cursor_ink(data, position):
    x, y = position
    return sum(min(data[at:at + 3]) >= 200
               for row in range(max(0, y - 2), min(HEIGHT, y + 32))
               for col in range(max(0, x - 2), min(WIDTH, x + 24))
               for at in (3 * (row * WIDTH + col),))


def lower_bright_pixels(data):
    # The initial session has no bright content below its top panel except the
    # software cursor. Extra old/burst cursors must not count as completed motion.
    return data[3 * WIDTH * 80 + 2::3].translate(BRIGHT).count(1)


def pointer_motion(console, qmp, output):
    result = dict(status='FAIL', scope='real_pointer_input_to_pixels_on_empty_background',
                  deadline_seconds=DEADLINE_SECONDS, samples=[],
                  complete_cursor_pixels=COMPLETE_CURSOR_PIXELS,
                  full_os_verified=False, cosmic_session_verified=False,
                  semantic_frame_verified=False)
    before = output / 'pointer-before.ppm'
    qmp.execute('screendump', {'filename': str(before.resolve())})
    initial = pixels(before)
    result['before_sha256'] = pc.sha(before)
    result['initial_cursor_pixels'] = cursor_ink(initial, (0, 0))
    result['initial_lower_bright_pixels'] = lower_bright_pixels(initial)
    pc.require(result['initial_cursor_pixels'] >= 8
               and result['initial_lower_bright_pixels'] == 0,
               'pointer measurement requires the original origin cursor and empty lower background')
    console.command('posix list')
    position = (0, 0)
    actions = [
        ('move-right-down', (256, 192), 1, 0),
        ('move-right', (640, 192), 1, 0),
        ('move-down', (640, 512), 1, 0),
        ('motion-burst', (832, 512), 24, 0),
        ('motion-stream-left', (448, 512), 96, .005),
    ]
    for name, target, packets, interval in actions:
        path = output / (name + '.ppm')
        dx, dy = target[0] - position[0], target[1] - position[1]
        started = time.monotonic()
        for i in range(packets):
            events = []
            for axis, delta in [('x', dx), ('y', dy)]:
                part = (delta * (i + 1) // packets) - (delta * i // packets)
                if part:
                    events.append({'type': 'rel', 'data': {'axis': axis, 'value': part}})
            qmp.execute('input-send-event', {'events': events})
            if interval and i + 1 < packets:
                time.sleep(interval)
        accepted = time.monotonic()
        matched = False
        count = 0
        while time.monotonic() - started < OBSERVE_SECONDS:
            console.pump()
            qmp.execute('screendump', {'filename': str(path.resolve())})
            data = pixels(path)
            current_ink = cursor_ink(data, target)
            old_ink = cursor_ink(data, position)
            bright = lower_bright_pixels(data)
            count += 1
            matched = (current_ink >= COMPLETE_CURSOR_PIXELS and old_ink <= 2
                       and bright <= current_ink + 4)
            if matched:
                break
            time.sleep(.05)
        elapsed = time.monotonic() - started
        # For a paced stream, measure settling after its final input. Ordinary
        # single moves and the unpaced burst retain the original first-input
        # deadline. Both durations are retained so the distinction is explicit.
        origin = accepted if interval else started
        latency = time.monotonic() - origin
        result['samples'].append(dict(name=name, start=position, target=target,
            packets=packets, matched=matched, elapsed_seconds=round(elapsed, 6),
            latency_seconds=round(latency, 6),
            deadline_origin='last_input_ack' if interval else 'first_input',
            packet_interval_seconds=interval,
            input_ack_seconds=round(accepted - started, 6),
            after_last_ack_seconds=round(time.monotonic() - accepted, 6),
            within_deadline=matched and latency <= DEADLINE_SECONDS,
            target_pixels=current_ink, old_pixels=old_ink, lower_bright_pixels=bright,
            captures=count, sha256=pc.sha(path)))
        if not matched:
            break
        position = target
    console.command('posix list')
    result['all_moves_within_deadline'] = len(result['samples']) == len(actions) and all(
        row['within_deadline'] for row in result['samples'])
    result['all_targets_matched'] = len(result['samples']) == len(actions) and all(
        row['matched'] for row in result['samples'])
    result['status'] = 'PASS' if result['all_moves_within_deadline'] else 'FAIL'
    pc.write_json(output / 'pointer-qmp.json', qmp.transcript)
    pc.write_json(output / 'pointer-measurements.json', result)
    return result


def main():
    startup.main(after_observation=pointer_motion)
    output = Path(sys.argv[sys.argv.index('--output') + 1])
    capture = pc.read_json(output / 'result.json')
    result = dict(capture.get('applet_diagnostic', {'status': 'FAIL'}),
        startup_status=capture['status'], image_sha256=capture['image_sha256'],
        serial_sha256=capture['serial_sha256'],
        error=capture.get('error'), producers=os_x86.producer_sources(__file__))
    pc.write_json(output / 'pointer-result.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'producers'}, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
