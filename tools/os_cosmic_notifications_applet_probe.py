#!/usr/bin/env python3
"""Use the guest's real D-Bus service and pointer to exercise Notification Center."""
import argparse
from pathlib import Path
import re
import sys
import time

import os_cosmic_pointer_probe as pointer
import os_cosmic_startup_probe as startup
import os_cosmic_time_probe as clock
import os_x86

pc = os_x86.pc
INTERACTION_SECONDS = 15
POPUP_BOUNDS = (580, 46, 1024, 432)


def interaction(console, qmp, output, *, bell_x, clear_x, clear_y):
    result = dict(status='FAIL', captures={})
    position = (0, 0)

    def snapshot(name):
        path = output / (name + '.ppm')
        qmp.execute('screendump', {'filename': str(path.resolve())})
        return path

    def capture_when(name, observe, predicate):
        started = time.monotonic()
        while True:
            console.pump()
            path = snapshot(name)
            value = observe(path)
            elapsed = time.monotonic() - started
            ready = predicate(value)
            if ready or elapsed >= INTERACTION_SECONDS:
                result['captures'][name] = dict(sha256=pc.sha(path), value=value,
                                                seconds=round(elapsed, 3))
                pc.require(ready and elapsed <= INTERACTION_SECONDS, name + ' did not settle before deadline')
                return value
            time.sleep(.2)

    def click(name, x, y):
        nonlocal position
        events = [dict(type='rel', data=dict(axis=axis, value=delta))
                  for axis, delta in (('x', x - position[0]), ('y', y - position[1])) if delta]
        if events:
            qmp.execute('input-send-event', {'events': events})
            position = (x, y)
            capture_when(name + '-pointer', lambda path: pointer.cursor_ink(pointer.pixels(path), position),
                         lambda pixels: pixels >= 90)
        for down in (True, False):
            qmp.execute('input-send-event', {'events': [
                dict(type='btn', data=dict(button='left', down=down))]})
            if down:
                time.sleep(.15)
        result.setdefault('clicks', {})[name] = [x, y]

    def active_processes():
        at = console.command('posix list')
        rows = re.findall(rb'UserStatus \{ pid: (\d+), parent_pid: (\d+),[^\r\n]*?'
                          rb'state: (?:Running|Waiting), code: 0,', console.raw[at:])
        return {int(pid): int(parent) for pid, parent in rows}

    def popup_ink(path):
        return clock.ink(path.read_bytes(), POPUP_BOUNDS)

    def shared_snapshot():
        at = len(console.raw)
        snapshot = clock.shared_state(console, compact=True)
        denied = re.search(rb'^AI_DOMAIN name=shared_objects [^\r\n]*\bdenied=(\d+)\b',
                           console.raw[at:], re.MULTILINE)
        pc.require(denied is not None, 'Missing real shared-object admission counters')
        return dict(snapshot, object_denials=int(denied[1]))

    try:
        ram = qmp.execute('query-memory-size-summary')['base-memory']
        cpus = len(qmp.execute('query-cpus-fast'))
        pc.require((ram, cpus) == (1024**3, 4), 'Expected the actual one-GiB four-core guest')
        result.update(ram_mib=ram // 1024**2, cpus=cpus)
        active = active_processes()
        result['initial_processes'] = active
        pc.require({1, 2, 3, 4, 5, 6} <= active.keys(), 'Stock COSMIC core is not running')
        result['shared_before_popup'] = shared_snapshot()
        initial = popup_ink(snapshot('notifications-closed'))
        click('open', bell_x, 18)
        empty = capture_when('notifications-empty', popup_ink, lambda pixels: pixels > initial + 160)

        result['shared_before_notify'] = shared_snapshot()
        at = console.command('posix exec notification-probe')
        created = console.until(rb'NOTIFICATION_PROBE CREATED id=([1-9]\d*) service_pid=(\d+) '
                                rb'capture_ms=0 render_verified=false', at, timeout=15)
        identified = console.until(rb'NOTIFICATION_PROBE OWNER PASS unique=:\d+\.\d+ '
                                    rb'service_pid=(\d+) client_pid=(\d+)', at, timeout=5)
        notification, service = created.groups()
        client = identified[2]
        pc.require(identified[1] == service and client != service and active.get(int(service)) == 2,
                   'Notification was not sent to the running session daemon')
        result.update(notification_id=int(notification), daemon_pid=int(service), sender_pid=int(client))
        try:
            capture_when('notification-visible', popup_ink, lambda pixels: pixels > empty + 300)
        finally:
            result['shared_after_notify'] = shared_snapshot()

        click('clear', clear_x, clear_y)
        console.until(rb'NOTIFICATION_PROBE CLOSED id=' + notification + rb' service_pid=' + service +
                      rb' reason=3\b', at, timeout=INTERACTION_SECONDS)
        console.until(rb'NOTIFICATION_PROBE PASS service_pid=' + service + rb' id=' + notification + rb'\b',
                      at, timeout=5)
        console.until(rb'USER pid=' + client + rb' Exited code=0\b', at, timeout=5)
        capture_when('notifications-cleared', popup_ink, lambda pixels: abs(pixels - empty) <= 180)

        click('close', bell_x, 18)
        capture_when('notifications-closed-again', popup_ink, lambda pixels: abs(pixels - initial) <= 20)
        before, after = result['shared_before_popup'], shared_snapshot()
        result['shared_after_close'] = after
        pc.require(after['object_denials'] == before['object_denials'],
                   'A shared object allocation was denied during the interaction')
        pc.require(all(after[key] <= before[key] for key in ('objects', 'mappings', 'grant_used')),
                   'Shared resources did not recover after closing the notification center')
        result['final_processes'] = active_processes()
        pc.require(result['final_processes'] == active, 'The normal session processes changed during the test')
        result['status'] = 'PASS'
        return result
    finally:
        pc.write_json(output / 'notifications-applet-result.json', result)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--bell-x', type=int, default=1004)
    parser.add_argument('--clear-x', type=int, default=975)
    parser.add_argument('--clear-y', type=int, default=177)
    args, remaining = parser.parse_known_args()
    if args.build is not None:
        manifest = os_x86.validate_build(args.build)
        pc.require('cosmic-notifications-applet-v1' in manifest['features']
                   and {'cosmic-applet-notifications.elf', 'notification-probe.elf'}
                       <= manifest['external_inputs'].keys(),
                   'Use the notification center catalog with the real D-Bus probe installed')
        remaining += ['--build', str(args.build)]
    if '--direct' in remaining or '--no-bus' in remaining:
        parser.error('The notification center requires the regular COSMIC session and bus')
    sys.argv = [sys.argv[0], *remaining]
    return startup.main(after_observation=lambda *values: interaction(
        *values, bell_x=args.bell_x, clear_x=args.clear_x, clear_y=args.clear_y))


if __name__ == '__main__':
    raise SystemExit(main())
