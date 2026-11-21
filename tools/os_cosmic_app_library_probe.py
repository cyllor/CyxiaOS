#!/usr/bin/env python3
"""Open the session's application library, search, then launch a real Wayland client."""
import argparse
from pathlib import Path
import re
import sys
import time

import os_cosmic_bg_probe as background
import os_cosmic_pointer_probe as pointer
import os_cosmic_startup_probe as startup
import os_cosmic_time_probe as clock
import os_x86

pc = os_x86.pc
APP_ID = b'com.system76.CosmicAppLibrary'
OBSERVATION_SECONDS = 45
SPAWN_RECEIPT = (rb'^SPAWN_CHILD pid,parent [^\r\n]+\r?\n'
                 rb'([0-9a-f]{16})\r?\n([0-9a-f]{16})\b')
SAMPLES = tuple(3 * (y * pointer.WIDTH + x)
                for y in range(160, 640, 4) for x in range(180, 860, 4))
TILES = tuple(tuple(3 * (y * pointer.WIDTH + x)
                    for y in range(165, 240, 3) for x in range(left, right, 3))
              for left, right in ((88, 165), (222, 300)))


def difference(before, after, offsets=SAMPLES):
    return sum(max(abs(before[at + channel] - after[at + channel]) for channel in range(3)) > 12
               for at in offsets)


def search_focus(frame):
    return sum(red < 145 and green > 155 and blue > 165
               for y in range(75, 116) for x in range(310, 714, 3)
               for at in (3 * (y * pointer.WIDTH + x),)
               for red, green, blue in (frame[at:at + 3],))


def checkered_window(frame):
    # The fixture commits a 160 by 100 buffer with 20-pixel alternating tiles.
    return min(frame.count(bytes((0x30, 0x60, 0x80))), frame.count(bytes((0x80, 0xb0, 0xd0))))


def key(qmp, code):
    # Keep a real press/release pair in one input report so a slow frame
    # between host commands cannot turn the tap into guest key repeat.
    qmp.execute('input-send-event', {'events': [
        dict(type='key', data=dict(key=dict(type='qcode', data=code), down=down))
        for down in (True, False)]})


def object_snapshot(console):
    start = len(console.raw)
    shared = clock.shared_state(console)
    raw = console.raw[start:]
    pool = re.search(rb'^PIPE_POOL capacity=(\d+) unavailable=(\d+) free=(\d+)', raw, re.MULTILINE)
    denied = re.search(rb'^AI_DOMAIN name=pipe [^\r\n]*?\bdenied=(\d+)', raw, re.MULTILINE)
    pc.require(pool is not None and denied is not None, 'Missing the guest pipe admission snapshot')
    capacity, used, free = map(int, pool.groups())
    return shared, dict(capacity=capacity, used=used, free=free, denied=int(denied[1]))


def interaction(console, qmp, output):
    result = dict(status='FAIL', frames={})

    def snapshot(name):
        path = output / (name + '.ppm')
        qmp.execute('screendump', {'filename': str(path.resolve())})
        return path

    def capture(name, metric, matches):
        started = time.monotonic()
        while True:
            console.pump()
            path = snapshot(name)
            frame = pointer.pixels(path)
            score = metric(frame)
            elapsed = time.monotonic() - started
            if matches(score) or elapsed >= OBSERVATION_SECONDS:
                result['frames'][name] = dict(sha256=pc.sha(path), metric=score, seconds=round(elapsed, 3))
                pc.require(matches(score) and elapsed <= OBSERVATION_SECONDS,
                           f'{name} did not reach the expected frame within {OBSERVATION_SECONDS}s')
                return frame
            time.sleep(.2)

    def activate():
        # A second invocation forwards Activate over the real session bus,
        # then exits while the application owned by cosmic-session renders.
        console.program('posix exec cosmic-app-library')

    try:
        ram = qmp.execute('query-memory-size-summary')['base-memory']
        cpus = len(qmp.execute('query-cpus-fast'))
        pc.require((ram, cpus) == (1024**3, 4), 'Expected the actual one-GiB four-core guest')
        result.update(ram_mib=ram // 1024**2, cpus=cpus)
        app_start = re.search(rb"starting process '[^\r\n]* cosmic-app-library ", console.raw)
        pc.require(app_start is not None,
                   'The normal COSMIC session did not start the application library')
        app_receipt = re.search(SPAWN_RECEIPT, console.raw[app_start.end():], re.MULTILINE)
        pc.require(app_receipt is not None, 'Missing the application library process receipt')
        library_pid, session_pid = (int(field, 16) for field in app_receipt.groups())
        console.program('posix exec dbus-send', b'"' + APP_ID + b'"')
        console.program('posix exec app-library-fixture', b'APP_LIBRARY_FIXTURE READY')
        console.command('cat /.local/share/applications/cyxia-birch.desktop',
                        [rb'Name=Birch Workspace', rb'Exec=workspace-window-probe --app-library\r?\n'])
        original = background.processes(console)
        result['initial_processes'] = original
        pc.require(original.get(library_pid) == session_pid and original.get(session_pid) == 0
                   and sum(parent == 6 for parent in original.values()) == 4,
                   'Expected the original session application library and four panel applets')
        result['library_pid'] = library_pid
        result['initial_shared'], result['initial_pipes'] = object_snapshot(console)
        pc.require(result['initial_pipes']['capacity'] == 40 and result['initial_pipes']['denied'] == 0,
                   'The guest did not admit the complete desktop pipe workload')
        desktop = pointer.pixels(snapshot('desktop'))
        activate()
        library = capture('library-open', lambda frame: difference(desktop, frame), lambda samples: samples > 19000)
        capture('search-focused', search_focus, lambda pixels: pixels > 100)

        def visible_tiles(frame):
            return [difference(library, frame, offsets) for offsets in TILES]

        # Both entries match "b". Only Birch Workspace matches "bi".
        key(qmp, 'b')
        capture('search-two-results', visible_tiles, lambda scores: min(scores) >= 70)
        key(qmp, 'i')
        capture('library-search', visible_tiles, lambda scores: scores[0] >= 70 and scores[1] < 8)
        launch_start = len(console.raw)
        key(qmp, 'ret')
        receipt = console.until(SPAWN_RECEIPT, launch_start, timeout=OBSERVATION_SECONDS)
        child, parent = (int(field, 16) for field in receipt.groups())
        pc.require(parent == library_pid and child not in original,
                   'The test window must be spawned by the session application library')
        result['launched'] = dict(program='workspace-window-probe', pid=child, parent_pid=parent)

        def window_pixels(frame):
            exit_status = re.search(rb'USER pid=' + str(child).encode() + rb' (\w+) code=(\d+)\b',
                                    console.raw[launch_start:])
            if exit_status:
                result['child_exit'] = dict(state=exit_status[1].decode(), code=int(exit_status[2]))
                raise ValueError('The launched Wayland client stopped before its window was visible')
            return checkered_window(frame)

        try:
            capture('application-started', window_pixels, lambda pixels: pixels >= 6000)
        except ValueError:
            console.command('ai system')
            raise
        with_child = background.processes(console)
        pc.require(with_child.get(child) == parent
                   and {pid: with_child.get(pid) for pid in original} == original,
                   'An existing COSMIC session process exited during the launch')
        console.command(f'posix kill {child}', [rb'killed; pages reclaimed'])
        capture('workspace-restored', lambda frame: difference(desktop, frame), lambda samples: samples < 24)
        activate()
        capture('library-reopened', lambda frame: difference(desktop, frame), lambda samples: samples > 19000)
        capture('search-focused-again', search_focus, lambda pixels: pixels > 100)
        key(qmp, 'esc')
        capture('library-dismissed', lambda frame: difference(desktop, frame), lambda samples: samples < 24)
        result['final_processes'] = background.processes(console)
        pc.require(child not in result['final_processes']
                   and {pid: result['final_processes'].get(pid) for pid in original} == original,
                   'An existing session component or the test window did not reach its expected state')
        result['final_shared'], result['final_pipes'] = object_snapshot(console)
        pc.require(result['final_pipes']['denied'] == 0
                   and result['final_pipes']['used'] <= result['initial_pipes']['used'],
                   'Application launch left pipes allocated or hit the guest admission limit')
        result['status'] = 'PASS'
        return result
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        pc.write_json(output / 'application-library-result.json', result)
        pc.write_json(output / 'application-library-qmp.json', qmp.transcript)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--build', required=True, type=Path)
    args, rest = parser.parse_known_args()
    manifest = os_x86.validate_build(args.build)
    pc.require('cosmic-app-library-v1' in manifest['features']
               and {'cosmic-app-library.elf', 'app-library-fixture.elf'} <= manifest['external_inputs'].keys(),
               'Expected the application library and the optional guest fixture')
    if '--direct' in rest or '--no-bus' in rest:
        parser.error('The application library regression requires the normal COSMIC session')
    sys.argv = [sys.argv[0], '--build', str(args.build), *rest]
    producers = os_x86.producer_sources(__file__)

    def check(console, qmp, output):
        result = interaction(console, qmp, output)
        pc.require(os_x86.producer_sources(__file__) == producers,
                   'Application library probe changed during capture')
        pc.write_json(output / 'application-library-producers.json', producers)
        return result

    return startup.main(after_observation=check)


if __name__ == '__main__':
    raise SystemExit(main())
