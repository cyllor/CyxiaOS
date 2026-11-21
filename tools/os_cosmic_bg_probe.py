#!/usr/bin/env python3
"""Exercise the session-started COSMIC wallpaper through its real config watch."""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import time

import os_cosmic_pointer_probe as pointer
import os_cosmic_startup_probe as startup
import os_cosmic_time_probe as clock
import os_x86

pc = os_x86.pc
CONFIG = '/.config/cosmic/com.system76.CosmicBackground/v1/all'
SOLID_RGB = (32, 64, 96)
GRADIENT = ('(output:"all",source:Color(Gradient((colors:[(0.125,0.25,0.375),(0.375,0.25,0.125)],'
            'radius:90.0))),filter_by_theme:false,rotation_frequency:3600)')
DEADLINE_SECONDS = 15


def write_background(console, settings):
    console.command('write ' + CONFIG + ' ' + settings)
    console.command('cat ' + CONFIG, [re.escape(settings.encode())])


def sample(path, solid_rgb):
    pixels = pointer.pixels(path)
    # Exclude the panel and the pointer origin. Use the same display coordinates
    # across all captures to distinguish the restored image from unrelated draws.
    columns = range(32, 992, 8)
    points = [pixels[at:at + 3] for y in range(80, 744, 8) for x in columns
              for at in (3 * (y * pointer.WIDTH + x),)]
    first = points[:len(columns)]
    colors = len(set(points))
    gradient = (colors >= 32 and first[0][0] < first[-1][0] and first[0][2] > first[-1][2]
                and all(rgb == first[index % len(columns)] for index, rgb in enumerate(points)))
    return dict(sha256=hashlib.sha256(b''.join(points)).hexdigest(),
                unique_colors=colors, horizontal_gradient=gradient,
                configured_color_pixels=sum(all(abs(value - expected) <= 2
                                                for value, expected in zip(rgb, solid_rgb))
                                            for rgb in points),
                sampled_pixels=len(points))


def capture_when(console, qmp, output, name, predicate, *, solid_rgb=SOLID_RGB):
    path = output / (name + '.ppm')
    started = time.monotonic()
    while True:
        console.pump()
        qmp.execute('screendump', {'filename': str(path.resolve())})
        profile = sample(path, solid_rgb)
        elapsed = time.monotonic() - started
        if predicate(profile) and elapsed <= DEADLINE_SECONDS:
            return dict(**profile, seconds=round(elapsed, 3), frame_sha256=pc.sha(path))
        if elapsed >= DEADLINE_SECONDS:
            raise TimeoutError(f'{name} was not drawn within {DEADLINE_SECONDS} seconds: {profile}')
        time.sleep(.2)


def solid_background(console, qmp, output, *, rgb=SOLID_RGB):
    normalized = tuple(channel / 255 for channel in rgb)
    write_background(console, f'(output:"all",source:Color(Single({normalized})),'
                              'filter_by_theme:false,rotation_frequency:3600)')
    return capture_when(console, qmp, output, 'solid',
                        lambda frame: frame['configured_color_pixels'] == frame['sampled_pixels'],
                        solid_rgb=rgb)


def processes(console):
    at = console.command('posix list')
    rows = re.findall(rb'UserStatus \{ pid: (\d+), parent_pid: (\d+),[^\r\n]*?'
                      rb'state: (?:Running|Waiting), code: 0,', console.raw[at:])
    return {int(pid): int(parent) for pid, parent in rows}


def interaction(console, qmp, output):
    result = dict(status='FAIL')
    try:
        ram = qmp.execute('query-memory-size-summary')['base-memory']
        cpus = len(qmp.execute('query-cpus-fast'))
        pc.require((ram, cpus) == (1024**3, 4), 'Expected the actual one-GiB four-core guest')
        result.update(ram_mib=ram // 1024**2, cpus=cpus)
        pc.require(re.search(rb"starting process '[^\r\n]* cosmic-bg ", console.raw) is not None,
                   'The normal COSMIC session did not launch the background program')
        before = processes(console)
        result['initial_processes'] = before
        result['initial_shared'] = clock.shared_state(console, compact=True)
        result['wallpaper'] = capture_when(console, qmp, output, 'wallpaper',
                                            lambda frame: frame['unique_colors'] >= 128)
        result['solid'] = solid_background(console, qmp, output)
        write_background(console, GRADIENT)
        result['gradient'] = capture_when(console, qmp, output, 'gradient',
                                            lambda frame: frame['horizontal_gradient'])
        console.command('rm ' + CONFIG)
        result['restored'] = capture_when(
            console, qmp, output, 'restored', lambda frame: frame['sha256'] == result['wallpaper']['sha256'])
        result['final_processes'] = processes(console)
        pc.require(result['final_processes'] == before, 'COSMIC restarted while reloading wallpaper')
        result['final_shared'] = clock.shared_state(console, compact=True)
        result['status'] = 'PASS'
        return result
    finally:
        pc.write_json(output / 'wallpaper-result.json', result)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--build', type=Path)
    args, remaining = parser.parse_known_args()
    if args.build is not None:
        manifest = os_x86.validate_build(args.build)
        pc.require(os_x86.WALLPAPER_FEATURES.intersection(manifest['features'])
                   and 'cosmic-bg.elf' in manifest['external_inputs'],
                   'Expected the catalog with the genuine COSMIC background binary')
        remaining += ['--build', str(args.build)]
    if '--direct' in remaining or '--no-bus' in remaining:
        parser.error('The wallpaper regression requires the normal COSMIC session')
    sys.argv = [sys.argv[0], *remaining]
    return startup.main(after_observation=interaction)


if __name__ == '__main__':
    raise SystemExit(main())
