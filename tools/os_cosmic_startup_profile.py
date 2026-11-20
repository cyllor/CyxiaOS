"""Attribute startup stages to real tasks in the one-GiB COSMIC image.

Snapshots are diagnostic wall observations, not CPU billing or session acceptance.
No program, limit, startup dependency or timing deadline is replaced.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

import elf64
import os_smoke
import os_x86 as profile
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from run_qemu import Qmp
from storage import create_disk

PROGRAMS = ('dbus-daemon', 'cosmic-session', 'cosmic-comp', 'cosmic-settings-daemon',
            'cosmic-notifications', 'cosmic-panel', 'cosmic-applet-time')
SNAPSHOTS = (0, 5, 10, 15, 20, 30, 45, 60, 90, 120, 150, 180)


def image_identities(manifest):
    prefix = Path(manifest['sysroot'])
    result = {}
    for name in PROGRAMS:
        path = prefix / (name + '.elf')
        header = elf64.decode(path.read_bytes())
        pages = set()
        executable = []
        for segment in header['segments']:
            if segment['type'] != 1 or not segment['mem']:
                continue
            pages.update(range(segment['va'] // 4096,
                               (segment['va'] + segment['mem'] + 4095) // 4096))
            if segment['flags'] & 1:
                executable.append((segment['va'], segment['va'] + segment['mem']))
        result[name] = dict(sha256=manifest['external_inputs'][name + '.elf'],
                            image_pages=len(pages) + 512, executable_ranges=executable)
    return result


def statuses(raw, identities):
    result = []
    for line in re.findall(rb'EL0 UserStatus \{ ([^\r\n]+)\}', raw):
        fields = {k.decode(): int(v) for k, v in re.findall(rb'\b(\w+): (\d+)', line)}
        state = re.search(rb'\bstate: (\w+)', line)
        fields['state'] = state[1].decode() if state else 'unknown'
        matches = [name for name, image in identities.items()
                   if image['image_pages'] == fields.get('image_pages')]
        fields['program'] = matches[0] if len(matches) == 1 else None
        if fields['program'] and fields.get('observed_pc', 0):
            fields['pc_in_executable'] = any(a <= fields['observed_pc'] < b
                for a, b in identities[fields['program']]['executable_ranges'])
        result.append(fields)
    return result


def scanout(path):
    parts = path.read_bytes().split(b'\n', 3)
    profile.pc.require(parts[:3] == [b'P6', b'1024 768', b'255']
                       and len(parts[3]) == 1024 * 768 * 3, 'Unexpected startup scanout')
    data = parts[3]
    clock = sum(min(data[p:p + 3]) > 140 for y in range(0, 64) for x in range(400, 624)
                for p in (3 * (1024 * y + x),))
    # Sparse dark-background milestone, separate from any semantic frame claim.
    dark = sum(max(data[p:p + 3]) < 100 for y in range(96, 768, 48) for x in range(32, 1024, 64)
               for p in (3 * (1024 * y + x),))
    return dict(clock_glyph_pixels=clock, background_candidate=dark >= 14 * 16 * .95)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('session', 'direct'), default='session')
    parser.add_argument('--no-status', action='store_true')
    args = parser.parse_args()
    pc = profile.pc
    process = None
    result = dict(status='INCOMPLETE', mode=args.mode, snapshots=[], frames=[], milestones={},
                  cpu_time_claim=False, full_os_verified=False, cosmic_session_verified=False)
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        manifest = profile.validate_build(args.build)
        identities = image_identities(manifest)
        output = pc.fresh_output(args.output)
        result.update(image_sha256=manifest['artifacts']['boot.bin'], programs=identities,
                      producers=profile.producer_sources(__file__), status_sampling=not args.no_status)
        disk = create_disk(output / 'data.raw')
        with tempfile.TemporaryDirectory(prefix='cyx-start-prof-') as temporary:
            temporary = Path(temporary)
            argv = profile.launch_argv(pc.executable('qemu-system-x86_64'), args.build / 'boot.bin',
                                       disk=disk, qmp=temporary / 'q.sock')
            at = argv.index('-serial')
            argv[at:at + 2] = ['-chardev', f'socket,id=osconsole,path={temporary / "s.sock"},server=on,wait=on',
                               '-serial', 'chardev:osconsole']
            pc.write_json(output / 'launch.json', argv)
            with (output / 'qemu-stderr.log').open('wb') as stderr:
                launched = time.monotonic()
                try:
                    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=stderr, env=pc.env())
                    console = os_smoke.Console(os_smoke.connect(temporary / 's.sock', process),
                                               process, output / 'serial.raw')
                    qmp = Qmp(os_smoke.connect(temporary / 'q.sock', process))
                    qmp.receive(time.monotonic() + 10)
                    qmp.execute('qmp_capabilities')
                    result['memory'] = qmp.execute('query-memory-size-summary')
                    pc.require(result['memory'] == {'base-memory': 1 << 30, 'plugged-memory': 0},
                               'Startup regression requires exactly one GiB')
                    console.until(os_smoke.PROMPT, timeout=90)
                    result['boot_to_prompt_seconds'] = time.monotonic() - launched
                    bus = time.monotonic()
                    console.command('posix exec dbus-daemon')
                    console.until(rb'unix:path=/run/user/0/bus,guid=', timeout=15)
                    result['bus_ready_seconds'] = time.monotonic() - bus
                    started = time.monotonic()
                    command = 'posix exec ' + ('cosmic-session' if args.mode == 'session' else 'cosmic-comp')
                    console.command(command)
                    next_snapshot = next_frame = 0
                    clock_count = 0
                    finish = 180.0
                    while time.monotonic() - started < finish:
                        console.pump()
                        elapsed = time.monotonic() - started
                        if not args.no_status and next_snapshot < len(SNAPSHOTS) and elapsed >= SNAPSHOTS[next_snapshot]:
                            began = time.monotonic()
                            offset = console.command('posix list')
                            rows = statuses(console.raw[offset:], identities)
                            pc.require(bool(rows), 'Missing actual process status rows')
                            result['snapshots'].append(dict(at_seconds=began - started,
                                command_seconds=time.monotonic() - began, processes=rows))
                            next_snapshot += 1
                        if elapsed >= next_frame:
                            capture_start = time.monotonic()
                            path = output / f'frame-{len(result["frames"]):03}.ppm'
                            qmp.execute('screendump', {'filename': str(path.resolve())})
                            frame = dict(at_seconds=capture_start - started, path=path.name, **scanout(path))
                            result['frames'].append(frame)
                            if frame['background_candidate']:
                                result['milestones'].setdefault('background_first_candidate', frame['at_seconds'])
                            clock_count = clock_count + 1 if frame['clock_glyph_pixels'] >= 100 else 0
                            if clock_count == 1:
                                clock_first = frame['at_seconds']
                            if clock_count >= 2 and 'clock_confirmed' not in result['milestones']:
                                result['milestones'].update(clock_first_candidate=clock_first,
                                                            clock_confirmed=frame['at_seconds'])
                                finish = min(180, max(45, frame['at_seconds'] + 10))
                            next_frame = time.monotonic() - started + 2
                            if args.mode == 'direct' and frame['background_candidate']:
                                finish = min(finish, max(45, frame['at_seconds'] + 10))
                        time.sleep(.01)
                    offset = console.command('posix list')
                    result['snapshots'].append(dict(at_seconds=time.monotonic() - started,
                        command_seconds=None, processes=statuses(console.raw[offset:], identities)))
                    result['observed_seconds'] = time.monotonic() - started
                    result['status'] = ('CLOCK_OBSERVED' if 'clock_confirmed' in result['milestones'] else
                                        'BACKGROUND_ONLY' if args.mode == 'direct' and result['milestones'] else 'NO_CLOCK')
                    pc.write_json(output / 'commands.json', console.commands)
                    qmp.execute('quit')
                    process.wait(timeout=10)
                    pc.write_json(output / 'qmp.json', qmp.transcript)
                except Exception as error:
                    result.update(status='FAIL', error=repr(error))
                finally:
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                    result['serial_sha256'] = pc.sha(output / 'serial.raw')
                    pc.write_json(output / 'result.json', result)
    print(json.dumps({k: v for k, v in result.items() if k not in ('programs', 'snapshots', 'frames', 'producers')}))
    return int(result['status'] == 'FAIL')


if __name__ == '__main__':
    raise SystemExit(main())
