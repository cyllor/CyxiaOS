#!/usr/bin/env python3
"""Run a genuine panel-SDK EGL client against the actual COSMIC compositor."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

import os_smoke
import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from run_qemu import Qmp
from storage import create_disk


def pixels(raw):
    header = raw.split(b'\n', 3)
    pc.require(header[:3] == [b'P6', b'1024 768', b'255'] and len(header[3]) == 1024 * 768 * 3,
               'Unexpected actual scanout')
    data = header[3]
    red = sum(data[3 * (y * 1024 + x):3 * (y * 1024 + x) + 3] == b'\xff\0\0'
              for y in range(712, 760) for x in range(8, 56))
    green = sum(data[3 * (y * 1024 + x):3 * (y * 1024 + x) + 3] == b'\0\xff\0'
                for y in range(712, 760) for x in range(72, 120))
    return dict(red_pixels=red, green_pixels=green, expected_each=2304,
                matched=red == green == 2304)


def run(build, output):
    output.mkdir(parents=True, exist_ok=False)
    manifest = pc.read_json(build / 'build-manifest.json')
    image = build / 'boot.bin'
    pc.require(manifest['status'] == 'BUILT_NOT_RUN'
               and pc.sha(image) == manifest['artifacts']['boot.bin'], 'EGL probe image changed')
    result = dict(status='FAIL', scope='actual_wayland_egl_layer_surface_and_scanout',
                  image_sha256=pc.sha(image), producers=os_x86.producer_sources(__file__),
                  semantic_frame_verified=False, full_os_verified=False, cosmic_session_verified=False)
    process = console = qmp = None
    with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-wl-egl-') as temporary:
        idle_native_host()
        control = Path(temporary).resolve()
        argv = os_x86.launch_argv(pc.executable('qemu-system-x86_64'), image,
                                 disk=create_disk(output / 'data.raw'), qmp=control / 'q.sock')
        index = argv.index('-serial')
        argv[index:index + 2] = ['-chardev', f'socket,id=console,path={control / "s.sock"},server=on,wait=on',
                                '-serial', 'chardev:console']
        with (output / 'qemu-stderr.log').open('wb') as errors:
            try:
                process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors, env=pc.env())
                console = os_smoke.Console(os_smoke.connect(control / 's.sock', process), process,
                                           output / 'serial.raw')
                qmp = Qmp(os_smoke.connect(control / 'q.sock', process))
                qmp.receive(time.monotonic() + 10)
                qmp.execute('qmp_capabilities')
                console.until(os_smoke.PROMPT, timeout=60)
                console.command('posix exec dbus-daemon')
                console.until(rb'unix:path=/run/user/0/bus,guid=', timeout=10)
                comp_at = console.command('posix exec cosmic-comp')
                comp_pid = console.until(rb'ELF pid=(\d+) started;', comp_at).group(1)
                result['compositor_pid'] = int(comp_pid)
                warming = time.monotonic()
                console.until(rb'CYXIA_COMP_PHASE_V1 pid=' + comp_pid
                              + rb' phase=first_full_scanout_complete ', comp_at, timeout=45)
                result['compositor_ready_seconds'] = round(time.monotonic() - warming, 3)
                started = time.monotonic()
                at = console.command('posix exec wayland-egl-probe')
                pid = console.until(rb'ELF pid=(\d+) started;', at).group(1)
                console.until(rb'WAYLAND_EGL_PROBE FRAME_READY\r?\n', at, timeout=30)
                for attempt in range(50):
                    frame = output / f'frame-{attempt}.ppm'
                    qmp.execute('screendump', {'filename': str(frame.resolve())})
                    actual = pixels(frame.read_bytes())
                    if actual['matched']:
                        result['scanout'] = dict(**actual, path=frame.name, sha256=pc.sha(frame))
                        break
                    console.pump()
                    time.sleep(.05)
                else:
                    result['scanout'] = actual
                    raise ValueError('Actual framebuffer has no expected EGL layer pixels')
                console.command('touch /egl-frame-captured')
                console.until(rb'WAYLAND_EGL_PROBE PASS\r?\n', at, timeout=10)
                console.until(rb'USER pid=' + pid + rb' Exited code=0\b', at, timeout=10)
                checks = ('CONNECTION', 'INITIALIZE', 'LAYER_CONFIGURE', 'WINDOW_CONTEXT', 'READBACK', 'SWAP')
                pc.require(all(('WAYLAND_EGL_PROBE ' + name + ' PASS').encode() in console.raw[at:]
                               for name in checks), 'Missing actual Wayland/EGL checks')
                result.update(status='PASS', probe_seconds=round(time.monotonic() - started, 3))
                result['checks'] = list(checks) + ['FRAME_CALLBACK', 'SCANOUT', 'CLEANUP']
            except Exception as error:
                result['error'] = str(error)
                if 'started' in locals():
                    result['probe_seconds'] = round(time.monotonic() - started, 3)
            finally:
                if console is not None:
                    for _ in range(10):
                        try:
                            console.pump(require_running=False)
                        except (ValueError, OSError):
                            pass
                        time.sleep(.01)
                    pc.write_json(output / 'commands.json', console.commands)
                    result['serial_sha256'] = pc.sha(output / 'serial.raw')
                    result['wayland_connected'] = b'WAYLAND_EGL_PROBE CONNECTION PASS' in console.raw
                    result['egl_initialized'] = b'WAYLAND_EGL_PROBE INITIALIZE PASS' in console.raw
                if qmp is not None and process.poll() is None:
                    try:
                        qmp.execute('stop')
                        qmp.execute('screendump', {'filename': str((output / 'scanout.ppm').resolve())})
                        qmp.execute('quit')
                        process.wait(timeout=10)
                        result['qemu_exit_code'] = process.returncode
                    except Exception as error:
                        result.update(status='FAIL', shutdown_error=str(error))
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    pc.write_json(output / 'result.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'producers'}, indent=2))
    return int(result['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run(args.build, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
