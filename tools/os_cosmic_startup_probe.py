"""Check COSMIC's 45-second boot-scanout replacement, with real guest pixels.

This narrow diagnostic is also runnable against a manifest-bound historical
image. It does not validate that historical source against today's checkout,
nor establish a semantic desktop frame, session readiness or reclamation.
"""
import argparse
import hashlib
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

FIRST_FRAME_SECONDS = 45
WIDTH, HEIGHT = 1024, 768


def scanout_evidence(raw):
    header, dimensions, maximum, pixels = raw.split(b'\n', 3)
    pc.require((header, dimensions, maximum) == (b'P6', b'1024 768', b'255'),
               'unexpected VirtIO scanout format')
    pc.require(len(pixels) == WIDTH * HEIGHT * 3, 'truncated or oversized scanout')
    colors = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
              (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
    expected = b''.join(bytes(rgb) * 128 for rgb in colors) * HEIGHT
    unchanged = sum(pixels[i:i+3] == expected[i:i+3] for i in range(0, len(pixels), 3))
    return dict(boot_pixels_remaining=unchanged, pixels=WIDTH * HEIGHT,
                scanout_sha256=hashlib.sha256(raw).hexdigest(),
                boot_scanout_replaced=unchanged < WIDTH * HEIGHT // 20)


def main(after_observation=None):
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--direct', action='store_true')
    parser.add_argument('--no-bus', action='store_true')
    parser.add_argument('--inspect-bus', action='store_true',
                        help='Query real bus names after the unchanged first-frame capture')
    parser.add_argument('--observe-seconds', type=float, default=FIRST_FRAME_SECONDS,
                        help='Optional later diagnostic; the first-frame gate stays fixed at 45 seconds')
    args = parser.parse_args()
    if args.no_bus and not args.direct:
        parser.error('--no-bus is only a compositor isolation scenario; use --direct')
    if args.no_bus and args.inspect_bus:
        parser.error('--inspect-bus requires the real session bus')
    if not FIRST_FRAME_SECONDS <= args.observe_seconds <= 180:
        parser.error('--observe-seconds must be between 45 and 180')
    args.output.mkdir(parents=True, exist_ok=False)
    image = args.build / 'boot.bin'
    manifest_path = args.build / 'build-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    image_sha256 = pc.sha(image)
    pc.require(manifest['status'] == 'BUILT_NOT_RUN'
               and image_sha256 == manifest['artifacts']['boot.bin'],
               'historical image identity mismatch')
    result = dict(status='FAIL', image_sha256=image_sha256, normal_session=not args.direct,
                  build_manifest_sha256=pc.sha(manifest_path),
                  producer_sha256=pc.sha(Path(__file__)),
                  session_bus=not args.no_bus, first_frame_seconds=FIRST_FRAME_SECONDS,
                  semantic_frame_verified=False,
                  full_os_verified=False, cosmic_session_verified=False)
    process = None
    qmp = None
    with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-start-') as tmp:
        idle_native_host()
        tmp = Path(tmp)
        disk = create_disk(args.output / 'data.raw')
        argv = os_x86.launch_argv(pc.executable('qemu-system-x86_64'), image,
                                 disk=disk, qmp=tmp / 'q.sock')
        i = argv.index('-serial')
        argv[i:i+2] = ['-chardev', f'socket,id=osconsole,path={tmp / "s.sock"},server=on,wait=on',
                       '-serial', 'chardev:osconsole']
        with (args.output / 'qemu-stderr.log').open('wb') as err:
            try:
                process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=err, env=pc.env())
                console = os_smoke.Console(os_smoke.connect(tmp / 's.sock', process), process,
                                           args.output / 'serial.raw')
                qmp = Qmp(os_smoke.connect(tmp / 'q.sock', process))
                qmp.receive(time.monotonic() + 10)
                qmp.execute('qmp_capabilities')
                console.until(os_smoke.PROMPT, timeout=90)
                if not args.no_bus:
                    console.command('posix exec dbus-daemon')
                    console.until(rb'unix:path=/run/user/0/bus,guid=', timeout=10)
                started = time.monotonic()
                console.command('posix exec ' + ('cosmic-comp' if args.direct else 'cosmic-session'))
                while time.monotonic() - started < FIRST_FRAME_SECONDS:
                    console.pump()
                    time.sleep(.02)
                result['gate_elapsed_seconds'] = round(time.monotonic() - started, 3)
                qmp.execute('stop')
                ppm = (args.output / 'gate.ppm').resolve()
                qmp.execute('screendump', {'filename': str(ppm)})
                result.update(scanout_evidence(ppm.read_bytes()))
                # Necessary first-frame diagnostic, not semantic desktop acceptance.
                result['status'] = 'PASS' if result['boot_scanout_replaced'] else 'FAIL'
                qmp.execute('cont')
                if args.inspect_bus:
                    at = console.command('posix exec dbus-send')
                    pid = console.until(rb'ELF pid=(\d+) started;', at, timeout=10).group(1)
                    console.until(rb'USER pid=' + pid + rb' Exited code=0\b', at, timeout=20)
                    result['bus_inspection'] = dict(
                        elapsed_seconds=round(time.monotonic() - started, 3),
                        notifications_name_present=b'"org.freedesktop.Notifications"' in console.raw[at:])
                if args.observe_seconds > FIRST_FRAME_SECONDS:
                    while time.monotonic() - started < args.observe_seconds:
                        console.pump()
                        time.sleep(.02)
                    qmp.execute('stop')
                    late = (args.output / 'later.ppm').resolve()
                    qmp.execute('screendump', {'filename': str(late)})
                    result['later_diagnostic'] = dict(
                        observed_seconds=round(time.monotonic() - started, 3),
                        **scanout_evidence(late.read_bytes()))
                    # A late frame cannot change the original 45-second verdict.
                    qmp.execute('cont')
                if after_observation is not None:
                    result['applet_diagnostic'] = after_observation(console, qmp, args.output)
                    if result['applet_diagnostic']['status'] != 'PASS':
                        result['status'] = 'FAIL'
                console.command('posix list')
                console.command('ai status')
                for _ in range(10):
                    console.pump()
                    time.sleep(.01)
                pc.write_json(args.output / 'commands.json', console.commands)
                result['serial_sha256'] = pc.sha(args.output / 'serial.raw')
                result['serial_bytes'] = len(console.raw)
                qmp.execute('quit')
                process.wait(timeout=10)
                result['qemu_exit_code'] = process.returncode
            except Exception as error:
                result['status'] = 'FAIL'
                result['error'] = str(error)
                # Failure can be recognized halfway through a UART chunk while
                # nested service loggers are still forwarding the panic. Keep
                # the verdict red and collect its bounded diagnostic tail.
                if 'console' in locals() and process is not None and process.poll() is None:
                    draining = time.monotonic() + 2
                    while time.monotonic() < draining:
                        try:
                            console.pump(require_running=False)
                        except (ValueError, OSError):
                            pass
                        time.sleep(.01)
                # Preserve the failing verdict even if a useful partial or late
                # frame exists. A user-process panic is distinct from scanout.
                if qmp is not None and process is not None and process.poll() is None:
                    try:
                        qmp.execute('stop')
                        failure_ppm = (args.output / 'failure.ppm').resolve()
                        qmp.execute('screendump', {'filename': str(failure_ppm)})
                        result['failure_scanout'] = scanout_evidence(failure_ppm.read_bytes())
                        qmp.execute('quit')
                        process.wait(timeout=10)
                        result['qemu_exit_code'] = process.returncode
                    except Exception as capture_error:
                        result['failure_capture_error'] = str(capture_error)
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    serial = args.output / 'serial.raw'
    if serial.is_file():
        result['serial_sha256'] = pc.sha(serial)
        result['serial_bytes'] = serial.stat().st_size
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
