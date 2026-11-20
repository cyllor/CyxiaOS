"""Open a verified two-GiB COSMIC image for manual mouse/keyboard testing."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import time

import os_smoke
import os_x86_2g as profile
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from run_qemu import Qmp
from storage import create_disk


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--display', choices=('cocoa', 'gtk', 'sdl'), default='cocoa')
    args = parser.parse_args()
    process = None
    pc = profile.pc
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        build = args.build.resolve()
        manifest = profile.validate_build(build)
        output = pc.fresh_output(args.output)
        disk = create_disk(output / 'data.raw')
        with tempfile.TemporaryDirectory(prefix='cyx-2g-') as temporary:
            temporary = Path(temporary)
            argv = profile.launch_argv(pc.executable('qemu-system-x86_64'), build / 'boot.bin',
                display=args.display, disk=disk, qmp=temporary / 'q.sock')
            at = argv.index('-serial')
            argv[at:at + 2] = ['-chardev',
                f'socket,id=osconsole,path={temporary / "s.sock"},server=on,wait=on',
                '-serial', 'chardev:osconsole']
            pc.write_json(output / 'launch.json', dict(argv=argv, build=str(build),
                ram_mib=2048, cpus=4, boot_sha256=manifest['artifacts']['boot.bin'],
                producers=profile.producer_sources(__file__)))
            with (output / 'qemu-stdout.log').open('wb') as stdout, (output / 'qemu-stderr.log').open('wb') as stderr:
                try:
                    process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=pc.env())
                    console = os_smoke.Console(os_smoke.connect(temporary / 's.sock', process),
                                               process, output / 'serial.raw')
                    qmp = Qmp(os_smoke.connect(temporary / 'q.sock', process))
                    qmp.receive(time.monotonic() + 10)
                    qmp.execute('qmp_capabilities')
                    memory = qmp.execute('query-memory-size-summary')
                    pc.require(memory.get('base-memory') == 2 * 1024**3,
                               'QEMU did not allocate the requested two GiB')
                    pc.write_json(output / 'memory.json', memory)
                    pc.write_json(output / 'qmp.json', qmp.transcript)
                    qmp.sock.close()
                    console.until(os_smoke.PROMPT, timeout=90)
                    pc.require(b'X86_RAM_2G_OK high_page=' in console.raw,
                               'Guest did not verify its upper GiB')
                    console.command('posix exec dbus-daemon')
                    console.until(rb'unix:path=/run/user/0/bus,guid=', timeout=15)
                    console.command('posix exec cosmic-session')
                    pc.write_json(output / 'commands.json', console.commands)
                    pc.write_json(output / 'state.json', dict(status='MANUAL_SESSION_STARTED',
                        qemu_pid=process.pid, ram_mib=2048, cpus=4,
                        memory_confirmed_bytes=memory['base-memory'], upper_gib_verified=True,
                        display=args.display, build=str(build)))
                    print('MANUAL_COSMIC_SESSION_STARTED ram_mib=2048 cpus=4', flush=True)
                    while process.poll() is None:
                        try:
                            data = console.sock.recv(65536)
                            if data:
                                with (output / 'serial.raw').open('ab') as stream:
                                    stream.write(data)
                        except BlockingIOError:
                            pass
                        time.sleep(.05)
                    pc.write_json(output / 'state.json', dict(status='MANUAL_WINDOW_CLOSED',
                        ram_mib=2048, qemu_exit_code=process.returncode, manual_result='not inferred'))
                finally:
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)


if __name__ == '__main__':
    main()
