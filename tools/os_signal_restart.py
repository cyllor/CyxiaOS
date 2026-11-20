#!/usr/bin/env python3
"""Run the real musl SA_RESTART regression in an isolated, manifest-bound VM."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

import os_smoke
import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from run_qemu import Qmp
from storage import create_disk

CHECKS = ('REGISTRATION', 'READ_RESTART', 'READ_EINTR', 'POLL_EINTR', 'SLEEP_EINTR',
          'TIMER_RESTART', 'FUTEX_RESTART', 'TIMED_FUTEX_EINTR', 'FLOCK_RESTART', 'WAIT_RESTART')


def rights_snapshot(console):
    at = console.command('ai system')
    console.until(rb'AI_SYSTEM_END\r?\n', at)
    output = bytes(console.raw[at:])

    def row(prefix, required):
        rows = re.findall(rb'^' + re.escape(prefix) + rb' ([^\r\n]+)\r?$', output, re.MULTILINE)
        pc.require(len(rows) == 1, 'missing or ambiguous guest receipt: ' + repr(prefix))
        values = {key.decode(): int(value) for key, value in re.findall(rb'(\w+)=(\d+)', rows[0])}
        pc.require(set(required) <= values.keys(), 'incomplete guest receipt: ' + repr(prefix))
        return values

    objects = row(b'OFD_OBJECTS', ('live', 'references', 'capacity', 'epolls', 'watches',
                                 'fd_refs', 'staged_refs', 'inflight_refs',
                                 'staged_messages', 'inflight_messages'))
    domains = {name: row(('AI_DOMAIN name=' + name).encode(),
                         ('granted', 'released', 'grant_units', 'release_units', 'cancelled'))
               for name in ('ancillary_messages', 'ancillary_references')}
    return dict(objects=objects, domains=domains)


def run_probe(build, output, program, marker, checks, *, producer_entry=None, end_pattern=None,
              required_fragments=(), verify_reclamation=False, observe_exit=None):
    output.mkdir(parents=True, exist_ok=False)
    manifest = pc.read_json(build / 'build-manifest.json')
    image = build / 'boot.bin'
    pc.require(manifest['status'] == 'BUILT_NOT_RUN'
               and pc.sha(image) == manifest['artifacts']['boot.bin'], 'probe image identity mismatch')
    result = dict(status='FAIL', program=program, image_sha256=pc.sha(image), full_os_verified=False,
                  producers=os_x86.producer_sources(producer_entry or __file__))
    process = qmp = console = None
    with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-signal-') as temporary:
        idle_native_host()
        control = Path(temporary).resolve()
        disk = create_disk(output / 'data.raw')
        argv = os_x86.launch_argv(pc.executable('qemu-system-x86_64'), image,
                                 disk=disk, qmp=control / 'q.sock')
        index = argv.index('-serial')
        argv[index:index+2] = ['-chardev', f'socket,id=console,path={control / "s.sock"},server=on,wait=on',
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
                if verify_reclamation:
                    before = rights_snapshot(console)
                    result['reclamation'] = dict(status='FAIL', before=before)
                    pc.require(before['objects']['capacity'] > 0 and
                               all(value == 0 for key, value in before['objects'].items()
                                   if key != 'capacity'), 'probe begins with live OFD state')
                started = time.monotonic()
                at = console.command('posix exec ' + program)
                pid = console.until(rb'ELF pid=(\d+) started;', at).group(1)
                console.until(end_pattern or marker.encode() + rb' PASS\r?\n', at, timeout=20)
                console.until(rb'USER pid=' + pid + rb' Exited code=0\b', at, timeout=10)
                if observe_exit is not None:
                    result['exit_receipts'] = observe_exit(console)
                for name in checks:
                    pc.require((marker + ' ' + name + ' PASS').encode() in console.raw[at:],
                               'missing actual guest check: ' + name)
                for fragment in required_fragments:
                    pc.require(fragment in console.raw[at:], 'missing actual guest result: ' + repr(fragment))
                elapsed = round(time.monotonic() - started, 3)
                if verify_reclamation:
                    after = rights_snapshot(console)
                    result['reclamation']['after'] = after
                    pc.require(after['objects'] == before['objects'], 'guest leaked OFD state')
                    for name, counters in after['domains'].items():
                        initial = before['domains'][name]
                        grants = counters['granted'] - initial['granted']
                        releases = counters['released'] - initial['released']
                        units = counters['grant_units'] - initial['grant_units']
                        released_units = counters['release_units'] - initial['release_units']
                        pc.require(grants == releases and grants > 0 and units == released_units
                                   and units > 0, 'unbalanced guest rights receipts: ' + name)
                    result['reclamation']['status'] = 'PASS'
                result.update(status='PASS', checks=list(checks),
                              probe_seconds=elapsed)
            except Exception as error:
                result['error'] = str(error)
            finally:
                if console is not None:
                    # A failure token may arrive before the end of its line.
                    for _ in range(10):
                        try:
                            console.pump(require_running=False)
                        except (ValueError, OSError):
                            pass  # Already recorded; still drain the real line.
                        time.sleep(.01)
                    pc.write_json(output / 'commands.json', console.commands)
                    result['serial_sha256'] = pc.sha(output / 'serial.raw')
                if qmp is not None and process.poll() is None:
                    try:
                        qmp.execute('quit')
                        process.wait(timeout=10)
                        result['qemu_exit_code'] = process.returncode
                        if process.returncode != 0:
                            result['status'] = 'FAIL'
                    except Exception as error:
                        result['shutdown_error'] = str(error)
                        result['status'] = 'FAIL'
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    pc.write_json(output / 'result.json', result)
    print(json.dumps(result, indent=2))
    return int(result['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'signal-restart-probe', 'SIGNAL_RESTART_PROBE', CHECKS)


if __name__ == '__main__':
    raise SystemExit(main())
