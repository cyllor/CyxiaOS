"""Actual upstream session broker and libdbus guest integration checks."""
from pathlib import Path
import re
import time

import x86_64 as pc


def validate_inputs(prefix):
    from build_dbus import validate_build
    prefix = Path(prefix)
    receipt = pc.read_json(prefix / 'dbus-origin.json')
    origin = Path(receipt['output'])
    report = validate_build(origin)
    pc.require(pc.sha(origin / 'dbus-build-report.json') == receipt['report_sha256'],
               'D-Bus upstream build receipt changed')
    images = ('dbus-daemon', 'dbus-send', 'dbus-uuidgen', 'dbus-probe')
    for name in images:
        pc.require(pc.sha(prefix / (name + '.elf')) == pc.sha(origin / (name + '.elf')),
                   'staged D-Bus executable differs from upstream build')
    for guest, digest in pc.read_json(origin / 'dbus-build-report.json')['rootfs'].items():
        pc.require(pc.sha(prefix / 'rootfs' / guest.lstrip('/')) == digest,
                   'staged D-Bus configuration differs from receipt')
    return dict(origin=receipt, validated=report)


def machine_id(console):
    console.program('posix exec dbus-uuidgen')
    at = console.command('cat /etc/machine-id')
    value = console.until(rb'^([0-9a-f]{32})\r?$', at).group(1).decode()
    pc.require(value != '0' * 32, 'machine ID is empty')
    return value


def start_bus(console):
    at = console.command('posix exec dbus-daemon')
    pid = console.until(rb'ELF pid=(\d+) started;', at).group(1)
    address = console.until(rb'^unix:path=/run/user/0/bus,guid=([0-9a-f]{32})\r?$', at)
    return dict(pid=int(pid), guid=address.group(1).decode(), serial_offset=at)


def list_names(console):
    at = console.program('posix exec dbus-send', b'method return')
    text = bytes(console.raw[at:])
    names = [value.decode() for value in re.findall(rb'string "([^"]+)"', text)]
    pc.require('org.freedesktop.DBus' in names, 'real broker missing from ListNames')
    return names


def idle_broker(console):
    from verify_ported import parse_processes
    deadline = time.monotonic() + 10
    while True:
        at = console.command('posix list')
        rows = [row for row in parse_processes(bytes(console.raw[at:])).values()
                if row['state'] in ('Running', 'Waiting')]
        pc.require(rows, 'broker exited while draining connections')
        if all(row['state'] == 'Waiting' for row in rows):
            return rows
        pc.require(time.monotonic() < deadline, 'broker did not return to its wait loop')
        time.sleep(.02)


def drain_connections(console, baseline):
    from os_smoke import object_snapshot
    # Waiting alone is not quiescence: the broker can park between consuming a
    # hangup and closing its peer descriptor. Require the pre-client baseline.
    deadline = time.monotonic() + 10
    while True:
        idle_broker(console)
        if object_snapshot(console) == baseline:
            return
        pc.require(time.monotonic() < deadline, 'broker connections did not return to baseline')
        time.sleep(.02)


def run_probe(console, baseline, free_pages):
    from os_smoke import reclaimed_probe
    drain_connections(console, baseline)
    at = console.command('posix exec dbus-probe')
    pid = console.until(rb'ELF pid=(\d+) started;', at).group(1)
    for phase in ('WRONG_IDENTITY_REJECTED', 'OWNERSHIP_CONFLICT',
                  'METHOD_ROUTING', 'RELEASE_DISCONNECT'):
        console.until(('DBUS_PROBE ' + phase + ' PASS').encode(), at)
    console.until(rb'DBUS_PROBE PASS', at)
    console.until(rb'pid=' + pid + rb' Exited code=0\b', at)
    drain_connections(console, baseline)
    result = reclaimed_probe(console, pid, baseline, free_pages=free_pages)
    rows = re.findall(rb'DBUS_PROBE IDENTITY PASS unique=([^ ]+) pid=(\d+) uid=(\d+) id=([0-9a-f]{32})',
                      bytes(console.raw[at:]))
    pc.require(len(rows) == 2 and rows[0][0] != rows[1][0] and
               all(row[1] == pid and row[2] == b'0' for row in rows) and rows[0][3] == rows[1][3],
               'broker did not return actual two-connection credentials and common GUID')
    result['identities'] = [[value.decode() for value in row] for row in rows]
    return result


def stop_bus(console, bus, before):
    from os_smoke import object_snapshot
    from verify_ported import parse_processes
    console.command('posix kill ' + str(bus['pid']), [rb'killed; pages reclaimed'])
    at = console.command('posix list')
    row = parse_processes(bytes(console.raw[at:]))[bus['pid']]
    for key, value in dict(state='Killed', code=137, heap_pages=0, image_pages=0,
                           thread_count=0, heap_allocations=0, heap_free=16384,
                           image_free=16384, free_pages=64).items():
        pc.require(row.get(key) == value, 'broker did not reclaim ' + key)
    pc.require(object_snapshot(console) == before, 'broker left open descriptions')
    return row


def checks(console, expected_machine_id=None):
    from os_smoke import object_snapshot
    before = object_snapshot(console)
    pc.require(before['live'] == before['references'] == 0, 'session bus begins with live objects')
    if expected_machine_id is not None:
        at = console.command('cat /etc/machine-id')
        recovered = console.until(rb'^([0-9a-f]{32})\r?$', at).group(1).decode()
        pc.require(recovered == expected_machine_id, 'machine ID did not survive disk reboot')
        console.program('posix exec fsync-verify', b'FSYNC_PROBE RECOVERED PASS')
    identity = machine_id(console)
    pc.require(machine_id(console) == identity, 'ensuring existing machine ID changed it')
    # dbus-uuidgen fsyncs its temporary file before rename. Syncing a directory
    # in the probe commits the final namespace through the same real service.
    console.program('posix exec fsync-probe', b'FSYNC_PROBE PASS')
    runs = []
    for _ in range(2):
        bus = start_bus(console)
        active = idle_broker(console)
        pc.require(len(active) == 1 and active[0]['pid'] == bus['pid'],
                   'broker-only baseline requires exactly the real broker')
        baseline = object_snapshot(console)
        names = list_names(console)
        probe = run_probe(console, baseline, active[0]['free_pages'])
        pc.require('org.cyxia.SessionBusProbe' not in list_names(console), 'disconnected name leaked')
        ended = stop_bus(console, bus, before)
        runs.append(dict(bus=bus, names=names, broker_baseline=baseline, probe=probe, ended=ended))
    pc.require(runs[0]['bus']['guid'] != runs[1]['bus']['guid'], 'broker restart reused bus GUID')
    return dict(machine_id=identity, runs=runs,
                scope='real upstream session broker; complete COSMIC session remains unverified')
