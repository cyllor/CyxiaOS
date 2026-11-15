"""Real COSMIC config client lifecycle and durable readback on the guest OS."""
from pathlib import Path
import re

import x86_64 as pc

CUSTOM = '/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom'
PROBE = '/.config/cosmic/org.cyxia.ConfigProbe/v1/'
DEFAULTS = re.compile(rb'COSMIC_CONFIG DEFAULTS PASS bindings=(\d+) actions=(\d+) rules=(\d+)')
READY = b'COSMIC_CONFIG READY'
VALUES_RECOVERED = b'COSMIC_CONFIG VALUES_RECOVERED PASS'
RECOVERED = b'COSMIC_CONFIG RECOVERED PASS'


def validate_inputs(prefix):
    from install_cosmic_config import validate_inputs as validate_assets
    from build_cosmic_config import validate_inputs as validate_client
    prefix = Path(prefix)
    return {'assets': validate_assets(prefix), 'client': validate_client(prefix)}


def validate_transcript(data, pid, alias, *, custom=None):
    """Reject missing, reordered, stale or contradictory client evidence."""
    launches = list(re.finditer(rb'^ELF pid=(\d+) started;[^\r\n]*\r?$', data, re.MULTILINE))
    endings = list(re.finditer(rb'^USER pid=(\d+) (Exited|Fault|Killed) code=(-?\d+)\b[^\r\n]*\r?$',
                              data, re.MULTILINE))
    pc.require(len(launches) == len(endings) == 1 and
               int(launches[0][1]) == int(endings[0][1]) == pid,
               'COSMIC config transcript lacks one matching launch and exit')
    launch, ending = launches[0], endings[0]
    expected_exit = 1 if custom == 'malformed' else 0
    pc.require(launch.end() < ending.start() and ending[2] == b'Exited'
               and int(ending[3]) == expected_exit, 'COSMIC config client exited unexpectedly')
    markers = [line for line in data.splitlines() if line.startswith(b'COSMIC_CONFIG ')]
    body_markers = [line for line in data[launch.end():ending.start()].splitlines()
                    if line.startswith(b'COSMIC_CONFIG ')]
    pc.require(markers == body_markers, 'COSMIC config markers lie outside the running process')
    result = {'alias': alias, 'exit_code': expected_exit, 'markers': [line.decode() for line in markers]}
    remaining = list(markers)
    if alias in ('defaults', 'init', 'check', 'raw'):
        counts = DEFAULTS.fullmatch(remaining.pop(0)) if remaining else None
        pc.require(counts is not None and all(int(value) > 0 for value in counts.groups()),
                   'COSMIC config did not parse all three nonempty upstream defaults')
        result['defaults'] = dict(zip(('bindings', 'actions', 'rules'), map(int, counts.groups())))
    if alias == 'defaults':
        expected = []
    elif alias == 'init':
        pc.require(custom in ('created', 'preserved', 'malformed'), 'Unknown initializer expectation')
        if custom == 'malformed':
            pc.require(len(remaining) == 1 and remaining[0].startswith(b'COSMIC_CONFIG FAIL: RonSpanned('),
                       'Malformed custom config was not rejected with a RON parse failure')
            expected = remaining
        else:
            expected = [('COSMIC_CONFIG CUSTOM_' + custom.upper()).encode(), READY]
        result['custom'] = custom
    elif alias in ('check', 'raw'):
        expected = [b'COSMIC_CONFIG NOTIFIED value=false', b'COSMIC_CONFIG NOTIFIED value=true',
                    VALUES_RECOVERED, RECOVERED, b'COSMIC_CONFIG EXERCISE PASS']
    elif alias == 'verify':
        expected = [VALUES_RECOVERED, RECOVERED]
    elif alias == 'values':
        expected = [VALUES_RECOVERED]
    else:
        raise ValueError('Unknown COSMIC config client alias')
    pc.require(remaining == expected, 'COSMIC config client markers are missing, reordered or contradictory')
    return result


def run_client(console, alias, *, custom=None):
    from os_smoke import object_snapshot, reclaimed_probe
    before = object_snapshot(console)
    pc.require(all(before.get(key) == 0 for key in ('live', 'references', 'epolls', 'watches',
               'inotify_instances', 'inotify_watches', 'inotify_events')),
               'COSMIC config client begins with live objects or incomplete accounting')
    start = console.command('posix exec cosmic-config-' + alias)
    pid = console.until(rb'^ELF pid=(\d+) started;', start).group(1)
    ending = console.until(rb'^USER pid=' + pid + rb' (?:Exited|Fault|Killed) code=-?\d+\b[^\r\n]*\r?$',
                           start, timeout=60)
    end = start + ending.end()
    parsed = validate_transcript(bytes(console.raw[start:end]), int(pid), alias, custom=custom)
    reclaimed = reclaimed_probe(console, pid, before, code=parsed['exit_code'])
    pc.require(reclaimed['process'].get('esr') == reclaimed['process'].get('far') == 0,
               'COSMIC config client recorded a CPU fault')
    return {**parsed, **reclaimed, 'serial_offset': start,
            'exit_serial_offset': start + ending.start(), 'serial_end': end}


def readback(console, path, expected):
    """Pair exact ASCII content with stat length, detecting hidden trailing bytes."""
    at = console.command('cat ' + path)
    value = console.until(rb'^(' + re.escape(expected.encode('ascii')) + rb')\r?$', at).group(1)
    stat_at = console.command('stat ' + path)
    size = int(console.until(rb'^' + re.escape(path.encode('ascii')) +
                            rb' File bytes=(\d+) reads=\d+ cached=(?:true|false)\r?$', stat_at).group(1))
    pc.require(size == len(value), 'COSMIC config readback has unexpected trailing or hidden bytes')
    return {'path': path, 'value': value.decode('ascii'), 'bytes': size,
            'sha256': pc.sha_bytes(value), 'serial_offset': at, 'stat_serial_offset': stat_at}


def checks(console, recover=False, library=False):
    runs, readbacks, writes = [], [], []

    def run(alias, **kwargs):
        result = run_client(console, alias, **kwargs)
        previous = next((entry['defaults'] for entry in runs if 'defaults' in entry), None)
        if previous is not None and 'defaults' in result:
            pc.require(result['defaults'] == previous, 'Upstream COSMIC default counts changed between processes')
        runs.append(result)

    def read(path, value):
        result = readback(console, path, value)
        readbacks.append(result)
        return result

    def write(value):
        at = console.command('write ' + CUSTOM + ' ' + value)
        writes.append({'path': CUSTOM, 'value': value, 'serial_offset': at})
        return read(CUSTOM, value)

    if recover:
        # No initializer, replacements, exercise, or external checkpoint here.
        run('values' if library else 'verify')
    else:
        run('defaults')
        run('init', custom='created')
        read(CUSTOM, '{}')
        valid = write('{ }')
        run('init', custom='preserved')
        preserved = read(CUSTOM, '{ }')
        pc.require(valid['sha256'] == preserved['sha256'], 'Initializer rewrote preexisting custom config')
        malformed = write('{')
        run('init', custom='malformed')
        rejected = read(CUSTOM, '{')
        pc.require(malformed['sha256'] == rejected['sha256'], 'Initializer rewrote malformed custom config')
        write('{ }')
        run('raw' if library else 'check')
        run('verify')
    read(CUSTOM, '{ }')
    read(PROBE + 'enabled', 'true')
    read(PROBE + 'generation', '2')
    return {'recovered': bool(recover), 'library_durability': bool(library),
            'recovery_directory_cleanup_checked': bool(recover and not library),
            'runs': runs, 'writes': writes, 'readbacks': readbacks,
            'scope': 'Actual upstream COSMIC config defaults, atomic writes, notifications and readback',
            'external_checkpoint_used': False, 'cosmic_session_verified': False}
