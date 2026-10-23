"""Real guest X11 window discovery shared by manual sessions and acceptance gates."""
import hashlib
import json
import re
import time

from doctor import ROOT
from verify_x11 import FATAL, pump


def embedded_programs(elf, names):
    image = elf.read_bytes()
    identities = {}
    for name in names:
        path = ROOT/'artifacts/sysroot/aarch64-musl'/(name+'.elf')
        binary = path.read_bytes()
        if image.count(binary) != 1:
            raise RuntimeError(f'{name}: selected kernel does not contain the current target ELF')
        identities[name] = hashlib.sha256(binary).hexdigest()
    return identities


def parse_windows(data):
    """A partial/interleaved console observation is never proof of absence.

    The guest inspector writes strings in several syscalls. Other guest/kernel
    logs can split its JSON even though the UART framing itself is intact.
    Reject the entire observation instead of dropping damaged client records.
    The guest's final count also detects a split/lost WINDOW prefix itself.
    """
    marker = b'X11_INSPECT WINDOW '
    declared = re.findall(rb'(?m)^X11_INSPECT PASS windows=(\d+)\r?$', data)
    if len(declared) != 1:
        raise ValueError('missing or ambiguous guest window count')
    records = re.findall(rb'X11_INSPECT WINDOW (\{[^\r\n]+\})\r?\n', data)
    if int(declared[0]) != len(records) or len(records) != data.count(marker):
        raise ValueError('interleaved/incomplete window observation')
    clients = [json.loads(record) for record in records]
    for client in clients:
        if (not isinstance(client, dict)
                or any(type(client.get(key)) is not int for key in ('id', 'x', 'y', 'width', 'height'))
                or any(not isinstance(client.get(key), str) for key in ('title', 'class', 'instance'))
                or client['id'] <= 0 or client['width'] <= 0 or client['height'] <= 0):
            raise ValueError('invalid window observation')
    if len({client['id'] for client in clients}) != len(clients):
        raise ValueError('duplicate window observation')
    return clients


def windows(guest, timeout=15):
    """Inspect through the guest X server and wait for the inspector to exit."""
    start = len(guest.text)
    guest.command('posix exec x11-inspect')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        guest.poll()
        data = bytes(guest.text[start:])
        if any(value in data for value in FATAL) or b'EL0 start failed' in data:
            raise RuntimeError(data[-2000:].decode(errors='replace'))
        launched = re.search(rb'X11_INSPECT START pid=(\d+)', data)
        if launched:
            finished = re.search(rb'EL0 pid='+launched[1]+rb' Exited code=(\d+)', data)
            if finished:
                if int(finished[1]) != 0:
                    if b'X11_INSPECT FAIL wm' in data:
                        return None
                    raise RuntimeError(data[-2000:].decode(errors='replace'))
                if b'X11_INSPECT PASS' not in data:
                    raise RuntimeError('Window inspector exited without a complete result')
                try:
                    return parse_windows(data)
                except (ValueError, UnicodeDecodeError):
                    # The inspector has exited, so its process resources are
                    # released before retrying. Retain the original deadline.
                    guest.window_inspection_retries = getattr(guest, 'window_inspection_retries', 0) + 1
                    start = len(guest.text)
                    guest.command('posix exec x11-inspect')
                    continue
            if re.search(rb'EL0 pid='+launched[1]+rb' Faulted', data):
                raise RuntimeError('Guest window inspector faulted')
        time.sleep(.01)
    raise TimeoutError('Guest window inspection timed out: '+data[-1500:].decode(errors='replace'))


def wait_window(guest, wm_class=None, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clients = windows(guest, min(15, max(1, deadline-time.monotonic())))
        if clients is not None:
            if wm_class is None:
                return clients
            matches = [w for w in clients if w['class'].casefold() == wm_class.casefold()]
            if matches:
                return matches
        pump(guest, .25)
    raise TimeoutError(f'Guest window did not become viewable: {wm_class or "window manager"}')
