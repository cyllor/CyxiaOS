#!/usr/bin/env python3
"""Assert the real session's panel/config and settings/state path errors are absent.

The fixed 45-second normal-session capture remains the original trigger. This
extra verdict checks the actual child diagnostics, not just replaced pixels.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import os_x86
import x86_64 as pc

ERRORS = ('NoConfigDirectory', 'Failed to watch xdg state dir:', 'Failed to watch xdg config dir:')


def assess(raw, capture):
    found = [error for error in ERRORS if error.encode() in raw]
    active = {int(match.group(1)) for match in re.finditer(
        rb'EL0 UserStatus \{ pid: (\d+),[^\r\n]*?state: (?:Running|Waiting), code: 0,', raw)}
    observed = {2, 3, 4, 5, 6} <= active
    initialized = b'theme work begin phase=initial-reset' in raw
    success = observed and initialized and not found and capture.get('qemu_exit_code') == 0 \
        and not capture.get('error')
    return dict(status='PASS' if success else 'FAIL', errors=found,
                core_children_observed=observed, settings_watch_setup_reached=initialized)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--observe-seconds', type=float, default=45)
    parser.add_argument('--inspect-bus', action='store_true')
    args = parser.parse_args()
    command = [sys.executable, str(Path(__file__).with_name('os_cosmic_startup_probe.py')),
               '--build', str(args.build), '--output', str(args.output),
               '--observe-seconds', str(args.observe_seconds)]
    if args.inspect_bus:
        command.append('--inspect-bus')
    child = subprocess.run(command, capture_output=True, text=True)
    capture = pc.read_json(args.output / 'result.json')
    raw_path = args.output / 'serial.raw'
    raw = raw_path.read_bytes()
    # Pixel timing has its own unchanged verdict. A path regression must not
    # mistake a late partial scanout for a directory failure, or a launched name
    # for a live initialized service.
    result = dict(**assess(raw, capture), image_sha256=capture['image_sha256'],
                  capture_exit_code=child.returncode,
                  serial_sha256=pc.sha(raw_path), startup_capture_status=capture['status'],
                  producers=os_x86.producer_sources(__file__),
                  full_os_verified=False, cosmic_session_verified=False)
    pc.write_json(args.output / 'xdg-result.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'producers'}, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
