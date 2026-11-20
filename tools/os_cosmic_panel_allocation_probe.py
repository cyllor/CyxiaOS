#!/usr/bin/env python3
"""Check panel survival in the unchanged normal COSMIC session capture."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import os_cosmic_xdg_probe
import os_x86
import x86_64 as pc


def assess(raw, capture):
    paths = os_cosmic_xdg_probe.assess(raw, capture)
    # Fresh normal-session startup assigns its five core children PID 2..6.
    # A replacement panel cannot satisfy the original panel's survival check.
    alive = bool(re.search(rb'EL0 UserStatus \{ pid: 6,[^\r\n]*?state: (?:Running|Waiting), code: 0,', raw))
    aborts = len(re.findall(rb'USER pid=\d+ Exited code=134\b', raw))
    observed = capture.get('later_diagnostic', {}).get('observed_seconds', 0)
    bus = capture.get('bus_inspection', {}).get('notifications_name_present', False)
    passed = (paths['status'] == 'PASS' and alive and aborts == 0 and observed >= 90
              and bus and capture.get('status') == 'PASS' and capture.get('first_frame_seconds') == 45)
    return dict(status='PASS' if passed else 'FAIL', panel_pid=6, original_panel_alive=alive,
                core_children_observed=paths['core_children_observed'], aborts=aborts,
                path_errors=paths['errors'], notifications_name_present=bus,
                observed_seconds=observed,
                missing_applet_diagnostics=raw.count(b'Applet desktop entry missing or invalid'),
                normal_peer_errors=raw.count(b'Failed to setup panel dbus server'),
                panel_applets_verified=False, semantic_frame_verified=False,
                full_os_verified=False, cosmic_session_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    subprocess.run([sys.executable, str(Path(__file__).with_name('os_cosmic_xdg_probe.py')),
                    '--build', str(args.build), '--output', str(args.output),
                    '--observe-seconds', '90', '--inspect-bus'], check=False,
                   capture_output=True, text=True)
    capture = pc.read_json(args.output / 'result.json')
    serial = args.output / 'serial.raw'
    result = dict(**assess(serial.read_bytes(), capture), image_sha256=capture['image_sha256'],
                  serial_sha256=pc.sha(serial), producers=os_x86.producer_sources(__file__))
    pc.write_json(args.output / 'panel-result.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'producers'}, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
