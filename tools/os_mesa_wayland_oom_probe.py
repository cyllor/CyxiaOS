#!/usr/bin/env python3
"""Require actual EGL failure propagation, recovery pixels and guest cleanup."""
import argparse
import json
from pathlib import Path
import re

import os_wayland_egl_probe as egl
import x86_64 as pc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    egl.run(args.build, args.output)
    result = pc.read_json(args.output / 'result.json')
    checks = ('RETAIN_REFERENCE', 'CURRENT_TARGET', 'SATURATE', 'SWAP_ERROR', 'DAMAGE_ERROR', 'RECOVERY')
    raw = (args.output / 'serial.raw').read_bytes()
    actual = [name for name in checks if ('MESA_WAYLAND_OOM_PROBE ' + name + ' PASS').encode() in raw]
    result.update(scope='actual_wayland_egl_metadata_denial_and_recovery',
                  oom_checks=actual, producers=egl.os_x86.producer_sources(__file__))
    held = re.findall(rb'MESA_WAYLAND_OOM_PROBE SATURATE PASS held=(\d+) errno=12', raw)
    if result['status'] != 'PASS' or actual != list(checks) or len(held) != 1:
        result['status'] = 'FAIL'
    else:
        result['metadata_fillers'] = int(held[0])
    pc.write_json(args.output / 'oom-result.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'producers'}, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
