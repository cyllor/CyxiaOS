#!/usr/bin/env python3
"""Replay the actual system Wayland client insertion used by COSMIC panel."""
import argparse
from pathlib import Path
from os_signal_restart import run_probe

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'wayland-server-probe', 'WAYLAND_SERVER_PROBE',
                     ('SOCKETPAIR', 'INSERT_CLIENT', 'CREDENTIALS'), producer_entry=__file__)

if __name__ == '__main__':
    raise SystemExit(main())
