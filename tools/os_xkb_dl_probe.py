#!/usr/bin/env python3
"""Check the actual Rust XKB loader, context, Unicode and real Compose data."""
import argparse
from pathlib import Path
from os_signal_restart import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'notifications-peer-probe', 'XKB_DL_PROBE',
        ('BINDINGS', 'CONTEXT', 'KEYSYM_UTF8', 'COMPOSE', 'CLEANUP'), producer_entry=__file__)


if __name__ == '__main__':
    raise SystemExit(main())
