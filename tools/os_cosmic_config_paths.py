#!/usr/bin/env python3
"""Real guest regressions for panel system defaults and settings state watches."""
import argparse
from pathlib import Path

from os_signal_restart import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', choices=('panel', 'state'), required=True)
    args = parser.parse_args()
    if args.check == 'panel':
        return run_probe(args.build, args.output, 'panel-config-probe', 'PANEL_CONFIG_PROBE',
                         ('USER_DIRECTORY', 'ENTRIES', 'COMPLETE_SCHEMA', 'APPLETS_18', 'USER_OVERRIDE'),
                         producer_entry=__file__)
    return run_probe(args.build, args.output, 'session-env-probe', 'SESSION_ENV_PROBE',
                     ('STATE_WATCH',), producer_entry=__file__)


if __name__ == '__main__':
    raise SystemExit(main())
