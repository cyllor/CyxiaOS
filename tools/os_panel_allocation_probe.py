#!/usr/bin/env python3
"""Exercise real panel connection creation under actual kernel FD pressure."""
import argparse
from pathlib import Path

from os_signal_restart import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'panel-allocation-probe', 'PANEL_ALLOCATION_PROBE',
                     ('HEALTHY_CLIENT', 'PAIR_EMFILE', 'INSERT_EMFILE', 'FAILURE_REFUND', 'RECOVERY'),
                     producer_entry=__file__)


if __name__ == '__main__':
    raise SystemExit(main())
