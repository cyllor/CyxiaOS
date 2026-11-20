#!/usr/bin/env python3
"""Check genuine xkbcommon Compose loading, aliases and output in the x86 guest."""
import argparse
from pathlib import Path

from os_signal_restart import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'compose-probe', 'COMPOSE_PROBE',
                     ('en_US.UTF-8', 'C.UTF-8', 'C.utf8', 'en_US.utf8'), producer_entry=__file__)


if __name__ == '__main__':
    raise SystemExit(main())
