#!/usr/bin/env python3
"""Run the real zbus peer handshake through the x86 guest's actual socket ABI."""
import argparse
from pathlib import Path
from os_signal_restart import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'zbus-peer-probe', 'ZBUS_PEER_PROBE',
                     ('HANDSHAKE', 'ROUNDTRIP', 'INHERITED_FD'), producer_entry=__file__)


if __name__ == '__main__':
    raise SystemExit(main())
