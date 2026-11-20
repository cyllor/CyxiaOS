#!/usr/bin/env python3
"""Replay the captured panel delay through the genuine notifications module."""
import argparse
from pathlib import Path
from os_signal_restart import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scope', choices=('full', 'handshake', 'delay'), default='full')
    args = parser.parse_args()
    checks = ('DELAYED_HANDSHAKE', 'IDLE_CANCEL', 'ACTIVE_TIMEOUT', 'PEER_CLOSED')
    if args.scope == 'full':
        checks += ('SCM_RIGHTS', 'ACTION')
    elif args.scope == 'delay':
        checks = ('DELAYED_HANDSHAKE',)
    return run_probe(args.build, args.output,
                     'notifications-peer-probe' if args.scope == 'full' else 'notifications-peer-handshake',
                     'NOTIFICATIONS_PEER_PROBE', checks,
                     producer_entry=__file__)


if __name__ == '__main__':
    raise SystemExit(main())
