#!/usr/bin/env python3
"""Run connected socket SCM_RIGHTS and final-reference cleanup in the real guest."""
import argparse
from pathlib import Path
from os_signal_restart import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'socket-rights-probe', 'SOCKET_RIGHTS_PROBE',
                     ('INFLIGHT', 'ROUNDTRIP', 'RELEASE', 'CREATOR_EXIT', 'SELF_CYCLE',
                      'CROSS_CYCLE', 'ROOTED_CYCLE', 'SHUTDOWN_CHAIN', 'TRUNCATION', 'CANCELLED_SEND'),
                     producer_entry=__file__, verify_reclamation=True)


if __name__ == '__main__':
    raise SystemExit(main())
