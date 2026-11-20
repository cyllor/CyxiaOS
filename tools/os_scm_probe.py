#!/usr/bin/env python3
"""Replay existing SCM_RIGHTS compatibility checks on an actual x86 image."""
import argparse
from pathlib import Path
from os_signal_restart import run_probe

CHECKS = ('CREATOR_EXIT', 'INFLIGHT_IDENTITY', 'STREAM_BOUNDARY', 'FAILURE_ATOMICITY',
          'CONTROL_TRUNCATION', 'FD_CAPACITY', 'QUEUE_BACKPRESSURE', 'SHORT_WRITE',
          'BLOCKING_SEND_BOUNDARY', 'UNRECEIVED_RELEASE')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run_probe(args.build, args.output, 'scm-probe', 'SCM_PROBE', CHECKS,
                     producer_entry=__file__, verify_reclamation=True)


if __name__ == '__main__':
    raise SystemExit(main())
