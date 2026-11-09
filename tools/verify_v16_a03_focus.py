#!/usr/bin/env python3
"""Replay released CoreSet custody or explicitly expected failed diagnostic custody."""
import argparse
import json
from pathlib import Path
from v16_a03_focus import verify_focus_capture, verify_diagnostic_capture


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    for name in ('source-root','build-manifest','formatter','qemu-binary','qemu-source'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--producer-tools-root',type=Path)
    parser.add_argument('--expected-diagnostic-failure',action='store_true')
    args=vars(parser.parse_args(argv))
    expected_failure=args.pop('expected_diagnostic_failure')
    verifier=verify_diagnostic_capture if expected_failure else verify_focus_capture
    result=verifier(**args)
    print(json.dumps(result,sort_keys=True,indent=2,allow_nan=False))
    return 0

if __name__=='__main__': raise SystemExit(main())
