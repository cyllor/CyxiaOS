#!/usr/bin/env python3
"""Verify producer v3 with qualified joint-proof offline v4-r2 evidence."""
import argparse
import json
from pathlib import Path
from v16_a03_data_offline_v4 import verify_offline_capture

def exit_code(result):
    """Zero confirms the scoped partial proof, never a full native PASS."""
    return int(result['status']!='OFFLINE_PARTIAL_PROTECTED_SAMPLE_VERIFIED')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    for name in ('source-root','build-manifest','formatter','qemu-binary','qemu-source','producer-tools-root'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--expected-original-summary-sha256',required=True)
    result=verify_offline_capture(**vars(parser.parse_args(argv)))
    print(json.dumps(result,sort_keys=True,indent=2,allow_nan=False))
    return exit_code(result)
if __name__=='__main__':raise SystemExit(main())
