#!/usr/bin/env python3
"""Replay bounded-data v3 custody; preparation history never grants authority."""
import argparse
import json
from pathlib import Path
from v16_a03_data import verify_data_capture,verify_diagnostic_capture

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    for name in ('source-root','build-manifest','formatter','qemu-binary','qemu-source'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--producer-tools-root',type=Path)
    parser.add_argument('--expected-diagnostic-failure',action='store_true')
    args=vars(parser.parse_args(argv));failure=args.pop('expected_diagnostic_failure')
    result=(verify_diagnostic_capture if failure else verify_data_capture)(**args)
    print(json.dumps(result,sort_keys=True,indent=2,allow_nan=False))
    return int(not (result['diagnostic_custody_verified'] if failure else result['data_collection_verified']))
if __name__=='__main__':raise SystemExit(main())
