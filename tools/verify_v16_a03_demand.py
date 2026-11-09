#!/usr/bin/env python3
"""Replay an ordinary A03 scene using explicit caller-selected source/tools."""
import argparse
import json
from pathlib import Path
from v16_a03_demand import verify_capture


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory','source-root','build-manifest','formatter','qemu-binary','qemu-source'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--producer-tools-root',type=Path)
    args = vars(parser.parse_args(argv)); directory = args.pop('directory')
    try: result = verify_capture(directory,**args)
    except (OSError,ValueError,RuntimeError,KeyError) as error:
        print(json.dumps(dict(status='FAIL',stimulus_verified=False,native_acceptance_status='NOT_RUN',error=str(error))))
        return 1
    print(json.dumps({k:v for k,v in result.items() if k != 'captured_inventory'},indent=2)); return 0


if __name__ == '__main__': raise SystemExit(main())
