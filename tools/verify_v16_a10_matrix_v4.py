#!/usr/bin/env python3
"""Independently rebuild exact native all/all A10 matrix coverage, including pauses."""
import argparse
import json
from pathlib import Path
from check_prototype_evidence import read_json, safe_path
from v16_a10_matrix_v4 import inspect_progress, load_progress


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path)
    for n in ('source-root','build-manifest','qemu-binary','qemu-source'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args(argv)
    result,_=inspect_progress(a.directory,read_json(safe_path(a.directory,'matrix-input.json')),
        load_progress(a.directory),context=dict(source_root=a.source_root,build_manifest=a.build_manifest,
        qemu_binary=a.qemu_binary,qemu_source=a.qemu_source))
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result['A10_complete'] else 2

if __name__=='__main__':
    raise SystemExit(main())
