#!/usr/bin/env python3
"""Capture actual single-node ABI3 model-driven 1-to-2-to-1 ownership.

No core target, score, owner result or model input is injected. The unchanged
guest's real protected jobs must select and execute both transitions. Failure
retains the raw stopped bank and does not become a scripted ownership PASS.
"""
import argparse
import json
from pathlib import Path
import subprocess

from check_prototype_evidence import safe_path,sha256
from run_v13_boot_evidence import preserve_evidence
from run_v13_boot_recovery import ROOT,run_case,write_json
from verify_v13_boot_receipt import TOOL_FILES
from verify_v13_boot_recovery import require
from verify_v15_ownership import verify_native


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('build','output','formatter','qemu','qemu-source'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--timeout',type=float,default=60)
    args=parser.parse_args(argv)
    require(5<=args.timeout<=120,'invalid bounded timeout')
    build,output,formatter,qemu,trusted=(p.resolve() for p in
        (args.build,args.output,args.formatter,args.qemu,args.qemu_source))
    require(qemu==(trusted/'build/qemu-system-aarch64').resolve(strict=True),
            'emulator differs from trusted explicit build')
    hashes={name:sha256(safe_path(ROOT,'tools/'+name)) for name in TOOL_FILES}
    try:
        result=run_case(build,output,formatter,qemu,trusted,0,args.timeout,ownership=True)
        preserve_evidence(output,ROOT,trusted,hashes)
        require(result['status']=='PASS',result.get('error','native ownership trace failed'))
        verified=verify_native(output,source_root=ROOT,qemu_source=trusted)
        write_json(output/'independent-a03.json',verified)
        print(json.dumps(verified,indent=2));return 0
    except (OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        if output.is_dir():write_json(output/'a03-error.json',dict(status='FAIL',error=str(error),native_acceptance_status='NOT_RUN'))
        print(json.dumps(dict(status='FAIL',error=str(error),native_acceptance_status='NOT_RUN')));return 1


if __name__=='__main__':raise SystemExit(main())
