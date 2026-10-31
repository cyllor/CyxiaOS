#!/usr/bin/env python3
"""Eight sequential A01 boots using one node image and its preserved disk lineage.

The formatter runs only for the first boot. Every later disk is a byte-identical
copy of its exited predecessor, which is retained read-only as evidence. A failed
regression blocks descendants; it never resets the disk or retries until green.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys

from boot_reboot_contract import SCENARIOS
from check_prototype_evidence import safe_path, sha256
from run_v13_boot_evidence import preserve_and_verify
from run_v13_boot_recovery import ROOT, run_case, write_json
from verify_v13_boot_receipt import TOOL_FILES
from verify_v13_boot_reboots import verify_chain
from verify_v13_boot_recovery import require


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'output', 'formatter', 'qemu', 'qemu-source'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args(argv)
    require(5 <= args.timeout <= 120, 'invalid bounded timeout')
    build, formatter, qemu, trusted_qemu = (p.resolve(strict=True) for p in
        (args.build, args.formatter, args.qemu, args.qemu_source))
    require(qemu == (trusted_qemu/'build/qemu-system-aarch64').resolve(strict=True),
            'emulator differs from explicit trusted build')
    root = args.output.resolve(); root.mkdir(parents=True, exist_ok=False)
    tools = {name: sha256(safe_path(ROOT, 'tools/' + name)) for name in TOOL_FILES}
    report = dict(scope='A01 sequential reboots; not formal acceptance or power-loss',
                  status='RUNNING', native_acceptance_status='NOT_RUN', boots={})
    previous, failed = None, False
    for name, mode in SCENARIOS:
        child = root/name
        if failed:
            child.mkdir()
            report['boots'][name] = dict(status='NOT_RUN', error='predecessor did not verify')
        else:
            try:
                run_case(build, child, formatter, qemu, trusted_qemu, mode, args.timeout, previous=previous)
                replay = preserve_and_verify(child, ROOT, trusted_qemu, tools)
                report['boots'][name] = dict(status='PASS', mode=mode, native_acceptance_status='NOT_RUN',
                                            independent_replay=replay)
                previous = child
            except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                failed = True
                child.mkdir(parents=True, exist_ok=True)
                report['boots'][name] = dict(status='FAIL', error=str(error), native_acceptance_status='NOT_RUN')
                write_json(child/'provenance-error.json', report['boots'][name])
        write_json(root/'summary.json', report)
        print(name, report['boots'][name]['status'], report['boots'][name].get('error', ''), flush=True)
    report['status'] = 'FAIL' if failed else 'PASS'
    if not failed:
        try:
            report['independent_chain'] = verify_chain(root, source_root=ROOT, qemu_source=trusted_qemu)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
            report.update(status='FAIL', error=str(error))
    write_json(root/'summary.json', report)
    return int(report['status'] != 'PASS')


if __name__ == '__main__': sys.exit(main())
