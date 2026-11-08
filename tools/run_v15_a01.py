#!/usr/bin/env python3
"""Capture actual A01 boot authority through eight immutable same-disk handoffs.

Only the fixed preboot fault/identity config is injected. Production code owns
the evidence rows. A failed profile blocks every descendant; no retry, disk
reformat or producer boolean can turn a failed execution into acceptance.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from boot_reboot_contract import SCENARIOS
from check_prototype_evidence import safe_path, sha256
from run_v13_boot_evidence import preserve_evidence
from run_v13_boot_recovery import ROOT, run_case, write_json
from verify_v13_boot_receipt import TOOL_FILES, verify_receipt
from verify_v13_boot_recovery import require
from verify_v15_a01 import verify_acceptance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'output', 'formatter', 'qemu', 'qemu-source'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args(argv)
    require(5 <= args.timeout <= 120, 'invalid bounded timeout')
    build, formatter, qemu, trusted = (p.resolve(strict=True) for p in
        (args.build, args.formatter, args.qemu, args.qemu_source))
    require(qemu == (trusted / 'build/qemu-system-aarch64').resolve(strict=True),
            'emulator differs from explicit trusted source')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    tool_hashes = {name: sha256(safe_path(ROOT, 'tools/' + name)) for name in TOOL_FILES}
    report = dict(scope='A01 captured authority and persistent boot lineage',
                  status='RUNNING', native_acceptance_status='NOT_RUN', boots={})
    previous, failed = None, False
    write_json(root / 'summary.json', report)
    caught = (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError)
    for name, mode in SCENARIOS:
        child = root / name
        if failed:
            child.mkdir()
            report['boots'][name] = dict(status='NOT_RUN', error='predecessor did not verify')
        else:
            try:
                raw = run_case(build, child, formatter, qemu, trusted, mode,
                               args.timeout, previous=previous, formal=True)
                receipt = preserve_evidence(child, ROOT, trusted, tool_hashes)
                require(raw['status'] == receipt['status'] == 'PASS',
                        raw.get('error', 'native A01 profile failed'))
                replay = verify_receipt(child, source_root=ROOT, qemu_source=trusted,
                                        formal=True)
                report['boots'][name] = dict(status='PASS', mode=mode, independent_replay=replay)
                previous = child
            except caught as error:
                failed = True
                child.mkdir(parents=True, exist_ok=True)
                report['boots'][name] = dict(status='FAIL', error=str(error))
                write_json(child / 'provenance-error.json', report['boots'][name])
        write_json(root / 'summary.json', report)
        print(name, report['boots'][name]['status'], report['boots'][name].get('error', ''), flush=True)
    report['status'] = 'FAIL' if failed else 'PASS'
    if not failed:
        try:
            report['independent_acceptance'] = verify_acceptance(root, source_root=ROOT,
                                                                qemu_source=trusted)
            report['native_acceptance_status'] = report['independent_acceptance']['native_acceptance_status']
        except caught as error:
            report.update(status='FAIL', error=str(error))
    write_json(root / 'summary.json', report)
    return int(report['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
