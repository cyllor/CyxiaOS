#!/usr/bin/env python3
"""Run and independently replay the A01 boot-regression evidence matrix.

No catalogue is modified. The underlying runner alone owns process creation and
preboot injection. This wrapper preserves the reviewed tools/build inputs and
adds a fail-closed provenance replay; it never edits captured memory or serial.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from check_elf import symbol
from check_prototype_evidence import safe_path, sha256
from run_v13_boot_recovery import ROOT, run_case, write_json
from verify_v13_model import loaded_bytes
from verify_v13_boot_recovery import MODES, require
from verify_v13_boot_receipt import BUILD_INPUTS, TOOL_FILES, verify_matrix, verify_receipt


def preserve_and_verify(output, project, trusted_qemu, original_tool_hashes):
    producer = output / 'summary.json'
    original = producer.read_bytes()
    (output / 'producer-summary.json').write_bytes(original)
    receipt = json.loads(original)
    for name in TOOL_FILES:
        source = safe_path(project, 'tools/' + name)
        require(sha256(source) == original_tool_hashes[name], 'tool changed during native run: ' + name)
        target = output / 'tooling' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for name in BUILD_INPUTS:
        target = output / 'build-inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_path(project, name), target)
    image = (output / 'node-a.elf').read_bytes()
    model = symbol(image, 'A02_BOOT_MODEL')
    (output / 'model.bin').write_bytes(loaded_bytes(image, model['va'], model['size']))
    tools = json.loads((output / 'tools.json').read_text())
    # This is the explicit runner argument, never a path selected by a receipt.
    require(tools.get('qemu_pmu_patch_attested') is True, 'pinned PMU-patched QEMU required')
    tools['qemu_source_directory'] = str(trusted_qemu)
    write_json(output / 'tools.json', tools)
    receipt.update(receipt_schema=1, test_id='A01_BOOT_REGRESSION',
                   native_acceptance_status='NOT_RUN', native_execution_verified=False,
                   runtime_truth_attested=False, full_v13_acceptance=False)
    receipt['files'] = {
        path.relative_to(output).as_posix(): dict(bytes=path.stat().st_size, sha256=sha256(path))
        for path in sorted(output.rglob('*')) if path.is_file() and path != producer
    }
    write_json(producer, receipt)
    replay = verify_receipt(output, source_root=project, qemu_source=trusted_qemu)
    receipt['independent_replay'] = replay
    receipt['native_execution_verified'] = True
    write_json(producer, receipt)
    return replay


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'output', 'formatter', 'qemu', 'qemu-source'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args(argv)
    require(5 <= args.timeout <= 120, 'invalid bounded timeout')
    build = args.build.resolve(strict=True)
    formatter = args.formatter.resolve(strict=True)
    trusted_qemu = args.qemu_source.resolve(strict=True)
    qemu = args.qemu.resolve(strict=True)
    require(qemu == (trusted_qemu / 'build/qemu-system-aarch64').resolve(strict=True),
            'emulator differs from the explicit trusted source build')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    project = ROOT.resolve(strict=True)
    tool_hashes = {name: sha256(safe_path(project, 'tools/' + name)) for name in TOOL_FILES}
    report = dict(scope='A01 native boot regression, not formal A01 acceptance',
                  status='RUNNING', native_acceptance_status='NOT_RUN',
                  native_execution_verified=False, runtime_truth_attested=False,
                  full_v13_acceptance=False, cases={})
    write_json(root / 'summary.json', report)
    for name, mode in MODES.items():
        directory = root / name
        try:
            raw = run_case(build, directory, formatter, qemu, trusted_qemu, mode, args.timeout)
            require(raw.get('status') == 'PASS', raw.get('error', 'native boot regression failed'))
            replay = preserve_and_verify(directory, project, trusted_qemu, tool_hashes)
            report['cases'][name] = dict(status='PASS', independent_replay=replay,
                                         native_acceptance_status='NOT_RUN')
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
            report['cases'][name] = dict(status='FAIL', error=str(error),
                                         native_execution_verified=False,
                                         native_acceptance_status='NOT_RUN')
            directory.mkdir(parents=True, exist_ok=True)
            write_json(directory / 'provenance-error.json', report['cases'][name])
        write_json(root / 'summary.json', report)
    report['status'] = 'PASS' if all(case['status'] == 'PASS' for case in report['cases'].values()) else 'FAIL'
    if report['status'] == 'PASS':
        try:
            report['independent_matrix'] = verify_matrix(root, source_root=project, qemu_source=trusted_qemu)
            report['native_execution_verified'] = True
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
            report['status'] = 'FAIL'
            report['error'] = str(error)
    write_json(root / 'summary.json', report)
    print(json.dumps({name: case['status'] for name, case in report['cases'].items()}, indent=2))
    return int(report['status'] != 'PASS')


if __name__ == '__main__':
    sys.exit(main())
