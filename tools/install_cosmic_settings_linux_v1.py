#!/usr/bin/env python3
"""Atomically install a verified genuine settings ELF and its three licenses.

This performs full read-only build validation, never a compiler or guest run.
The original NotSupported boundaries are preserved in the installation receipt.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

if __package__:
    from . import cosmic_settings_inputs_v1 as inputs
else:
    import cosmic_settings_inputs_v1 as inputs

contract, require = inputs.contract, inputs.require
PROGRAM = inputs.PROGRAM
RECEIPT = 'cosmic-settings-linux-v1-origin.json'
RECEIPT_KEYS = {'schema_version', 'kind', 'status', 'build_output', 'inputs', 'producers', 'artifacts',
                'guest_execution', 'settings_verified', 'cosmic_session_ready', 'cosmic_session_verified'}


def artifacts(proof):
    result = [{'path': PROGRAM, 'guest_path': '/bin/cosmic-settings-daemon',
               'bytes': proof['executable']['bytes'], 'sha256': proof['executable']['sha256']}]
    result.extend({'path': row['path'], 'guest_path': '/' + row['path'].removeprefix('rootfs/'),
                   'bytes': row['bytes'], 'sha256': row['sha256']} for row in proof['licenses'])
    return result


def validate_inputs(prefix):
    prefix = inputs.selected(prefix, directory=True)
    receipt = contract.read_json(prefix / RECEIPT)
    require(set(receipt) == RECEIPT_KEYS and type(receipt['schema_version']) is int
            and receipt['schema_version'] == 1 and receipt['kind'] == contract.KIND
            and receipt['status'] == 'INSTALLED_NOT_RUN' and receipt['guest_execution'] == 'not performed'
            and receipt['settings_verified'] is False and receipt['cosmic_session_ready'] is False
            and receipt['cosmic_session_verified'] is False, 'Invalid settings installation receipt')
    require(receipt['producers'] == contract.files.producer_sources(__file__), 'Settings installer changed')
    proof = inputs.validate_build(receipt['build_output'])
    require(proof == receipt['inputs'] and receipt['artifacts'] == artifacts(proof),
            'Settings installation inputs changed')
    for row in receipt['artifacts']:
        path = prefix / contract.base.dependencies.relative_path(row['path'])
        data = contract.read_regular(path, 64 * 1024**2)
        require(len(data) == row['bytes'] and contract.files.sha(data) == row['sha256'],
                'Installed settings file changed: ' + row['path'])
        require(stat.S_IMODE(path.lstat().st_mode) == (0o755 if row['path'] == PROGRAM else 0o644),
                'Installed settings file mode changed')
    require(contract.elf.inspect_full_os_elf(prefix / PROGRAM, proof['resource_profile']) == proof['image_admission'],
            'Installed settings ELF admission changed')
    return {'status': 'VALIDATED_NOT_RUN', 'receipt': receipt, 'guest_execution': 'not performed',
            'settings_verified': False, 'cosmic_session_ready': False, 'cosmic_session_verified': False}


def install(build_output, output):
    proof = inputs.validate_build(build_output)
    output = contract.base.no_symlink_path(output)
    require(not output.exists(), 'Preserving existing settings installation')
    for name in proof['input_directories']:
        path = inputs.selected(name, directory=True)
        require(not output.is_relative_to(path) and not path.is_relative_to(output),
                'Settings installation overlaps a read-only input')
    for name in proof['hashes']:
        path = Path(name)
        require(not path.is_relative_to(output) and path != output, 'Settings installation overwrites an input')
    receipt = {'schema_version': 1, 'kind': contract.KIND, 'status': 'INSTALLED_NOT_RUN',
               'build_output': proof['build_output'], 'inputs': proof,
               'producers': contract.files.producer_sources(__file__), 'artifacts': artifacts(proof),
               'guest_execution': 'not performed', 'settings_verified': False,
               'cosmic_session_ready': False, 'cosmic_session_verified': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        sources = [Path(proof['program'])]
        sources.extend(Path(proof['build_output']) / 'source' / row['source_relative'] for row in proof['licenses'])
        for row, source in zip(receipt['artifacts'], sources):
            data = contract.read_regular(source, 64 * 1024**2)
            require(len(data) == row['bytes'] and contract.files.sha(data) == row['sha256'],
                    'Settings input changed during installation')
            target = pending / row['path']; target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            target.chmod(0o755 if row['path'] == PROGRAM else 0o644)
        with (pending / RECEIPT).open('x') as stream:
            json.dump(receipt, stream, indent=2, allow_nan=False); stream.write('\n')
            stream.flush(); os.fsync(stream.fileno())
        validate_inputs(pending)
        require(not output.exists() and not output.is_symlink(), 'Preserving concurrently created settings installation')
        pending.rename(output)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = install(args.build, args.output)
        print(json.dumps({key: receipt[key] for key in
                         ('status', 'artifacts', 'settings_verified', 'cosmic_session_ready')}, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print('Settings installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
