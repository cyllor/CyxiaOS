#!/usr/bin/env python3
"""Install the independently admitted genuine Linux-v2 settings build.

This version uses a distinct installation receipt and preserves the original
v1/v2 installers, Linux-v1 build producer and read-only consumer. The new receipt
binds the complete original consumer proof, installer source closure, ELF,
three upstream licenses and the original explicit service boundaries.
Installation and validation do not establish guest or session readiness.
CLI operations share the native lease for complete input revalidation.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

if __package__:
    from . import cosmic_settings_inputs_v2 as consumer
    from . import build_notification_probe as provenance
    from . import native_session
else:
    import cosmic_settings_inputs_v2 as consumer
    import build_notification_probe as provenance
    import native_session

contract = consumer.contract
ROOT = contract.ROOT
PROGRAM = consumer.PROGRAM
RECEIPT = 'cosmic-settings-linux-v2-installation.json'
KIND = 'cosmic-settings-linux-v2-installation'
NATIVE_LOCK = ROOT / 'artifacts/v017-cosmic-completion-20261116/native-session.lock'
LICENSES = {
    'LICENSE': 'rootfs/usr/share/doc/cosmic-settings-daemon/LICENSE',
    'native-deps/cosmic-comp-config/LICENSE': 'rootfs/usr/share/doc/cosmic-settings-daemon/cosmic-comp-config-LICENSE',
    'native-deps/wayland-sys/LICENSE.txt': 'rootfs/usr/share/doc/cosmic-settings-daemon/wayland-sys-LICENSE',
}
KEYS = {'schema_version', 'kind', 'status', 'origin', 'consumer_identity_sha256',
        'build_report_sha256', 'producer_sources', 'files', 'required_pages',
        'image_load_pages', 'boundary', 'guest_execution', 'settings_verified',
        'cosmic_session_ready', 'cosmic_session_verified', 'full_cosmic_complete'}
require, BuildError = consumer.require, consumer.BuildError


def plain(value):
    selected = Path(value).absolute()
    require('..' not in selected.parts, 'Settings installation path traversal')
    return consumer.base.no_symlink_path(selected)


def read(selected, limit=64 * 1024**2):
    return contract.read_regular(plain(selected), limit)


def identify(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def producers():
    selected = plain(__file__)
    require(selected == ROOT / 'tools/install_cosmic_settings_linux_v3.py',
            'Use the reviewed installed settings v3 installer')
    return provenance.producer_sources(selected)


def inputs(build_output):
    output = plain(build_output)
    validated = consumer.validate_build(output)
    require(validated['status'] == 'VALIDATED_NOT_RUN' and validated['kind'] == contract.KIND
            and validated['guest_execution'] == 'not performed'
            and validated['settings_verified'] is False
            and validated['cosmic_session_ready'] is False
            and validated['cosmic_session_verified'] is False,
            'Only a preserved independently admitted settings build may be installed')
    require(validated['build_output'] == str(output)
            and validated['program'] == str(output / PROGRAM)
            and validated['executable']['file'] == PROGRAM,
            'Settings consumer output mismatch')
    admission = validated['image_admission']
    require(admission['executable'] == validated['executable']
            and all(type(admission[key]) is int and admission[key] > 0
                    for key in ('required_pages', 'image_load_pages')),
            'Invalid settings image admission')
    files = {PROGRAM: {**identify(read(output / PROGRAM, validated['resource_profile']['max_elf_bytes'])),
                       'mode': 0o755}}
    require(all(files[PROGRAM][key] == validated['executable'][key] for key in ('bytes', 'sha256')),
            'Settings executable changed after independent admission')
    licenses = []
    for relative, destination in LICENSES.items():
        identity = identify(read(output / 'source' / relative, 2 * 1024**2))
        files[destination] = {**identity, 'mode': 0o644}
        licenses.append({'source_relative': relative, 'path': destination, **identity})
    require(validated['licenses'] == licenses and len(files) == 4,
            'Settings installation must retain all three full independently verified upstream licenses')

    report_path = output / 'build-report.json'
    report_raw = read(report_path)
    require(identify(report_raw)['sha256'] == validated['hashes'][str(report_path)],
            'Settings build report changed after independent admission')
    report = json.loads(report_raw, object_pairs_hook=contract.files.no_duplicates)
    protected = [output, ROOT / 'tools', ROOT / 'ports', ROOT / 'kernel', ROOT / 'crates']
    protected += [plain(path) for path in validated['input_directories']]
    protected += [plain(report[name]) for name in ('sysroot', 'source_cache', 'cargo_cache')]
    protected.append(plain(report['toolchain']['selection']['rust_root']))
    for name in validated['hashes']:
        path = Path(name)
        require(path.is_absolute() and '..' not in path.parts, 'Invalid settings bound input path')
        # Hashes can name legitimate executable symlinks. Their declared
        # directories stay protected without rejecting the final symlink.
        protected.append(plain(path.parent))
    for row in report['toolchain']['tools'].values():
        tool = Path(row['path'])
        protected.append(plain(tool.parent))
        # An unavailable optional tool has no existing target to resolve.
        if row['available'] is True:
            protected.append(plain(tool.resolve(strict=True).parent))
    return validated, files, protected


def publish_directory(pending, output):
    """Linux atomic no-replace publication, including a concurrent empty dir."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise OSError(errno.ENOSYS, 'Atomic no-replace directory publication is unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(pending), -100, os.fsencode(output), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(output))


def validate_inputs(prefix):
    prefix = plain(prefix)
    receipt_path = prefix / RECEIPT
    receipt_raw = read(receipt_path, 2 * 1024**2)
    receipt = json.loads(receipt_raw, object_pairs_hook=contract.files.no_duplicates)
    require(type(receipt) is dict and set(receipt) == KEYS
            and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
            and receipt['kind'] == KIND and receipt['status'] == 'INSTALLED_NOT_RUN'
            and receipt['guest_execution'] == 'not performed'
            and receipt['settings_verified'] is False and receipt['cosmic_session_ready'] is False
            and receipt['cosmic_session_verified'] is False and receipt['full_cosmic_complete'] is False,
            'Invalid settings v2 installation receipt or verification claim')
    require(type(receipt['origin']) is dict and set(receipt['origin']) == {'build_output'},
            'Invalid settings installation origin')
    require(receipt['producer_sources'] == producers(), 'Settings installer source closure changed')
    validated, files, protected = inputs(receipt['origin']['build_output'])
    admission = validated['image_admission']
    report_sha256 = validated['hashes'][str(Path(validated['build_output']) / 'build-report.json')]
    require(receipt['consumer_identity_sha256'] == contract.canonical(validated)
            and receipt['build_report_sha256'] == report_sha256
            and type(receipt['required_pages']) is int
            and receipt['required_pages'] == admission['required_pages']
            and type(receipt['image_load_pages']) is int
            and receipt['image_load_pages'] == admission['image_load_pages']
            and contract.canonical(receipt['boundary']) == contract.canonical(validated['boundary'])
            and contract.canonical(receipt['files']) == contract.canonical(files),
            'Installed settings origin or file contract changed')
    for name, row in files.items():
        selected = prefix / name
        require(identify(read(selected)) == {key: row[key] for key in ('bytes', 'sha256')},
                'Installed settings bytes changed: ' + name)
        require(selected.stat().st_mode & 0o7777 == row['mode'],
                'Installed settings file mode changed: ' + name)
    require(contract.elf.inspect_full_os_elf(prefix / PROGRAM, validated['resource_profile']) == admission,
            'Installed settings ELF admission changed')
    require(read(receipt_path, 2 * 1024**2) == receipt_raw
            and receipt['producer_sources'] == producers(),
            'Settings receipt or installer changed during validation')
    return {'schema_version': 1, 'kind': KIND, 'status': 'SETTINGS_INSTALLATION_REVALIDATED_NOT_RUN',
            'protected_paths': sorted({str(path) for path in protected}),
            'receipt': identify(receipt_raw), 'consumer_identity_sha256': contract.canonical(validated),
            'build_report_sha256': report_sha256, 'files': files,
            'required_pages': admission['required_pages'], 'image_load_pages': admission['image_load_pages'],
            'boundary': validated['boundary'], 'guest_execution': 'not performed',
            'settings_verified': False, 'cosmic_session_ready': False,
            'cosmic_session_verified': False, 'full_cosmic_complete': False}


def install(build_output, output):
    output, build_output = plain(output), plain(build_output)
    require(not output.exists(), 'Preserving existing settings installation')
    validated, files, protected = inputs(build_output)
    require(all(not output.is_relative_to(source) and not source.is_relative_to(output) for source in protected),
            'Settings installation overlaps a protected input')
    source_identity = producers()
    admission = validated['image_admission']
    receipt = {'schema_version': 1, 'kind': KIND, 'status': 'INSTALLED_NOT_RUN',
        'origin': {'build_output': str(build_output)},
        'consumer_identity_sha256': contract.canonical(validated),
        'build_report_sha256': validated['hashes'][str(build_output / 'build-report.json')],
        'producer_sources': source_identity, 'files': files,
        'required_pages': admission['required_pages'], 'image_load_pages': admission['image_load_pages'],
        'boundary': validated['boundary'], 'guest_execution': 'not performed',
        'settings_verified': False, 'cosmic_session_ready': False,
        'cosmic_session_verified': False, 'full_cosmic_complete': False}
    sources = {PROGRAM: build_output / PROGRAM,
               **{destination: build_output / 'source' / relative for relative, destination in LICENSES.items()}}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        for name, row in files.items():
            raw = read(sources[name])
            require(identify(raw) == {key: row[key] for key in ('bytes', 'sha256')},
                    'Settings source changed during installation')
            target = pending / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(row['mode'])
        with (pending / RECEIPT).open('x') as stream:
            json.dump(receipt, stream, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        validate_inputs(pending)
        require(producers() == source_identity, 'Settings installer changed during installation')
        require(not output.exists() and not output.is_symlink(),
                'Preserving concurrently created settings installation')
        publish_directory(pending, output)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-lock', type=Path, default=NATIVE_LOCK)
    commands = parser.add_subparsers(dest='operation', required=True)
    create = commands.add_parser('install')
    create.add_argument('--build', type=Path, required=True)
    create.add_argument('--output', type=Path, required=True)
    check = commands.add_parser('validate')
    check.add_argument('--prefix', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with native_session.native_lease(plain(args.native_lock)):
            native_session.idle_native_host()
            result = install(args.build, args.output) if args.operation == 'install' else validate_inputs(args.prefix)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (BuildError, OSError, ValueError, KeyError, TypeError) as error:
        print('Settings installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
