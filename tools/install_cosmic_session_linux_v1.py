#!/usr/bin/env python3
"""Install the independently admitted genuine Linux-v1 session and licenses.

The old session origin format and producers stay unchanged. A receipt binds
this installer, its transitive source closure, the original Linux-v1 consumer,
and the exact files copied. Installation is not guest/session verification.
CLI operations share the existing native lane because full input revalidation
reads the original compiler, SDK, source and archive evidence.
"""
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
    from . import cosmic_session_inputs_v1 as consumer
    from . import build_notification_probe as provenance
    from . import native_session
else:
    import cosmic_session_inputs_v1 as consumer
    import build_notification_probe as provenance
    import native_session

ROOT = consumer.ROOT
PROGRAM = 'cosmic-session.elf'
RECEIPT = 'cosmic-session-linux-v1-origin.json'
KIND = 'cosmic-session-linux-v1-installation'
NATIVE_LOCK = ROOT / 'artifacts/v017-cosmic-completion-20261116/native-session.lock'
LICENSES = {
    'LICENSE.md': 'rootfs/usr/share/doc/cosmic-session/LICENSE',
    'native-deps/launch-pad/LICENSE.md': 'rootfs/usr/share/doc/cosmic-session/launch-pad-LICENSE',
}
KEYS = {'schema_version', 'kind', 'status', 'origin', 'build_identity_sha256',
        'build_receipt_sha256', 'producer_sources', 'files', 'required_pages',
        'image_load_pages', 'guest_execution', 'cosmic_session_ready', 'full_cosmic_complete'}
require, BuildError = consumer.require, consumer.BuildError


def plain(value):
    selected = Path(value).absolute()
    require('..' not in selected.parts, 'Session installation path traversal')
    return consumer.base.no_symlink_path(selected)


def read(selected, limit=64 * 1024**2):
    return consumer.contract.elf._read_regular(plain(selected), limit)


def identify(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def producers():
    selected = plain(__file__)
    require(selected == ROOT / 'tools/install_cosmic_session_linux_v1.py',
            'Use the reviewed installed session installer')
    return provenance.producer_sources(selected)


def inputs(build_output):
    output = plain(build_output)
    validated = consumer.validate_build(output)
    require(validated['status'] == 'SESSION_BUILD_REVALIDATED_NOT_RUN'
            and validated['guest_execution'] is False and validated['cosmic_session_ready'] is False,
            'Only a preserved independently admitted session build may be installed')
    require(validated['output'] == str(output), 'Session consumer output mismatch')
    files = {PROGRAM: {**identify(read(output / PROGRAM)), 'mode': 0o755}}
    require(all(files[PROGRAM][key] == validated['executable'][key] for key in ('bytes', 'sha256')),
            'Session executable changed after independent admission')
    for relative, destination in LICENSES.items():
        files[destination] = {**identify(read(output / 'source' / relative, 2 * 1024**2)), 'mode': 0o644}
    require(len(files) == 3, 'Session installation must retain both full upstream licenses')
    report, _ = consumer.read_json(output / 'build-report.json')
    protected = [output, ROOT / 'tools', ROOT / 'ports', ROOT / 'kernel', ROOT / 'crates']
    protected += [plain(report[name]) for name in ('sysroot', 'source_cache', 'cargo_cache')]
    protected.append(plain(report['toolchain']['selection']['rust_root']))
    for row in report['toolchain']['tools'].values():
        # The original consumer permits genuine executable symlinks, e.g.
        # pkg-config -> pkgconf. Protect both names' directories without
        # imposing a new no-symlink rule on its already verified executable.
        tool = Path(row['path'])
        protected.append(plain(tool.parent))
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
    receipt = json.loads(receipt_raw, object_pairs_hook=consumer.base.ports.unique_object)
    require(type(receipt) is dict and set(receipt) == KEYS
            and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
            and receipt['kind'] == KIND and receipt['status'] == 'INSTALLED_NOT_RUN'
            and receipt['guest_execution'] is False and receipt['cosmic_session_ready'] is False
            and receipt['full_cosmic_complete'] is False,
            'Invalid Linux-v1 session installation receipt or verification claim')
    require(type(receipt['origin']) is dict and set(receipt['origin']) == {'build_output'},
            'Invalid session installation origin')
    require(receipt['producer_sources'] == producers(), 'Session installer source closure changed')
    validated, files, _ = inputs(receipt['origin']['build_output'])
    require(receipt['build_identity_sha256'] == validated['identity_sha256']
            and receipt['build_receipt_sha256'] == validated['receipt_sha256']
            and type(receipt['required_pages']) is int
            and receipt['required_pages'] == validated['required_pages']
            and type(receipt['image_load_pages']) is int
            and receipt['image_load_pages'] == validated['image_load_pages']
            and receipt['files'] == files, 'Installed session origin or file contract changed')
    for name, row in files.items():
        selected = prefix / name
        require(identify(read(selected)) == {key: row[key] for key in ('bytes', 'sha256')},
                'Installed session bytes changed: ' + name)
        require(selected.stat().st_mode & 0o7777 == row['mode'], 'Installed session file mode changed: ' + name)
    require(read(receipt_path, 2 * 1024**2) == receipt_raw
            and receipt['producer_sources'] == producers(), 'Session receipt or installer changed during validation')
    return {'schema_version': 1, 'status': 'SESSION_INSTALLATION_REVALIDATED_NOT_RUN',
            'receipt': identify(receipt_raw), 'build_identity_sha256': validated['identity_sha256'],
            'files': files, 'guest_execution': False, 'cosmic_session_ready': False,
            'full_cosmic_complete': False}


def install(build_output, output):
    output, build_output = plain(output), plain(build_output)
    require(not output.exists(), 'Preserving existing session installation')
    validated, files, protected = inputs(build_output)
    require(all(not output.is_relative_to(source) and not source.is_relative_to(output) for source in protected),
            'Session installation overlaps a protected input')
    source_identity = producers()
    receipt = {'schema_version': 1, 'kind': KIND, 'status': 'INSTALLED_NOT_RUN',
        'origin': {'build_output': str(build_output)},
        'build_identity_sha256': validated['identity_sha256'],
        'build_receipt_sha256': validated['receipt_sha256'], 'producer_sources': source_identity,
        'files': files, 'required_pages': validated['required_pages'],
        'image_load_pages': validated['image_load_pages'], 'guest_execution': False,
        'cosmic_session_ready': False, 'full_cosmic_complete': False}
    sources = {PROGRAM: build_output / PROGRAM,
               **{destination: build_output / 'source' / relative for relative, destination in LICENSES.items()}}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        for name, row in files.items():
            raw = read(sources[name])
            require(identify(raw) == {key: row[key] for key in ('bytes', 'sha256')},
                    'Session source changed during installation')
            target = pending / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(row['mode'])
        with (pending / RECEIPT).open('x') as stream:
            json.dump(receipt, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        validate_inputs(pending)
        require(producers() == source_identity, 'Session installer changed during installation')
        require(not output.exists() and not output.is_symlink(), 'Preserving concurrently created session installation')
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
        print(json.dumps(result, indent=2))
        return 0
    except (BuildError, OSError, ValueError, KeyError, TypeError) as error:
        print('Session installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
