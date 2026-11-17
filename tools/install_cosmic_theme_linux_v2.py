#!/usr/bin/env python3
"""Install all 79 independently verified Linux-host-generated theme assets.

This distinct receipt does not substitute for missing legacy guest-generation
evidence. It can be copied intact into a combined catalog and revalidated;
the receipt binds the genuine retained origin, not the installation prefix.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

if __package__:
    from . import cosmic_theme_inputs_v2 as consumer
    from . import install_cosmic_settings_linux_v2 as atomic
else:
    import cosmic_theme_inputs_v2 as consumer
    import install_cosmic_settings_linux_v2 as atomic

producer = consumer.producer
ROOT = producer.ROOT
RECEIPT = 'cosmic-theme-linux-v2-assets.json'
KIND = 'cosmic-theme-linux-v2-assets'
STATUS = 'THEME_HOST_ASSETS_REVALIDATED_NOT_GUEST_RUN'
require, BuildError = producer.require, producer.BuildError
KEYS = {'schema_version', 'kind', 'status', 'origin', 'consumer_identity_sha256',
        'build_report_sha256', 'producer_sources', 'assets', 'bounds', 'commit', 'theme_version',
        'host_generation', 'guest_execution', 'reference_is_generation_proof', 'full_cosmic_complete'}


def sources():
    require(producer.plain(__file__) == ROOT / 'tools/install_cosmic_theme_linux_v2.py',
            'Use the reviewed installed Linux theme installer')
    return producer.provenance.producer_sources(ROOT / 'tools/install_cosmic_theme_linux_v2.py')


def identify(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def inputs(build_output):
    output = producer.plain(build_output)
    proof = consumer.validate_build(output)
    require(proof['kind'] == producer.KIND and proof['status'] == 'THEME_HOST_GENERATION_REVALIDATED_NOT_GUEST_RUN'
            and proof['build_output'] == str(output) and proof['host_generation'] is True
            and proof['guest_execution'] is False and proof['full_cosmic_complete'] is False
            and proof['reference_is_generation_proof'] is False and proof['commit'] == producer.COMMIT
            and type(proof['theme_version']) is int and proof['theme_version'] == 2,
            'Only complete genuinely generated host assets may be installed')
    require(proof['identity_sha256'] == producer.canonical({k: v for k, v in proof.items() if k != 'identity_sha256'}),
            'Invalid complete theme consumer proof identity')
    require(proof['assets'] == producer.reference_assets()['assets']
            and proof['bounds'] == consumer.bounds(proof['assets'])
            and proof['bounds']['asset_files'] == 79 and proof['bounds']['asset_bytes'] == 34654,
            'Installation requires all 39 dark keys, 39 light keys and the full upstream license')
    return proof


def verify_files(prefix, assets):
    for row in assets:
        path = producer.plain(prefix / 'rootfs' / row['path'][1:])
        require(identify(producer.read(path, producer.reference.common.MAX_INPUT_BYTES))
                == {key: row[key] for key in ('bytes', 'sha256')}
                and path.stat().st_mode & 0o7777 == row['mode'],
                'Installed generated theme asset changed: ' + row['path'])


def validate_inputs(prefix):
    prefix = producer.plain(prefix)
    receipt_path = prefix / RECEIPT
    raw = producer.read(receipt_path, 2 * 1024 ** 2)
    receipt = producer.decode(raw)
    require(type(receipt) is dict and set(receipt) == KEYS
            and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
            and receipt['kind'] == KIND and receipt['status'] == 'INSTALLED_HOST_GENERATED_NOT_GUEST_RUN'
            and receipt['host_generation'] is True and receipt['guest_execution'] is False
            and receipt['reference_is_generation_proof'] is False and receipt['full_cosmic_complete'] is False
            and receipt['commit'] == producer.COMMIT and type(receipt['theme_version']) is int
            and receipt['theme_version'] == 2 and receipt_path.stat().st_mode & 0o7777 == 0o644,
            'Invalid distinct Linux theme installation receipt or guest claim')
    require(type(receipt['origin']) is dict and set(receipt['origin']) == {'build_output'}
            and receipt['producer_sources'] == sources(), 'Theme installation origin/source closure changed')
    proof = inputs(receipt['origin']['build_output'])
    require(receipt['consumer_identity_sha256'] == proof['identity_sha256']
            and receipt['build_report_sha256'] == proof['receipt_sha256']
            and producer.canonical(receipt['assets']) == producer.canonical(proof['assets'])
            and producer.canonical(receipt['bounds']) == producer.canonical(proof['bounds']),
            'Theme installed origin or complete inventory changed')
    verify_files(prefix, proof['assets'])
    require(producer.read(receipt_path, 2 * 1024 ** 2) == raw and receipt['producer_sources'] == sources(),
            'Theme receipt or installer changed during validation')
    return {'schema_version': 1, 'kind': KIND, 'status': STATUS, 'origin': receipt['origin'],
            'receipt': identify(raw), 'consumer_identity_sha256': proof['identity_sha256'],
            'build_report_sha256': proof['receipt_sha256'], 'producer_sources': receipt['producer_sources'],
            'protected_paths': proof['protected_paths'], 'assets': proof['assets'], 'bounds': proof['bounds'], 'commit': producer.COMMIT, 'theme_version': 2,
            'host_generation': True, 'guest_execution': False,
            'reference_is_generation_proof': False, 'full_cosmic_complete': False}


def install(build_output, output):
    build_output, output = producer.plain(build_output), producer.plain(output)
    require(not output.exists(), 'Preserving an existing theme installation')
    proof = inputs(build_output)
    protected = [producer.plain(path) for path in proof['protected_paths']]
    protected += [ROOT / name for name in ('tools', 'ports', 'kernel', 'crates')]
    require(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in protected),
            'Theme installation overlaps a preserved input')
    source_identity = sources()
    receipt = {'schema_version': 1, 'kind': KIND, 'status': 'INSTALLED_HOST_GENERATED_NOT_GUEST_RUN',
        'origin': {'build_output': str(build_output)}, 'consumer_identity_sha256': proof['identity_sha256'],
        'build_report_sha256': proof['receipt_sha256'], 'producer_sources': source_identity,
        'assets': proof['assets'], 'bounds': proof['bounds'], 'commit': producer.COMMIT, 'theme_version': 2,
        'host_generation': True, 'guest_execution': False,
        'reference_is_generation_proof': False, 'full_cosmic_complete': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        for row in proof['assets']:
            raw = producer.read(build_output / 'rootfs' / row['path'][1:], producer.reference.common.MAX_INPUT_BYTES)
            require(identify(raw) == {k: row[k] for k in ('bytes', 'sha256')},
                    'Generated source changed during installation')
            target = pending / 'rootfs' / row['path'][1:]
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o644)
        with (pending / RECEIPT).open('x') as stream:
            json.dump(receipt, stream, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        (pending / RECEIPT).chmod(0o644)
        validate_inputs(pending)
        require(sources() == source_identity and not output.exists() and not output.is_symlink(),
                'Installer changed or an installation appeared before publication')
        atomic.publish_directory(pending, output)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    install_parser = sub.add_parser('install')
    install_parser.add_argument('--build-output', type=Path, required=True)
    install_parser.add_argument('--output', type=Path, required=True)
    validate_parser = sub.add_parser('validate')
    validate_parser.add_argument('--prefix', type=Path, required=True)
    for command in (install_parser, validate_parser):
        command.add_argument('--native-lock', type=Path, default=producer.NATIVE_LOCK)
    args = parser.parse_args(argv)
    try:
        require(producer.plain(args.native_lock) == producer.plain(producer.NATIVE_LOCK),
                'Use the original shared native lease')
        with producer.native_session.native_lease(args.native_lock):
            result = install(args.build_output, args.output) if args.operation == 'install' else validate_inputs(args.prefix)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (BuildError, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
