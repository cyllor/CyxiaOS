#!/usr/bin/env python3
"""Combine a historical OS input catalog with independently admitted notifications.

All original image/asset bytes and modes are preserved. The explicit core v1
profile has a 128 MiB raw ROM catalog; per-process runtime/AI limits are separate.
No kernel, compiler or guest executes here. Publication is fresh and atomic.
"""
import argparse
import json
from pathlib import Path
import tempfile

import build_cosmic as base
import install_cosmic_notifications_static_v1 as notifications
import os_x86

MAX_BYTES = 128 * 1024**2
MAX_ENTRIES = 256
CORE = ('cosmic-comp', 'cosmic-session', 'cosmic-settings-daemon',
        'cosmic-notifications', 'cosmic-panel')


def assemble(build, installation, output):
    build, installation, output = map(base.no_symlink_path, (build, installation, output))
    notifications.require(not output.exists(), 'Preserving existing core catalog')
    manifest_path = build / 'build-manifest.json'
    manifest = base.load_json(manifest_path)
    parent = base.no_symlink_path(manifest['sysroot'])
    for protected in (build, installation, parent, base.ROOT / 'ports'):
        notifications.require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                           'Core catalog output overlaps an input')
    original = os_x86.catalog_inputs(parent)
    notifications.require(manifest['status'] == 'BUILT_NOT_RUN'
                       and original == manifest['external_inputs'],
                       'Historical OS input catalog changed')
    admitted = notifications.validate_inputs(installation)
    receipt = admitted['receipt']
    sources = {name: parent / name for name in original}
    hashes = dict(original)
    for item in receipt['artifacts']:
        name = item['path']
        notifications.require(name not in sources, 'Notification addition would replace an original input')
        sources[name] = installation / name
        hashes[name] = item['sha256']
    notifications.require(all(name + '.elf' in sources for name in CORE), 'Missing genuine core image')
    identities = {}
    for name, path in sources.items():
        path = base.no_symlink_path(path)
        size = path.stat().st_size
        guest = ('/bin/' + name.removesuffix('.elf') if name.endswith('.elf')
                 else '/' + name.removeprefix('rootfs/'))
        notifications.require(0 <= size <= 64 * 1024**2 and len(guest.encode()) < 96,
                           'Core catalog file/path bound')
        identities[name] = dict(bytes=size, sha256=hashes[name], mode=path.stat().st_mode & 0o777)
    total = sum(item['bytes'] for item in identities.values())
    notifications.require(total <= MAX_BYTES and len(sources) <= MAX_ENTRIES,
                       'Core v1 raw catalog exceeds its explicit capacity')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary).resolve()
        for name, source in sources.items():
            data = notifications.legacy.common.read_regular(source, 64 * 1024**2)
            expected = identities[name]
            notifications.require(len(data) == expected['bytes'] and notifications.static.sha(data) == expected['sha256'],
                               'Core catalog source changed during copy')
            destination = pending / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as stream:
                stream.write(data)
            destination.chmod(expected['mode'])
        origin_name = notifications.RECEIPT
        data = notifications.legacy.common.read_regular(installation / origin_name, 64 * 1024**2)
        (pending / origin_name).write_bytes(data)
        (pending / origin_name).chmod(0o644)
        notifications.require(os_x86.catalog_inputs(pending) == hashes, 'Copied core catalog differs')
        notifications.validate_inputs(pending)
        notifications.require(os_x86.catalog_inputs(parent) == original
                           and base.load_json(manifest_path) == manifest,
                           'Original input catalog/build manifest changed during assembly')
        for name, expected in identities.items():
            path = pending / name
            notifications.require(path.stat().st_mode & 0o777 == expected['mode'], 'Copied catalog mode changed')
        record = dict(schema_version=1, status='CORE_CATALOG_ASSEMBLED_NOT_RUN',
                      profile='cosmic-core-services-v1', raw_catalog_bytes=total,
                      max_catalog_bytes=MAX_BYTES, entries=len(sources), max_entries=MAX_ENTRIES,
                      base_build=str(build), base_manifest_sha256=base.digest(manifest_path),
                      notification_installation=str(installation),
                      notification_receipt_sha256=base.digest(installation / origin_name),
                      files=identities, producer_sources=os_x86.producer_sources(__file__),
                      original_catalog_preserved=True, guest_execution=False,
                      full_os_verified=False, cosmic_session_verified=False)
        (pending / 'core-catalog-origin.json').write_text(json.dumps(record, indent=2) + '\n')
        notifications.require(not output.exists(), 'Catalog output appeared during assembly')
        pending.rename(output)
    return {key: record[key] for key in ('status', 'profile', 'raw_catalog_bytes',
                                        'entries', 'original_catalog_preserved')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--notifications', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(assemble(args.base_build, args.notifications, args.output), indent=2))


if __name__ == '__main__':
    main()
