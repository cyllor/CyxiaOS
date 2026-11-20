#!/usr/bin/env python3
"""Add complete pinned libX11 Compose data to a manifest-bound OS catalog.

Uses the independently rebuilt notifications SDK. Preserves the v1 installer,
all parent catalog bytes/modes, complete upstream rules and license. No builds
or guest execution; output is a fresh, atomically published catalog.
"""
import argparse
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile

import build_cosmic as base
import install_cosmic_locale_v1 as policy
import os_x86

SDK = base.ROOT / 'artifacts/v017-notifications-sdk-v2'
RECEIPT = 'cosmic-locale-assets-v2.json'
PINNED = {
    **policy.PINNED,
    'sdk_origin': {'bytes': 693961, 'sha256': '916621b6952f8296d699aa11c5f83f9e4421b5e2c7455b26cac5e158587281a1'},
    'xorg_report': {'bytes': 11380, 'sha256': 'c5ae5238af98b357b5199ae9257b9f162a9219de9c6a26ebab4c62e058abc56e'},
    'archive_provenance': {'bytes': 604, 'sha256': '529def776eae5363ca2e3c716b390e89db2e293c61c868dc80046f0e50794f2c'},
}
FILES = {key: dict(value) for key, value in policy.FILES.items()}
FILES['/usr/share/X11/locale/en_US.UTF-8/Compose'].update(
    bytes=456142, sha256='556b31b41770077bef86e67dfc96855d543020cc1a83c6ecbccc5044a8e30a96')
require, read, identity = policy.require, policy.read_regular, policy.identity


def verify_sources():
    paths = dict(sdk_origin=SDK / 'runtime-sdk-origin.json',
                 xorg_report=SDK / 'xorg-bootstrap-report.json', xorg_manifest=policy.MANIFEST,
                 archive=policy.ARCHIVE, archive_provenance=policy.PROVENANCE)
    raw = {name: read(path, policy.MAX_SOURCE_BYTES) for name, path in paths.items()}
    require(all(identity(raw[name]) == PINNED[name] for name in paths), 'Locale v2 source identity changed')
    origin, report, manifest, provenance = (policy.document(raw[name]) for name in
        ('sdk_origin', 'xorg_report', 'xorg_manifest', 'archive_provenance'))
    require(origin['status'] == 'NOTIFICATION_SDK_ASSEMBLED_NOT_RUN'
            and origin['architecture'] == 'x86_64' and origin['guest_execution'] is False
            and origin['parent_preserved'] is True
            and origin['reports'][str(paths['xorg_report'])] == PINNED['xorg_report']['sha256'],
            'Rebuilt SDK does not bind its actual X.Org report')
    selected = [row for row in manifest['packages'] if row['name'] == 'libX11']
    require(len(selected) == 1 and selected[0]['version'] == policy.PACKAGE['version']
            and selected[0]['expected_sha256'] == policy.ARCHIVE_SHA256
            and selected[0]['source_url'] == policy.PACKAGE['source_url']
            and selected[0]['archive_root'] == 'libX11-1.8.12'
            and selected[0]['license_file'] == 'COPYING', 'Different libX11 package selected')
    require(provenance['identity'] == policy.PACKAGE
            and provenance['sha256'] == policy.ARCHIVE_SHA256
            and provenance['bytes'] == PINNED['archive']['bytes']
            and provenance['retrieved_from'] == policy.PACKAGE['source_url'], 'Archive provenance changed')
    require([row for row in report['sources'] if row.get('identity', {}).get('name') == 'libX11']
            == [{'status': 'verified', 'directory': str(policy.ARCHIVE_DIR), **provenance}]
            and report['architecture'] == 'x86_64'
            and report['target_triple'] == 'x86_64-unknown-linux-musl', 'X.Org archive binding changed')
    contents = {}
    for guest, row in FILES.items():
        path = SDK / row['source_group'] / row['source_relative']
        content = read(path)
        expected = {key: row[key] for key in ('bytes', 'sha256')}
        require(identity(content) == expected and stat.S_IMODE(path.stat().st_mode) == 0o644,
                'Locale file bytes or mode changed: ' + guest)
        if row['source_group'] == 'sysroot':
            require(origin['sysroot_tree']['files'][row['source_relative']] == expected,
                    'Locale file no longer matches rebuilt SDK origin')
        contents[guest] = content
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw['archive']), mode='r:xz') as archive:
        for relative, expected in policy.ARCHIVE_MEMBERS.items():
            entries = [entry for entry in archive.getmembers() if entry.name == 'libX11-1.8.12/' + relative]
            require(len(entries) == 1 and entries[0].isfile() and entries[0].size == expected['bytes'],
                    'Upstream locale archive member changed')
            with archive.extractfile(entries[0]) as stream:
                content = stream.read(policy.MAX_FILE_BYTES + 1)
            require(identity(content) == expected, 'Upstream locale member identity changed')
            members[relative] = content
    compose = contents['/usr/share/X11/locale/en_US.UTF-8/Compose']
    rules = lambda data: [line for line in data.splitlines() if line.lstrip().startswith(b'<')]
    require(len(rules(compose)) == 5145 and rules(compose) == rules(members['nls/en_US.UTF-8/Compose.pre']),
            'Complete generated Compose rules differ from genuine upstream bytes')
    require(not any(line.lstrip().split(maxsplit=1)[:1] == [b'include'] for line in compose.splitlines()),
            'Compose closure unexpectedly needs other files')
    rows = lambda data: [line.split()[:2] for line in data.splitlines()
                         if line.strip() and not line.lstrip().startswith(b'#')]
    require([b'en_US.UTF-8/Compose', b'en_US.UTF-8']
            in rows(contents['/usr/share/X11/locale/compose.dir']), 'Missing Compose mapping')
    require(all([alias, b'en_US.UTF-8'] in rows(contents['/usr/share/X11/locale/locale.alias'])
                for alias in (b'C.UTF-8', b'C.utf8', b'en_US.utf8')), 'Missing locale aliases')
    require(contents['/usr/share/licenses/libX11/COPYING'] == members['COPYING'], 'Incomplete libX11 license')
    return contents, {name: dict(path=str(path), **PINNED[name]) for name, path in paths.items()}


def validate_inputs(prefix):
    prefix = base.no_symlink_path(prefix)
    record = policy.document(read(prefix / RECEIPT))
    contents, sources = verify_sources()
    require(record['status'] == 'LOCALE_CATALOG_ASSEMBLED_NOT_RUN'
            and record['schema_version'] == 2 and record['sources'] == sources
            and record['files'] == FILES and record['compose_rules'] == 5145
            and record['asset_bytes'] == sum(map(len, contents.values()))
            and record['guest_locale_loading_observed'] is False
            and record['producers'] == os_x86.producer_sources(__file__),
            'Locale catalog source/producer receipt changed')
    for guest, content in contents.items():
        path = prefix / 'rootfs' / guest.lstrip('/')
        require(read(path) == content and stat.S_IMODE(path.stat().st_mode) == 0o644,
                'Installed locale bytes or mode changed')
    require(os_x86.catalog_inputs(prefix) == record['catalog_inputs'], 'Locale catalog changed')
    return record


def install(build, output):
    build, output = map(base.no_symlink_path, (build, output))
    manifest_path = build / 'build-manifest.json'
    manifest = base.load_json(manifest_path)
    parent = base.no_symlink_path(manifest['sysroot'])
    original = os_x86.catalog_inputs(parent)
    require(manifest['status'] == 'BUILT_NOT_RUN' and original == manifest['external_inputs'],
            'Parent build no longer binds its catalog')
    require(not output.exists(), 'Preserving existing locale catalog')
    for source in (parent, build, SDK, policy.ARCHIVE_DIR, base.ROOT / 'ports', base.ROOT / 'tools'):
        require(not output.is_relative_to(source) and not source.is_relative_to(output), 'Output overlaps source')
    contents, sources = verify_sources()
    added = {'rootfs/' + guest.lstrip('/'): identity(content)['sha256'] for guest, content in contents.items()}
    require(not original.keys() & added.keys(), 'Locale addition would overwrite parent input')
    expected = {**original, **added}
    size = sum((parent / name).stat().st_size for name in original) + sum(map(len, contents.values()))
    require(size <= 128 * 1024**2 and len(expected) <= 256, 'Explicit core catalog capacity exceeded')
    record = dict(schema_version=2, status='LOCALE_CATALOG_ASSEMBLED_NOT_RUN',
                  base_build=str(build), base_manifest_sha256=base.digest(manifest_path),
                  sources=sources, files=FILES, catalog_inputs=expected, raw_catalog_bytes=size,
                  compose_rules=5145, asset_bytes=sum(map(len, contents.values())),
                  producers=os_x86.producer_sources(__file__),
                  original_catalog_preserved=True, guest_locale_loading_observed=False,
                  full_os_verified=False, cosmic_session_verified=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary).resolve()
        for name, digest in original.items():
            path = parent / name
            content = read(path, 64 * 1024**2)
            require(identity(content)['sha256'] == digest, 'Parent input changed while copying')
            target = pending / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(stat.S_IMODE(path.stat().st_mode))
        # Retain parent receipts outside the kernel's ELF/rootfs input catalog.
        for path in sorted(parent.glob('*.json')):
            require(path.name != RECEIPT, 'Parent already has a locale v2 receipt')
            (pending / path.name).write_bytes(read(path, 4 * 1024**2))
        for guest, content in contents.items():
            target = pending / 'rootfs' / guest.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o644)
        (pending / RECEIPT).write_text(json.dumps(record, indent=2) + '\n')
        validate_inputs(pending)
        require(os_x86.catalog_inputs(parent) == original and base.load_json(manifest_path) == manifest,
                'Parent catalog/build changed during installation')
        require(not output.exists(), 'Locale output appeared during publication')
        pending.rename(output)
    return {key: record[key] for key in ('status', 'compose_rules', 'asset_bytes', 'raw_catalog_bytes')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-build', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--validate-prefix', type=Path)
    args = parser.parse_args()
    if args.validate_prefix:
        require(not args.base_build and not args.output, 'Choose validation or installation')
        record = validate_inputs(args.validate_prefix)
        print(json.dumps({key: record[key] for key in ('status', 'compose_rules', 'asset_bytes')}, indent=2))
    else:
        require(args.base_build is not None and args.output is not None, 'Provide base build and fresh output')
        print(json.dumps(install(args.base_build, args.output), indent=2))


if __name__ == '__main__':
    main()
