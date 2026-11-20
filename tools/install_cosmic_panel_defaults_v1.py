#!/usr/bin/env python3
"""Install the complete pinned panel default schema and license in a fresh catalog."""
import argparse
import json
from pathlib import Path
import stat
import tempfile

import build_cosmic as base
import build_cosmic_comp_linux as common
import os_x86
import x86_64 as pc

SOURCE = base.ROOT / 'artifacts/cosmic-sources/cosmic-panel'
COMMIT = '3ce6ce1cec97669f91e809962d9446aaefe8a06e'
TREE = '664e1b3dec3d7790a80375a50361bcc09bd54988'
RECEIPT = 'cosmic-panel-defaults-v1.json'


def sources():
    identity = common.git_identity(SOURCE, COMMIT)
    pc.require(identity['git_tree'] == TREE, 'Pinned panel source tree changed')
    selected = {name: row for name, row in identity['files'].items()
                if name.startswith('data/default_schema/') or name == 'LICENSE.md'}
    pc.require(len(selected) == 46 and all(row['mode'] == '100644' for row in selected.values()),
               'Complete panel default schema/license closure changed')
    files = {}
    for name, row in selected.items():
        path = base.no_symlink_path(SOURCE / name)
        raw = pc.bounded_bytes(path, 64 * 1024)
        pc.require(pc.sha_bytes(raw) == row['sha256'], 'Working source differs from pinned panel object')
        guest = ('/usr/share/licenses/cosmic-panel-defaults/LICENSE.md' if name == 'LICENSE.md'
                 else '/usr/share/cosmic/' + name.removeprefix('data/default_schema/'))
        pc.require(len(guest.encode()) < 96, 'Panel default path exceeds existing guest bound')
        files['rootfs' + guest] = dict(source=str(path), bytes=len(raw), sha256=row['sha256'], mode=0o644)
    pc.require(sum(row['bytes'] for name, row in files.items() if '/licenses/' not in name) == 1072,
               'Complete upstream panel data byte count changed')
    return files


def validate_inputs(prefix):
    prefix = base.no_symlink_path(prefix)
    record = pc.read_json(prefix / RECEIPT)
    files = sources()
    pc.require(record['status'] == 'PANEL_DEFAULTS_INSTALLED_NOT_RUN' and record['schema_version'] == 1
               and record['commit'] == COMMIT and record['git_tree'] == TREE and record['files'] == files
               and record['producers'] == os_x86.producer_sources(__file__)
               and record['full_os_verified'] is False and record['panel_verified'] is False,
               'Panel defaults source/producer receipt changed')
    for name, row in files.items():
        path = base.no_symlink_path(prefix / name)
        pc.require(pc.sha(path) == row['sha256'] and path.stat().st_size == row['bytes']
                   and stat.S_IMODE(path.stat().st_mode) == row['mode'], 'Installed panel default changed')
    pc.require(os_x86.catalog_inputs(prefix) == record['catalog_inputs'], 'Panel defaults catalog changed')
    return record


def install(build, output):
    build, output = map(base.no_symlink_path, (build, output))
    manifest_path = build / 'build-manifest.json'
    manifest = pc.read_json(manifest_path)
    parent = base.no_symlink_path(manifest['sysroot'])
    original = os_x86.catalog_inputs(parent)
    pc.require(manifest['status'] == 'BUILT_NOT_RUN' and original == manifest['external_inputs'],
               'Parent build no longer binds its actual catalog')
    pc.require(not output.exists(), 'Preserving an existing panel defaults catalog')
    for source in (build, parent, SOURCE, base.ROOT / 'tools', base.ROOT / 'ports'):
        pc.require(not output.is_relative_to(source) and not source.is_relative_to(output), 'Output overlaps input')
    files = sources()
    pc.require(not original.keys() & files.keys(), 'Panel defaults would replace a parent input')
    expected = {**original, **{name: row['sha256'] for name, row in files.items()}}
    total = sum((parent / name).stat().st_size for name in original) + sum(row['bytes'] for row in files.values())
    pc.require(total <= 128 * 1024**2 and len(expected) <= 256, 'Existing core v1 catalog capacity exceeded')
    record = dict(schema_version=1, status='PANEL_DEFAULTS_INSTALLED_NOT_RUN', commit=COMMIT, git_tree=TREE,
                  base_build=str(build), base_manifest_sha256=pc.sha(manifest_path), files=files,
                  catalog_inputs=expected, raw_catalog_bytes=total, default_schema_files=45,
                  source_preserved=True, original_catalog_preserved=True,
                  producers=os_x86.producer_sources(__file__), panel_verified=False, full_os_verified=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary).resolve()
        for name, digest in original.items():
            source = parent / name
            raw = pc.bounded_bytes(source, 64 * 1024**2)
            pc.require(pc.sha_bytes(raw) == digest, 'Parent input changed during copy')
            path = pending / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(stat.S_IMODE(source.stat().st_mode))
        for path in sorted(parent.glob('*.json')):
            pc.require(path.name != RECEIPT, 'Panel defaults already installed in parent')
            (pending / path.name).write_bytes(pc.bounded_bytes(base.no_symlink_path(path), 4 * 1024**2))
        for name, row in files.items():
            raw = pc.bounded_bytes(Path(row['source']), 64 * 1024)
            pc.require(pc.sha_bytes(raw) == row['sha256'], 'Panel source changed during copy')
            path = pending / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(row['mode'])
        pc.write_json(pending / RECEIPT, record)
        validate_inputs(pending)
        pc.require(os_x86.catalog_inputs(parent) == original and pc.read_json(manifest_path) == manifest,
                   'Parent catalog/build changed during installation')
        pc.require(not output.exists(), 'Panel defaults output appeared during publication')
        pending.rename(output)
    return {key: record[key] for key in ('status', 'default_schema_files', 'raw_catalog_bytes')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-build', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--validate-prefix', type=Path)
    args = parser.parse_args()
    if args.validate_prefix:
        pc.require(not args.base_build and not args.output, 'Choose installation or validation')
        report = validate_inputs(args.validate_prefix)
        print(report['status'])
    else:
        pc.require(args.base_build is not None and args.output is not None, 'Provide base build and fresh output')
        print(json.dumps(install(args.base_build, args.output), indent=2))


if __name__ == '__main__':
    main()
