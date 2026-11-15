#!/usr/bin/env python3
"""Export the pinned compositor and apply its ordered, hash-bound port series.

This does not resolve Cargo, compile the compositor, or run a desktop. The
original Git checkout is read-only; incomplete output never becomes a source
directory that a later build can mistake for a successful preparation.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

try:
    from . import build_cosmic as build
    from . import cosmic_dependencies as dependencies
    from . import cosmic_ports as ports
except ImportError:
    import build_cosmic as build
    import cosmic_dependencies as dependencies
    import cosmic_ports as ports

ROOT = ports.ROOT
SERIES = ROOT / 'ports/cosmic/native-comp/series.json'
SOURCE = ports.CACHE / 'cosmic-comp-epoch'


def bound_path(root, name):
    relative = dependencies.relative_path(name)
    path = build.no_symlink_path(Path(root).resolve() / relative)
    if not path.is_file():
        raise build.CosmicBuildError('bound input is absent: ' + str(path))
    return path


def load_series(path):
    series = build.load_json(path)
    if series.get('schema_version') != 1 or series.get('component') != 'cosmic-comp':
        raise build.CosmicBuildError('unsupported compositor series')
    ports.validate_source(dict(name=series['component'], directory='source',
                               repository=series['repository'], commit=series['commit']))
    if not re.fullmatch('[0-9a-f]{64}', series.get('source_lock_sha256', '')):
        raise build.CosmicBuildError('series needs pinned Cargo.lock identity')
    if not isinstance(series.get('patches'), list) or not series['patches']:
        raise build.CosmicBuildError('series needs an ordered patch list')
    for entry in series['patches']:
        if not re.fullmatch('[0-9a-f]{64}', entry.get('manifest_sha256', '')):
            raise build.CosmicBuildError('series must pin every patch manifest identity')
    return series


def verify_files(stage, expected, label):
    for name, checksum in expected.items():
        relative = dependencies.relative_path(name)
        path = build.no_symlink_path(stage / relative)
        if checksum is None:
            valid = not path.exists()
        else:
            if not isinstance(checksum, str) or not re.fullmatch('[0-9a-f]{64}', checksum):
                raise build.CosmicBuildError('invalid ' + label + ' hash: ' + name)
            valid = path.is_file() and build.digest(path) == checksum
        if not valid:
            raise build.CosmicBuildError(label + ' mismatch: ' + name)


def apply_series(stage, series_path=SERIES, *, root=ROOT):
    """Apply only exact preimages; shared by staging and Cargo acquisition."""
    series = load_series(series_path)
    if build.digest(stage / 'Cargo.lock') != series['source_lock_sha256']:
        raise build.CosmicBuildError('source Cargo.lock identity mismatch')
    records = []
    for entry in series['patches']:
        manifest_path = bound_path(root, entry['manifest'])
        patch_path = bound_path(root, entry['patch'])
        if build.digest(manifest_path) != entry['manifest_sha256']:
            raise build.CosmicBuildError('patch manifest identity mismatch: ' + entry['manifest'])
        manifest = build.load_json(manifest_path)
        if (manifest.get('schema_version') != 1 or manifest.get('commit') != series['commit']
                or ports.repository_url(manifest.get('repository')) != ports.repository_url(series['repository'])):
            raise build.CosmicBuildError('patch manifest source identity mismatch')
        before, after = manifest.get('before'), manifest.get('after')
        if not isinstance(before, dict) or not before or not isinstance(after, dict) or before.keys() != after.keys():
            raise build.CosmicBuildError('patch manifest needs matching preimage/postimage paths')
        verify_files(stage, before, 'preimage')
        old = build.tree_identity(stage)['files']
        build.apply_patches({'patches': [{'path': entry['patch'], 'sha256': manifest['patch_sha256']}]},
                            stage, Path(root))
        verify_files(stage, after, 'postimage')
        new = build.tree_identity(stage)['files']
        changed = {name for name in old.keys() | new.keys() if old.get(name) != new.get(name)}
        expected = {name for name in before if before[name] != after[name]}
        if changed != expected:
            raise build.CosmicBuildError('patch contains unbound changes: ' + ', '.join(sorted(changed ^ expected)))
        records.append({'patch': entry['patch'], 'patch_sha256': build.digest(patch_path),
                        'manifest': entry['manifest'], 'manifest_sha256': build.digest(manifest_path),
                        'changed_paths': sorted(changed)})
    return records


def prepare(source=SOURCE, output=None, *, series_path=SERIES, root=ROOT):
    series = load_series(series_path)
    source = build.no_symlink_path(source)
    pin = dict(name=series['component'], directory=source.name,
               repository=series['repository'], commit=series['commit'])
    build.inspect_source(source.parent, pin)
    output = build.new_output(output)
    report = {'schema_version': 1, 'status': 'INCOMPLETE', 'source': pin,
              'series_sha256': build.digest(series_path), 'compositor_built': False,
              'cargo_resolved': False, 'guest_tested': False}
    try:
        # Git apply must not inherit the outer repository. Cargo source exports
        # also need an independent directory, so use the existing safe exporter.
        with tempfile.TemporaryDirectory(prefix='cyxia-comp-series-') as temporary:
            stage = Path(temporary).resolve() / 'source'
            build.export_source(source, stage)
            report['patches'] = apply_series(stage, series_path, root=root)
            report['effective_lock_sha256'] = build.digest(stage / 'Cargo.lock')
            report['source_tree'] = build.tree_identity(stage)
            report['source_preserved'] = build.inspect_source(source.parent, pin)['verified']
            pending = output / '.source-incomplete'
            shutil.copytree(stage, pending, symlinks=True)
            if build.tree_identity(pending) != report['source_tree']:
                raise build.CosmicBuildError('source copy differs from verified export')
            pending.rename(output / 'source')
            report['status'] = 'PATCHED_NOT_COMPOSITOR_BUILT'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status='FAILED', error=str(error))
        raise
    finally:
        (output / 'preparation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--series', type=Path, default=SERIES)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = prepare(args.source, args.output, series_path=args.series)
        print(json.dumps({'status': report['status'], 'report': str(args.output / 'preparation.json')}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('prepare_cosmic_comp: ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
