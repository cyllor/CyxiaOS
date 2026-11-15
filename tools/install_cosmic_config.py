#!/usr/bin/env python3
"""Copy pinned upstream COSMIC defaults offline; never build or generate assets."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

if __package__:
    from . import build_sysroot, install_xkb_data
else:
    import build_sysroot
    import install_xkb_data

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'ports/cosmic/config-assets.json'
BuildError = build_sysroot.BuildError
MAX_INPUT_BYTES = 128 * 1024
MAX_ASSET_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
PINS = {
    'cosmic-comp': ('https://github.com/pop-os/cosmic-comp',
                    '41497b42d9744d9963c4c6d17e8add49489b45ee', 'GPL-3.0-only', 'justfile'),
    'cosmic-settings-daemon': ('https://github.com/pop-os/cosmic-settings-daemon',
                               'e37160f14d1e7ee428f973cd2848b4e95f83dfe1',
                               'GPL-3.0-or-later', 'Makefile'),
}
FILES = {
    'cosmic-comp': {
        'data/keybindings.ron': '/usr/share/cosmic/com.system76.CosmicSettings.Shortcuts/v1/defaults',
        'data/tiling-exceptions.ron': '/usr/share/cosmic/com.system76.CosmicSettings.WindowRules/v1/tiling_exception_defaults',
        'LICENSE': '/usr/share/doc/cosmic-comp/LICENSE',
        'Cargo.toml': None, 'debian/copyright': None, 'justfile': None,
    },
    'cosmic-settings-daemon': {
        'data/system_actions.ron': '/usr/share/cosmic/com.system76.CosmicSettings.Shortcuts/v1/system_actions',
        'LICENSE': '/usr/share/doc/cosmic-settings-daemon/LICENSE',
        'Cargo.toml': None, 'Makefile': None,
    },
}


def require(condition, message):
    if not condition:
        raise BuildError(message)


def relative_path(value):
    require(isinstance(value, str) and '\x00' not in value, 'Invalid relative path')
    path = PurePosixPath(value)
    require(bool(path.parts) and not path.is_absolute() and '..' not in path.parts
            and str(path) == value and '\\' not in value, 'Unsafe relative path')
    return path


def plain_path(path):
    """Reject aliases before resolving, including a symlink in any ancestor."""
    path = Path(path).absolute()
    require('..' not in path.parts, 'Path traversal is not allowed')
    for ancestor in (*reversed(path.parents), path):
        require(not ancestor.is_symlink(), 'Symlink input or output is not allowed: ' + str(ancestor))
    return path


def read_regular(path, limit=MAX_INPUT_BYTES):
    path = plain_path(path)
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode), 'Missing regular file: ' + str(path))
    require(path.stat().st_size <= limit, 'Input exceeds byte budget: ' + str(path))
    data = path.read_bytes()
    require(len(data) <= limit, 'Input grew beyond byte budget: ' + str(path))
    return data


def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path):
    try:
        return json.loads(read_regular(path, MAX_RECEIPT_BYTES), object_pairs_hook=no_duplicate_keys)
    except (ValueError, UnicodeError) as error:
        raise BuildError('Invalid JSON: ' + str(path)) from error


def load_manifest(path=MANIFEST):
    manifest = read_json(path)
    require(isinstance(manifest, dict) and manifest.get('schema_version') == 1,
            'Unsupported COSMIC asset manifest')
    packages = manifest.get('packages')
    require(isinstance(packages, list) and len(packages) == len(PINS), 'Unexpected package closure')
    require([p.get('name') for p in packages if isinstance(p, dict)] == list(PINS),
            'Unexpected or duplicate packages')
    destinations = []
    for package in packages:
        name = package['name']
        require(tuple(package.get(k) for k in ('repository', 'commit', 'license', 'install_recipe')) == PINS[name],
                'Upstream package identity changed: ' + name)
        relative_path(package.get('checkout'))
        files = package.get('files')
        require(isinstance(files, list) and len(files) == len(FILES[name]), 'Unexpected file closure')
        seen = set()
        for entry in files:
            require(isinstance(entry, dict), 'Invalid source entry')
            source = str(relative_path(entry.get('source')))
            require(source in FILES[name] and source not in seen, 'Unexpected or duplicate source file')
            seen.add(source)
            require(entry.get('destination') == FILES[name][source], 'Unexpected install destination')
            require(type(entry.get('bytes')) is int and 0 < entry['bytes'] <= MAX_INPUT_BYTES,
                    'Invalid source size')
            require(isinstance(entry.get('sha256'), str)
                    and re.fullmatch('[0-9a-f]{64}', entry['sha256']), 'Invalid source hash')
            if entry.get('destination'):
                destinations.append(entry['destination'])
    install_xkb_data.catalog_bounds(destinations)
    require(sum(e['bytes'] for p in packages for e in p['files'] if e.get('destination')) <= MAX_ASSET_BYTES,
            'Asset closure exceeds byte budget')
    return manifest


def git_output(source, *args):
    # No ambient Git aliases, worktree overrides or replacement objects.
    env = {'PATH': os.defpath, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_OPTIONAL_LOCKS': '0'}
    try:
        result = subprocess.run(['git', '-C', str(source), *args], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise BuildError('Cannot inspect cached Git source: ' + str(source)) from error
    require(result.returncode == 0 and len(result.stdout) <= MAX_INPUT_BYTES,
            'Cached Git source or pinned blob is unavailable: ' + str(source))
    return result.stdout


def source_paths(manifest, sources):
    if sources is None:
        sources = {p['name']: ROOT / p['checkout'] for p in manifest['packages']}
    require(isinstance(sources, dict) and set(sources) == set(PINS), 'Unexpected source roots')
    paths = {name: plain_path(path) for name, path in sources.items()}
    require(len(set(paths.values())) == len(paths), 'Duplicate source roots')
    return paths


def verify_sources(manifest, sources):
    records = []
    for package in manifest['packages']:
        source = sources[package['name']]
        require(source.is_dir(), 'Cached source directory is missing')
        require(git_output(source, 'rev-parse', '--show-toplevel').decode().strip() == str(source),
                'Source root is not its own Git checkout')
        require(git_output(source, 'rev-parse', 'HEAD').decode().strip() == package['commit'],
                'Cached source HEAD differs from pinned commit')
        files = []
        for entry in package['files']:
            data = read_regular(source / entry['source'])
            expected = {key: entry[key] for key in ('bytes', 'sha256')}
            require(identity(data) == expected, 'Cached source identity changed: ' + entry['source'])
            blob = git_output(source, 'cat-file', 'blob', package['commit'] + ':' + entry['source'])
            require(blob == data, 'Cached source differs from pinned Git blob: ' + entry['source'])
            files.append({'source': entry['source'], **expected})
        records.append({key: package[key] for key in ('name', 'repository', 'commit', 'license', 'install_recipe')}
                       | {'root': str(source), 'files': files})
    return records


def expected_assets(manifest):
    return sorted([{'path': entry['destination'], 'package': package['name'],
                    'source': entry['source'], 'bytes': entry['bytes'], 'sha256': entry['sha256']}
                   for package in manifest['packages'] for entry in package['files']
                   if entry.get('destination')], key=lambda entry: entry['path'])


def producer_identity():
    return {str(path.relative_to(ROOT)): identity(read_regular(path)) for path in (
        Path(__file__).resolve(), Path(install_xkb_data.__file__).resolve(),
        Path(build_sysroot.__file__).resolve())}


def install(output, sources=None, manifest=MANIFEST):
    manifest_path = plain_path(manifest)
    manifest_data = read_regular(manifest_path)
    config = load_manifest(manifest_path)
    sources = source_paths(config, sources)
    output = plain_path(output)
    require(not output.exists(), 'Output must be a new directory; existing data is never overwritten')
    for source in sources.values():
        require(not output.is_relative_to(source) and not source.is_relative_to(output),
                'Output must not overlap a source checkout')
    before = verify_sources(config, sources)
    assets = expected_assets(config)
    bounds = install_xkb_data.catalog_bounds([entry['path'] for entry in assets])
    producers = producer_identity()
    output.mkdir(parents=True, exist_ok=False)
    pending = output / 'rootfs.pending'
    pending.mkdir()
    for entry in assets:
        data = read_regular(sources[entry['package']] / entry['source'])
        require(identity(data) == {key: entry[key] for key in ('bytes', 'sha256')}, 'Source changed while copying')
        target = plain_path(pending / entry['path'].lstrip('/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o644)  # The pinned upstream recipes install data with -m0644.
        require(read_regular(target) == data, 'Copied asset differs from source')
    after = verify_sources(config, sources)
    require(before == after and read_regular(manifest_path) == manifest_data
            and producer_identity() == producers, 'Source, manifest or installer changed during staging')
    report = {'schema_version': 1, 'status': 'PASS',
              'scope': 'Pinned upstream configuration assets only',
              'cosmic_session_verified': False, 'guest_config_verified': False,
              'source_preserved': True, 'sources_before': before, 'sources_after': after,
              'manifest': {'path': str(manifest_path), **identity(manifest_data)},
              'producers': producers, 'assets': assets,
              'asset_bytes': sum(entry['bytes'] for entry in assets), 'bounds': bounds,
              'rootfs': str(output / 'rootfs')}
    with (output / 'report.pending.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    pending.rename(output / 'rootfs')
    (output / 'report.pending.json').rename(output / 'report.json')
    validate_inputs(output, manifest_path, receipt='report.json')
    return report


def validate_inputs(prefix, manifest=MANIFEST, *, receipt='cosmic-config-assets.json'):
    """Validate the five selected assets in a curated rootfs containing other packages."""
    prefix = plain_path(prefix)
    relative_path(receipt)
    config = load_manifest(manifest)
    report = read_json(prefix / receipt)
    require(isinstance(report, dict) and report.get('schema_version') == 1
            and report.get('status') == 'PASS' and report.get('source_preserved') is True
            and report.get('cosmic_session_verified') is False
            and report.get('guest_config_verified') is False, 'Invalid asset receipt status')
    manifest_record = report.get('manifest', {})
    require(isinstance(manifest_record, dict)
            and {key: manifest_record.get(key) for key in ('bytes', 'sha256')} == identity(read_regular(manifest)),
            'Asset manifest identity changed')
    require(report.get('producers') == producer_identity(), 'Asset installer identity changed')
    before = report.get('sources_before')
    require(isinstance(before, list) and len(before) == len(config['packages'])
            and before == report.get('sources_after'), 'Source preservation receipt differs')
    for record, package in zip(before, config['packages']):
        require(isinstance(record, dict), 'Invalid source receipt')
        expected = {key: package[key] for key in ('name', 'repository', 'commit', 'license', 'install_recipe')}
        expected['files'] = [{key: entry[key] for key in ('source', 'bytes', 'sha256')}
                             for entry in package['files']]
        require({key: value for key, value in record.items() if key != 'root'} == expected,
                'Pinned source receipt changed')
        require(isinstance(record.get('root'), str) and Path(record['root']).is_absolute(),
                'Invalid source root receipt')
    assets = expected_assets(config)
    require(report.get('assets') == assets, 'Missing, duplicate, foreign or changed asset receipt')
    require(report.get('bounds') == install_xkb_data.catalog_bounds([entry['path'] for entry in assets])
            and report.get('asset_bytes') == sum(entry['bytes'] for entry in assets), 'Asset bounds receipt differs')
    for entry in assets:
        data = read_regular(prefix / 'rootfs' / entry['path'].lstrip('/'))
        require(identity(data) == {key: entry[key] for key in ('bytes', 'sha256')}, 'Staged asset identity changed')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Fresh output directory')
    parser.add_argument('--cosmic-comp-source', type=Path)
    parser.add_argument('--settings-daemon-source', type=Path)
    args = parser.parse_args(argv)
    try:
        config = load_manifest()
        sources = {p['name']: ROOT / p['checkout'] for p in config['packages']}
        if args.cosmic_comp_source is not None:
            sources['cosmic-comp'] = args.cosmic_comp_source
        if args.settings_daemon_source is not None:
            sources['cosmic-settings-daemon'] = args.settings_daemon_source
        report = install(args.output, sources)
        print(json.dumps({key: report[key] for key in ('status', 'rootfs', 'asset_bytes', 'bounds')}, indent=2))
        return 0
    except (BuildError, OSError, ValueError) as error:
        print('COSMIC asset installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
