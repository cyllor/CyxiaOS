#!/usr/bin/env python3
"""Install verified, guest-generated upstream COSMIC theme defaults offline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys

if __package__:
    from . import build_cosmic_theme_defaults as builder
    from . import install_cosmic_config as common
else:
    import build_cosmic_theme_defaults as builder
    import install_cosmic_config as common

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'ports/cosmic/theme-defaults/assets.json'
REPOSITORY = 'https://github.com/pop-os/libcosmic'
COMMIT = '5a8bd9482a35ae94c1e54edf77b331c6b970f170'
CHECKOUT = 'artifacts/cosmic-cargo-cache/git/checkouts/libcosmic-41009aea1d72760b/5a8bd94'
SOURCE_FILE = CHECKOUT + '/cosmic-theme/src/model/theme.rs'
GENERATOR_FILE = 'ports/cosmic/theme-defaults/client.rs'
LICENSE_PATH = '/usr/share/doc/libcosmic/LICENSE'
IDS = {'dark': 'com.system76.CosmicTheme.Dark', 'light': 'com.system76.CosmicTheme.Light'}
KEYS = tuple(sorted(('name', 'background', 'primary', 'secondary', 'transparent_background',
    'transparent_primary', 'transparent_secondary', 'button', 'accent', 'success', 'destructive',
    'warning', 'accent_button', 'success_button', 'destructive_button', 'warning_button',
    'icon_button', 'link_button', 'list_button', 'text_button', 'palette', 'spacing', 'corner_radii',
    'is_dark', 'is_high_contrast', 'gaps', 'active_hint', 'window_hint', 'frosted', 'frosted_windows',
    'frosted_system_interface', 'frosted_panel', 'frosted_applets', 'frosted_maximized_apps',
    'alpha_map', 'shade', 'accent_text', 'control_tint', 'text_tint')))
MAX_KEY_BYTES = 8192
MAX_TOTAL_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 16 * 1024 ** 2
BuildError = common.BuildError
require = common.require


def destination(mode, key):
    return '/usr/share/cosmic/' + IDS[mode] + '/v2/' + key


def expected_paths():
    return sorted([destination(mode, key) for mode in IDS for key in KEYS] + [LICENSE_PATH])


def repo_path(value):
    return common.plain_path(ROOT / common.relative_path(value))


def valid_identity(record, limit):
    require(type(record.get('bytes')) is int and 0 < record['bytes'] <= limit,
            'Invalid byte bound')
    require(isinstance(record.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', record['sha256']),
            'Invalid SHA-256')


def evidence(record, *, limit=MAX_EVIDENCE_BYTES):
    require(isinstance(record, dict) and set(record) == {'path', 'bytes', 'sha256'},
            'Malformed evidence identity')
    valid_identity(record, limit)
    path = repo_path(record['path'])
    data = common.read_regular(path, limit)
    require(common.identity(data) == {k: record[k] for k in ('bytes', 'sha256')},
            'Evidence identity changed: ' + record['path'])
    return path, data


def parse_json(data):
    try:
        return json.loads(data, object_pairs_hook=common.no_duplicate_keys)
    except (ValueError, UnicodeError) as error:
        raise BuildError('Invalid JSON evidence') from error


def load_manifest(path=MANIFEST):
    data = common.read_regular(path, MAX_EVIDENCE_BYTES)
    manifest = parse_json(data)
    require(isinstance(manifest, dict) and set(manifest) == {
        'schema_version', 'repository', 'commit', 'license', 'theme_version', 'files', 'provenance'},
        'Unsupported theme asset manifest shape')
    require(type(manifest['schema_version']) is int and manifest['schema_version'] == 1
            and manifest['repository'] == REPOSITORY and manifest['commit'] == COMMIT
            and manifest['license'] == 'MPL-2.0' and type(manifest['theme_version']) is int
            and manifest['theme_version'] == 2, 'Theme source or schema identity changed')
    files = manifest['files']
    require(isinstance(files, list) and len(files) == 79, 'Expected 78 theme keys and one license')
    require(all(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'} for row in files),
            'Malformed asset identity')
    require([row['path'] for row in files] == expected_paths(),
            'Missing, extra, duplicate, unsorted or noncanonical theme destinations')
    for row in files:
        valid_identity(row, common.MAX_INPUT_BYTES if row['path'] == LICENSE_PATH else MAX_KEY_BYTES)
    require(sum(row['bytes'] for row in files) <= MAX_TOTAL_BYTES, 'Asset payload exceeds bound')
    provenance = manifest['provenance']
    require(isinstance(provenance, dict) and set(provenance) == {'source', 'generator', 'build', 'captures'},
            'Incomplete generation provenance')
    require(isinstance(provenance['source'], dict) and isinstance(provenance['generator'], dict)
            and provenance['source'].get('path') == SOURCE_FILE
            and provenance['generator'].get('path') == GENERATOR_FILE, 'Unexpected source or generator')
    build = provenance['build']
    require(isinstance(build, dict) and set(build) == {'prefix', 'receipt'}
            and isinstance(build['receipt'], dict) and 'path' in build['receipt'], 'Malformed build provenance')
    prefix = repo_path(build['prefix'])
    require(repo_path(build['receipt']['path']) == prefix / builder.RECEIPT,
            'Build receipt does not belong to selected prefix')
    captures = provenance['captures']
    require(isinstance(captures, list) and len(captures) == 2
            and all(isinstance(row, dict) and set(row) == {'mode', 'capture', 'serial'} for row in captures)
            and [row['mode'] for row in captures] == ['dark', 'light'], 'Expected separate dark/light captures')
    return manifest


def parse_serial(data, mode):
    require(len(data) <= MAX_EVIDENCE_BYTES, 'Serial exceeds bound')
    rows = [line.rstrip(b'\r') for line in data.split(b'\n') if line.startswith(b'THEME_DEFAULTS ')]
    begin = (f'THEME_DEFAULTS BEGIN mode={mode} id={IDS[mode]} version=2 keys=39 '
             f'source=libcosmic@{COMMIT}').encode()
    end = f'THEME_DEFAULTS PASS mode={mode} keys=39'.encode()
    require(len(rows) == 41 and rows[0] == begin and rows[-1] == end,
            'Incomplete, repeated or failed theme generation serial')
    result = {}
    for expected, row in zip(KEYS, rows[1:-1]):
        match = re.fullmatch(rb'THEME_DEFAULTS KEY name=([a-z_]+) bytes=([1-9][0-9]*) hex=([0-9a-f]+)', row)
        require(match is not None and match[1].decode() == expected, 'Serial key order or shape differs')
        count = int(match[2])
        require(count <= MAX_KEY_BYTES and len(match[3]) == count * 2, 'Serial key byte count differs')
        payload = bytes.fromhex(match[3].decode())
        result[expected] = payload
    require(result['is_dark'] == (b'true' if mode == 'dark' else b'false'), 'Generated theme mode differs')
    return result


def key_records(files, mode):
    by_path = {row['path']: row for row in files}
    return [{'name': key, **{name: by_path[destination(mode, key)][name]
                             for name in ('bytes', 'sha256')}} for key in KEYS]


def verify_capture(record, manifest, build_proof):
    mode = record['mode']
    _, data = evidence(record['capture'])
    _, serial = evidence(record['serial'])
    capture = parse_json(data)
    require(isinstance(capture, dict) and capture.get('status') == 'PASS' and capture.get('mode') == mode,
            'Capture did not pass for the selected theme')
    require(all(type(capture.get(key)) is int and capture[key] == 0 for key in ('exit_code', 'returncode'))
            and capture.get('forced', False) is False and capture.get('forced_shutdown', False) is False,
            'Capture did not exit normally')
    require(capture.get('full_os_verified') is False and capture.get('cosmic_session_verified') is False,
            'Capture contains unsupported full-system claims')
    require(isinstance(capture.get('before'), dict) and capture['before']
            and capture['before'] == capture.get('after'), 'Capture object cleanup was not preserved')
    require(capture.get('inputs') == build_proof, 'Capture uses different exporter build inputs')
    require(capture.get('images') == {builder.EXECUTABLE: build_proof['executable']['sha256']},
            'Capture did not bind the admitted exporter ELF')
    require(capture.get('serial_sha256') == record['serial']['sha256']
            and capture.get('generator_sha256') == manifest['provenance']['generator']['sha256'],
            'Capture serial or generator hash differs')
    for key in ('source_sha256', 'build_manifest_sha256', 'producer_sha256'):
        require(isinstance(capture.get(key), str) and re.fullmatch('[0-9a-f]{64}', capture[key]),
                'Capture lacks a bounded source/build/producer identity')
    producers = capture.get('producer_inputs')
    require(isinstance(producers, dict) and producers and capture['producer_sha256'] in producers.values(),
            'Capture producer closure is incomplete')
    for path, digest in producers.items():
        require(common.identity(common.read_regular(repo_path(path), MAX_EVIDENCE_BYTES))['sha256'] == digest,
                'Capture producer input changed: ' + path)
    require(capture.get('keys') == key_records(manifest['files'], mode), 'Capture key identities differ')
    values = parse_serial(serial, mode)
    for row in key_records(manifest['files'], mode):
        require(common.identity(values[row['name']]) == {k: row[k] for k in ('bytes', 'sha256')},
                'Asset bytes differ from successful guest serial')
    return values


def source_inventory(rootfs):
    rootfs = common.plain_path(rootfs)
    require(rootfs.is_dir(), 'Missing committed generated rootfs')
    paths = []
    for path in sorted(rootfs.rglob('*')):
        require(not path.is_symlink(), 'Symlink in generated asset tree')
        if path.is_file():
            paths.append('/' + str(path.relative_to(rootfs)))
        else:
            require(path.is_dir(), 'Non-regular generated asset')
    require(paths == expected_paths(), 'Generated asset tree has missing or extra files')


def verify_inputs(manifest_path, manifest):
    _, source_bytes = evidence(manifest['provenance']['source'])
    _, generator_bytes = evidence(manifest['provenance']['generator'])
    receipt, _ = evidence(manifest['provenance']['build']['receipt'])
    require(source_bytes == common.git_output(ROOT / CHECKOUT, 'cat-file', 'blob',
                COMMIT + ':cosmic-theme/src/model/theme.rs'), 'Theme source differs from pinned Git blob')
    build_proof = builder.validate_inputs(receipt.parent)
    require(build_proof['receipt_sha256'] == manifest['provenance']['build']['receipt']['sha256'],
            'Validated build receipt changed while reading')
    rootfs = common.plain_path(Path(manifest_path).parent / 'rootfs')
    source_inventory(rootfs)
    captures = {row['mode']: verify_capture(row, manifest, build_proof)
                for row in manifest['provenance']['captures']}
    for row in manifest['files']:
        data = common.read_regular(rootfs / row['path'].lstrip('/'))
        require(common.identity(data) == {key: row[key] for key in ('bytes', 'sha256')},
                'Committed generated asset changed: ' + row['path'])
        if row['path'] == LICENSE_PATH:
            require(data == common.git_output(ROOT / CHECKOUT, 'cat-file', 'blob', COMMIT + ':LICENSE'),
                    'License differs from pinned upstream license')
        else:
            mode = next(mode for mode in IDS if row['path'].startswith('/usr/share/cosmic/' + IDS[mode] + '/'))
            require(data == captures[mode][PurePosixPath(row['path']).name], 'Generated key differs from serial')
    return {'build': build_proof, 'provenance': manifest['provenance'],
            'source': common.identity(source_bytes), 'generator': common.identity(generator_bytes)}


def producer_identity():
    return {str(path.relative_to(ROOT)): common.identity(common.read_regular(path, MAX_EVIDENCE_BYTES))
            for path in (Path(__file__).resolve(), Path(common.__file__).resolve(),
                         Path(builder.__file__).resolve())}


def bounds(files):
    paths = [row['path'] for row in files]
    directories = {str(parent) for path in paths for parent in PurePosixPath(path).parents}
    require(all(len(path.encode()) < 96 for path in paths) and len(directories) <= 128,
            'Generated assets exceed full-os path or directory bounds')
    return {'asset_files': len(files), 'asset_bytes': sum(row['bytes'] for row in files),
            'directory_nodes': len(directories), 'catalog_file_limit': 256,
            'directory_node_limit': 128, 'path_byte_limit_exclusive': 96}


def validate_destination(output, manifest_path, config, inputs):
    protected = [manifest_path.parent, ROOT / CHECKOUT, ROOT / 'artifacts/cosmic-cargo-cache',
                 ROOT / 'artifacts/cosmic-sources', builder.DEFAULT_BUILD, builder.SDK,
                 builder.DEFAULT_SETTINGS_PREFIX, repo_path(config['provenance']['build']['prefix'])]
    proof = inputs['build']
    for key in ('output', 'validated_output'):
        if key in proof:
            protected.append(common.plain_path(proof[key]))
    receipt = repo_path(config['provenance']['build']['receipt']['path'])
    helper_report = parse_json(common.read_regular(receipt, MAX_EVIDENCE_BYTES))
    settings = helper_report.get('inputs_before', {}).get('settings_prefix')
    if settings:
        protected.append(common.plain_path(settings))
    for capture in config['provenance']['captures']:
        protected += [repo_path(capture[key]['path']).parent for key in ('capture', 'serial')]
        summary = parse_json(common.read_regular(repo_path(capture['capture']['path']), MAX_EVIDENCE_BYTES))
        protected += [repo_path(path) for path in summary['producer_inputs']]
    for source in protected:
        source = common.plain_path(source)
        require(not output.is_relative_to(source) and not source.is_relative_to(output),
                'Output overlaps preserved generation inputs')


def install(output, manifest=MANIFEST):
    manifest_path = common.plain_path(manifest)
    manifest_bytes = common.read_regular(manifest_path, MAX_EVIDENCE_BYTES)
    config = load_manifest(manifest_path)
    output = common.plain_path(output)
    require(not output.exists(), 'Output must be a new directory')
    require(not output.is_relative_to(manifest_path.parent)
            and not manifest_path.parent.is_relative_to(output), 'Output overlaps generated sources')
    before = verify_inputs(manifest_path, config)
    validate_destination(output, manifest_path, config, before)
    producers = producer_identity()
    output.mkdir(parents=True, exist_ok=False)
    pending = output / 'rootfs.pending'
    pending.mkdir()
    for row in config['files']:
        data = common.read_regular(manifest_path.parent / 'rootfs' / row['path'].lstrip('/'))
        require(common.identity(data) == {key: row[key] for key in ('bytes', 'sha256')}, 'Source changed while copying')
        target = common.plain_path(pending / row['path'].lstrip('/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o644)
        require(common.read_regular(target) == data, 'Copied theme asset differs from source')
    after = verify_inputs(manifest_path, config)
    require(before == after and common.read_regular(manifest_path, MAX_EVIDENCE_BYTES) == manifest_bytes
            and producer_identity() == producers, 'Generation inputs changed during installation')
    report = {'schema_version': 1, 'status': 'PASS', 'source_preserved': True,
              'full_os_verified': False, 'cosmic_session_verified': False,
              'manifest': {'path': str(manifest_path), **common.identity(manifest_bytes)},
              'inputs_before': before, 'inputs_after': after, 'producers': producers,
              'assets': config['files'], 'bounds': bounds(config['files']), 'rootfs': str(output / 'rootfs')}
    (output / 'report.pending.json').write_text(json.dumps(report, indent=2) + '\n')
    pending.rename(output / 'rootfs')
    (output / 'report.pending.json').rename(output / 'report.json')
    return report


def validate_inputs(prefix, manifest=MANIFEST, *, receipt='cosmic-theme-assets.json'):
    prefix = common.plain_path(prefix)
    require(receipt in ('cosmic-theme-assets.json', 'report.json'), 'Unexpected theme receipt name')
    config = load_manifest(manifest)
    report = parse_json(common.read_regular(prefix / receipt, MAX_EVIDENCE_BYTES))
    require(isinstance(report, dict) and report.get('schema_version') == 1 and report.get('status') == 'PASS'
            and report.get('source_preserved') is True and report.get('full_os_verified') is False
            and report.get('cosmic_session_verified') is False, 'Invalid theme asset receipt')
    require(report.get('manifest') == {'path': str(common.plain_path(manifest)),
            **common.identity(common.read_regular(manifest, MAX_EVIDENCE_BYTES))}, 'Manifest identity changed')
    require(report.get('producers') == producer_identity(), 'Installer identity changed')
    require(report.get('inputs_before') == report.get('inputs_after') == verify_inputs(manifest, config),
            'Generation provenance changed')
    require(report.get('assets') == config['files'] and report.get('bounds') == bounds(config['files']),
            'Asset inventory or bounds changed')
    for row in config['files']:
        data = common.read_regular(prefix / 'rootfs' / row['path'].lstrip('/'))
        require(common.identity(data) == {key: row[key] for key in ('bytes', 'sha256')},
                'Curated theme asset changed')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    args = parser.parse_args(argv)
    try:
        report = install(args.output, args.manifest)
        print(json.dumps({key: report[key] for key in ('status', 'rootfs', 'bounds')}, indent=2))
        return 0
    except (BuildError, builder.CosmicBuildError, OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print('COSMIC theme asset installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
