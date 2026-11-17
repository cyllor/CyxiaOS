#!/usr/bin/env python3
"""Copy four complete libX11 locale/license files from the genuine original SDK.

No acquisition, compilation, rewriting, synthesized rules or guest execution.
Pinned policy lives in this tool; no new ports manifest changes OS code identity.
Apply to tools after review. A private draft is not an installed producer.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / 'artifacts/v017-cosmic-runtime-20261116'
SDK = OLD / 'runtime-sdk-x86_64'
ORIGIN = SDK / 'runtime-sdk-origin.json'
XORG_REPORT = OLD / 'sdk-x86_64/xorg-bootstrap-report.json'
MANIFEST = ROOT / 'ports/libc/xorg-bootstrap.json'
ARCHIVE_SHA256 = 'fa026f9bb0124f4d6c808f9aef4057aad65e7b35d8ff43951cef0abe06bb9a9a'
ARCHIVE_DIR = ROOT / ('artifacts/desktop-sources/libX11-1.8.12-' + ARCHIVE_SHA256)
ARCHIVE = ARCHIVE_DIR / 'source.archive'
PROVENANCE = ARCHIVE_DIR / 'provenance.json'
RECEIPT = 'cosmic-locale-assets-v1.json'
MAX_FILE_BYTES = 2 * 1024**2
MAX_SOURCE_BYTES = 3 * 1024**2
TOTAL_ASSET_BYTES = 610900
PACKAGE = {
    'name': 'libX11', 'version': '1.8.12', 'kind': 'sha256-archive',
    'pin': ARCHIVE_SHA256,
    'source_url': 'https://xorg.freedesktop.org/archive/individual/lib/libX11-1.8.12.tar.xz',
}
PINNED = {
    'sdk_origin': {'bytes': 1428760, 'sha256': 'bf26026042bca8b6d83727844e59fcbd70efe34e63835a838dbccbb78fe7b7f3'},
    'xorg_report': {'bytes': 12217, 'sha256': 'd9434640d3f3455a8d1677e431aaeac02e922e4849bb7b5b1d4cb3ccf8ba043f'},
    'xorg_manifest': {'bytes': 2937, 'sha256': 'a903cb67a3997051c511de1f9043a38a73279d02299187f0d194d8ba0dd5b901'},
    'archive': {'bytes': 1895256, 'sha256': ARCHIVE_SHA256},
    'archive_provenance': {'bytes': 604, 'sha256': '1879418d6b7e0f062f094b69c05f03fffa658baa8d993615fd0c5ee0bb0b8948'},
}
FILES = {
    '/usr/share/X11/locale/en_US.UTF-8/Compose': {
        'source_group': 'sysroot', 'source_relative': 'usr/share/X11/locale/en_US.UTF-8/Compose',
        'bytes': 456061, 'sha256': 'a3077ce7fdae43776b9a485d8a9689c0bfeb0cd17348a87b7a06818e59554ea1', 'mode': '0644',
    },
    '/usr/share/X11/locale/compose.dir': {
        'source_group': 'sysroot', 'source_relative': 'usr/share/X11/locale/compose.dir',
        'bytes': 31977, 'sha256': 'cd648b9ecd0e03ff658bf0d87cdf0cd3256d65ecb6d070397c70be90d78f1d3a', 'mode': '0644',
    },
    '/usr/share/X11/locale/locale.alias': {
        'source_group': 'sysroot', 'source_relative': 'usr/share/X11/locale/locale.alias',
        'bytes': 76404, 'sha256': 'b6ee751a789421e30a1515e529d3cdc60c912e88169940d2a3c76953835a12eb', 'mode': '0644',
    },
    '/usr/share/licenses/libX11/COPYING': {
        'source_group': 'licenses', 'source_relative': 'libX11/COPYING',
        'bytes': 46458, 'sha256': '2e7012a140f000735a7172674a2d314398d79622444fba65d108b029b29ab283', 'mode': '0644',
    },
}
ARCHIVE_MEMBERS = {
    'COPYING': {'bytes': 46458, 'sha256': '2e7012a140f000735a7172674a2d314398d79622444fba65d108b029b29ab283'},
    'nls/en_US.UTF-8/Compose.pre': {'bytes': 457364, 'sha256': 'cba1921a6b927218a9d4c2888454ec4970ce976842ba7a6a1dc018220bf55ac0'},
    'nls/compose.dir.pre': {'bytes': 16248, 'sha256': 'fcabb58c68fe8722a5b20b1d952b7b5f915b8b2b6f7fb99450da08b5780c42df'},
    'nls/locale.alias.pre': {'bytes': 43916, 'sha256': '0ba4a3756b6dd4da40979d4030735d6d4de71a7df3f93123063408b09718fb6e'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def plain_path(path):
    require(isinstance(path, (str, Path)), 'Invalid locale input/output path')
    path = Path(path).absolute()
    require('..' not in path.parts, 'Locale path traversal is not allowed')
    for parent in (*reversed(path.parents), path):
        require(not parent.is_symlink(), 'Linked locale path is not allowed: ' + str(parent))
    return path


def read_regular(path, limit=MAX_FILE_BYTES):
    path = plain_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
                'Locale input is not a bounded regular file')
        raw = stream.read(limit + 1)
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size and len(raw) <= limit
                and key(before) == key(os.fstat(stream.fileno())) == key(path.stat(follow_symlinks=False)),
                'Locale input changed during read')
        return raw


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate locale evidence JSON key')
        result[key] = value
    return result


def document(raw):
    result = json.loads(raw, object_pairs_hook=no_duplicates)
    require(type(result) is dict, 'Locale evidence must be a JSON object')
    return result


def source_roots():
    return (SDK, XORG_REPORT.parent, MANIFEST.parent, ARCHIVE_DIR, ROOT / 'tools')


def producers():
    path = plain_path(__file__)
    require(path == ROOT / 'tools/install_cosmic_locale_v1.py', 'Use the reviewed installed tool path')
    return {str(path.relative_to(ROOT)): identity(read_regular(path))}


def verify_sources():
    paths = dict(sdk_origin=ORIGIN, xorg_report=XORG_REPORT, xorg_manifest=MANIFEST,
                 archive=ARCHIVE, archive_provenance=PROVENANCE)
    raw = {name: read_regular(path, MAX_SOURCE_BYTES) for name, path in paths.items()}
    require(all(identity(raw[name]) == PINNED[name] for name in paths),
            'Original SDK, X.Org pin/report, archive or provenance identity changed')
    origin, xorg, manifest, provenance = (document(raw[name]) for name in
        ('sdk_origin', 'xorg_report', 'xorg_manifest', 'archive_provenance'))
    require(origin['status'] == 'NATIVE_RUNTIME_SDK_ASSEMBLED_NOT_RUN'
            and origin['inputs_preserved'] is True and origin['cosmic_session_verified'] is False
            and origin['original_reports']['xorg-bootstrap-report.json']
            == {'origin': str(XORG_REPORT), 'sha256': PINNED['xorg_report']['sha256']},
            'Original SDK does not bind the actual preserved X.Org report')
    selected = [row for row in manifest['packages'] if row['name'] == 'libX11']
    require(len(selected) == 1 and selected[0]['version'] == PACKAGE['version']
            and selected[0]['expected_sha256'] == ARCHIVE_SHA256
            and selected[0]['source_url'] == PACKAGE['source_url']
            and selected[0]['archive_root'] == 'libX11-1.8.12'
            and selected[0]['license_file'] == 'COPYING', 'Existing X.Org manifest selects different libX11 inputs')
    require(provenance['identity'] == PACKAGE and provenance['sha256'] == ARCHIVE_SHA256
            and provenance['bytes'] == PINNED['archive']['bytes']
            and provenance['retrieved_from'] == PACKAGE['source_url'], 'Archive provenance differs from its package pin')
    selected_sources = [row for row in xorg['sources'] if row.get('identity', {}).get('name') == 'libX11']
    require(selected_sources == [{'status': 'verified', 'directory': str(ARCHIVE_DIR), **provenance}]
            and xorg['architecture'] == 'x86_64' and xorg['target_triple'] == 'x86_64-unknown-linux-musl',
            'X.Org report does not bind the actual pinned libX11 archive')
    files, contents = {}, {}
    for guest, expected in FILES.items():
        require(guest.startswith('/') and len(guest.encode()) < 96 and '..' not in Path(guest).parts,
                'Locale guest path exceeds the existing kernel bound')
        path = plain_path(SDK / expected['source_group'] / expected['source_relative'])
        content = read_regular(path)
        expected_identity = {key: expected[key] for key in ('bytes', 'sha256')}
        require(identity(content) == expected_identity
                and origin[expected['source_group']]['files'][expected['source_relative']] == expected_identity
                and stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) == 0o644,
                'Locale/license bytes, original receipt binding or observed mode changed')
        contents[guest] = content
        files[guest] = {**expected, 'source': str(path)}
    require(len(files) == 4 and sum(row['bytes'] for row in files.values()) == TOTAL_ASSET_BYTES,
            'The complete four-file locale closure is required')
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw['archive']), mode='r:xz') as archive:
        entries = archive.getmembers()
        for relative, expected in ARCHIVE_MEMBERS.items():
            name = 'libX11-1.8.12/' + relative
            selected_members = [entry for entry in entries if entry.name == name]
            require(len(selected_members) == 1 and selected_members[0].isfile()
                    and selected_members[0].size == expected['bytes'], 'Pinned archive member changed')
            with archive.extractfile(selected_members[0]) as stream:
                content = stream.read(MAX_FILE_BYTES + 1)
            require(identity(content) == expected, 'Pinned archive member bytes changed')
            members[relative] = content
    compose = contents['/usr/share/X11/locale/en_US.UTF-8/Compose']
    rules = lambda content: [line for line in content.splitlines() if line.lstrip().startswith(b'<')]
    require(len(rules(compose)) == 5145 and rules(compose) == rules(members['nls/en_US.UTF-8/Compose.pre']),
            'Complete generated Compose rules differ from the genuine upstream rule bytes')
    require(not any(line.lstrip().split(maxsplit=1)[:1] == [b'include'] for line in compose.splitlines()),
            'This fixed Compose table unexpectedly requires another input')
    rows = lambda content: [line.split()[:2] for line in content.splitlines()
                            if line.strip() and not line.lstrip().startswith(b'#')]
    require([b'en_US.UTF-8/Compose', b'en_US.UTF-8']
            in rows(contents['/usr/share/X11/locale/compose.dir']), 'Complete compose.dir is missing its UTF-8 mapping')
    aliases = rows(contents['/usr/share/X11/locale/locale.alias'])
    require(all([alias, b'en_US.UTF-8'] in aliases for alias in (b'C.UTF-8', b'C.utf8', b'en_US.utf8')),
            'Complete locale.alias is missing the selected UTF-8 aliases')
    require(contents['/usr/share/licenses/libX11/COPYING'] == members['COPYING'],
            'Preserve the entire multi-contributor upstream COPYING file')
    return {
        'source': {'package': PACKAGE, 'sdk': str(SDK),
                   'evidence': {name: {'path': str(path), **PINNED[name]} for name, path in paths.items()},
                   'archive_members': ARCHIVE_MEMBERS,
                   'mode_evidence': '0644 observed on each original source; original SDK origin records bytes/SHA only'},
        'files': files,
        'completeness': {'compose_rule_lines': 5145, 'rules_equal_upstream_bytes': True,
                         'compose_include_directives': 0, 'complete_generated_mapping_files_copied': True,
                         'full_upstream_COPYING_preserved': True, 'asset_count': 4,
                         'asset_bytes': TOTAL_ASSET_BYTES, 'scope': 'en_US.UTF-8 Compose and its original mapping files'},
    }


def validate_inputs(prefix):
    """Validate a standalone or curated prefix without loading locale data."""
    prefix = plain_path(prefix)
    report = document(read_regular(prefix / RECEIPT))
    require(set(report) == {'schema_version', 'status', 'source', 'files', 'completeness',
                            'producers', 'guest_locale_loading_observed'}
            and type(report['schema_version']) is int and report['schema_version'] == 1
            and report['status'] == 'ASSETS_INSTALLED_NOT_RUN'
            and report['guest_locale_loading_observed'] is False, 'Invalid locale installation receipt')
    proof = verify_sources()
    require(all(report[key] == value for key, value in proof.items()) and report['producers'] == producers(),
            'Locale source or producer receipt changed')
    for guest, row in proof['files'].items():
        installed = plain_path(prefix / 'rootfs' / guest.lstrip('/'))
        require(identity(read_regular(installed)) == {key: row[key] for key in ('bytes', 'sha256')}
                and stat.S_IMODE(installed.stat(follow_symlinks=False).st_mode) == 0o644,
                'Installed locale/license bytes or mode changed')
    return report


def install(output):
    output = plain_path(output)
    require(not output.exists(), 'Preserving an existing locale output')
    for source in source_roots():
        source = plain_path(source)
        require(not output.is_relative_to(source) and not source.is_relative_to(output),
                'Locale output overlaps a preserved source')
    proof = verify_sources()
    producer = producers()
    report = dict(schema_version=1, status='ASSETS_INSTALLED_NOT_RUN', **proof,
                  producers=producer, guest_locale_loading_observed=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        for guest, row in proof['files'].items():
            raw = read_regular(row['source'])
            require(identity(raw) == {key: row[key] for key in ('bytes', 'sha256')},
                    'Locale source changed while copying')
            target = pending / 'rootfs' / guest.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o644)
        with (pending / RECEIPT).open('x') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        (pending / RECEIPT).chmod(0o644)
        require(validate_inputs(pending) == report and producers() == producer,
                'Locale inputs changed before publication')
        require(not output.exists() and not output.is_symlink(), 'Preserving a concurrently created locale output')
        pending.rename(output)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--output', type=Path)
    selection.add_argument('--validate-prefix', type=Path)
    args = parser.parse_args(argv)
    try:
        report = install(args.output) if args.output is not None else validate_inputs(args.validate_prefix)
        print(json.dumps({key: report[key] for key in ('status', 'completeness', 'guest_locale_loading_observed')}, indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError) as error:
        print('COSMIC locale installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
