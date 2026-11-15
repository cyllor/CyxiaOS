#!/usr/bin/env python3
"""Read-only COSMIC lock source availability, patch identity and build blockers.

This is deliberately NOT a Cargo resolver. All lock packages are inspected,
including inactive/other-target packages. Missing lock sources block complete
lock availability, not necessarily a narrower Cargo target build. Verified
archives/checkouts are reusable inputs, not proof Cargo can consume them offline.
No Cargo, compiler, network, extraction, source mutation or cache mutation occurs.
JSON goes to stdout; exit 1 means blocked, 2 means invalid invocation/input.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'ports/cosmic/manifest.json'
SOURCE = ROOT / 'artifacts/cosmic-sources/cosmic-comp-epoch'
PATCH = ROOT / 'ports/cosmic/patches/cosmic-comp-41497b42-cyxia-nested.json'
TARGET = 'x86_64-unknown-linux-musl'
SHA256 = re.compile(r'[0-9a-f]{64}')
REVISION = re.compile(r'[0-9a-f]{40}')


class UnverifiedSource(ValueError):
    """Source exists but this inspector cannot establish complete identity."""


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def git_blob(path):
    """Bind working bytes directly; index flags/timestamps are not identity."""
    value = hashlib.sha1(b'blob ' + str(path.stat().st_size).encode() + b'\0')
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def document(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique_object)


def relative(name):
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('unsafe relative path: ' + name)
    return path


def regular(path, root):
    """Do not accept aliases or silently follow a cache/source symlink."""
    path, root = Path(path).absolute(), Path(root).absolute()
    if not path.is_relative_to(root):
        raise ValueError('path escapes selected root: ' + str(path))
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('symlink input: ' + str(item))
        if item == root:
            break
    if not path.is_file():
        raise ValueError('missing regular file: ' + str(path))
    return path


def git(path, *arguments):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, LC_ALL='C')
    result = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
                             '-C', str(path), *arguments], env=env, text=True,
                            capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('read-only Git check failed: ' + result.stderr.strip())
    return result.stdout.rstrip('\n')


def repository(url):
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.netloc or parts.username or parts.password:
        raise ValueError('unsupported Git repository URL')
    return parts.netloc.lower() + '/' + '/'.join(p for p in parts.path.split('/') if p).removesuffix('.git')


def checkout(path, expected_commit, expected_repository, *, cargo_checkout=False, depth=0):
    path = Path(path).absolute()
    if not REVISION.fullmatch(expected_commit):
        raise ValueError('Git commit must be an exact 40-character pin')
    if path.is_symlink() or not path.is_dir():
        raise ValueError('checkout missing or aliased')
    if depth > 8:
        raise UnverifiedSource('Git submodule nesting exceeds inspection bound')
    if Path(git(path, 'rev-parse', '--show-toplevel')).resolve() != path.resolve():
        raise ValueError('path inherits an ancestor Git repository')
    commit = git(path, 'rev-parse', 'HEAD')
    if commit != expected_commit:
        raise ValueError('checkout commit differs from pin')
    # Cargo's detached checkouts need not have an upstream remote. Their exact
    # content-addressed commit remains the lock's source identity; a directory
    # name or Cargo completion marker alone is never evidence.
    origin = None if cargo_checkout else git(path, 'remote', 'get-url', 'origin')
    if not cargo_checkout and repository(origin) != repository(expected_repository):
        raise ValueError('checkout origin differs from pin')
    tree = [entry for entry in git(path, 'ls-tree', '-r', '-z', 'HEAD').split('\0') if entry]
    gitlinks = {line.partition('\t')[2]: line.partition('\t')[0].split()[2]
                for line in tree if line.startswith('160000 ')}
    if gitlinks and not cargo_checkout:
        raise UnverifiedSource('non-Cargo checkout has gitlinks; recursive source closure unverified')
    status = git(path, 'status', '--porcelain', '--untracked-files=all', '--ignored').splitlines()
    if cargo_checkout and (path / '.cargo-ok').exists():
        marker = regular(path / '.cargo-ok', path).read_bytes()
        if marker not in (b'', b'{"v":1}'):
            raise ValueError('unexpected Cargo checkout completion marker')
        status = [line for line in status if line not in ('?? .cargo-ok', '!! .cargo-ok')]
    # A submodule's Cargo marker marks the parent dirty. Only defer these exact
    # worktree entries; recursively validate its commit and every other change.
    status = [line for line in status if not
              (line[:2] in (' M', ' m', ' ?') and line[3:] in gitlinks)]
    if status:
        raise ValueError('checkout has modified, untracked or ignored inputs')
    entries = [entry.partition('\t')[2] for entry in tree]
    entries = [name for name in entries if name not in gitlinks]
    for entry in tree:
        header, _, name = entry.partition('\t')
        if name in gitlinks:
            continue
        original = regular(path / relative(name), path)
        if git_blob(original) != header.split()[2]:
            raise ValueError('tracked source bytes differ from pinned Git blob: ' + name)
    submodules = []
    for name, revision in gitlinks.items():
        child, nested = checkout(path / relative(name), revision, expected_repository,
                                 cargo_checkout=True, depth=depth + 1)
        submodules.append({'path': name, 'commit': child['commit'], 'tree': child['tree'],
                           'verified': True, 'submodules': child['submodules']})
        entries.extend(name + '/' + entry for entry in nested)
    return {'path': str(path), 'commit': commit, 'repository': expected_repository,
            'origin_verified': not cargo_checkout,
            'tree': git(path, 'rev-parse', 'HEAD^{tree}'), 'verified': True,
            'submodules': submodules}, entries


def patch_bytes(source, patch, before):
    """Strict unified diff in memory; no fuzz, external patch process or writes."""
    lines = patch.decode().splitlines(keepends=True)
    i, outputs = 0, {}
    while i < len(lines):
        if not lines[i].startswith('--- '):
            raise ValueError('unsupported patch syntax')
        old = lines[i][4:].rstrip('\n')
        i += 1
        if i >= len(lines) or not lines[i].startswith('+++ '):
            raise ValueError('missing patch destination')
        new = lines[i][4:].rstrip('\n')
        i += 1
        if not new.startswith('b/') or (old != '/dev/null' and old != 'a/' + new[2:]):
            raise ValueError('patch rename/deletion unsupported')
        name = str(relative(new[2:]))
        if name not in before or name in outputs:
            raise ValueError('patch file not uniquely declared by manifest')
        original = (source / name).read_bytes() if before[name] is not None else b''
        original_lines = original.decode().splitlines(keepends=True)
        cursor, out = 0, []
        while i < len(lines) and lines[i].startswith('@@ '):
            hunk = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?', lines[i])
            if not hunk:
                raise ValueError('invalid patch hunk')
            start, old_count, new_start, new_count = hunk.groups()
            old_count, new_count = int(old_count or 1), int(new_count or 1)
            start = int(start) - (1 if old_count else 0)
            if start < cursor or start > len(original_lines):
                raise ValueError('patch hunk lies outside source')
            out.extend(original_lines[cursor:start])
            cursor, removed, added = start, 0, 0
            if len(out) != int(new_start) - (1 if new_count else 0):
                raise ValueError('patch new line position differs')
            i += 1
            while removed < old_count or added < new_count:
                if i >= len(lines) or lines[i][:1] not in (' ', '+', '-'):
                    raise ValueError('truncated patch hunk')
                prefix, content = lines[i][0], lines[i][1:]
                if prefix in (' ', '-'):
                    if cursor >= len(original_lines) or original_lines[cursor] != content:
                        raise ValueError('patch context differs from source')
                    removed += 1
                    cursor += 1
                if prefix in (' ', '+'):
                    out.append(content)
                    added += 1
                i += 1
            if removed != old_count or added != new_count:
                raise ValueError('patch hunk counts differ')
        out.extend(original_lines[cursor:])
        outputs[name] = ''.join(out).encode()
    if set(outputs) != set(before):
        raise ValueError('patch file set differs from manifest')
    return outputs


def inspect_patch(source, path, pin):
    manifest = document(path)
    patch = Path(path).with_suffix('.patch')
    record = {'manifest': str(path), 'manifest_sha256': digest(path),
              'path': str(patch), 'verified': False}
    try:
        if (manifest.get('schema_version') != 1 or manifest.get('commit') != pin['commit'] or
                repository(manifest['repository']) != repository(pin['repository'])):
            raise ValueError('patch does not identify pinned source')
        regular(patch, patch.parent)
        record['sha256'] = digest(patch)
        if record['sha256'] != manifest['patch_sha256']:
            raise ValueError('patch checksum mismatch')
        if set(manifest['before']) != set(manifest['after']):
            raise ValueError('patch before/after file sets differ')
        for name, expected in manifest['before'].items():
            original = source / relative(name)
            if expected is None:
                if original.exists() or original.is_symlink():
                    raise ValueError('patch new file already exists: ' + name)
            elif digest(regular(original, source)) != expected:
                raise ValueError('patch before identity mismatch: ' + name)
        changed = patch_bytes(source, patch.read_bytes(), manifest['before'])
        for name, data in changed.items():
            if hashlib.sha256(data).hexdigest() != manifest['after'][name]:
                raise ValueError('patch after identity mismatch: ' + name)
        record.update(verified=True, files=len(changed), application='verified in memory; source unchanged')
        return record, changed, manifest.get('features', [])
    except (OSError, ValueError, KeyError) as error:
        record['error'] = str(error)
        return record, {}, []


def feature_analysis(data, arguments):
    manifest = tomllib.loads(data.decode())
    features = manifest.get('features', {})
    selected = [] if '--no-default-features' in arguments else ['default']
    for i, argument in enumerate(arguments):
        if argument == '--features':
            if i + 1 == len(arguments):
                raise ValueError('missing patch feature selection')
            selected.extend(arguments[i + 1].replace(',', ' ').split())
    todo, active = list(selected), set()
    while todo:
        item = todo.pop()
        if item in active:
            continue
        active.add(item)
        todo.extend(features.get(item, []))
    direct = {}
    for name, spec in manifest.get('dependencies', {}).items():
        spec = spec if isinstance(spec, dict) else {'version': spec}
        enabled = not spec.get('optional') or name in active or 'dep:' + name in active
        enabled = enabled or any(item.startswith(name + '/') for item in active)
        if enabled:
            selected_features = set(spec.get('features', []))
            selected_features.update(item.split('/', 1)[1] for item in active
                                     if item.startswith(name + '/') or item.startswith(name + '?/'))
            direct[name] = {'features': sorted(selected_features),
                            'default_features': spec.get('default-features', True)}
    return {'scope': 'root manifest only; no dependency/target resolution',
            'selected': selected, 'expanded_root_features': sorted(active),
            'enabled_direct_dependencies': direct, 'cargo_resolved': False}


def package_manifests(path, entries):
    result = []
    manifests = {str(PurePosixPath(entry)): tomllib.loads((path / entry).read_text())
                 for entry in entries if PurePosixPath(entry).name == 'Cargo.toml'}
    for entry, manifest in manifests.items():
        item = manifest.get('package', {})
        version = item.get('version')
        if isinstance(version, dict) and version.get('workspace'):
            directory = PurePosixPath(entry).parent
            if item.get('workspace'):
                selected = (path / directory / item['workspace'] / 'Cargo.toml').resolve()
                if not selected.is_relative_to(path.resolve()):
                    raise UnverifiedSource('package workspace escapes pinned checkout')
                ancestors = [str(selected.relative_to(path.resolve()))]
            else:
                ancestors = [str(parent / 'Cargo.toml') for parent in (directory, *directory.parents)]
            workspace = next((manifests[p]['workspace'] for p in ancestors
                              if p in manifests and 'workspace' in manifests[p]), {})
            version = workspace.get('package', {}).get('version')
        if item.get('name') and isinstance(version, str):
            result.append((item['name'], version, entry))
    return result


def closure(packages, source, source_record, source_entries, archive_caches, cargo_caches, git_sources):
    roots = [Path(p).absolute() for p in archive_caches]
    checkouts = [(Path(p), False) for p in git_sources]
    caches = []
    for cache in map(Path, cargo_caches):
        caches.append({'path': str(cache), 'exists': cache.is_dir(),
                       'configuration_present': any((cache / p).exists() for p in ('config', 'config.toml'))})
        roots.extend(sorted((cache / 'registry/cache').glob('*')))
        checkouts.extend((p, True) for p in sorted((cache / 'git/checkouts').glob('*/*')))
    local = package_manifests(source, source_entries) if source_record['verified'] else []
    git_results, records, seen = {}, [], set()
    for package in packages:
        name, version, spec = package['name'], package['version'], package.get('source')
        identity = (name, version, spec)
        if identity in seen:
            raise ValueError('duplicate locked package identity')
        seen.add(identity)
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or not re.fullmatch(r'[A-Za-z0-9.+_-]+', version):
            raise ValueError('invalid locked package name/version')
        record = {'name': name, 'version': version, 'source': spec, 'status': 'missing', 'evidence': [], 'errors': []}
        if spec is None:
            record['kind'] = 'local'
            for n, v, entry in local:
                if (n, v) == (name, version):
                    record['evidence'].append({'path': str(source / entry), 'sha256': digest(source / entry)})
        elif spec.startswith('registry+'):
            record['kind'] = 'registry'
            checksum = package.get('checksum', '')
            if not SHA256.fullmatch(checksum):
                record['errors'].append('locked registry source lacks a SHA256 checksum')
            else:
                record['checksum'] = checksum
                for root in roots:
                    path = root / f'{name}-{version}.crate'
                    if not path.exists() and not path.is_symlink():
                        continue
                    try:
                        actual = digest(regular(path, root))
                        if actual != checksum:
                            raise ValueError('archive checksum mismatch: ' + str(path))
                        record['evidence'].append({'path': str(path), 'sha256': actual,
                                                   'kind': 'locked-registry-archive'})
                    except (OSError, ValueError) as error:
                        record['errors'].append(str(error))
        elif spec.startswith('git+'):
            record['kind'] = 'git'
            if spec not in git_results:
                url, separator, commit = spec[4:].partition('#')
                url = url.partition('?')[0]
                valid, errors, unverified = [], [], False
                if not separator or not REVISION.fullmatch(commit):
                    errors.append('Git lock source lacks exact revision')
                else:
                    for candidate, cargo_checkout in checkouts:
                        try:
                            # Unrelated checkouts are not corruption of this source.
                            if cargo_checkout and git(candidate, 'rev-parse', 'HEAD') != commit:
                                continue
                            if not cargo_checkout and repository(git(candidate, 'remote', 'get-url', 'origin')) != repository(url):
                                continue
                            info, entries = checkout(candidate, commit, url, cargo_checkout=cargo_checkout)
                            valid.append((info, package_manifests(candidate, entries)))
                        except (OSError, ValueError, subprocess.SubprocessError) as error:
                            errors.append(str(candidate) + ': ' + str(error))
                            unverified = unverified or isinstance(error, UnverifiedSource)
                git_results[spec] = (valid, errors, unverified)
            valid, errors, unverified = git_results[spec]
            record['errors'].extend(errors)
            if unverified:
                record['status'] = 'unverified'
            for info, members in valid:
                for n, v, entry in members:
                    if (n, v) == (name, version):
                        record['evidence'].append({**info, 'manifest': entry, 'kind': 'clean-pinned-git-checkout'})
            if valid and not record['evidence']:
                record['errors'].append('locked package/version absent from pinned checkout manifests')
        else:
            record['kind'] = 'unsupported'
            record['errors'].append('unsupported locked source')
        if record['evidence']:
            record['status'] = 'available'
        elif record['status'] != 'unverified':
            record['status'] = 'invalid' if record['errors'] else 'missing'
        records.append(record)
    counts = Counter((p['kind'], p['status']) for p in records)
    return {'scope': 'all Cargo.lock packages; includes inactive and other-target packages',
            'all_locked_sources_available': source_record['verified'] and bool(records) and
                all(p['status'] == 'available' for p in records),
            'package_count': len(records), 'git_source_count': len(git_results),
            **{kind + '_' + status: counts[kind, status] for kind in ('registry', 'git', 'local')
               for status in ('available', 'missing', 'invalid', 'unverified')},
            'archive_roots': [{'path': str(p), 'exists': p.is_dir()} for p in roots],
            'cargo_caches': caches, 'packages': records}


def inspect(*, source=SOURCE, manifest=MANIFEST, patch_manifest=PATCH,
            archive_caches=(), cargo_caches=(), git_sources=(),
            sysroot=ROOT / 'artifacts/sysroot/x86_64-musl', target=TARGET):
    if target != TARGET:
        raise ValueError('this preflight currently supports only ' + TARGET)
    source, manifest, sysroot = Path(source).absolute(), Path(manifest), Path(sysroot)
    contract = document(manifest)
    pin = next(p for p in contract['components'] if p['name'] == 'cosmic-comp')
    record = {'path': str(source), 'expected_commit': pin['commit'], 'verified': False}
    entries, blockers = [], []
    lock = regular(source / 'Cargo.lock', source)
    record['lock_sha256'] = digest(lock)
    try:
        info, entries = checkout(source, pin['commit'], pin['repository'])
        if record['lock_sha256'] != contract['compositor']['cargo_lock_sha256']:
            raise ValueError('source Cargo.lock checksum differs from manifest')
        record.update(info)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record['error'] = str(error)
        blockers.append({'id': 'source_identity', 'detail': str(error)})
    packages = tomllib.loads(lock.read_text())['package']
    availability = closure(packages, source, record, entries, archive_caches, cargo_caches, git_sources)
    if not availability['all_locked_sources_available']:
        blockers.append({'id': 'locked_source_closure_incomplete',
                         'detail': 'Some full-lock source inputs are missing or invalid; selected-target requirements remain unresolved.'})
    patch_record, changed, features = {'verified': False, 'selected': False}, {}, []
    if patch_manifest is not None:
        patch_record, changed, features = inspect_patch(source, Path(patch_manifest), pin)
        if not patch_record['verified']:
            blockers.append({'id': 'patch_identity', 'detail': patch_record.get('error')})
    effective = changed.get('Cargo.toml', regular(source / 'Cargo.toml', source).read_bytes())
    analysis = feature_analysis(effective, features)
    analysis['manifest_sha256'] = hashlib.sha256(effective).hexdigest()
    analysis['trusted'] = record['verified'] and (patch_manifest is None or patch_record['verified'])
    libraries = []
    for library in contract.get('target_libraries', []):
        found = sorted({str(p) for pattern in library['filenames']
                        for p in (sysroot / 'sysroot/usr/lib').glob(pattern) if p.is_file()})
        libraries.append({'name': library['name'], 'scope': library.get('scope'),
                          'paths': found, 'present': bool(found), 'note': library.get('note'),
                          'selected_target_requirement_proven': False})
    blockers.extend([
        {'id': 'cargo_target_resolution_unperformed', 'detail': 'No --locked --offline Cargo metadata was run for this target and selected features.'},
        {'id': 'cargo_cache_consumability_unverified', 'detail': 'Archive bytes and clean Git checkouts do not establish a Cargo source replacement/index configuration.'},
        {'id': 'native_build_contract_unverified', 'detail': 'A reviewed cosmic-comp target recipe must pin the selected native inputs, toolchain and effective lock; SDK presence is only inventory.'},
        {'id': 'compositor_build_unperformed', 'detail': 'No cosmic-comp compiler/linker or guest execution proof is produced by this read-only command.'},
    ])
    return {'schema_version': 1, 'status': 'blocked', 'target': target, 'read_only': True,
            'source_manifest': {'path': str(manifest), 'sha256': digest(manifest)},
            'source': record, 'patch': patch_record, 'feature_analysis': analysis,
            'closure': availability, 'native_inventory': {'sysroot': str(sysroot),
                'scope': 'committed inventory, not resolved link requirements; no architecture or ABI proof',
                'libraries': libraries}, 'blockers': blockers,
            'cargo_offline_ready': False, 'target_resolution_proven': False,
            'compositor_built': False, 'guest_executed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    parser.add_argument('--patch-manifest', type=Path, default=PATCH,
                        help='exact before/after identity manifest; patch has same stem and .patch suffix')
    parser.add_argument('--no-patch', action='store_true')
    parser.add_argument('--target', default=TARGET)
    parser.add_argument('--archive-cache', type=Path, action='append',
                        help='flat directory of name-version.crate archives; repeatable')
    parser.add_argument('--cargo-cache', type=Path, action='append',
                        help='Cargo home to inspect read-only; repeatable, never implicitly uses ~/.cargo')
    parser.add_argument('--git-source', type=Path, action='append', default=[],
                        help='additional exact clean Git checkout; repeatable')
    parser.add_argument('--sysroot', type=Path, default=ROOT / 'artifacts/sysroot/x86_64-musl')
    args = parser.parse_args(argv)
    try:
        report = inspect(source=args.source, manifest=args.manifest,
                         patch_manifest=None if args.no_patch else args.patch_manifest,
                         target=args.target, sysroot=args.sysroot, git_sources=args.git_source,
                         archive_caches=args.archive_cache if args.archive_cache is not None else
                            [ROOT / 'artifacts/smithay-wayland-research/cache'],
                         cargo_caches=args.cargo_cache if args.cargo_cache is not None else
                            [ROOT / 'artifacts/cosmic-cargo-cache'])
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        print(json.dumps({'schema_version': 1, 'status': 'invalid', 'error': str(error),
                          'cargo_offline_ready': False, 'target_resolution_proven': False,
                          'compositor_built': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
