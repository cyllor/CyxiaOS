#!/usr/bin/env python3
"""Inspect pinned COSMIC metadata without cloning, building, or fetching assets.

The default inventory is offline. Explicit `fetch` retrieves a bounded Git tree
and selected text blobs from one immutable GitHub commit. A lockfile identity is
not a vendored dependency closure or a validated target feature selection.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from . import cosmic_ports as ports
except ImportError:
    import cosmic_ports as ports

ROOT = ports.ROOT
CACHE = ROOT / 'artifacts/cosmic-metadata'
OUTPUT = ROOT / 'ports/cosmic/dependencies.json'
MAX_FILE = 2 * 1024 * 1024
MAX_TREE = 12 * 1024 * 1024
MAX_SELECTED = 180


class DependencyError(ports.PortError):
    """Untrusted, inconsistent, or unavailable source metadata."""


def relative_path(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise DependencyError('invalid relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or str(path) != value:
        raise DependencyError('unsafe relative path')
    return path


def git_blob_sha(data):
    return hashlib.sha1(f'blob {len(data)}\0'.encode() + data).hexdigest()


def validate_tree(data):
    if data.get('truncated') is not False or not isinstance(data.get('tree'), list):
        raise DependencyError('missing or truncated Git tree')
    seen = set()
    for item in data['tree']:
        path = str(relative_path(item['path']))
        if path in seen or not re.fullmatch(r'[0-9a-f]{40}', item.get('sha', '')):
            raise DependencyError('duplicate path or invalid Git object')
        seen.add(path)
        if item.get('type') not in ('blob', 'tree', 'commit'):
            raise DependencyError('unsupported Git object type')
        if item['type'] == 'blob' and (not isinstance(item.get('size'), int) or item['size'] < 0):
            raise DependencyError('invalid blob size')
    return data['tree']


def github_repository(source):
    url = ports.repository_url(source['repository'])
    match = re.fullmatch(r'https://github.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)', url)
    if not match:
        raise DependencyError('metadata fetch currently supports fixed GitHub sources only')
    return match[1]


def download(url, limit):
    request = Request(url, headers={'User-Agent': 'CyxiaOS-pinned-metadata/1',
                                    'Accept': 'application/vnd.github+json'})
    with urlopen(request, timeout=40) as response:
        final = response.geturl()
        if not final.startswith(('https://api.github.com/', 'https://raw.githubusercontent.com/')):
            raise DependencyError('unexpected metadata redirect')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise DependencyError('metadata response exceeds bounded size')
    return data


def selected_paths(tree):
    """Cargo manifests, install instructions, licenses and bounded service entrypoints."""
    paths = []
    for item in tree:
        if item['type'] != 'blob' or item.get('mode') not in ('100644', '100755'):
            continue
        path = PurePosixPath(item['path'])
        root_file = len(path.parts) == 1 and (
            path.name in ('Cargo.lock', 'justfile', 'Makefile', 'meson.build', 'README.md')
            or path.name.upper().startswith(('LICENSE', 'COPYING')))
        service = (path.suffix in ('.service', '.socket', '.policy')
                   or item['path'] in ('src/main.rs', 'src/lib.rs'))
        if path.name in ('Cargo.toml', 'build.rs') or root_file or service:
            if item['size'] > MAX_FILE:
                raise DependencyError('selected text file exceeds limit: ' + item['path'])
            paths.append(item)
    if len(paths) > MAX_SELECTED:
        raise DependencyError('selected metadata exceeds file limit; narrow explicit audit needed')
    return sorted(paths, key=lambda p: p['path'])


def local_tree(path):
    entries = []
    raw = subprocess.check_output(['git', '-C', str(path), 'ls-tree', '-rzl', 'HEAD'])
    for row in raw.split(b'\0'):
        if not row:
            continue
        fields, name = row.decode().split('\t', 1)
        mode, kind, sha, size = fields.split()
        item = {'path': name, 'mode': mode, 'type': kind, 'sha': sha}
        if kind == 'blob':
            item['size'] = int(size)
        entries.append(item)
    return {'truncated': False, 'tree': entries}


def read_evidence(directory, source):
    directory = Path(directory)
    if directory.is_symlink() or directory.parent.is_symlink():
        raise DependencyError('metadata directory is a symlink')
    evidence = json.loads((directory / 'evidence.json').read_text(), object_pairs_hook=ports.unique_object)
    if evidence['source'] != source:
        raise DependencyError('cached source identity differs from manifest')
    seen = set()
    for item in evidence['files']:
        relative_path(item['path'])
        path = directory / item['path']
        if item['path'] in seen or path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
            raise DependencyError('duplicate or escaping evidence file')
        seen.add(item['path'])
        data = path.read_bytes()
        if (len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']
                or git_blob_sha(data) != item['git_blob']):
            raise DependencyError('cached blob identity mismatch: ' + item['path'])
    return evidence


def fetch(source, cache=CACHE, source_cache=ports.CACHE):
    ports.validate_source(source)
    cache = Path(cache)
    if cache.is_symlink():
        raise DependencyError('metadata cache is a symlink')
    destination = cache / source['name'] / source['commit']
    if destination.exists():
        return read_evidence(destination, source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    record = ports.inspect_source(source_cache, source)
    repo = github_repository(source)
    url = f'https://api.github.com/repos/{repo}/git/trees/{source["commit"]}?recursive=1'
    local = Path(record['path']) if record['verified'] else None
    if record['status'] == 'invalid':
        raise DependencyError('existing checkout is invalid; preserved: ' + record.get('error', ''))
    tree_data = local_tree(local) if local else json.loads(download(url, MAX_TREE))
    tree = validate_tree(tree_data)
    items = selected_paths(tree)
    if sum(item['size'] for item in items) > 32 * 1024 * 1024:
        raise DependencyError('component text evidence exceeds 32 MiB')
    with tempfile.TemporaryDirectory(prefix='.metadata-', dir=destination.parent) as temporary:
        stage = Path(temporary) / 'data'
        stage.mkdir()
        (stage / 'git-tree.json').write_text(json.dumps(tree_data, indent=2) + '\n')

        def get(item):
            raw_url = f'https://raw.githubusercontent.com/{repo}/{source["commit"]}/{item["path"]}'
            data = (subprocess.check_output(['git', '-C', str(local), 'show', 'HEAD:' + item['path']])
                    if local else download(raw_url, MAX_FILE))
            if len(data) != item['size'] or git_blob_sha(data) != item['sha']:
                raise DependencyError('Git blob differs from fixed tree: ' + item['path'])
            path = stage / item['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return {'path': item['path'], 'url': raw_url, 'bytes': len(data),
                    'git_blob': item['sha'], 'sha256': hashlib.sha256(data).hexdigest()}

        with ThreadPoolExecutor(max_workers=4) as pool:
            files = list(pool.map(get, items))
        evidence = {'source': source, 'tree_url': url, 'tree_sha256': hashlib.sha256(
            (stage / 'git-tree.json').read_bytes()).hexdigest(), 'files': files,
            'mode': 'verified-local-git' if local else 'https-fixed-commit',
            'assets_downloaded': False, 'recursive_source_fetch': False,
            'text_bytes': sum(p['bytes'] for p in files), 'complete_checkout': False}
        (stage / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if destination.exists():
            raise DependencyError('destination appeared during fetch; preserving it')
        stage.rename(destination)
    return read_evidence(destination, source)


def cargo_summary(data):
    document = tomllib.loads(data.decode())
    dependencies = []

    def walk(table, prefix=''):
        for key, value in table.items():
            name = prefix + key
            if key in ('dependencies', 'build-dependencies', 'dev-dependencies') and isinstance(value, dict):
                dependencies.extend({'name': dep, 'scope': name, 'spec': spec}
                                    for dep, spec in sorted(value.items()))
            elif isinstance(value, dict):
                walk(value, name + '.')

    walk(document)
    package = document.get('package', {})
    return {'package': package, 'workspace_members': document.get('workspace', {}).get('members', []),
            'binaries_declared': document.get('bin', []), 'dependencies': dependencies,
            'features': document.get('features', {}),
            'default_features': document.get('features', {}).get('default', [])}


def lock_summary(data):
    packages = tomllib.loads(data.decode()).get('package', [])
    unfixed = []
    for package in packages:
        source = package.get('source', '')
        if source.startswith('git+'):
            if not re.fullmatch(r'git\+https://[^\s#]+#[0-9a-f]{40}', source):
                unfixed.append(package['name'])
        elif source.startswith('registry+'):
            if not re.fullmatch(r'[0-9a-f]{64}', package.get('checksum', '')):
                unfixed.append(package['name'])
        elif source:
            unfixed.append(package['name'])
    return {'sha256': hashlib.sha256(data).hexdigest(), 'package_count': len(packages),
            'registry_count': sum(p.get('source', '').startswith('registry+') for p in packages),
            'git_sources': sorted({p['source'] for p in packages if p.get('source', '').startswith('git+')}),
            'unfixed_sources': unfixed, 'vendored': False,
            'resolved_target_features_audited': False}


def inventory_component(source, cache=CACHE):
    directory = Path(cache) / source['name'] / source['commit']
    result = {'name': source['name'], 'commit': source['commit'], 'repository': source['repository'],
              'metadata_status': 'not-fetched', 'target_built': False, 'guest_tested': False,
              'dependency_closure_complete': False, 'build_contract_reviewed': False}
    if not directory.exists():
        result['unknown'] = ['Fixed-commit metadata not yet retrieved.']
        return result
    evidence = read_evidence(directory, source)
    tree_bytes = (directory / 'git-tree.json').read_bytes()
    if hashlib.sha256(tree_bytes).hexdigest() != evidence['tree_sha256']:
        raise DependencyError('tree evidence identity mismatch')
    tree = validate_tree(json.loads(tree_bytes))
    files = {item['path']: item for item in evidence['files']}
    cargo = {name: cargo_summary((directory / name).read_bytes())
             for name in files if PurePosixPath(name).name == 'Cargo.toml'}
    lock = lock_summary((directory / 'Cargo.lock').read_bytes()) if 'Cargo.lock' in files else None
    asset_suffixes = ('.svg', '.png', '.jpg', '.jpeg', '.webp', '.ogg', '.wav', '.ftl', '.ttf', '.otf', '.desktop', '.xml')
    assets = [p for p in tree if p['type'] == 'blob' and p['path'].endswith(asset_suffixes)]
    services = []
    for name in files:
        if name.endswith(('.rs', '.service', '.policy', '.socket')):
            for number, line in enumerate((directory / name).read_text(errors='replace').splitlines(), 1):
                if any(word in line for word in ('org.freedesktop.', 'com.system76.', 'org.cosmic.',
                                                 'Process::new(', 'start_process(', 'Command::new(')):
                    services.append({'file': name, 'line': number, 'text': line.strip()[:300]})
    result.update(metadata_status='verified-selected-text', evidence_directory=str(directory.relative_to(ROOT))
                  if directory.is_relative_to(ROOT) else str(directory), evidence=evidence,
                  cargo_manifests=cargo, cargo_lock=lock,
                  gitlinks=[p for p in tree if p['type'] == 'commit'],
                  source_blob_bytes=sum(p['size'] for p in tree if p['type'] == 'blob'),
                  assets={'count': len(assets), 'source_bytes': sum(p['size'] for p in assets),
                          'extensions': sorted({PurePosixPath(p['path']).suffix for p in assets}),
                          'installed_bytes': None, 'payload_downloaded': False,
                          'lfs_and_generated_payload_sizes_audited': False},
                  install_evidence=[name for name in files if name in ('justfile', 'Makefile', 'meson.build')],
                  service_entrypoint_evidence=services,
                  unknown=['Native/dynamic/plugin closure and selected target features need review.',
                           'Cargo sources are pinned by lock where present, but not vendored or target-resolved.',
                           'Asset source sizes exclude generated, dependency and installed runtime data.',
                           'Service literals/entrypoints are evidence, not a complete D-Bus method contract.',
                           'Target ELF/RSS/thread/FD peaks and guest behavior have not been measured.'])
    result['declared_native_or_service_candidates'] = sorted({dependency['name']
        for item in cargo.values() for dependency in item['dependencies']
        if re.search(r'(sys$|dbus|zbus|pulse|pipewire|gstreamer|libinput|udev|libseat|xkb|libloading|'
                     r'nmrs|pam|greetd|gvfs|io-uring|flatpak|packagekit|font|notify|systemd|logind|'
                     r'nvml|password|secret)', dependency['name'])})
    result['license_evidence'] = [name for name in files
                                  if PurePosixPath(name).name.upper().startswith(('LICENSE', 'COPYING'))]
    if cargo and lock is None:
        result['unknown'].append('No root Cargo.lock in pinned tree; no reproducible build lock established.')
    return result


def inventory(manifest, cache=CACHE):
    components = [inventory_component(source, cache) for source in manifest['components']]
    return {'schema_version': 1, 'epoch_commit': manifest['epoch']['commit'], 'target': manifest['target'],
            'manifest_sha256': hashlib.sha256(ports.MANIFEST.read_bytes()).hexdigest(),
            'component_count': len(components), 'components': components,
            'metadata_components_verified': sum(p['metadata_status'] == 'verified-selected-text' for p in components),
            'full_dependency_closure_locked': False, 'full_dependency_closure_vendored': False,
            'all_target_builds_ready': False, 'network_used_for_inventory': False,
            'scope': 'Pinned metadata and selected text evidence only; not full source/feature/service closure.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inventory', 'fetch'), nargs='?', default='inventory')
    parser.add_argument('--component')
    parser.add_argument('--all', action='store_true', help='fetch bounded metadata for all 30 components')
    parser.add_argument('--cache', type=Path, default=CACHE)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = ports.load_manifest()
        if args.action == 'fetch':
            if bool(args.component) == args.all:
                raise DependencyError('fetch needs exactly one of --component or --all')
            selected = [s for s in manifest['components'] if args.all or s['name'] == args.component]
            if not selected:
                raise DependencyError('unknown component')
            failed = []
            for source in selected:
                try:
                    evidence = fetch(source, args.cache)
                    print(f'{source["name"]}: {len(evidence["files"])} verified text files; {evidence["text_bytes"]} bytes', flush=True)
                except (OSError, ValueError, KeyError, HTTPError, URLError, subprocess.SubprocessError) as error:
                    failed.append({'component': source['name'], 'error': str(error)})
                    print(f'{source["name"]}: {error}', file=sys.stderr, flush=True)
            if failed:
                if args.output:
                    args.output.write_text(json.dumps({'failures': failed}, indent=2) + '\n')
                return 1
            return 0
        if args.component or args.all:
            raise DependencyError('component selection is only valid for explicit fetch')
        result = inventory(manifest, args.cache)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + '\n')
            print(args.output)
        else:
            print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('cosmic_dependencies: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
