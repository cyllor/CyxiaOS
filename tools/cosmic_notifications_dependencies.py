"""Notification metadata validation with one exact pinned Git link boundary.

Winit workspace crates share tracked licenses/readmes across package roots.
Their complete fixed Git checkout, every tracked blob and every symlink target
are validated; no cache bytes, frozen helpers or source identities are changed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib

try:
    from . import build_cosmic as build
except ImportError:
    import build_cosmic as build

WINIT_SOURCE = 'git+https://github.com/pop-os/winit.git?rev=9567503#9567503d34130113e36b0167a2b8829c3756e429'
WINIT_COMMIT = '9567503d34130113e36b0167a2b8829c3756e429'
WINIT_TREE = '89af16268b36f659035cc6c523d398c4f0ddd4da'


def require(value, message):
    if not value:
        raise build.CosmicBuildError(message)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def pinned_git(source, *arguments):
    """Read canonical Git objects, never a cache's local replacement refs.

    HEAD and HEAD^{tree} keep their original IDs under a tree replacement while
    ls-tree follows the replacement. Apply this option to every identity read;
    the frozen shared Git producer remains unchanged.
    """
    return build.git(source, '--no-replace-objects', *arguments)


def parse_git_tree(text):
    records = {}
    for row in text.split('\0'):
        if not row:
            continue
        head, name = row.split('\t', 1)
        mode, kind, blob = head.split()
        build.dependencies.relative_path(name)
        require(name not in records and kind == 'blob' and mode in ('100644', '100755', '120000')
                and re.fullmatch('[0-9a-f]{40}', blob), 'Unsupported/duplicate pinned Git tree entry')
        records[name] = {'mode': mode, 'blob': blob}
    require(records, 'Empty pinned Git checkout tree')
    return records


def validate_checkout_tree(root, declared):
    """Public filesystem validator; declared objects come from the fixed Git tree."""
    root = build.no_symlink_path(root)
    observed = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in list(directories):
            selected = parent / name
            if selected == root / '.git':
                require(not selected.is_symlink(), 'Aliased checkout Git metadata')
                directories.remove(name)
            elif selected.is_symlink():
                observed.add(str(selected.relative_to(root)))
                directories.remove(name)
        for name in files:
            selected = parent / name
            if selected == root / '.cargo-ok':
                require(not selected.is_symlink() and selected.is_file(), 'Aliased Cargo cache marker')
                continue
            observed.add(str(selected.relative_to(root)))
    require(observed == set(declared), 'Pinned Git checkout file inventory changed')
    files = {}; total = 0
    for name, record in sorted(declared.items()):
        relative = build.dependencies.relative_path(name)
        selected = root / relative
        info = selected.lstat()
        if record['mode'] == '120000':
            require(stat.S_ISLNK(info.st_mode), 'Tracked Git symlink was replaced: ' + name)
            target = os.readlink(selected)
            raw = os.fsencode(target)
            require(not Path(target).is_absolute(), 'Absolute tracked Git symlink: ' + name)
            lexical = Path(os.path.normpath(selected.parent / target))
            require(lexical.is_relative_to(root), 'Git link escapes pinned checkout: ' + name)
            try:
                resolved = selected.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise build.CosmicBuildError('Broken/cyclic pinned Git symlink: ' + name) from error
            require(resolved.is_relative_to(root), 'Git link resolves outside pinned checkout: ' + name)
            target_name = str(resolved.relative_to(root))
            if resolved.is_file():
                require(target_name in declared and declared[target_name]['mode'] in ('100644', '100755'),
                        'Git link target is not a pinned regular file: ' + name)
                target_identity = {'bytes': resolved.stat().st_size, 'sha256': build.digest(resolved)}
            else:
                require(resolved.is_dir() and any(p.startswith(target_name + '/') for p in declared),
                        'Git link target is not a pinned directory: ' + name)
                target_identity = {'git_entries_sha256': canonical_hash(
                    {p: v for p, v in declared.items() if p.startswith(target_name + '/')})}
            item = {'mode': record['mode'], 'git_blob': record['blob'], 'symlink': target,
                    'resolved_path': target_name, 'resolved_identity': target_identity}
        else:
            require(record['mode'] in ('100644', '100755') and stat.S_ISREG(info.st_mode),
                    'Tracked Git file is not regular: ' + name)
            require(bool(info.st_mode & 0o111) == (record['mode'] == '100755'),
                    'Pinned Git file executable mode changed: ' + name)
            require(info.st_size <= 16 * 1024**2, 'Pinned Git blob exceeds size bound')
            raw = selected.read_bytes()
            total += len(raw)
            require(total <= 64 * 1024**2, 'Pinned Git checkout exceeds size bound')
            item = {'mode': record['mode'], 'git_blob': record['blob'],
                    'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        require(git_blob(raw) == record['blob'], 'Pinned Git blob bytes changed: ' + name)
        files[name] = item
    return {'sha256': canonical_hash(files), 'files': files}


def checkout_identity(manifest, cache, spec):
    require(spec == WINIT_SOURCE, 'Undeclared cross-package Git symlink source')
    checkouts = build.no_symlink_path(cache / 'git/checkouts')
    manifest = build.no_symlink_path(manifest)
    require(manifest.is_relative_to(checkouts), 'Git package escapes checkout cache')
    relative = manifest.relative_to(checkouts)
    require(len(relative.parts) >= 4, 'Git package lacks a checkout root and package path')
    root = checkouts / relative.parts[0] / relative.parts[1]
    require((root / '.git').is_dir() and not (root / '.git').is_symlink()
            and Path(pinned_git(root, 'rev-parse', '--show-toplevel')) == root,
            'Git package is not in its own pinned checkout')
    require(pinned_git(root, 'rev-parse', 'HEAD') == WINIT_COMMIT
            and pinned_git(root, 'rev-parse', 'HEAD^{tree}') == WINIT_TREE,
            'Git package checkout commit/tree differs from declared source')
    declared = parse_git_tree(pinned_git(root, 'ls-tree', '-rz', 'HEAD'))
    identity = validate_checkout_tree(root, declared)
    require(str(manifest.relative_to(root)) in declared, 'Package manifest is not in pinned Git tree')
    return {'path': str(root), 'source': spec, 'commit': WINIT_COMMIT, 'git_tree': WINIT_TREE,
            'tree_sha256': identity['sha256'], 'files': identity['files']}


def verify_metadata(metadata, source, cache, recipe):
    source, cache = build.no_symlink_path(source), build.no_symlink_path(cache)
    packages = metadata.get('packages', [])
    require(metadata.get('version') == 1 and packages, 'Incomplete notification Cargo metadata')
    ids = {p['id'] for p in packages}
    require(len(ids) == len(packages), 'Duplicate Cargo package identity')
    nodes = metadata.get('resolve', {}).get('nodes', [])
    require(nodes and len({n['id'] for n in nodes}) == len(nodes)
            and all(n['id'] in ids and all(d in ids for d in n['dependencies']) for n in nodes),
            'Incomplete Cargo dependency graph')
    locked = {(p['name'], p['version'], p.get('source'))
              for p in tomllib.loads((source / 'Cargo.lock').read_text())['package']}
    selected = [p for p in packages if p['name'] == recipe['package'] and p.get('source') is None
                and Path(p['manifest_path']) == source / 'Cargo.toml']
    require(len(selected) == 1 and any(t['name'] == recipe['binary'] and 'bin' in t['kind']
                                      for t in selected[0]['targets']),
            'Recipe does not select exactly one local package binary')
    origins, records = {}, []
    for package in packages:
        manifest = build.no_symlink_path(package['manifest_path'])
        require(manifest.is_file(), 'Missing dependency manifest')
        spec = package.get('source')
        require((package['name'], package['version'], spec) in locked,
                'Cargo package differs from effective source lock')
        allowed = source if spec is None else cache / ('registry/src' if spec.startswith('registry+') else 'git/checkouts')
        require(manifest.is_relative_to(allowed), 'Cargo dependency escapes its declared source/cache')
        require(spec is None or spec.startswith('registry+') or re.fullmatch(r'git\+https://[^\s#]+#[0-9a-f]{40}', spec),
                'Cargo resolved an unpinned source')
        record = {'name': package['name'], 'version': package['version'], 'source': spec,
                  'manifest': str(manifest)}
        if spec == WINIT_SOURCE:
            root = Path(*manifest.parts[:len((cache / 'git/checkouts').parts) + 2])
            key = str(root)
            if key not in origins:
                origins[key] = checkout_identity(manifest, cache, spec)
            origin = origins[key]
            require(str(manifest.relative_to(root)) in origin['files'], 'Untracked Git package manifest')
            record['git_checkout'] = origin
            record['source_tree_sha256'] = origin['tree_sha256']
        else:
            record['source_tree_sha256'] = build.tree_identity(manifest.parent)['sha256']
        records.append(record)
    return records
