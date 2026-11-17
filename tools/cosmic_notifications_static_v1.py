"""Versioned, source-only static bindings for the genuine notification package.

The original Git checkout, Cargo cache and prior producers remain read-only.
Only two complete, checksum-bound registry packages are exported locally. Their
real function tables retain the upstream GUI, accessibility and X11 features.
No function in this module invokes Cargo, a compiler, a service or a guest.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tomllib

if __package__:
    from . import build_cosmic as build
    from . import cosmic_notifications_dependencies as dependencies
else:
    import build_cosmic as build
    import cosmic_notifications_dependencies as dependencies

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / 'ports/cosmic/native-notifications-static-v1'
POLICY_SHA256 = '1d019f34e76492345c429ad0489904c1ff463e164fea57041015d5cc29f67c20'
RESOURCE_SHA256 = 'fd26aed065743c2b6c8b450d3fbff999537e156b510397a9d3ac4231c61e5e0f'
TARGET = 'x86_64-unknown-linux-musl'
PROFILE = 'notifications-static-bindings-x86_64-full-os-v1'
FEATURES = ['cyxia-static']
FLAGS = ['--cfg', 'tokio_unstable']
MAX_FILE_BYTES = 16 * 1024**2
MAX_TREE_BYTES = 64 * 1024**2
MAX_ARCHIVE_BYTES = 2 * 1024**2
NATIVE_NAMES = ('libc.a', 'libclang_rt.builtins-x86_64.a', 'crt1.o', 'crti.o', 'crtn.o',
                'libwayland-client.a', 'libffi.a', 'libxkbcommon.a', 'libxkbcommon-x11.a',
                'libxcb-xkb.a', 'libxcb.a', 'libXau.a')
STATIC_NAMES = NATIVE_NAMES[5:]
require = dependencies.require


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate source-policy JSON key')
        result[key] = value
    return result


def read_regular(path, limit=MAX_FILE_BYTES):
    path = build.no_symlink_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
                'Source input is not a bounded regular file: ' + str(path))
        data = stream.read(limit + 1)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(len(data) == before.st_size and len(data) <= limit
                and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(path.stat(follow_symlinks=False)),
                'Source input changed during read: ' + str(path))
    return data


def load_policy(path=PORT / 'source-policy.json'):
    data = read_regular(path, 2 * 1024**2)
    require(sha(data) == POLICY_SHA256, 'Unreviewed notification static source policy')
    policy = json.loads(data, object_pairs_hook=no_duplicates)
    require(type(policy) is dict and policy['kind'] == 'cosmic-notifications-static-v1'
            and policy['runtime_verified'] is False, 'Invalid static notification policy')
    return policy


def support_sources(policy_path, policy):
    policy_path = build.no_symlink_path(policy_path)
    result = {str(policy_path): sha(read_regular(policy_path))}
    require(result[str(policy_path)] == POLICY_SHA256, 'Static source policy changed')
    for patch in policy['patches']:
        relative = build.dependencies.relative_path(patch['path'])
        selected = build.no_symlink_path(policy_path.parent / relative)
        require(selected.is_relative_to(policy_path.parent)
                and sha(read_regular(selected)) == patch['sha256'], 'Static patch identity changed')
        result[str(selected)] = patch['sha256']
    return dict(sorted(result.items()))


def producer_sources(entry):
    """The existing transitive local-import representation, without native probes."""
    pending, result = [build.no_symlink_path(entry)], {}
    while pending:
        path = pending.pop()
        key = str(path.relative_to(ROOT))
        if key in result:
            continue
        data = read_regular(path)
        result[key] = sha(data)
        for node in ast.walk(ast.parse(data)):
            names = ([item.name for item in node.names] if isinstance(node, ast.Import) else
                     [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for name in names:
                local = ROOT / 'tools' / (name.split('.')[0] + '.py')
                if local.is_file():
                    pending.append(build.no_symlink_path(local))
    return dict(sorted(result.items()))


def file_tree(files):
    inventory = {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in sorted(files.items())}
    return {'files': inventory, 'sha256': canonical_hash(inventory)}


def read_tree(root):
    """Complete export inventory: no ignored directories, links or cache markers."""
    root = build.no_symlink_path(root)
    require(root.is_dir(), 'Missing source tree')
    files, total = {}, 0
    for parent, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            require(not (Path(parent) / name).is_symlink(), 'Linked source directory')
        for name in names:
            path = Path(parent) / name
            data = read_regular(path)
            total += len(data)
            require(total <= MAX_TREE_BYTES, 'Source tree exceeds byte budget')
            files[str(path.relative_to(root))] = data
    return file_tree(files)


def snapshot_source(original, policy):
    original = build.no_symlink_path(original)
    git = dependencies.pinned_git
    require(git(original, 'rev-parse', '--show-toplevel') == str(original)
            and git(original, 'rev-parse', 'HEAD') == policy['commit']
            and git(original, 'rev-parse', 'HEAD^{tree}') == policy['git_tree']
            and build.ports.repository_url(git(original, 'remote', 'get-url', 'origin'))
                == build.ports.repository_url(policy['repository']), 'Wrong original notification checkout')
    require(not git(original, 'status', '--porcelain', '--untracked-files=all', '--ignored'),
            'Original notification checkout is not clean')
    declared = dependencies.parse_git_tree(git(original, 'ls-tree', '-rz', 'HEAD'))
    require(all(item['mode'] in ('100644', '100755') for item in declared.values()),
            'Notification source contains an unreviewed link or gitlink')
    identity = dependencies.validate_checkout_tree(original, declared)
    files = {name: read_regular(original / name) for name in declared}
    require(all(sha(data) == identity['files'][name]['sha256'] for name, data in files.items()),
            'Notification source changed during snapshot')
    tree = file_tree(files)
    require(tree['sha256'] == policy['original_tree_sha256']
            and sha(files['Cargo.lock']) == policy['source_lock_sha256'], 'Original source inventory changed')
    for name, expected in policy['root_before'].items():
        require(sha(files[name]) == expected, 'Root patch preimage changed: ' + name)
    modes = {name: int(item['mode'], 8) & 0o777 for name, item in declared.items()}
    return files, modes, {'path': str(original), 'commit': policy['commit'], 'git_tree': policy['git_tree'],
                          'canonical_tree_sha256': identity['sha256'], 'tree': tree}


def registry_snapshot(cache, package):
    """Verify the entire fixed archive against its complete cached extraction."""
    cache = build.no_symlink_path(cache)
    stem = package['name'] + '-' + package['version']
    archives = list((cache / 'registry/cache').glob('*/' + stem + '.crate'))
    require(len(archives) == 1, 'Ambiguous or missing pinned registry archive: ' + stem)
    archive = build.no_symlink_path(archives[0])
    packed = read_regular(archive, MAX_ARCHIVE_BYTES)
    require(sha(packed) == package['archive_sha256'], 'Registry archive checksum changed: ' + stem)
    source = build.no_symlink_path(cache / 'registry/src' / archive.parent.name / stem)
    prefix, files, modes, seen, expanded = stem + '/', {}, {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as stream:
        for member in stream:
            require(member.isfile() or member.isdir(), 'Non-regular registry archive member')
            require(member.name.startswith(prefix), 'Registry archive member escapes its root')
            name = member.name[len(prefix):].rstrip('/')
            if not name and member.isdir():
                continue
            relative = build.dependencies.relative_path(name)
            require(str(relative) == name and name not in seen, 'Duplicate or noncanonical archive path')
            seen.add(name)
            if member.isdir():
                continue
            expanded += member.size
            require(0 <= member.size <= MAX_FILE_BYTES and expanded <= 32 * 1024**2,
                    'Registry archive exceeds expanded byte budget')
            data = stream.extractfile(member).read(member.size + 1)
            require(len(data) == member.size and read_regular(source / relative) == data,
                    'Registry extraction differs from archive: ' + name)
            files[name], modes[name] = data, member.mode & 0o777
    inventory = {}
    for parent, directories, names in os.walk(source, followlinks=False):
        for name in directories:
            require(not (Path(parent) / name).is_symlink(), 'Linked registry directory')
        for name in names:
            path = Path(parent) / name
            relative = str(path.relative_to(source))
            data = read_regular(path)
            if relative not in ('.cargo-ok', '.cargo-checksum.json'):
                inventory[relative] = data
    require(inventory == files and files, 'Registry extraction inventory changed')
    declared = {name: {'bytes': len(data), 'sha256': sha(data), 'mode': modes[name]}
                for name, data in sorted(files.items())}
    require(declared == package['files'] and file_tree(files)['sha256'] == package['before_tree_sha256']
            and package['license_files'] and all(name in files for name in package['license_files']),
            'Registry package differs from reviewed full inventory')
    checksum_manifest = source / '.cargo-checksum.json'
    checksum_sha = None
    if checksum_manifest.exists() or checksum_manifest.is_symlink():
        raw = read_regular(checksum_manifest, MAX_ARCHIVE_BYTES)
        value = json.loads(raw, object_pairs_hook=no_duplicates)
        require(value == {'package': package['archive_sha256'],
                          'files': {name: sha(data) for name, data in files.items()}},
                'Registry checksum manifest differs from the archive')
        checksum_sha = sha(raw)
    return files, modes, {'name': package['name'], 'version': package['version'],
                          'archive': str(archive), 'archive_sha256': sha(packed), 'source': str(source),
                          'source_tree_sha256': file_tree(files)['sha256'],
                          'checksum_manifest_sha256': checksum_sha}


def lock_delta(before, after, policy):
    original, effective = tomllib.loads(before.decode()), tomllib.loads(after.decode())
    require({key: value for key, value in original.items() if key != 'package'}
            == {key: value for key, value in effective.items() if key != 'package'},
            'Static lock changed non-package structure')
    def packages(lock):
        items = lock['package']
        result = {(item['name'], item['version']): item for item in items}
        require(len(result) == len(items), 'Ambiguous lock package identity')
        return result
    old, new = packages(original), packages(effective)
    require(old.keys() == new.keys(), 'Static lock added, removed or upgraded a package')
    overrides = {item['name']: item for item in policy['registry_inputs']}
    changed = []
    for key, item in old.items():
        expected = dict(item)
        if item['name'] in overrides:
            package = overrides[item['name']]
            require(item['version'] == package['version'] and item['source'] == package['source']
                    and item['checksum'] == package['archive_sha256'], 'Wrong registry lock override')
            del expected['source']; del expected['checksum']
        elif item['name'] == 'cosmic-notifications':
            require('source' not in item, 'Notification root is not a local package')
            expected['dependencies'] = sorted([*item['dependencies'], *overrides])
        require(new[key] == expected, 'Unreviewed static lock delta: ' + item['name'])
        if expected != item:
            changed.append({'name': key[0], 'version': key[1], 'before': item, 'after': expected})
    require(len(changed) == 3, 'Incomplete static lock override')
    return {'source_sha256': sha(before), 'effective_sha256': sha(after),
            'package_count': len(old), 'changed_packages': sorted(changed, key=lambda item: item['name']),
            'cargo_resolution_verified': False}


def materialize(destination, files, modes):
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in sorted(files.items()):
        relative = build.dependencies.relative_path(name)
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(modes[name])


def export_source(original, cache, output, policy_path=PORT / 'source-policy.json'):
    policy = load_policy(policy_path)
    supports = support_sources(policy_path, policy)
    original, cache, output = map(build.no_symlink_path, (original, cache, output))
    require(not output.exists(), 'Preserving existing notification static export')
    for protected in (original.parent, cache, build.no_symlink_path(policy_path).parent):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                'Static export overlaps an input')
    files, modes, source = snapshot_source(original, policy)
    inputs = [registry_snapshot(cache, item) for item in policy['registry_inputs']]
    materialize(output, files, modes)
    for spec, (content, permissions, _) in zip(policy['registry_inputs'], inputs):
        materialize(output / build.dependencies.relative_path(spec['destination']), content, permissions)
    for patch in policy['patches']:
        path = build.no_symlink_path(policy_path).parent / patch['path']
        for check in (['--check'], []):
            subprocess.run(['/usr/bin/git', 'apply', *check, str(path)], cwd=output, check=True,
                           env=build.clean_environment('/usr/bin:/bin'), capture_output=True)
    tree = read_tree(output)
    require(tree['sha256'] == policy['source_tree_sha256'], 'Patched notification export differs from policy')
    delta = lock_delta(files['Cargo.lock'], read_regular(output / 'Cargo.lock'), policy)
    require(delta['effective_sha256'] == policy['effective_lock_sha256'], 'Static effective lock changed')
    for spec in policy['registry_inputs']:
        require(read_tree(output / spec['destination'])['sha256'] == spec['after_tree_sha256'],
                'Static vendor output differs from reviewed patch')
    result = {'schema_version': 1, 'kind': policy['kind'], 'policy_sha256': POLICY_SHA256,
              'support_sources': supports, 'original_source': source,
              'registry_inputs': [item[2] for item in inputs], 'source_tree': tree,
              'lock_delta': delta, 'source_preserved': True, 'runtime_verified': False}
    validate_export(original, cache, output, result, policy_path)
    return result


def validate_export(original, cache, exported, record, policy_path=PORT / 'source-policy.json'):
    policy = load_policy(policy_path)
    _, _, source = snapshot_source(original, policy)
    registry = [registry_snapshot(cache, item)[2] for item in policy['registry_inputs']]
    require(record['schema_version'] == 1 and record['kind'] == policy['kind']
            and record['policy_sha256'] == POLICY_SHA256 and record['source_preserved'] is True
            and record['runtime_verified'] is False
            and record['support_sources'] == support_sources(policy_path, policy)
            and record['original_source'] == source and record['registry_inputs'] == registry,
            'Static export provenance changed')
    tree = read_tree(exported)
    require(tree == record['source_tree'] and tree['sha256'] == policy['source_tree_sha256'],
            'Static exported source changed')
    delta = lock_delta(read_regular(Path(original) / 'Cargo.lock'), read_regular(Path(exported) / 'Cargo.lock'), policy)
    require(delta == record['lock_delta'] and delta['effective_sha256'] == policy['effective_lock_sha256'],
            'Static lock provenance changed')
    return record


def normalized_resolution(metadata):
    require(metadata.get('version') == 1, 'Unsupported static Cargo metadata')
    packages, nodes = metadata['packages'], metadata['resolve']['nodes']
    by_id, by_node = {p['id']: p for p in packages}, {n['id']: n for n in nodes}
    require(len(by_id) == len(packages) and len(by_node) == len(nodes) and by_id.keys() == by_node.keys(),
            'Incomplete or duplicate static Cargo graph')
    members = set(metadata['workspace_members'])
    require(members <= by_id.keys(), 'Unknown Cargo workspace member')
    key = lambda p: [p['name'], p['version'], p.get('source')]
    result = []
    for identifier, package in by_id.items():
        node = by_node[identifier]
        require(len(node['features']) == len(set(node['features']))
                and set(node['dependencies']) == {d['pkg'] for d in node['deps']},
                'Inconsistent static Cargo feature/edge inventory')
        edges = [{'name': d['name'], 'package': key(by_id[d['pkg']]),
                  'kinds': sorted(d['dep_kinds'], key=lambda item: json.dumps(item, sort_keys=True))}
                 for d in node['deps']]
        result.append({'package': key(package), 'features': sorted(node['features']),
                       'workspace_member': identifier in members,
                       'dependencies': sorted(edges, key=lambda item: json.dumps(item, sort_keys=True))})
    return sorted(result, key=lambda item: json.dumps(item['package']))


def verify_resolution(metadata, policy):
    graph = normalized_resolution(metadata)
    expected = policy['resolution']
    require(len(graph) == expected['package_count']
            and sum(item['workspace_member'] for item in graph) == expected['workspace_package_count']
            and sum(item['package'][2] is None for item in graph) == expected['local_package_count']
            and canonical_hash(graph) == expected['expected_sha256'],
            'Static Cargo resolution changed pinned versions, sources, features or dependency edges')
    return canonical_hash(graph)


def verify_metadata(metadata, source, cache, recipe, policy):
    source = build.no_symlink_path(source)
    require(metadata.get('workspace_root') == str(source), 'Static metadata workspace changed')
    records = dependencies.verify_metadata(metadata, source, cache, recipe)
    for package in policy['registry_inputs']:
        selected = [p for p in metadata['packages'] if p['name'] == package['name']]
        require(len(selected) == 1 and selected[0]['version'] == package['version']
                and selected[0].get('source') is None
                and Path(selected[0]['manifest_path']) == source / package['destination'] / 'Cargo.toml',
                'Cargo did not select the reviewed local static binding')
    verify_resolution(metadata, policy)
    return records


def validate_recipe(recipe, source, policy):
    build.validate_recipe(recipe, source)
    require(recipe['target'] == TARGET and recipe['package'] == recipe['binary'] == 'cosmic-notifications'
            and recipe['resource_profile'] == PROFILE and recipe['default_features'] is False
            and recipe['features'] == FEATURES and recipe['patches'] == policy['patches']
            and recipe['source_lock_sha256'] == policy['source_lock_sha256']
            and recipe['effective_lock_sha256'] == policy['effective_lock_sha256']
            and recipe.get('static_source_policy') == {'path': 'source-policy.json', 'sha256': POLICY_SHA256}
            and recipe.get('reviewed_rust_flags') == recipe.get('reviewed_rustdoc_flags') == FLAGS
            and 'source_series' not in recipe and 'source_export_policy' not in recipe,
            'Recipe is not the reviewed static notification selection')
    names = [item['path'] for item in recipe['native_inputs']]
    require(names == ['sysroot/usr/lib/' + name for name in NATIVE_NAMES]
            and recipe['static_link_inputs'] == ['sysroot/usr/lib/' + name for name in STATIC_NAMES],
            'Static notification recipe has an unreviewed native library closure')
    origin = recipe.get('native_sdk_origin')
    require(type(origin) is dict and set(origin) == {'path', 'sha256'}
            and origin['path'] == 'runtime-sdk-origin.json' and isinstance(origin['sha256'], str)
            and re.fullmatch('[0-9a-f]{64}', origin['sha256']), 'Static recipe lacks its SDK assembly identity')
    return recipe


def sdk_origin(sysroot, recipe):
    path = build.no_symlink_path(Path(sysroot) / recipe['native_sdk_origin']['path'])
    data = read_regular(path)
    require(sha(data) == recipe['native_sdk_origin']['sha256'], 'Static SDK assembly report changed')
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}


def select_profile(path, jobs):
    data = read_regular(path)
    require(sha(data) == RESOURCE_SHA256, 'Unreviewed static notification resource profile')
    return build.select_profile(json.loads(data, object_pairs_hook=no_duplicates), PROFILE,
                                jobs, build.ports.user_target(TARGET))


def native_archive_sources(sysroot, recipe, toolchain):
    """Read the exact native archives rustc must find while creating rlibs.

    Final-link arguments alone cannot supply rustc's static-library bundling
    phase. The frozen environment already searches output/native for unwind;
    this port puts its seven other hash-bound archives in that same directory.
    """
    sysroot = build.no_symlink_path(sysroot)
    expected = ['sysroot/usr/lib/' + name for name in STATIC_NAMES]
    require(build.static_link_inputs(recipe) == expected
            and toolchain['static_link_inputs'] == expected
            and toolchain['native_inputs'] == recipe['native_inputs'],
            'Unreviewed rustc native archive closure')
    declared = {row['path']: row['sha256'] for row in recipe['native_inputs']}
    require(len(declared) == len(recipe['native_inputs']), 'Duplicate native archive source')
    unwind = toolchain['unwind']
    selected = {'libunwind.a': (Path(unwind['path']), unwind['sha256'])}
    selected.update({Path(name).name: (sysroot / name, declared[name]) for name in expected})
    require(len(selected) == 8, 'Missing or aliased native archive name')
    result = {}
    for name, (path, digest) in sorted(selected.items()):
        path = build.no_symlink_path(path)
        data = read_regular(path)
        require(sha(data) == digest, 'Rustc native archive source changed: ' + name)
        architecture = build.ports.architecture(path, target=build.ports.user_target(TARGET))
        require(architecture['kind'] == 'static-archive' and architecture['sha256'] == digest
                and architecture['bytes'] == len(data), 'Invalid target static archive: ' + name)
        result[name] = {'source': str(path), 'bytes': len(data), 'sha256': digest}
    return result


def native_archive_search(output, sysroot, recipe, toolchain, environment=None):
    """Pure read-only verification of the entire rustc -L native directory."""
    native = build.no_symlink_path(Path(output) / 'native')
    expected = native_archive_sources(sysroot, recipe, toolchain)
    require(native.is_dir() and {path.name for path in native.iterdir()} == set(expected),
            'Rustc native search directory has missing or extra entries')
    flags = ['-L', 'native=' + str(native)]
    if environment is not None:
        encoded = environment.get('CARGO_ENCODED_RUSTFLAGS')
        require(isinstance(encoded, str) and 'RUSTFLAGS' not in environment,
                'Missing explicit rustc native search flags')
        tokens = encoded.split('\x1f')
        searches = []
        for index, token in enumerate(tokens):
            if token == '-L':
                require(index + 1 < len(tokens), 'Incomplete rustc search flag')
                searches.append(tokens[index + 1])
            elif token.startswith('-L'):
                searches.append(token[2:])
        require(searches == flags[1:], 'Rustc does not search exactly the staged native directory')
    for name, record in expected.items():
        data = read_regular(native / name)
        require(len(data) == record['bytes'] and sha(data) == record['sha256'],
                'Staged rustc native archive changed: ' + name)
    return {'schema_version': 1, 'purpose': 'rustc-static-rlib-bundling', 'directory': str(native),
            'rustc_search_flags': flags, 'files': expected}


def verify_native_archive_search(output, sysroot, recipe, toolchain, record, environment=None):
    actual = native_archive_search(output, sysroot, recipe, toolchain, environment)
    require(canonical_hash(actual) == canonical_hash(record), 'Rustc native archive search receipt changed')
    return actual


def stage_native_archives(output, sysroot, recipe, toolchain, environment):
    """Copy only the seven reviewed SDK archives after the frozen unwind copy."""
    native = build.no_symlink_path(Path(output) / 'native')
    sources = native_archive_sources(sysroot, recipe, toolchain)
    require(native.is_dir() and {path.name for path in native.iterdir()} == {'libunwind.a'},
            'Expected only the frozen environment unwind archive before staging')
    unwind = read_regular(native / 'libunwind.a')
    require(len(unwind) == sources['libunwind.a']['bytes'] and sha(unwind) == sources['libunwind.a']['sha256'],
            'Frozen unwind copy differs from its bound source')
    for name, record in sources.items():
        if name == 'libunwind.a':
            continue
        data = read_regular(record['source'])
        require(len(data) == record['bytes'] and sha(data) == record['sha256'],
                'Native archive changed during staging: ' + name)
        with (native / name).open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        (native / name).chmod(0o644)
    return native_archive_search(output, sysroot, recipe, toolchain, environment)


def cargo_environment(environment):
    result = dict(environment)
    require(not any(name in result for name in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS')),
            'Unreviewed static compiler flag environment')
    existing = result.get('CARGO_ENCODED_RUSTFLAGS', '')
    result['CARGO_ENCODED_RUSTFLAGS'] = (existing + '\x1f' if existing else '') + '\x1f'.join(FLAGS)
    result['CARGO_ENCODED_RUSTDOCFLAGS'] = '\x1f'.join(FLAGS)
    result['CARGO_NET_OFFLINE'] = 'true'
    return result
