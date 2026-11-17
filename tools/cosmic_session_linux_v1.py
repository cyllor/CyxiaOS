"""Pinned source and host-input contract for the genuine native session port.

All inspection functions are read-only. Export writes only its fresh destination.
The historical patch and original producer remain untouched; a separate policy
rebinds the same original launch-pad tree at its newly acquired source path.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import sys

_TOOLS = str(Path(__file__).resolve().parent)
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

if __package__:
    from . import build_cosmic_comp_linux as common
    from . import build_cosmic_component as packages
    from . import cosmic_notifications_elf as elf
    from . import cosmic_registry_inputs_v1 as registry
else:
    import build_cosmic_comp_linux as common
    import build_cosmic_component as packages
    import cosmic_notifications_elf as elf
    import cosmic_registry_inputs_v1 as registry

base = common.base
ROOT = base.ROOT
PORT = 'ports/cosmic/native-session-linux-v1'
POLICY_SHA256 = 'ff57a5887c06eb77ef116efdcbadeb8fc0496cca6f522eed2a36680548e5826a'
RECIPE_SHA256 = 'ef86a227412448fc86a20c3bc7da2f27c4ff608f33f94e9fd8a5aa00de6c76cd'
RESOURCE_SHA256 = 'bac0084a8d1c693b59a4544227b3de63e838363f23d3fa1e7bbda231a9262613'
PROFILE = 'session-native-linux-x86_64-full-os-v1'
KIND = 'cosmic-session-native-linux-v1'
TARGET = 'x86_64-unknown-linux-musl'
FEATURES = ['cyxia-native']
NATIVE_NAMES = ('libc.a', 'libclang_rt.builtins-x86_64.a', 'crt1.o', 'crti.o', 'crtn.o')
TIMEOUT_SCOPE = 'Shared across export, Cargo commands and validation; publication refuses an expired deadline'
require = common.require
BuildError = base.CosmicBuildError


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def read_json(path, expected=None):
    path = base.no_symlink_path(path)
    raw = elf._read_regular(path, 4 * 1024**2)
    checksum = hashlib.sha256(raw).hexdigest()
    require(expected is None or checksum == expected, 'Unreviewed session contract: ' + str(path))
    value = json.loads(raw, object_pairs_hook=base.ports.unique_object)
    require(isinstance(value, dict), 'Session contract must be an object')
    return value, checksum


def contract(recipe_path, profile_path, jobs):
    policy, _ = read_json(ROOT / PORT / 'source-policy.json', POLICY_SHA256)
    recipe, _ = read_json(recipe_path, RECIPE_SHA256)
    source = next(s for s in base.ports.load_manifest()['components']
                  if s['name'] == 'cosmic-session')
    require(source['commit'] == policy['commit'] and source['directory'] == policy['directory']
            and base.ports.repository_url(source['repository']) == policy['repository'],
            'Session epoch source differs from the fixed policy')
    base.validate_recipe(recipe, source)
    require(policy['kind'] == KIND and policy['guest_execution'] is False
            and policy['cosmic_session_ready'] is False
            and recipe['component'] == recipe['package'] == recipe['binary'] == 'cosmic-session'
            and recipe['target'] == TARGET and recipe['default_features'] is False
            and recipe['features'] == FEATURES == policy['features']
            and recipe['source_lock_sha256'] == policy['source_lock_sha256']
            and recipe['effective_lock_sha256'] == policy['effective_lock_sha256']
            and recipe['patches'] == [{'path': 'cosmic-session-native.patch',
                                      'sha256': policy['original_patch']['sha256']}]
            and [item['path'] for item in recipe['native_inputs']]
                == ['sysroot/usr/lib/' + name for name in NATIVE_NAMES]
            and base.static_link_inputs(recipe) == []
            and 'source_series' not in recipe, 'Unexpected native session recipe')
    document, _ = read_json(profile_path, RESOURCE_SHA256)
    profile = base.select_profile(document, PROFILE, jobs, 'x86_64')
    require(recipe['resource_profile'] == PROFILE and profile['target_runtime_validated'] is False
            and profile['image_bytes'] == profile['max_elf_bytes'] == 64 * 1024**2
            and profile['stack_bytes'] == 2 * 1024**2 and profile['jobs_max'] == 1
            and profile['timeout_seconds'] == 900 and profile['max_build_bytes'] == 512 * 1024**2
            and profile['min_free_bytes'] == 1024**3, 'Unexpected native session resource profile')
    return policy, recipe, source, profile


def verify_sources(source_cache, recipe_path, policy):
    """Bind both complete original trees, their upstream origin and old patch."""
    source_cache = base.no_symlink_path(source_cache)
    require(read_json(ROOT / PORT / 'source-policy.json', POLICY_SHA256)[0] == policy,
            'Session source policy changed')
    manifest_path = ROOT / base.dependencies.relative_path(policy['patch_manifest']['path'])
    manifest, _ = read_json(manifest_path, policy['patch_manifest']['sha256'])
    require(manifest['commit'] == policy['commit'] and manifest['component'] == 'cosmic-session'
            and manifest['source_lock_sha256'] == policy['source_lock_sha256']
            and manifest['effective_lock_sha256'] == policy['effective_lock_sha256']
            and manifest['patch_sha256'] == policy['original_patch']['sha256']
            and manifest['support_inputs'] == policy['support_inputs'], 'Historical session port identity changed')
    bindings = {str(ROOT / PORT / 'source-policy.json'): POLICY_SHA256,
                str(manifest_path): policy['patch_manifest']['sha256']}
    for selected, checksum in [
        (ROOT / base.dependencies.relative_path(policy['original_patch']['path']), policy['original_patch']['sha256']),
        (Path(recipe_path).parent / 'cosmic-session-native.patch', policy['original_patch']['sha256']),
        *[(ROOT / base.dependencies.relative_path(name), value) for name, value in policy['support_inputs'].items()],
    ]:
        selected = base.no_symlink_path(selected)
        require(base.digest(selected) == checksum, 'Session patch/support changed: ' + str(selected))
        bindings[str(selected)] = checksum
    records = {}
    for key, expected in [('session', policy), ('launch_pad', policy['launch_pad'])]:
        path = source_cache / base.dependencies.relative_path(expected['directory'])
        identity = common.git_identity(path, expected['commit'])
        require(identity['git_tree'] == expected['git_tree'], 'Session original Git tree changed: ' + key)
        origin = common.objects.pinned_git(path, 'remote', 'get-url', 'origin')
        require(base.ports.repository_url(origin) == expected['repository'], 'Session original repository changed: ' + key)
        require(all(item['mode'] in ('100644', '100755') for item in identity['files'].values()),
                'Original session port requires regular pinned source files')
        files = {name: item['sha256'] for name, item in identity['files'].items()}
        old = manifest['source_inputs'][key]
        require(old['commit'] == expected['commit'] and old['git_tree'] == expected['git_tree']
                and old['files'] == files and old['tree_sha256'] == canonical(files),
                'Current original bytes differ from the historical pinned port: ' + key)
        records[key] = {'path': str(path), **identity}
    require(base.digest(Path(records['session']['path']) / 'Cargo.lock') == policy['source_lock_sha256'],
            'Original session Cargo.lock changed')
    return {'originals': records, 'bindings': bindings,
            'patch_manifest_sha256': policy['patch_manifest']['sha256'],
            'patch_sha256': policy['original_patch']['sha256']}


def verify_export(source_cache, recipe_path, policy, retained, original_receipt):
    actual_inputs = verify_sources(source_cache, recipe_path, policy)
    require(actual_inputs == original_receipt, 'Session source inputs changed during the operation')
    manifest, _ = read_json(ROOT / policy['patch_manifest']['path'], policy['patch_manifest']['sha256'])
    original = actual_inputs['originals']['session']['files']
    expected = {name: item['sha256'] for name, item in original.items()}
    modes = {name: item['mode'] for name, item in original.items()}
    before, after = manifest['before'], manifest['after']
    require(isinstance(before, dict) and before and before.keys() == after.keys(), 'Malformed session patch closure')
    for name, checksum in before.items():
        base.dependencies.relative_path(name)
        require(expected.get(name) == checksum, 'Session patch preimage changed: ' + name)
        result = after[name]
        if result is None:
            expected.pop(name, None)
            modes.pop(name, None)
        else:
            require(isinstance(result, str) and re.fullmatch('[0-9a-f]{64}', result), 'Invalid session patch postimage')
            expected[name] = result
            modes.setdefault(name, '100644')
    observed = base.tree_identity(retained)
    require(set(observed['files']) == set(expected), 'Retained session source closure changed')
    for name, checksum in expected.items():
        require(not ('.cargo' in Path(name).parts and Path(name).name in ('config', 'config.toml')),
                'Unreviewed session Cargo configuration')
        item = observed['files'][name]
        info = (Path(retained) / name).lstat()
        require(set(item) == {'bytes', 'sha256'} and item['sha256'] == checksum
                and stat.S_ISREG(info.st_mode)
                and bool(info.st_mode & 0o111) == (modes[name] == '100755'),
                'Retained session differs from fixed patch postimage: ' + name)
    require(base.digest(Path(retained) / 'Cargo.lock') == policy['effective_lock_sha256'],
            'Effective session Cargo.lock changed')
    return observed


def export_source(source_cache, recipe_path, recipe, policy, destination):
    inputs = verify_sources(source_cache, recipe_path, policy)
    common.export_canonical(Path(inputs['originals']['session']['path']), destination, policy['commit'])
    patches = base.apply_patches(recipe, destination, Path(recipe_path).parent)
    tree = verify_export(source_cache, recipe_path, policy, destination, inputs)
    return inputs, patches, tree


def resolution(metadata, stage, recipe, policy):
    package_id = packages.local_package(metadata, Path(stage), recipe)
    roots = [p for p in metadata['packages'] if p['id'] == package_id]
    launches = [p for p in metadata['packages'] if p.get('source') is None and p['name'] == 'launch-pad'
                and Path(p['manifest_path']) == Path(stage) / 'native-deps/launch-pad/Cargo.toml']
    require(len(roots) == 1 and roots[0]['version'] == policy['version'] and len(launches) == 1
            and launches[0]['version'] == policy['launch_pad']['version'], 'Wrong local session or native launch-pad package')
    nodes = metadata.get('resolve', {}).get('nodes', [])
    for package, features in [(roots[0], FEATURES), (launches[0], policy['launch_pad_features'])]:
        selected = [n for n in nodes if n['id'] == package['id']]
        require(len(selected) == 1 and selected[0]['features'] == features,
                'Session/launch-pad feature selection differs from the native port')
    require(launches[0]['id'] in next(n for n in nodes if n['id'] == package_id)['dependencies'],
            'Native launch-pad is not the selected session dependency')
    return package_id


def metadata_identity(metadata, stage, cache, recipe, policy):
    resolution(metadata, stage, recipe, policy)
    records = common.metadata_identity(metadata, stage, cache, recipe)
    archives = registry.registry_identities(metadata, stage, cache)
    for package, record in zip(metadata['packages'], records):
        if package['id'] in archives:
            record['registry_archive'] = archives[package['id']]
    return records


def generated_inputs(output, toolchain):
    output = base.no_symlink_path(output)
    required = {'bin': {'target-pkg-config', 'host-pkg-config'}, 'native': {'libunwind.a'}}
    if toolchain['tools']['target_cxx']['available'] is False:
        required['bin'].add('unavailable-target-cxx')
    actual = {name: base.tree_identity(output / name) for name in required}
    for name in required:
        require(set(actual[name]['files']) == required[name], 'Unexpected generated session inputs: ' + name)
    require(actual['native']['files']['libunwind.a']['sha256'] == toolchain['unwind']['sha256'],
            'Generated unwind differs from the selected runtime')
    return actual


def rust_libraries(toolchain):
    directory = base.no_symlink_path(Path(toolchain['std']['path']).parent)
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.suffix in ('.rlib', '.a'):
            raw = elf._read_regular(path, 128 * 1024**2)
            result[str(path.relative_to(directory))] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    require(result, 'Official target runtime archive closure is empty')
    return result


def check_toolchain(toolchain):
    selected = toolchain.get('selection')
    require(isinstance(selected, dict) and selected.get('schema_version') == 1,
            'Explicit Linux session Rust/Clang selection required')
    match = re.search(r'^release: (\d+)\.(\d+)\.(\d+)(?:[^\n]*)$', toolchain['rustc_version'], re.MULTILINE)
    require(match and tuple(map(int, match.groups())) >= (1, 93, 0)
            and toolchain['host'].startswith('x86_64-') and 'linux' in toolchain['host'],
            'Native session requires an x86 Linux Rust host at least 1.93')


def commands(cargo, stage, recipe, jobs, package_id=None):
    common_flags = ['--manifest-path', str(Path(stage) / 'Cargo.toml'), '--locked', '--offline',
                    '--no-default-features', '--features', ','.join(FEATURES)]
    metadata = [str(cargo), 'metadata', '--format-version', '1', '--filter-platform',
                recipe['target'], *common_flags]
    build = None if package_id is None else [str(cargo), 'build', '--release', '--target', recipe['target'],
            '--jobs', str(jobs), '--package', package_id, '--bin', recipe['binary'], *common_flags]
    return metadata, build
