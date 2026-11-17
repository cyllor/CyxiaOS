"""Read-only source and input contracts for the genuine native settings port.

The historical patch is reused byte for byte. Export alone writes a new tree;
validation never fetches, invokes Cargo/compiler probes, or runs a daemon.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

_TOOLS = str(Path(__file__).resolve().parent)
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

if __package__:
    from . import build_cosmic_comp_linux as common
    from . import build_cosmic_component as packages
    from . import cosmic_notifications_static_v1 as files
    from . import cosmic_notifications_elf as elf
    from . import cosmic_registry_inputs_v1 as registry
    from . import install_cosmic_notifications as legacy
else:
    import build_cosmic_comp_linux as common
    import build_cosmic_component as packages
    import cosmic_notifications_static_v1 as files
    import cosmic_notifications_elf as elf
    import cosmic_registry_inputs_v1 as registry
    import install_cosmic_notifications as legacy

base = common.base
ROOT = base.ROOT
PORT = 'ports/cosmic/native-settings-linux-v1'
POLICY_SHA256 = '9491dd501e250ad58f380e2b7c3e0c4d0074c97a86bf01d51bd68e945e562672'
RECIPE_SHA256 = '6e8d1365f0091877f6c12bedf40feef2132cf87700daa58c89627f46875510c7'
RESOURCE_SHA256 = '35244c49b8c40df7a536227ca65ecb2676f6881a5fab4a87de955e016295a1f2'
KIND = 'cosmic-settings-native-linux-v1'
PROFILE = 'settings-native-linux-x86_64-full-os-v1'
COMPONENT = 'cosmic-settings-daemon'
TARGET = 'x86_64-unknown-linux-musl'
FEATURES = ['cyxia-native']
NATIVE_NAMES = ('libc.a', 'libclang_rt.builtins-x86_64.a', 'crt1.o', 'crti.o', 'crtn.o',
                'libwayland-client.a', 'libffi.a', 'libxkbcommon.a')
STATIC_NAMES = NATIVE_NAMES[5:]
LOGS = ('metadata.json', 'metadata.stderr.log', 'cargo.log')
TIMEOUT_SCOPE = 'Shared across export, Cargo and validation; publication refuses an expired deadline'
require, BuildError = common.require, base.CosmicBuildError
canonical, read_regular = files.canonical_hash, files.read_regular


def read_json(path, checksum=None):
    raw = read_regular(path, 64 * 1024**2)
    require(checksum is None or files.sha(raw) == checksum, 'Unreviewed settings contract: ' + str(path))
    value = json.loads(raw, object_pairs_hook=files.no_duplicates)
    require(type(value) is dict, 'Settings JSON must be an object')
    return value


def contract(recipe_path, resource_path, jobs):
    policy = read_json(Path(recipe_path).parent / 'source-policy.json', POLICY_SHA256)
    recipe = read_json(recipe_path, RECIPE_SHA256)
    source = next(item for item in base.ports.load_manifest()['components'] if item['name'] == COMPONENT)
    require(source['commit'] == policy['commit'] and source['directory'] == policy['directory']
            and base.ports.repository_url(source['repository']) == policy['repository'],
            'Settings epoch source differs from its policy')
    base.validate_recipe(recipe, source)
    require(policy['kind'] == KIND and policy['guest_execution'] is False
            and policy['settings_verified'] is False and policy['cosmic_session_ready'] is False
            and recipe['component'] == recipe['package'] == recipe['binary'] == COMPONENT
            and recipe['target'] == TARGET and recipe['default_features'] is False
            and recipe['features'] == policy['features'] == FEATURES
            and recipe['source_lock_sha256'] == policy['source_lock_sha256']
            and recipe['effective_lock_sha256'] == policy['effective_lock_sha256']
            and recipe['patches'] == [{'path': 'cosmic-settings-native.patch',
                                      'sha256': policy['original_patch']['sha256']}]
            and [row['path'] for row in recipe['native_inputs']]
                == ['sysroot/usr/lib/' + name for name in NATIVE_NAMES]
            and base.static_link_inputs(recipe) == ['sysroot/usr/lib/' + name for name in STATIC_NAMES]
            and not {'source_series', 'source_export_policy', 'reviewed_rust_flags'} & recipe.keys(),
            'Unexpected settings native recipe')
    sdk = recipe['native_sdk_origin']
    require(set(sdk) == {'path', 'sha256'} and sdk['path'] == 'runtime-sdk-origin.json'
            and re.fullmatch('[0-9a-f]{64}', sdk['sha256']), 'Missing settings SDK assembly identity')
    document = read_json(resource_path, RESOURCE_SHA256)
    profile = base.select_profile(document, PROFILE, jobs, 'x86_64')
    require(recipe['resource_profile'] == PROFILE and profile['target_runtime_validated'] is False
            and profile['image_bytes'] == profile['max_elf_bytes'] == 64 * 1024**2
            and profile['stack_bytes'] == 2 * 1024**2 and profile['jobs_max'] == 2
            and profile['timeout_seconds'] == 1200 and profile['max_build_bytes'] == 1536 * 1024**2
            and profile['min_free_bytes'] == 1024**3, 'Settings resource limits changed')
    return policy, recipe, source, profile


def verify_sources(source_cache, cache, recipe_path, policy):
    """Bind both canonical Git trees, the original archive and historical patch."""
    source_cache, cache = map(base.no_symlink_path, (source_cache, cache))
    require(read_json(Path(recipe_path).parent / 'source-policy.json', POLICY_SHA256) == policy,
            'Settings source policy changed')
    manifest_path = ROOT / base.dependencies.relative_path(policy['patch_manifest']['path'])
    manifest = read_json(manifest_path, policy['patch_manifest']['sha256'])
    require(manifest['commit'] == policy['commit'] and manifest['component'] == COMPONENT
            and manifest['repository'] == policy['repository']
            and manifest['source_lock_sha256'] == policy['source_lock_sha256']
            and manifest['effective_lock_sha256'] == policy['effective_lock_sha256']
            and manifest['patch_sha256'] == policy['original_patch']['sha256']
            and manifest['support_inputs'] == policy['support_inputs'], 'Historical settings patch changed')
    bindings = {str(manifest_path): policy['patch_manifest']['sha256'],
                str(Path(recipe_path).parent / 'source-policy.json'): POLICY_SHA256}
    for path, expected in [
        (ROOT / base.dependencies.relative_path(policy['original_patch']['path']), policy['original_patch']['sha256']),
        (Path(recipe_path).parent / 'cosmic-settings-native.patch', policy['original_patch']['sha256']),
        *[(ROOT / base.dependencies.relative_path(name), value) for name, value in policy['support_inputs'].items()],
    ]:
        path = base.no_symlink_path(path)
        require(files.sha(read_regular(path)) == expected, 'Settings patch/support changed: ' + str(path))
        bindings[str(path)] = expected
    originals = {}
    for key, expected in (('settings', policy), ('compositor', policy['compositor'])):
        path = source_cache / base.dependencies.relative_path(expected['directory'])
        identity = common.git_identity(path, expected['commit'])
        require(identity['git_tree'] == expected['git_tree']
                and base.ports.repository_url(common.objects.pinned_git(path, 'remote', 'get-url', 'origin'))
                    == expected['repository'], 'Settings original Git identity changed: ' + key)
        require(all(row['mode'] in ('100644', '100755') for row in identity['files'].values())
                and not identity.get('submodules'), 'Unreviewed settings source link or gitlink')
        inventory = {name: row['sha256'] for name, row in identity['files'].items()}
        previous = manifest['source_inputs'][key]
        require(previous['commit'] == expected['commit'] and previous['git_tree'] == expected['git_tree']
                and previous['files'] == inventory and previous['tree_sha256'] == canonical(inventory),
                'Canonical settings input differs from the reviewed historical source: ' + key)
        originals[key] = {'path': str(path), **identity}
    require(base.digest(Path(originals['settings']['path']) / 'Cargo.lock') == policy['source_lock_sha256'],
            'Original settings lock changed')
    registry = []
    for spec in policy['registry_inputs']:
        content, _, record = files.registry_snapshot(cache, spec)
        old = manifest['registry_inputs'][spec['name']]
        require(old['archive_sha256'] == spec['archive_sha256']
                and old['files'] == {name: files.sha(data) for name, data in content.items()},
                'Original settings vendor archive differs from the historical patch')
        registry.append(record)
    return {'originals': originals, 'registry_inputs': registry, 'bindings': bindings,
            'patch_manifest_sha256': policy['patch_manifest']['sha256'],
            'patch_sha256': policy['original_patch']['sha256']}


def verify_export(source_cache, cache, recipe_path, policy, retained, source_inputs):
    require(verify_sources(source_cache, cache, recipe_path, policy) == source_inputs,
            'Settings source inputs changed')
    manifest = read_json(ROOT / policy['patch_manifest']['path'], policy['patch_manifest']['sha256'])
    original = source_inputs['originals']['settings']['files']
    expected = {name: row['sha256'] for name, row in original.items()}
    modes = {name: row['mode'] for name, row in original.items()}
    before, after = manifest['before'], manifest['after']
    require(type(before) is dict and before and before.keys() == after.keys(), 'Invalid settings patch closure')
    for name, checksum in before.items():
        base.dependencies.relative_path(name)
        require(expected.get(name) == checksum, 'Settings patch preimage changed: ' + name)
        if after[name] is None:
            expected.pop(name, None); modes.pop(name, None)
        else:
            require(isinstance(after[name], str) and re.fullmatch('[0-9a-f]{64}', after[name]),
                    'Invalid settings patch postimage')
            expected[name] = after[name]
            modes.setdefault(name, '100644')
    observed = files.read_tree(retained)
    require(set(observed['files']) == set(expected), 'Retained settings source inventory changed')
    directories = {str(parent) for name in expected for parent in Path(name).parents if parent != Path('.')}
    require({str(path.relative_to(retained)) for path in Path(retained).rglob('*') if path.is_dir()} == directories,
            'Retained settings source directory inventory changed')
    for name, checksum in expected.items():
        path = Path(retained) / name
        require(not ('.cargo' in Path(name).parts and Path(name).name in ('config', 'config.toml')),
                'Unreviewed settings Cargo configuration')
        require(observed['files'][name]['sha256'] == checksum
                and bool(path.lstat().st_mode & 0o111) == (modes[name] == '100755'),
                'Retained settings source differs from canonical patch output: ' + name)
    require(base.digest(Path(retained) / 'Cargo.lock') == policy['effective_lock_sha256'],
            'Effective settings lock changed')
    return observed


def export_source(source_cache, cache, recipe_path, recipe, policy, destination):
    inputs = verify_sources(source_cache, cache, recipe_path, policy)
    common.export_canonical(Path(inputs['originals']['settings']['path']), destination, policy['commit'])
    records = []
    for row in recipe['patches']:
        patch = base.no_symlink_path(Path(recipe_path).parent / row['path'])
        require(base.digest(patch) == row['sha256'], 'Settings patch changed before export')
        for check in (['--check'], []):
            subprocess.run(['/usr/bin/git', 'apply', *check, str(patch)], cwd=destination,
                           check=True, capture_output=True, env=base.clean_environment('/usr/bin:/bin'))
        records.append({'path': str(patch), 'sha256': row['sha256']})
    tree = verify_export(source_cache, cache, recipe_path, policy, destination, inputs)
    return inputs, records, tree


def resolution(metadata, stage, recipe, policy):
    graph = files.normalized_resolution(metadata)
    package_id = packages.local_package(metadata, Path(stage), recipe)
    by_id = {item['id']: item for item in metadata['packages']}
    nodes = {item['id']: item for item in metadata['resolve']['nodes']}
    require(by_id[package_id]['version'] == policy['version'] and nodes[package_id]['features'] == FEATURES,
            'Settings root version/features differ from cyxia-native')
    binaries = [target for target in by_id[package_id]['targets']
                if target['name'] == COMPONENT and 'bin' in target['kind']]
    require(len(binaries) == 1 and binaries[0].get('src_path') == str(Path(stage) / 'src/main.rs'),
            'Settings metadata selects a different binary source')
    selected = {}
    for name, version, relative in [('cosmic-comp-config', policy['compositor']['version'],
                                     'native-deps/cosmic-comp-config/Cargo.toml'),
                                    ('wayland-sys', '0.31.11', 'native-deps/wayland-sys/Cargo.toml'),
                                    ('geonames', policy['version'], 'geonames/Cargo.toml')]:
        matches = [row for row in by_id.values() if row['name'] == name and row.get('source') is None
                   and Path(row['manifest_path']) == Path(stage) / relative]
        require(len(matches) == 1 and matches[0]['version'] == version
                and matches[0]['id'] in nodes[package_id]['dependencies'],
                'Missing exact selected native settings dependency: ' + name)
        selected[name] = matches[0]['id']
    require(nodes[selected['cosmic-comp-config']]['features'] == [], 'Settings libinput/config features changed')
    require({'client', 'dlopen', 'cyxia-static-client'} <= set(nodes[selected['wayland-sys']]['features']),
            'Settings did not select the genuine static Wayland client')
    require(nodes[selected['geonames']]['features'] == [], 'Settings unexpectedly selects the geonames generator')
    direct = {by_id[item]['name'] for item in nodes[package_id]['dependencies']}
    require(not direct & {'cosmic-settings-audio-server', 'cosmic-settings-varlink-server', 'udev', 'ddc-hi'},
            'Settings native profile activated unsupported audio/backlight integrations')
    return {'package_id': package_id, 'graph_sha256': canonical(graph),
            'package_count': len(graph), 'features': FEATURES, 'native_packages': selected}


def metadata_identity(metadata, stage, cache, recipe, policy):
    stage, cache = map(base.no_symlink_path, (stage, cache))
    selected = resolution(metadata, stage, recipe, policy)
    require(metadata.get('workspace_root') == str(stage), 'Settings metadata workspace changed')
    records = common.metadata_identity(metadata, stage, cache, recipe)
    archives = registry.registry_identities(metadata, stage, cache)
    for record, package in zip(records, metadata['packages']):
        if package['id'] in archives:
            record['registry_archive'] = archives[package['id']]
    return {'resolution': selected, 'packages': records}


def check_toolchain(toolchain):
    selected = toolchain.get('selection')
    require(type(selected) is dict and type(selected.get('schema_version')) is int
            and selected['schema_version'] == 1, 'Explicit settings Rust/Clang selection required')
    require(re.search(r'^release: 1\.95\.0$', toolchain.get('rustc_version', ''), re.MULTILINE)
            and re.search(r'\bclang version 19\.', toolchain.get('host_cc_version', ''))
            and toolchain['host'].startswith('x86_64-') and 'linux' in toolchain['host'],
            'Settings Linux profile requires Rust 1.95.0 and Clang 19')


def rust_libraries(toolchain):
    directory = base.no_symlink_path(Path(toolchain['std']['path']).parent)
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.suffix in ('.rlib', '.a'):
            data = read_regular(path, 128 * 1024**2)
            result[str(path.relative_to(directory))] = {'bytes': len(data), 'sha256': files.sha(data)}
    require(result, 'Missing official Rust target archive closure')
    return result


def native_sources(sysroot, recipe, toolchain):
    require(toolchain['native_inputs'] == recipe['native_inputs']
            and toolchain['static_link_inputs'] == recipe['static_link_inputs']
            and recipe['static_link_inputs'] == ['sysroot/usr/lib/' + name for name in STATIC_NAMES],
            'Settings native library selection changed')
    declared = {row['path']: row['sha256'] for row in recipe['native_inputs']}
    require(len(declared) == len(recipe['native_inputs']), 'Duplicate settings native source')
    sources = {'libunwind.a': (Path(toolchain['unwind']['path']), toolchain['unwind']['sha256'])}
    sources.update({name: (Path(sysroot) / 'sysroot/usr/lib' / name,
                          declared['sysroot/usr/lib/' + name]) for name in STATIC_NAMES})
    result = {}
    for name, (path, expected) in sources.items():
        data = read_regular(path, 64 * 1024**2)
        require(files.sha(data) == expected, 'Settings native archive source changed: ' + name)
        base.ports.architecture(path, target='x86_64')
        result[name] = {'source': str(path), 'bytes': len(data), 'sha256': expected}
    return result


def native_search(output, sysroot, recipe, toolchain, environment=None):
    native = base.no_symlink_path(Path(output) / 'native')
    expected = native_sources(sysroot, recipe, toolchain)
    require(native.is_dir() and {path.name for path in native.iterdir()} == set(expected),
            'Settings native search has missing or extra archives')
    for name, row in expected.items():
        data = read_regular(native / name, 64 * 1024**2)
        require(len(data) == row['bytes'] and files.sha(data) == row['sha256']
                and stat.S_IMODE((native / name).lstat().st_mode) == 0o644,
                'Staged settings native archive changed: ' + name)
    search = ['-L', 'native=' + str(native)]
    if environment is not None:
        flags = environment.get('CARGO_ENCODED_RUSTFLAGS', '').split('\x1f')
        locations = []
        for index, value in enumerate(flags):
            if value == '-L':
                require(index + 1 < len(flags), 'Incomplete rustc library search flag')
                locations.append(flags[index + 1])
            elif value.startswith('-L'):
                locations.append(value[2:])
        require('RUSTFLAGS' not in environment and locations == search[1:]
                and environment.get('CARGO_NET_OFFLINE') == 'true',
                'Settings requires one explicit offline rustc archive search')
    return {'schema_version': 1, 'purpose': 'rustc-static-rlib-bundling',
            'directory': str(native), 'rustc_search_flags': search, 'files': expected}


def stage_native_archives(output, sysroot, recipe, toolchain, environment):
    expected = native_sources(sysroot, recipe, toolchain)
    native = base.no_symlink_path(Path(output) / 'native')
    require({path.name for path in native.iterdir()} == {'libunwind.a'},
            'Settings archive staging requires only the original unwind copy')
    require(files.sha(read_regular(native / 'libunwind.a')) == expected['libunwind.a']['sha256'],
            'Settings unwind copy differs from selected runtime')
    for name in STATIC_NAMES:
        row = expected[name]
        data = read_regular(row['source'])
        require(files.sha(data) == row['sha256'] and len(data) == row['bytes'], 'Archive changed during staging')
        with (native / name).open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        (native / name).chmod(0o644)
    return native_search(output, sysroot, recipe, toolchain, environment)


def generated_inputs(output, sysroot, recipe, toolchain):
    wrappers = {'target-pkg-config', 'host-pkg-config'}
    if toolchain['tools']['target_cxx']['available'] is False:
        wrappers.add('unavailable-target-cxx')
    tree = files.read_tree(Path(output) / 'bin')
    require(set(tree['files']) == wrappers and {path.name for path in (Path(output) / 'bin').iterdir()} == wrappers,
            'Settings generated wrapper inventory changed')
    require(all(stat.S_IMODE((Path(output) / 'bin' / name).lstat().st_mode) == 0o755 for name in wrappers),
            'Settings generated wrapper mode changed')
    return {'bin': tree, 'native_search': native_search(output, sysroot, recipe, toolchain)}


def commands(cargo, stage, recipe, jobs, package_id=None):
    options = ['--manifest-path', str(Path(stage) / 'Cargo.toml'), '--locked', '--offline',
               '--no-default-features', '--features', ','.join(FEATURES)]
    metadata = [str(cargo), 'metadata', '--format-version', '1', '--filter-platform', recipe['target'], *options]
    compile_command = None if package_id is None else [str(cargo), 'build', '--release', '--target', recipe['target'],
        '--jobs', str(jobs), '--package', package_id, '--bin', recipe['binary'], *options]
    return metadata, compile_command
