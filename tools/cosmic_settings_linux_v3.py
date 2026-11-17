"""Read-only source and input contracts for the genuine native settings port.

The original native and Linux-v2 theme patches are reused byte for byte, then
one fixed interface-read-guard delta is appended. Both old contracts remain
independently pinned; this version makes no claim about the observed timeout.
Validation never fetches, invokes compiler probes, or runs a daemon.
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
    from . import cosmic_settings_linux_v2 as previous
    from . import build_cosmic_comp_linux as common
    from . import build_cosmic_component as packages
    from . import cosmic_notifications_static_v1 as files
    from . import cosmic_notifications_elf as elf
    from . import cosmic_registry_inputs_v1 as registry
    from . import install_cosmic_notifications as legacy
else:
    import cosmic_settings_linux_v2 as previous
    import build_cosmic_comp_linux as common
    import build_cosmic_component as packages
    import cosmic_notifications_static_v1 as files
    import cosmic_notifications_elf as elf
    import cosmic_registry_inputs_v1 as registry
    import install_cosmic_notifications as legacy

base = common.base
ROOT = base.ROOT
PORT = 'ports/cosmic/native-settings-linux-v3'
POLICY_SHA256 = 'eccaaf03a5bff83e56fa4ea85df0969d9b3b99509a233ee18f081638f8dd94b7'
RECIPE_SHA256 = '78e746618786907cf7d927ffa00868da923ac911697f99da58d8bb0ddf177c85'
RESOURCE_SHA256 = '58470d82921731629c372162cf75291798852e005a3a397442eee7ae79e46d0c'
KIND = 'cosmic-settings-native-linux-v3'
PROFILE = 'settings-native-linux-x86_64-full-os-v3'
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


def prior_contract(jobs):
    directory = ROOT / previous.PORT
    result = previous.contract(directory / 'native-recipe.json', directory / 'resource-profile.json', jobs)
    bindings = {
        'source-policy.json': {'path': previous.PORT + '/source-policy.json', 'sha256': previous.POLICY_SHA256},
        'native-recipe.json': {'path': previous.PORT + '/native-recipe.json', 'sha256': previous.RECIPE_SHA256},
        'resource-profile.json': {'path': previous.PORT + '/resource-profile.json', 'sha256': previous.RESOURCE_SHA256},
    }
    return result, bindings


def contract(recipe_path, resource_path, jobs):
    policy = read_json(Path(recipe_path).parent / 'source-policy.json', POLICY_SHA256)
    recipe = read_json(recipe_path, RECIPE_SHA256)
    document = read_json(resource_path, RESOURCE_SHA256)
    (old_policy, old_recipe, source, old_profile), prior = prior_contract(jobs)
    additions = {'prior_linux_v2', 'interface_guard'}
    require(set(policy) == set(old_policy) | additions
            and {key: value for key, value in policy.items() if key not in additions | {'kind'}}
                == {key: value for key, value in old_policy.items() if key != 'kind'}
            and policy['kind'] == KIND and policy['prior_linux_v2'] == prior,
            'Settings v3 must preserve the exact complete Linux-v2 policy')
    delta = policy['interface_guard']
    require(type(delta) is dict and delta['patch']['path'] == 'cosmic-settings-interface-guard.patch'
            and set(delta['patch']) == {'path', 'sha256'}
            and re.fullmatch('[0-9a-f]{64}', delta['patch']['sha256'])
            and set(delta['files']) == {'src/main.rs'}
            and set(delta['files']['src/main.rs']) == {'before_sha256', 'after_sha256', 'mode'}
            and delta['files']['src/main.rs']['mode'] == '100644'
            and all(re.fullmatch('[0-9a-f]{64}', delta['files']['src/main.rs'][key])
                    for key in ('before_sha256', 'after_sha256'))
            and delta['guest_execution'] is False and delta['no_reply_cause_proven'] is False
            and delta['no_reply_fixed'] is False,
            'Settings v3 permits only the reviewed one-file interface-guard delta, without runtime claims')
    require(recipe == {**old_recipe, 'resource_profile': PROFILE,
                        'patches': [*old_recipe['patches'], delta['patch']]},
            'Settings v3 recipe changed features, locks, native inputs or either previous patch')
    base.validate_recipe(recipe, source)
    profile = base.select_profile(document, PROFILE, jobs, 'x86_64')
    require(set(document['build_profiles']) == {PROFILE}
            and {key: value for key, value in profile.items() if key != 'purpose'}
                == {key: value for key, value in old_profile.items() if key != 'purpose'},
            'Settings v3 resource limits differ from the original profile')
    preserved = policy['preserved_resolution']
    require(type(preserved['package_count']) is int and preserved['package_count'] == 502
            and len(preserved['workspace']) == 11
            and preserved['default_members'] == ['Cargo.toml']
            and preserved['reference_is_new_build_proof'] is False,
            'Settings v3 must preserve the complete original workspace/selected graph')
    return policy, recipe, source, profile

def verify_sources(source_cache, cache, recipe_path, policy):
    """Validate the original complete source chain and the separate v3 guard delta."""
    require(read_json(Path(recipe_path).parent / 'source-policy.json', POLICY_SHA256) == policy,
            'Settings v3 source policy changed')
    old_directory = ROOT / previous.PORT
    old_policy = previous.read_json(old_directory / 'source-policy.json', previous.POLICY_SHA256)
    inputs = previous.verify_sources(source_cache, cache, old_directory / 'native-recipe.json', old_policy)
    bindings = dict(inputs['bindings'])
    for row in policy['prior_linux_v2'].values():
        path = ROOT / base.dependencies.relative_path(row['path'])
        require(files.sha(read_regular(path)) == row['sha256'], 'Settings prior contract changed: ' + str(path))
        bindings[str(path)] = row['sha256']
    for name, expected in [
        ('source-policy.json', POLICY_SHA256), ('native-recipe.json', RECIPE_SHA256),
        ('cosmic-settings-native.patch', policy['original_patch']['sha256']),
        (policy['theme_dispatch']['patch']['path'], policy['theme_dispatch']['patch']['sha256']),
        (policy['interface_guard']['patch']['path'], policy['interface_guard']['patch']['sha256']),
    ]:
        path = base.no_symlink_path(Path(recipe_path).parent / base.dependencies.relative_path(name))
        require(files.sha(read_regular(path)) == expected, 'Settings v3 patch/contract changed: ' + str(path))
        bindings[str(path)] = expected
    return {**inputs, 'bindings': dict(sorted(bindings.items())),
            'prior_linux_v2': policy['prior_linux_v2'], 'interface_guard': policy['interface_guard']}

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
    delta = policy['theme_dispatch']['files']
    require(set(delta) == {'src/theme.rs'}, 'Unexpected settings v2 source delta inventory')
    for name, row in delta.items():
        require(expected.get(name) == row['before_sha256'] and modes.get(name) == row['mode'],
                'Settings v2 delta preimage differs from the exact original patch output')
        expected[name] = row['after_sha256']
    guard = policy['interface_guard']['files']
    require(set(guard) == {'src/main.rs'}, 'Unexpected settings v3 guard source inventory')
    for name, row in guard.items():
        require(expected.get(name) == row['before_sha256'] and modes.get(name) == row['mode'],
                'Settings v3 guard preimage differs from the exact Linux-v2 patch output')
        expected[name] = row['after_sha256']
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
    preserved = policy['preserved_resolution']
    require(len(graph) == preserved['package_count']
            and canonical(graph) == preserved['normalized_graph_sha256'],
            'Settings v2 selected package graph/features/workspace changed')
    by_package = {row['id']: row for row in metadata['packages']}
    members = metadata['workspace_members']
    defaults = metadata.get('workspace_default_members')
    require(type(defaults) is list and len(members) == len(set(members)) == 11
            and len(defaults) == len(set(defaults)) == 1,
            'Settings v2 workspace/default member inventory changed')
    workspace = []
    for identifier in members:
        package = by_package[identifier]
        manifest = Path(package['manifest_path'])
        require(package.get('source') is None and manifest.is_relative_to(Path(stage)),
                'Settings v2 workspace member escapes the retained source')
        workspace.append({'name': package['name'], 'version': package['version'],
                          'manifest': str(manifest.relative_to(Path(stage)))})
    require(sorted(workspace, key=lambda row: row['manifest']) == preserved['workspace']
            and all(identifier in members for identifier in defaults)
            and sorted(str(Path(by_package[identifier]['manifest_path']).relative_to(Path(stage)))
                       for identifier in defaults) == preserved['default_members'],
            'Settings v2 lost an original workspace/default member')
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
