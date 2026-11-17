"""Complete genuine panel source, native-library and build-input contracts.

Validation is read-only and never fetches, invokes Cargo/compiler probes, or
runs the target. Export explicitly copies every canonical file and license from
the original three-member panel and its exact adapted dependency trees.
"""
from __future__ import annotations

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
    from . import cosmic_notifications_static_v1 as files
    from . import cosmic_notifications_elf as elf
    from . import install_cosmic_notifications as legacy
    from . import cosmic_panel_metadata_v1 as metadata_contract
else:
    import build_cosmic_comp_linux as common
    import cosmic_notifications_static_v1 as files
    import cosmic_notifications_elf as elf
    import install_cosmic_notifications as legacy
    import cosmic_panel_metadata_v1 as metadata_contract

base = common.base
ROOT = base.ROOT
PORT = 'ports/cosmic/native-panel-linux-v1'
POLICY_SHA256 = '2e2fc7a554392e0b9aec6119374c53b9dd241157edc72ac82d8b4eae176b98eb'
RECIPE_SHA256 = '5f7b1e984faae78e072647a6edcfbf9a7a973dccb226a768eddcd592ce2d2f4e'
RESOURCE_SHA256 = 'b96596aa56646e5ef4f812b488fe29f2251ec971fcbe9f6e1dce56f0daacefca'
KIND = 'cosmic-panel-native-linux-v1'
PROFILE = 'panel-native-linux-x86_64-full-os-v1'
COMPONENT, PACKAGE = 'cosmic-panel', 'cosmic-panel-bin'
TARGET = 'x86_64-unknown-linux-musl'
FEATURES = ['cosmic-panel-bin/cyxia-native']
NATIVE_PATHS = (
    'sysroot/usr/lib/libc.a', 'sysroot/usr/lib/libclang_rt.builtins-x86_64.a',
    'sysroot/usr/lib/crt1.o', 'sysroot/usr/lib/crti.o', 'sysroot/usr/lib/crtn.o',
    'mesa-native-port/cxx-runtime/libcyxia-mesa-cxx.a',
    'mesa-native-port/build/src/egl/libEGL.a',
    'mesa-native-port/build/src/gallium/targets/dri/libgallium-26.2.3.a',
    'mesa-native-port/build/src/mesa/glapi/es2api/libGLESv2.a',
    'sysroot/usr/lib/libwayland-client.a', 'sysroot/usr/lib/libwayland-server.a',
    'sysroot/usr/lib/libwayland-egl.a', 'sysroot/usr/lib/libffi.a',
    'sysroot/usr/lib/libz.a', 'sysroot/usr/lib/libxkbcommon.a',
)
STATIC_PATHS = NATIVE_PATHS[5:]
LOGS = ('metadata.json', 'metadata.stderr.log', 'cargo.log')
TIMEOUT_SCOPE = 'Shared across export, Cargo and validation; publication refuses an expired deadline'
REPOSITORIES = {'panel': 'https://github.com/pop-os/cosmic-panel',
                'launch_pad': 'https://github.com/pop-os/launch-pad', 'smithay': 'https://github.com/smithay/smithay'}
require, BuildError = common.require, base.CosmicBuildError
canonical, read_regular = files.canonical_hash, files.read_regular


def read_json(path, checksum=None):
    raw = read_regular(path, 64 * 1024**2)
    require(checksum is None or files.sha(raw) == checksum, 'Unreviewed panel contract: ' + str(path))
    value = json.loads(raw, object_pairs_hook=files.no_duplicates)
    require(type(value) is dict, 'Panel JSON must be an object')
    return value


def protected_input_paths(recipe_path):
    """Protect immutable provenance before creating an output directory."""
    policy = read_json(Path(recipe_path).parent / 'source-policy.json', POLICY_SHA256)
    result = []
    for key in ('native_mesa_validation', 'source_acquisition'):
        row = policy[key]
        path = base.no_symlink_path(ROOT / base.dependencies.relative_path(row['path']))
        read_json(path, row['sha256'])
        result.append(path.parent)
    return result


def contract(recipe_path, resource_path, jobs):
    policy = read_json(Path(recipe_path).parent / 'source-policy.json', POLICY_SHA256)
    recipe = read_json(recipe_path, RECIPE_SHA256)
    source = next(item for item in base.ports.load_manifest()['components'] if item['name'] == COMPONENT)
    require(source['commit'] == policy['commit'] and source['directory'] == policy['directory']
            and base.ports.repository_url(source['repository']) == policy['repository'],
            'Panel epoch source differs from its fixed policy')
    base.validate_recipe(recipe, source)
    require(policy['kind'] == KIND and policy['guest_execution'] is False and policy['panel_verified'] is False
            and policy['panel_applet_lifecycle_verified'] is False and policy['cosmic_session_ready'] is False
            and policy['cosmic_session_verified'] is False and policy['full_cosmic_complete'] is False
            and recipe['component'] == recipe['binary'] == COMPONENT and recipe['package'] == PACKAGE
            and recipe['target'] == TARGET and recipe['default_features'] is policy['default_features'] is True
            and recipe['features'] == policy['features'] == FEATURES
            and policy['workspace_members'] == list(metadata_contract.MEMBERS)
            and recipe['source_lock_sha256'] == policy['source_lock_sha256']
            and recipe['effective_lock_sha256'] == policy['effective_lock_sha256']
            and recipe['patches'] == [{'path': policy['patch']['path'], 'sha256': policy['patch']['sha256']}]
            and recipe['native_inputs'] == policy['native_inputs']
            and [row['path'] for row in recipe['native_inputs']] == list(NATIVE_PATHS)
            and base.static_link_inputs(recipe) == policy['static_link_inputs'] == list(STATIC_PATHS)
            and recipe['native_sdk_origin'] == policy['native_sdk_origin']
            and not {'source_series', 'source_export_policy', 'reviewed_rust_flags', 'reviewed_rustdoc_flags'} & recipe.keys(),
            'Unexpected complete panel native recipe')
    sdk = recipe['native_sdk_origin']
    require(set(sdk) == {'path', 'sha256'} and sdk['path'] == 'runtime-sdk-origin.json'
            and re.fullmatch('[0-9a-f]{64}', sdk['sha256']), 'Missing panel Wayland SDK identity')
    document = read_json(resource_path, RESOURCE_SHA256)
    profile = base.select_profile(document, PROFILE, jobs, 'x86_64')
    require(recipe['resource_profile'] == PROFILE and profile['target_runtime_validated'] is False
            and profile['image_bytes'] == profile['max_elf_bytes'] == 64 * 1024**2
            and profile['stack_bytes'] == 2 * 1024**2 and profile['jobs_max'] == 2
            and profile['timeout_seconds'] == 3600 and profile['max_build_bytes'] == 3 * 1024**3
            and profile['min_free_bytes'] == 1024**3, 'Panel FullOs resource bounds changed')
    return policy, recipe, source, profile


def verify_sources(source_cache, native_source_cache, cache, recipe_path, policy):
    """Canonical Git/file/mode/submodule closure and complete registry archive."""
    source_cache, native_source_cache, cache = map(base.no_symlink_path, (source_cache, native_source_cache, cache))
    require(read_json(Path(recipe_path).parent / 'source-policy.json', POLICY_SHA256) == policy,
            'Panel source policy changed')
    bindings = {str(Path(recipe_path).parent / 'source-policy.json'): POLICY_SHA256}
    for name, checksum in policy['support_inputs'].items():
        path = base.no_symlink_path(ROOT / base.dependencies.relative_path(name))
        require(files.sha(read_regular(path)) == checksum, 'Exact panel NativeChild support changed: ' + name)
        bindings[str(path)] = checksum
    patch = base.no_symlink_path(Path(recipe_path).parent / base.dependencies.relative_path(policy['patch']['path']))
    require(files.sha(read_regular(patch)) == policy['patch']['sha256'], 'Panel source patch changed')
    bindings[str(patch)] = policy['patch']['sha256']
    provenance = policy['source_acquisition']
    receipt_path = base.no_symlink_path(ROOT / base.dependencies.relative_path(provenance['path']))
    acquired = read_json(receipt_path, provenance['sha256'])
    require(acquired['status'] == 'THREE_EXACT_PANEL_SOURCES_AVAILABLE_NOT_RESOLVED_NOT_BUILT'
            and acquired['originals_preserved'] is True and acquired['protected_preserved'] is True,
            'Panel exact-source acquisition receipt changed')
    bindings[str(receipt_path)] = provenance['sha256']
    require(set(policy['git_sources']) == set(REPOSITORIES), 'Incomplete panel canonical source selection')
    originals = {}
    for name, expected in policy['git_sources'].items():
        require(expected['cache'] in ('original', 'native'), 'Unknown panel canonical cache selection')
        root = source_cache if expected['cache'] == 'original' else native_source_cache
        path = root / base.dependencies.relative_path(expected['directory'])
        identity = common.git_identity(path, expected['commit'])
        require(identity['commit'] == expected['commit'] and identity['git_tree'] == expected['git_tree']
                and identity['sha256'] == expected['tree_sha256'] and len(identity['files']) == expected['file_count']
                and identity['total_bytes'] == expected['source_bytes'] and identity['submodules'] == {}
                and all(row['mode'] in ('100644', '100755') for row in identity['files'].values())
                and base.ports.repository_url(common.objects.pinned_git(path, 'remote', 'get-url', 'origin'))
                    == REPOSITORIES[name], 'Original complete panel Git source changed: ' + name)
        originals[name] = {'path': str(path), **identity}
    require(base.digest(Path(originals['panel']['path']) / 'Cargo.lock') == policy['source_lock_sha256'],
            'Original complete panel Cargo.lock changed')
    config = policy['original_panel_configuration']
    require(originals['panel']['files'][config['path']]['sha256'] == config['sha256']
            and len(config['applets']) == config['occurrences'] == 18
            and len(set(config['applets'])) == config['unique_ids'] == 16,
            'Original complete panel applet configuration changed')
    registry = []
    for spec in policy['registry_inputs']:
        _, _, record = files.registry_snapshot(cache, spec)
        registry.append(record)
    return {'originals': originals, 'registry_inputs': registry, 'bindings': bindings,
            'patch_sha256': policy['patch']['sha256'], 'original_panel_configuration': config}


def expected_export(policy, source_inputs):
    """Derive the full stage from complete original trees, then exact patch delta."""
    expected, modes = {}, {}
    for name, original in source_inputs['originals'].items():
        prefix = policy['git_sources'][name]['prefix']
        for relative, row in original['files'].items():
            target = prefix + relative
            base.dependencies.relative_path(target)
            require(target not in expected, 'Overlapping complete panel source input')
            expected[target] = row['sha256']
            modes[target] = 0o755 if row['mode'] == '100755' else 0o644
    for spec in policy['registry_inputs']:
        for name, row in spec['files'].items():
            target = spec['prefix'] + name
            base.dependencies.relative_path(target)
            require(target not in expected, 'Overlapping complete panel registry input')
            expected[target], modes[target] = row['sha256'], row['mode']
    before, after = policy['patch']['before'], policy['patch']['after']
    require(type(before) is dict and before and before.keys() == after.keys(), 'Invalid panel patch closure')
    for name, checksum in before.items():
        base.dependencies.relative_path(name)
        require(expected.get(name) == checksum, 'Panel canonical patch preimage changed: ' + name)
        value = after[name]
        require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
                'The panel patch must retain all original files; deletions are not permitted')
        expected[name] = value
        modes.setdefault(name, 0o644)
    require(all(expected[name] == checksum for name, checksum in policy['native_child_postimages'].items()),
            'Panel launch-pad differs from the exact same-pin NativeChild adaptation')
    config = policy['original_panel_configuration']
    require(expected[config['path']] == config['sha256'], 'Panel defaults may not be pruned')
    return expected, modes


def verify_export(source_cache, native_source_cache, cache, recipe_path, policy, retained, source_inputs):
    require(verify_sources(source_cache, native_source_cache, cache, recipe_path, policy) == source_inputs,
            'Panel original inputs changed')
    retained = base.no_symlink_path(retained)
    expected, modes = expected_export(policy, source_inputs)
    observed = files.read_tree(retained)
    require(set(observed['files']) == set(expected), 'Retained full panel source has missing or extra files')
    directories = {str(parent) for name in expected for parent in Path(name).parents if parent != Path('.')}
    require({str(path.relative_to(retained)) for path in retained.rglob('*') if path.is_dir()} == directories,
            'Retained panel source directory inventory changed')
    for name, checksum in expected.items():
        relative = base.dependencies.relative_path(name)
        require(not ('.cargo' in relative.parts and relative.name in ('config', 'config.toml')),
                'Unreviewed panel Cargo configuration')
        require(observed['files'][name]['sha256'] == checksum
                and stat.S_IMODE((retained / name).lstat().st_mode) == modes[name],
                'Retained panel source differs from the complete canonical patch output: ' + name)
    require(base.digest(retained / 'Cargo.lock') == policy['effective_lock_sha256'], 'Effective panel lock changed')
    return observed


def export_source(source_cache, native_source_cache, cache, recipe_path, recipe, policy, destination):
    inputs = verify_sources(source_cache, native_source_cache, cache, recipe_path, policy)
    destination = base.no_symlink_path(destination)
    for name in ('panel', 'launch_pad', 'smithay'):
        original = inputs['originals'][name]
        prefix = policy['git_sources'][name]['prefix']
        target = destination if not prefix else destination / prefix.rstrip('/')
        common.export_canonical(Path(original['path']), target, original['commit'])
    for spec in policy['registry_inputs']:
        content, modes, _ = files.registry_snapshot(cache, spec)
        root = destination / spec['prefix'].rstrip('/')
        root.mkdir(parents=True, exist_ok=False)
        for name, data in content.items():
            path = root / base.dependencies.relative_path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:stream.write(data)
            path.chmod(modes[name])
    records = []
    for row in recipe['patches']:
        patch = base.no_symlink_path(Path(recipe_path).parent / row['path'])
        require(base.digest(patch) == row['sha256'], 'Panel patch changed before export')
        for check in (['--check'], []):
            subprocess.run(['/usr/bin/git', 'apply', *check, str(patch)], cwd=destination,
                           check=True, capture_output=True, env=base.clean_environment('/usr/bin:/bin'))
        records.append({'path': str(patch), 'sha256': row['sha256']})
    tree = verify_export(source_cache, native_source_cache, cache, recipe_path, policy, destination, inputs)
    return inputs, records, tree


def metadata_identity(metadata, stage, cache, recipe, policy):
    require(policy['workspace_members'] == list(metadata_contract.MEMBERS)
            and policy['features'] == FEATURES, 'Panel metadata source policy changed')
    return metadata_contract.metadata_identity(metadata, stage, cache, recipe)


def mesa_inputs(sysroot, recipe, policy):
    """Bind the independently consumed real Wayland Mesa and selected archives."""
    sysroot = base.no_symlink_path(sysroot)
    row = policy['native_mesa_validation']
    path = base.no_symlink_path(ROOT / base.dependencies.relative_path(row['path']))
    proof = read_json(path, row['sha256'])
    require(proof['status'] == 'MESA_WAYLAND_PRODUCTION_LIBRARIES_CONSUMED_NOT_RUN'
            and proof['genuine_helper_embedded_in_egl'] is True and proof['surfaceless_preserved'] is True
            and proof['original_inputs_preserved'] is True and proof['source_and_uapi_unchanged'] is True
            and proof['guest_execution'] is False and proof['g_egl_pass'] is False
            and proof['cosmic_session_verified'] is False and proof['full_os_verified'] is False
            and proof['sdk_assembly']['path'] == str(sysroot / 'runtime-sdk-origin.json')
            and proof['sdk_assembly']['sha256'] == recipe['native_sdk_origin']['sha256']
            and proof['original_build_limits'] == {'jobs': 2, 'timeout_seconds': 3600,
                'max_output_bytes': 3 * 1024**3, 'min_free_bytes': 1024**3},
            'Panel requires the fixed genuine Wayland/surfaceless Mesa consumption')
    producer = proof['completed_producer']
    producer_path = sysroot / 'mesa-native-port/latest-report.json'
    producer_raw = read_regular(producer_path)
    require(producer['path'] == str(producer_path) and producer['bytes'] == len(producer_raw)
            and producer['sha256'] == files.sha(producer_raw), 'Completed Mesa producer receipt changed')
    sdk = read_json(sysroot / 'runtime-sdk-origin.json', recipe['native_sdk_origin']['sha256'])
    original = sdk['new_inputs']['trees']['sysroot']['files']
    linked = proof['actual_build_validation']['actual_final_link_inputs']
    for entry in recipe['native_inputs']:
        relative = entry['path']
        actual = original[relative[len('sysroot/'):]] if relative.startswith('sysroot/') else linked[str(sysroot / relative)]
        require(actual['sha256'] == entry['sha256'], 'Panel archive is outside the genuine consumed native closure')
    return {'receipt': {'path': str(path), 'sha256': row['sha256']},
            'completed_producer': producer, 'sdk_assembly': proof['sdk_assembly'],
            'genuine_wayland_egl': True, 'surfaceless_preserved': True,
            'guest_execution': False, 'g_egl_pass': False}


def check_toolchain(toolchain):
    selected = toolchain.get('selection')
    require(type(selected) is dict and type(selected.get('schema_version')) is int
            and selected['schema_version'] == 1, 'Explicit panel Rust/Clang selection required')
    require(re.search(r'^release: 1\.95\.0$', toolchain.get('rustc_version', ''), re.MULTILINE)
            and re.search(r'\bclang version 19\.', toolchain.get('host_cc_version', ''))
            and toolchain['host'].startswith('x86_64-') and 'linux' in toolchain['host'],
            'Panel Linux profile requires Rust 1.95.0 and Clang 19')


def rust_libraries(toolchain):
    directory = base.no_symlink_path(Path(toolchain['std']['path']).parent)
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.suffix in ('.rlib', '.a'):
            data = read_regular(path, 128 * 1024**2)
            result[str(path.relative_to(directory))] = {'bytes': len(data), 'sha256': files.sha(data)}
    require(result, 'Missing official panel Rust target archive closure')
    return result


def native_sources(sysroot, recipe, toolchain):
    require(toolchain['native_inputs'] == recipe['native_inputs']
            and toolchain['static_link_inputs'] == recipe['static_link_inputs'] == list(STATIC_PATHS),
            'Panel native library selection changed')
    declared = {row['path']: row['sha256'] for row in recipe['native_inputs']}
    require(len(declared) == len(NATIVE_PATHS) and set(declared) == set(NATIVE_PATHS),
            'Panel native source inventory changed')
    sources = {'libunwind.a': (Path(toolchain['unwind']['path']), toolchain['unwind']['sha256'])}
    for relative in STATIC_PATHS:
        name = Path(relative).name
        require(name not in sources, 'Ambiguous panel native archive basename')
        sources[name] = (Path(sysroot) / relative, declared[relative])
    result = {}
    for name, (path, expected) in sources.items():
        data = read_regular(path, 64 * 1024**2)
        require(files.sha(data) == expected, 'Panel native archive source changed: ' + name)
        base.ports.architecture(path, target='x86_64')
        result[name] = {'source': str(path), 'bytes': len(data), 'sha256': expected}
    return result


def native_search(output, sysroot, recipe, toolchain, environment=None):
    native = base.no_symlink_path(Path(output) / 'native')
    expected = native_sources(sysroot, recipe, toolchain)
    require(native.is_dir() and {path.name for path in native.iterdir()} == set(expected),
            'Panel static search has missing or extra archives')
    for name, row in expected.items():
        data = read_regular(native / name, 64 * 1024**2)
        require(len(data) == row['bytes'] and files.sha(data) == row['sha256']
                and stat.S_IMODE((native / name).lstat().st_mode) == 0o644,
                'Staged panel native archive changed: ' + name)
    search = ['-L', 'native=' + str(native)]
    if environment is not None:
        flags = environment.get('CARGO_ENCODED_RUSTFLAGS', '').split('\x1f')
        locations = []
        for index, value in enumerate(flags):
            if value == '-L':
                require(index + 1 < len(flags), 'Incomplete panel rustc native search flag')
                locations.append(flags[index + 1])
            elif value.startswith('-L'):
                locations.append(value[2:])
        require('RUSTFLAGS' not in environment and locations == search[1:]
                and environment.get('CARGO_NET_OFFLINE') == 'true',
                'Panel requires one explicit offline rustc static archive search')
    return {'schema_version': 1, 'purpose': 'rustc-static-rlib-bundling',
            'directory': str(native), 'rustc_search_flags': search, 'files': expected}


def stage_native_archives(output, sysroot, recipe, toolchain, environment):
    expected = native_sources(sysroot, recipe, toolchain)
    native = base.no_symlink_path(Path(output) / 'native')
    require({path.name for path in native.iterdir()} == {'libunwind.a'},
            'Panel staging requires only the original real unwind copy')
    require(files.sha(read_regular(native / 'libunwind.a', 64 * 1024**2)) == expected['libunwind.a']['sha256'],
            'Panel unwind copy differs from the selected runtime')
    for relative in STATIC_PATHS:
        name = Path(relative).name
        row = expected[name]
        data = read_regular(row['source'], 64 * 1024**2)
        require(files.sha(data) == row['sha256'] and len(data) == row['bytes'], 'Archive changed during panel staging')
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
            'Panel generated wrapper inventory changed')
    require(all(stat.S_IMODE((Path(output) / 'bin' / name).lstat().st_mode) == 0o755 for name in wrappers),
            'Panel generated wrapper mode changed')
    return {'bin': tree, 'native_search': native_search(output, sysroot, recipe, toolchain)}


def commands(cargo, stage, recipe, jobs, package_id=None):
    return metadata_contract.commands(cargo, stage, recipe, jobs, package_id)
