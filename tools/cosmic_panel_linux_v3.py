"""Read-only source and input contracts for the genuine native panel Linux-v2 port.

The complete Linux-v1 policy is preserved byte for byte except four reviewed
build-input/provenance identity rebinds and the kind: native_inputs and
native_sdk_origin are rebound to the locally rebuilt x86_64 musl SDK +
native-wayland Mesa (sdk_rebind); source_acquisition is rebound to a locally
verified three-source acquisition receipt (acquisition_rebind); and
native_mesa_validation is rebound to a Mesa consumption proof regenerated from
verified local nm/link/producer-input evidence (mesa_validation_rebind). Source,
patches, locks, features, git_sources, registry_inputs, the 18-applet config and
the resource profile are unchanged. The host Clang-19 / x86_64-linux pins are
relaxed for pure cross-compilation, mirroring settings Linux-v4. Validation never
fetches, invokes compiler probes, or runs the target.
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
    from . import cosmic_panel_linux_v2 as previous
else:
    import cosmic_panel_linux_v2 as previous

# Re-export the unchanged v1 machinery. These functions consume the policy passed
# to them (or identity constants identical across versions), so the rebound v2
# policy's local receipts flow through without modification.
from cosmic_panel_linux_v2 import (  # noqa: F401
    base, common, files, elf, legacy, metadata_contract,
    require, BuildError, canonical, read_regular, read_json,
    ROOT, TARGET, FEATURES, NATIVE_PATHS, STATIC_PATHS, LOGS, TIMEOUT_SCOPE,
    REPOSITORIES, COMPONENT, PACKAGE, PROFILE,
    expected_export, mesa_inputs, native_sources, rust_libraries,
    metadata_identity, commands, stage_native_archives, generated_inputs, native_search,
)

PORT = 'ports/cosmic/native-panel-linux-v2'
POLICY_SHA256 = '5953657424bbac8812a44eb6227421b9283611008def949bcc9057c048587aa9'
RECIPE_SHA256 = 'ba760a383c785e14604dbfe833015de55275696b76835139c0c9430528b1f076'
RESOURCE_SHA256 = 'b96596aa56646e5ef4f812b488fe29f2251ec971fcbe9f6e1dce56f0daacefca'
KIND = 'cosmic-panel-native-linux-v2'


def prior_contract(jobs):
    directory = ROOT / previous.PORT
    result = previous.contract(directory / 'native-recipe.json', directory / 'resource-profile.json', jobs)
    bindings = {
        'source-policy.json': {'path': previous.PORT + '/source-policy.json', 'sha256': previous.POLICY_SHA256},
        'native-recipe.json': {'path': previous.PORT + '/native-recipe.json', 'sha256': previous.RECIPE_SHA256},
        'resource-profile.json': {'path': previous.PORT + '/resource-profile.json', 'sha256': previous.RESOURCE_SHA256},
    }
    return result, bindings


def protected_input_paths(recipe_path):
    """Protect the rebound local provenance receipts before any output write."""
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
    document = read_json(resource_path, RESOURCE_SHA256)
    (old_policy, old_recipe, source, old_profile), prior = prior_contract(jobs)
    additions = {'prior_linux_v1', 'sdk_rebind', 'acquisition_rebind', 'mesa_validation_rebind'}
    replaced = {'kind', 'native_inputs', 'native_sdk_origin', 'source_acquisition', 'native_mesa_validation'}
    require(set(policy) == set(old_policy) | additions
            and {k: v for k, v in policy.items() if k not in additions | replaced}
                == {k: v for k, v in old_policy.items() if k not in replaced}
            and policy['kind'] == KIND and policy['prior_linux_v1'] == prior,
            'Panel v2 must preserve the exact complete Linux-v1 policy except reviewed rebinds')
    sdk = policy['sdk_rebind']
    acq = policy['acquisition_rebind']
    mesa = policy['mesa_validation_rebind']
    require(sdk['guest_execution'] is False and acq['guest_execution'] is False and mesa['guest_execution'] is False
            and policy['native_inputs'] == sdk['native_inputs']
            and policy['native_sdk_origin'] == sdk['native_sdk_origin']
            and sdk['prior_native_inputs'] == old_policy['native_inputs']
            and sdk['prior_native_sdk_origin'] == old_policy['native_sdk_origin']
            and [r['path'] for r in sdk['native_inputs']] == list(NATIVE_PATHS)
            and all(set(r) == {'path', 'sha256'} and re.fullmatch('[0-9a-f]{64}', r['sha256'])
                    for r in sdk['native_inputs'])
            and set(sdk['native_sdk_origin']) == {'path', 'sha256'}
            and sdk['native_sdk_origin']['path'] == 'runtime-sdk-origin.json'
            and re.fullmatch('[0-9a-f]{64}', sdk['native_sdk_origin']['sha256']),
            'Panel v2 permits only the reviewed SDK native-input/assembly rebind, without runtime claims')
    require(policy['source_acquisition'] == acq['source_acquisition']
            and acq['prior_source_acquisition'] == old_policy['source_acquisition']
            and set(acq['source_acquisition']) == {'path', 'sha256'}
            and re.fullmatch('[0-9a-f]{64}', acq['source_acquisition']['sha256']),
            'Panel v2 acquisition_rebind must bind the verified local receipt')
    require(policy['native_mesa_validation'] == mesa['native_mesa_validation']
            and mesa['prior_native_mesa_validation'] == old_policy['native_mesa_validation']
            and set(mesa['native_mesa_validation']) == {'path', 'sha256'}
            and re.fullmatch('[0-9a-f]{64}', mesa['native_mesa_validation']['sha256']),
            'Panel v2 mesa_validation_rebind must bind the verified local proof')
    require(recipe == {**old_recipe, 'native_inputs': sdk['native_inputs'],
                       'native_sdk_origin': sdk['native_sdk_origin']},
            'Panel v2 recipe changed features, locks, patches or profile beyond the SDK rebind')
    require(recipe['component'] == recipe['binary'] == COMPONENT and recipe['package'] == PACKAGE
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
    base.validate_recipe(recipe, source)
    profile = base.select_profile(document, PROFILE, jobs, 'x86_64')
    require(recipe['resource_profile'] == PROFILE and profile['target_runtime_validated'] is False
            and profile['image_bytes'] == profile['max_elf_bytes'] == 64 * 1024**2
            and profile['stack_bytes'] == 2 * 1024**2 and profile['jobs_max'] == 2
            and profile['timeout_seconds'] == 3600 and profile['max_build_bytes'] == 3 * 1024**3
            and profile['min_free_bytes'] == 1024**3, 'Panel FullOs resource bounds changed')
    return policy, recipe, source, profile


def verify_sources(source_cache, native_source_cache, cache, recipe_path, policy):
    """Canonical Git/file/mode/submodule closure and complete registry archive.

    Identical to Linux-v1 except the policy is read with the v2 SHA and the
    source_acquisition receipt is the rebound locally verified one.
    """
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
            with path.open('xb') as stream:
                stream.write(data)
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


def check_toolchain(toolchain):
    selected = toolchain.get('selection')
    require(type(selected) is dict and type(selected.get('schema_version')) is int
            and selected['schema_version'] == 1, 'Explicit panel Rust/Clang selection required')
    # v2 relaxes the v1 Clang-19 / x86_64-linux HOST pins: the panel build is a
    # pure cross-compile to x86_64-unknown-linux-musl driven by the host clang
    # with --target, and the locally rebuilt SDK/Mesa/wayland were built with that
    # same host clang, so the local lineage is internally consistent regardless of
    # host ISA or clang minor version. The rustc 1.95.0 pin is retained.
    require(re.search(r'^release: 1\.95\.0$', toolchain.get('rustc_version', ''), re.MULTILINE)
            and re.search(r'\bclang version \d+\.', toolchain.get('host_cc_version', '')),
            'Panel Linux profile requires Rust 1.95.0 and a clang host compiler')