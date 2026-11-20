#!/usr/bin/env python3
"""Build the pinned genuine compositor with bounded phase observations.

This versioned orchestration preserves the original builders and port series.
Preparation acquires source only. Builds are locked/offline and use the fixed
FullOsV3 parser contract; neither result attests a running COSMIC session.

v3 differs from v2 only in the recipe canonical binding: it selects the
native-comp-phase-v2 recipe whose native_inputs SHA pins bind the locally
rebuilt x86_64 musl SDK (tools/build_sysroot.py et al., 2026-11-17) instead of
the original cyx SDK bytes. The source commit, Cargo.lock, port series, phase
observation policy and resource profile are unchanged from v2. The rebuilt SDK
is functionally equivalent but not byte-identical to the cyx SDK; this is a new
SDK-version build lineage, not a claim of byte identity with retained captures.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time
import tomllib
from urllib.parse import parse_qsl, urlsplit

try:
    from . import build_cosmic as base
    from . import cosmic_port_source as acquisition
    from . import prepare_cosmic_comp as series
    from . import cosmic_notifications_toolchain as selection
    from . import cosmic_notifications_dependencies as objects
    from . import cosmic_comp_git as git_graph
    from . import cosmic_notifications_static_v1 as files
    from .cosmic_notifications_elf import inspect_full_os_elf
    from . import os_x86
    from .native_session import DEFAULT_NATIVE_LOCK, native_lease, idle_native_host
except ImportError:
    import build_cosmic as base
    import cosmic_port_source as acquisition
    import prepare_cosmic_comp as series
    import cosmic_notifications_toolchain as selection
    import cosmic_notifications_dependencies as objects
    import cosmic_comp_git as git_graph
    import cosmic_notifications_static_v1 as files
    from cosmic_notifications_elf import inspect_full_os_elf
    import os_x86
    from native_session import DEFAULT_NATIVE_LOCK, native_lease, idle_native_host

ROOT = base.ROOT
COMMIT = '41497b42d9744d9963c4c6d17e8add49489b45ee'
SERIES = 'ports/cosmic/native-comp-phase-v1/native-series.json'
SERIES_SHA256 = '7c487f8462cbc27456d8a4a364d8efbd2860e38beed0f765ab85b7573644ddb0'
POLICY = 'ports/cosmic/native-comp-phase-v1/source-policy.json'
POLICY_SHA256 = '4bba61838eab0b48adfae1444a28da67d55d3372478cdea8622c140f8ef80726'
RECIPE_CANONICAL_SHA256 = '7db7b3a02420bb3de8c217fd4004a0bb07b30d19e3cc44dfb2889d464bd70057'
KIND = 'cosmic-comp-native-linux-phase-v1'
LOCK_SHA256 = 'ecfa6705314e3821534170a01afd5014478fd4800bd699abb7ccd04b7dfb34b8'
PROFILE = 'comp-full-os-linux-v1'


def require(value, message):
    if not value:
        raise base.CosmicBuildError(message)


def remaining_bounds(deadline, bounds):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Compositor operation deadline exceeded')
    return remaining, bounds[1], bounds[2]


def phase_policy():
    require(base.digest(ROOT / POLICY) == POLICY_SHA256, "Compositor phase policy changed")
    policy = base.load_json(ROOT / POLICY)
    require(policy.get("kind") == KIND and policy.get("guest_execution") is False,
            "Invalid compositor phase policy")
    return policy


def resolution(metadata, stage):
    """Preserve the actual 468-package graph, features, edges and workspace."""
    expected = phase_policy()["preserved_resolution"]
    graph = files.normalized_resolution(metadata)
    require(len(graph) == expected["package_count"]
            and files.canonical_hash(graph) == expected["normalized_graph_sha256"],
            "Compositor selected graph or features changed")
    packages = {row["id"]: row for row in metadata["packages"]}
    members, defaults = metadata["workspace_members"], metadata.get("workspace_default_members")
    require(type(defaults) is list and len(members) == len(set(members)) == 2
            and len(defaults) == len(set(defaults)) == 1 and set(defaults) <= set(members),
            "Compositor workspace/default members changed")
    workspace = []
    for identifier in members:
        row = packages[identifier]
        manifest = Path(row["manifest_path"])
        require(row.get("source") is None and manifest.is_relative_to(Path(stage)),
                "Compositor workspace member escapes source")
        workspace.append({"name": row["name"], "version": row["version"],
                          "manifest": str(manifest.relative_to(Path(stage)))})
    require(sorted(workspace, key=lambda row: row["manifest"]) == expected["workspace"]
            and sorted(str(Path(packages[identifier]["manifest_path"]).relative_to(Path(stage)))
                       for identifier in defaults) == expected["default_members"],
            "Compositor workspace inventory changed")
    return expected


def contract(recipe):
    phase_policy()
    require(files.canonical_hash(recipe) == RECIPE_CANONICAL_SHA256
            and recipe.get("phase_observation_policy") == {"path": POLICY, "sha256": POLICY_SHA256},
            "Compositor phase recipe changed native inputs or observation policy")
    require(recipe.get('component') == recipe.get('package') == recipe.get('binary') == 'cosmic-comp'
            and recipe.get('commit') == COMMIT
            and recipe.get('target') == 'x86_64-unknown-linux-musl'
            and recipe.get('default_features') is False
            and recipe.get('features') == ['backend-cyxia']
            and recipe.get('source_lock_sha256') == recipe.get('effective_lock_sha256') == LOCK_SHA256
            and recipe.get('source_series') == {'path': SERIES, 'sha256': SERIES_SHA256}
            and recipe.get('patches') == [], 'Unsupported native compositor source/feature contract')
    require(base.digest(ROOT / SERIES) == SERIES_SHA256, 'Compositor series changed')


def full_os_profile(document, recipe, jobs):
    require(recipe.get('resource_profile') == PROFILE, 'Explicit FullOs compositor profile required')
    profile = base.select_profile(document, PROFILE, jobs, 'x86_64')
    require(profile.get('target_runtime_validated') is False
            and profile['max_elf_bytes'] == profile['image_bytes'] == 64 * 1024**2
            and profile['stack_bytes'] == 2 * 1024**2
            and profile['jobs_max'] == 2
            and profile['min_free_bytes'] == 1024**3
            and profile['max_build_bytes'] == 3 * 1024**3
            and profile['timeout_seconds'] == 3600, 'Unsupported compositor resource bounds')
    return profile


def git_identity(root, expected_commit):
    return git_graph.git_identity(root, expected_commit)


def source_key(spec):
    """Cargo metadata decodes Git query values that Cargo.lock percent-escapes."""
    if spec is None or spec.startswith('registry+'):
        return spec
    require(re.fullmatch(r'git\+https://[^\s#]+#[0-9a-f]{40}', spec), 'Unpinned Git source')
    parsed = urlsplit(spec[4:])
    require(parsed.username is None and parsed.password is None
            and not re.search(r'%(?![0-9a-fA-F]{2})', parsed.query), 'Invalid Git source URL')
    query = tuple(parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                           encoding='utf-8', errors='strict'))
    require(len(query) <= 1 and all(key in ('branch','tag','rev') and value for key,value in query),
            'Unsupported Git revision query')
    return parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment


def metadata_identity(metadata, stage, cache, recipe):
    """Validate locked packages and canonical Git blobs, including tracked links."""
    stage, cache = base.no_symlink_path(stage), base.no_symlink_path(cache)
    resolution(metadata, stage)
    packages = metadata.get('packages', [])
    require(metadata.get('version') == 1 and packages, 'Missing compositor metadata')
    ids = {p['id'] for p in packages}
    nodes = metadata.get('resolve', {}).get('nodes', [])
    require(len(ids) == len(packages) and nodes
            and len({n['id'] for n in nodes}) == len(nodes)
            and all(n['id'] in ids and all(d in ids for d in n['dependencies']) for n in nodes),
            'Incomplete compositor dependency graph')
    locked = {(p['name'], p['version'], source_key(p.get('source')))
              for p in tomllib.loads((stage / 'Cargo.lock').read_text())['package']}
    selected = [p for p in packages if p['name'] == recipe['package'] and p.get('source') is None
                and Path(p['manifest_path']) == stage / 'Cargo.toml']
    require(len(selected) == 1 and any(t['name'] == recipe['binary'] and 'bin' in t['kind']
                                      for t in selected[0]['targets']), 'Missing exact local compositor binary')
    roots, records = {}, []
    for package in packages:
        manifest = base.no_symlink_path(package['manifest_path'])
        spec = package.get('source')
        require(manifest.is_file() and (package['name'], package['version'], source_key(spec)) in locked,
                'Dependency differs from Cargo.lock: ' + package['name'] + ' ' + package['version'])
        record = {'name': package['name'], 'version': package['version'], 'source': spec,
                  'manifest': str(manifest)}
        if spec is None:
            require(manifest.is_relative_to(stage), 'Local dependency escapes source')
            record['source_tree_sha256'] = base.tree_identity(manifest.parent)['sha256']
        elif spec.startswith('registry+'):
            require(manifest.is_relative_to(cache / 'registry/src'), 'Registry source escapes private cache')
            record['source_tree_sha256'] = base.tree_identity(manifest.parent)['sha256']
        else:
            match = re.fullmatch(r'git\+https://[^\s#]+#([0-9a-f]{40})', spec)
            require(match is not None and manifest.is_relative_to(cache / 'git/checkouts'),
                    'Unpinned or external Git dependency')
            relative = manifest.relative_to(cache / 'git/checkouts')
            require(len(relative.parts) >= 3, 'Missing Git checkout/package path')
            checkout = cache / 'git/checkouts' / relative.parts[0] / relative.parts[1]
            key = str(checkout)
            if key not in roots:
                roots[key] = git_identity(checkout, match.group(1))
            require(roots[key]['commit'] == match.group(1)
                    and str(manifest.relative_to(checkout)) in roots[key]['files'], 'Untracked Git manifest')
            record['git_checkout'] = {'path': key, **roots[key]}
            record['source_tree_sha256'] = roots[key]['sha256']
        records.append(record)
    return records


def export_canonical(original, stage, expected_commit):
    """Materialize verified canonical blobs without consulting replacement refs."""
    original = base.no_symlink_path(original)
    identity = git_identity(original, expected_commit)
    stage.mkdir(parents=True, exist_ok=False)
    for name, item in identity['files'].items():
        relative = base.dependencies.relative_path(name)
        require(not ('.cargo' in relative.parts and relative.name in ('config','config.toml')),
                'Source Cargo configuration requires explicit review')
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if item['mode'] == '120000':
            require(os.readlink(original/relative) == item['symlink'], 'Source link changed during export')
            destination.symlink_to(item['symlink'])
        else:
            descriptor = os.open(original/relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor,'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size == item['bytes'] <= 16*1024**2,
                        'Source export requires a bounded pinned regular file')
                raw = stream.read(item['bytes']+1)
            require(len(raw) == item['bytes'] and objects.git_blob(raw) == item['git_blob']
                    and hashlib.sha256(raw).hexdigest() == item['sha256'], 'Source blob changed during export')
            with destination.open('xb') as stream:
                stream.write(raw)
            destination.chmod(0o755 if item['mode']=='100755' else 0o644)
    require(git_identity(original, expected_commit) == identity, 'Canonical source changed during export')


def export(original, stage):
    export_canonical(original, stage, COMMIT)
    patches = series.apply_series(stage, ROOT / SERIES)
    require(base.digest(stage / 'Cargo.lock') == LOCK_SHA256, 'Compositor lock changed during export')
    return patches


def check_control(control):
    require(not any((p / 'Cargo.toml').exists() or any((p / '.cargo' / n).exists()
            for n in ('config', 'config.toml')) for p in (control, *control.parents)),
            'Inherited Cargo workspace or configuration')


def perform(action, recipe_path, profile_path, output, sysroot, source_cache, cache,
            rust_root, host_cc, jobs=2, fetch=False):
    require(action in ('prepare', 'build'), 'Unsupported compositor operation')
    require(type(fetch) is bool and (action == 'prepare' or not fetch), 'Only preparation may acquire sources')
    recipe_path = base.no_symlink_path(recipe_path)
    source_cache = base.no_symlink_path(source_cache)
    profile_path = base.no_symlink_path(profile_path) if profile_path is not None else None
    source, original, recipe = base.source_and_recipe('cosmic-comp', recipe_path,
                                                      base.ports.load_manifest(), source_cache)
    contract(recipe)
    profile = full_os_profile(base.load_json(profile_path), recipe, jobs) if action == 'build' else None
    cache = base.no_symlink_path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    base.validate_cache(cache)
    output = base.new_output(output)
    producers = os_x86.producer_sources(__file__)
    original_path = Path(original['path'])
    source_identity = git_identity(original_path, COMMIT)
    report = {'schema_version': 1, 'kind': KIND,
              'phase_policy_sha256': POLICY_SHA256,
              'phase_observation_contract': phase_policy()['observation'],
              'status': 'FAILED', 'operation': action, 'component': source,
              'output': str(output), 'recipe_path': str(recipe_path), 'source_cache': str(source_cache),
              'cargo_cache': str(cache),
              'recipe': recipe, 'recipe_sha256': base.digest(recipe_path), 'producer_sources': producers,
              'builder_sha256': base.digest(__file__), 'canonical_source': source_identity,
              'series_sha256': SERIES_SHA256, 'target': recipe['target'], 'architecture': 'x86_64',
              'jobs': jobs, 'link_completed': False, 'target_linked': False, 'guest_execution': 'not performed',
              'cosmic_session_ready': False, 'cargo_offline': action == 'build' or not fetch,
              'build_script_network_sandbox': False}
    started = time.monotonic()
    timeout = profile['timeout_seconds'] if profile else 1200
    deadline = started + timeout
    report.update(operation_timeout_seconds=timeout,
                  timeout_scope='Shared across export, Cargo commands and validation; publication refuses an expired deadline')
    try:
        with (cache / '.cyxia-build.lock').open('a') as cache_lock, \
                tempfile.TemporaryDirectory(prefix='cyxia-native-comp-phase-v1-') as temporary:
            fcntl.flock(cache_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            control = Path(temporary).resolve()
            check_control(control)
            stage = control / 'source'
            report['original_export_root'] = str(stage)
            report['patches'] = export(original_path, stage)
            report['source_tree'] = base.tree_identity(stage)
            shutil.copytree(stage, output / 'source', symlinks=True)
            baseline = base.directory_bytes(cache)
            budget = dict(budget_root=output, scratch_roots=(control,), growth_roots=((cache, baseline),))
            features = ['--no-default-features', '--features', 'backend-cyxia']
            common = ['--manifest-path', str(stage / 'Cargo.toml'), '--locked', '--offline']
            if action == 'prepare':
                cargo, env, report['toolchain_selection'] = selection.acquisition_environment(cache, rust_root)
                env.update(CARGO_NET_OFFLINE='false' if fetch else 'true', CARGO_TARGET_DIR=str(output / 'target'))
                bounds = (1200, 1024**3, 3 * 1024**3)
                command = [str(cargo), 'fetch', '--manifest-path', str(stage / 'Cargo.toml'), '--locked']
                if not fetch:
                    command.append('--offline')
                report['fetch_command'] = command
                base.run_bounded(command, control, env, output / 'fetch.log',
                                 *remaining_bounds(deadline, bounds), **budget)
            else:
                require(sysroot is not None, 'Build requires a read-only target SDK')
                sysroot = base.no_symlink_path(sysroot)
                sdk_lock = (sysroot / '.build.lock').open('a')
                try:
                    fcntl.flock(sdk_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    tools, identities = selection.tools_and_sysroot(sysroot, recipe, rust_root=rust_root, host_cc=host_cc)
                    report.update(toolchain=identities, sysroot=str(sysroot), resource_profile=profile,
                                  profile_file=str(profile_path), profile_file_sha256=base.digest(profile_path),
                                  sysroot_before=base.tree_identity(sysroot / 'sysroot'))
                    env = base.cargo_environment(tools, identities, sysroot, output, cache, control)
                    report['generated_build_inputs'] = {name:base.tree_identity(output/name)
                                                        for name in ('bin','native')}
                    cargo = tools['cargo']
                    env['SOURCE_DATE_EPOCH'] = objects.pinned_git(original_path, 'show', '-s', '--format=%ct')
                    env['CYXIA_COSMIC_UPSTREAM_COMMIT'] = COMMIT
                    bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
                    compile_selected(report, cargo, env, control, stage, output, common, features,
                                     bounds, budget, recipe, cache, profile, sysroot, deadline)
                finally:
                    sdk_lock.close()
            if action == 'prepare':
                metadata_command = [str(cargo), 'metadata', '--format-version', '1', '--filter-platform', recipe['target'], *common, *features]
                report['metadata_command'] = metadata_command
                base.run_bounded(metadata_command, control, env, output / 'metadata.json',
                                 *remaining_bounds(deadline, bounds),
                                 stderr_log=output / 'metadata.stderr.log', **budget)
                metadata = base.load_json(output / 'metadata.json')
                report['cargo_dependencies'] = metadata_identity(metadata, stage, cache, recipe)
                report['preserved_resolution'] = resolution(metadata, stage)
                report['resolved'] = acquisition.summarize_metadata(output / 'metadata.json', stage)
            require(base.tree_identity(stage) == report['source_tree'] == base.tree_identity(output / 'source'),
                    'Compositor source changed')
            require(git_identity(original_path, COMMIT) == source_identity, 'Original compositor checkout changed')
            require(os_x86.producer_sources(__file__) == producers and base.digest(recipe_path) == report['recipe_sha256'],
                    'Compositor producer or recipe changed')
            contract(recipe)
            report.update(source_preserved=True, producer_sources_preserved=True,
                          cache_growth_bytes=max(0, base.directory_bytes(cache)-baseline))
            report['retained_logs'] = {name:base.digest(output/name) for name in
                                      ('fetch.log','metadata.json','metadata.stderr.log','cargo.log')
                                      if (output/name).is_file()}
            remaining_bounds(deadline, bounds)
            if action == 'build':
                require(base.digest(profile_path) == report['profile_file_sha256'], 'Resource profile changed')
                require(selection.tools_and_sysroot(sysroot, recipe, rust_root=rust_root, host_cc=host_cc)[1]
                        == report['toolchain'], 'Compiler or native input changed')
                require(base.tree_identity(sysroot / 'sysroot') == report['sysroot_before'], 'Target SDK changed before publication')
                require({name:base.tree_identity(output/name) for name in ('bin','native')}
                        == report['generated_build_inputs'], 'Generated linker inputs or wrappers changed')
                linked = output / 'target' / recipe['target'] / 'release/cosmic-comp'
                inspection = inspect_full_os_elf(linked, profile)
                final = output / 'cosmic-comp.elf'
                with tempfile.TemporaryDirectory(prefix='.publication-', dir=output) as publishing:
                    candidate = Path(publishing) / 'cosmic-comp.elf'
                    shutil.copyfile(linked, candidate)
                    candidate_inspection = inspect_full_os_elf(candidate, profile)
                    require(candidate_inspection['executable']['sha256'] == inspection['executable']['sha256'],
                            'Compositor bytes changed before publication')
                    remaining_bounds(deadline, bounds)
                    candidate.replace(final)
                report.update(status='cross-built', executable={**candidate_inspection['executable'], 'path':str(final)},
                              full_os_inspection=inspection, image_load_pages=inspection['image_load_pages'], target_linked=True)
            else:
                report['status'] = 'CARGO_SOURCES_AVAILABLE'
    except Exception as error:
        report.update(status='FAILED', error=str(error))
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic()-started
        report['producer_sources_after'] = os_x86.producer_sources(__file__)
        report['producer_sources_preserved'] = report['producer_sources_after'] == producers
        if not report['producer_sources_preserved']:
            report.update(status='FAILED', error='Transitive compositor producers changed')
        if report['status'] == 'FAILED':
            report['target_linked'] = False
            (output / 'cosmic-comp.elf').unlink(missing_ok=True)
        (output / ('preparation.json' if action == 'prepare' else 'build-report.json')).write_text(json.dumps(report, indent=2)+'\n')
        require(report['producer_sources_preserved'], 'Transitive compositor producers changed')
    return report


def compile_selected(report, cargo, env, control, stage, output, common, features,
                     bounds, budget, recipe, cache, profile, sysroot, deadline):
    metadata_command = [str(cargo), 'metadata', '--format-version', '1', '--filter-platform', recipe['target'], *common, *features]
    report['metadata_command'] = metadata_command
    base.run_bounded(metadata_command, control, env, output / 'metadata.json',
                     *remaining_bounds(deadline, bounds),
                     stderr_log=output / 'metadata.stderr.log', **budget)
    metadata = base.load_json(output / 'metadata.json')
    report['cargo_dependencies'] = metadata_identity(metadata, stage, cache, recipe)
    report['preserved_resolution'] = resolution(metadata, stage)
    command = [str(cargo), 'build', '--release', '--target', recipe['target'], '--jobs', str(report['jobs']),
               '--package', 'cosmic-comp', '--bin', 'cosmic-comp', *common, *features]
    report['command'] = command
    base.run_bounded(command, control, env, output / 'cargo.log',
                     *remaining_bounds(deadline, bounds), **budget)
    require(metadata_identity(metadata, stage, cache, recipe) == report['cargo_dependencies'], 'Dependency source changed')
    require(base.tree_identity(sysroot / 'sysroot') == report['sysroot_before'], 'Target SDK changed')
    for entry in recipe['native_inputs']:
        require(base.digest(sysroot / entry['path']) == entry['sha256'], 'Native archive changed')
    linked = output / 'target' / recipe['target'] / 'release/cosmic-comp'
    require(linked.is_file() and not linked.is_symlink() and linked.resolve().is_relative_to(output),
            'Linked compositor missing or outside output')
    report.update(link_completed=True, linked_binary={'path':str(linked), 'bytes':linked.stat().st_size, 'sha256':base.digest(linked)})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'build'))
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--resource-profile', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path)
    parser.add_argument('--source-cache', type=Path, default=base.ports.CACHE)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--host-cc', type=Path)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    args = parser.parse_args(argv)
    if args.action == 'build' and (args.resource_profile is None or args.sysroot is None or args.host_cc is None):
        parser.error('build requires --resource-profile, --sysroot and --host-cc')
    with native_lease(args.native_lock):
        idle_native_host()
        result = perform(args.action, args.recipe.resolve(), args.resource_profile, args.output,
                         args.sysroot, args.source_cache, args.cache, args.rust_root,
                         args.host_cc, args.jobs, args.fetch)
    print(json.dumps({'status':result['status'], 'output':str(args.output)}))


if __name__ == '__main__':
    main()
