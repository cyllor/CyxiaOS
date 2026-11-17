#!/usr/bin/env python3
"""Build the genuine notifications with versioned real static client bindings.

The caller must hold the shared root native lease. Original builders, checkouts,
cache extractions and historical reports are unchanged. Cargo is locked/offline;
the fixed FullOsV3 parser admits actual link output without changing guest flags.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

if __package__:
    from . import build_cosmic_component as component_builder
    from . import cosmic_notifications_static_v1 as static
    from . import cosmic_notifications_toolchain as toolchain_selection
    from . import cosmic_notifications_elf as image
else:
    import build_cosmic_component as component_builder
    import cosmic_notifications_static_v1 as static
    import cosmic_notifications_toolchain as toolchain_selection
    import cosmic_notifications_elf as image

base = static.build


def publication_paths(output, recipe):
    final = output / (recipe['binary'] + '.elf')
    return final, final.with_name('.' + final.name + '.pending')


def discard_publication(output, recipe, report):
    """Revoke only this producer's publication; preserve raw target/log evidence."""
    report['target_linked'] = False
    for path in publication_paths(output, recipe):
        path.unlink(missing_ok=True)


def publish_candidate(linked, output, recipe, profile, inspection):
    final, candidate = publication_paths(output, recipe)
    static.require(not final.exists() and not final.is_symlink(), 'Unexpected published notification ELF')
    with linked.open('rb') as source, candidate.open('xb') as destination:
        shutil.copyfileobj(source, destination)
        destination.flush(); os.fsync(destination.fileno())
    candidate_inspection = image.inspect_full_os_elf(candidate, profile)
    expected = dict(inspection['executable'], file=candidate.name)
    static.require(candidate_inspection['executable'] == expected, 'Candidate static ELF differs from link output')
    candidate.replace(final)
    final_inspection = image.inspect_full_os_elf(final, profile)
    expected_inspection = dict(candidate_inspection,
                              executable=dict(candidate_inspection['executable'], file=final.name))
    static.require(final_inspection == expected_inspection, 'Published static ELF differs from verified candidate')
    return final_inspection


def tool_inputs_preserved(identity):
    records = [identity['std'], identity['unwind'], *identity['tools'].values()]
    for record in records:
        path = Path(record['path'])
        if record.get('available') is False:
            static.require(not path.exists() and not path.is_symlink(), 'Absent compiler capability changed')
        else:
            static.require(path.is_file() and base.digest(path) == record['sha256'],
                           'Compiler or Rust runtime input changed: ' + str(path))


def perform_build(recipe_path, resource_path, output, sysroot, cache, source_cache, jobs,
                  *, rust_root, host_cc, metadata_only=False):
    static.require(type(metadata_only) is bool, 'Invalid metadata-only selection')
    recipe_path, resource_path, sysroot, cache, source_cache = map(
        base.no_symlink_path, (recipe_path, resource_path, sysroot, cache, source_cache))
    output = base.no_symlink_path(output)
    static.require(not output.exists(), 'Preserving existing static notification build')
    for protected in (sysroot, cache, source_cache, recipe_path.parent, base.no_symlink_path(rust_root)):
        static.require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                       'Static notification build output overlaps an input')
    policy_path = recipe_path.parent / 'source-policy.json'
    policy = static.load_policy(policy_path)
    source = next(item for item in base.ports.load_manifest()['components']
                  if item['name'] == 'cosmic-notifications')
    recipe_data = static.read_regular(recipe_path)
    recipe = static.validate_recipe(json.loads(recipe_data, object_pairs_hook=static.no_duplicates), source, policy)
    profile = static.select_profile(resource_path, jobs)
    cache = base.validate_cache(cache)
    sdk_origin = static.sdk_origin(sysroot, recipe)
    original = source_cache / source['directory']
    static.snapshot_source(original, policy)
    producers = static.producer_sources(__file__)
    started = time.monotonic()
    with base.no_symlink_path(sysroot / '.build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tools, identities = toolchain_selection.tools_and_sysroot(
            sysroot, recipe, rust_root=rust_root, host_cc=host_cc)
        output = base.new_output(output)
        report = {'schema_version': 1, 'kind': policy['kind'], 'status': 'building',
                  'component': source, 'recipe': recipe, 'recipe_sha256': static.sha(recipe_data),
                  'resource_profile': profile, 'resource_source_sha256': static.RESOURCE_SHA256,
                  'profile_sha256': hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest(),
                  'target': static.TARGET, 'architecture': 'x86_64', 'toolchain': identities,
                  'native_sdk_origin': sdk_origin,
                  'producer_sources': producers, 'policy_sha256': static.POLICY_SHA256,
                  'source_cache': str(source_cache), 'cache': str(cache), 'sysroot': str(sysroot),
                  'recipe_path': str(recipe_path), 'resource_path': str(resource_path),
                  'operation': 'metadata' if metadata_only else 'build', 'cargo_offline': True,
                  'build_script_network_sandbox': False, 'guest_execution': 'not performed',
                  'link_completed': False, 'target_linked': False, 'cargo_resolution_verified': False,
                  'native_archive_search_preserved': False,
                  'cosmic_session_ready': False, 'notifications_verified': False,
                  'cosmic_session_verified': False}
        try:
            with tempfile.TemporaryDirectory(prefix='cyxia-notifications-static-v1-') as temporary:
                control = Path(temporary).resolve()
                for parent in (control, *control.parents):
                    static.require(not (parent / 'Cargo.toml').exists()
                                   and not any((parent / '.cargo' / name).exists() for name in ('config', 'config.toml')),
                                   'Inherited Cargo workspace or configuration')
                stage = control / 'source'
                report['static_source'] = static.export_source(original, cache, stage, policy_path)
                report['source_tree'] = report['static_source']['source_tree']
                shutil.copytree(stage, output / 'source')
                env = static.cargo_environment(
                    base.cargo_environment(tools, identities, sysroot, output, cache, control))
                report['native_archive_search'] = static.stage_native_archives(
                    output, sysroot, recipe, identities, env)
                env['SOURCE_DATE_EPOCH'] = static.dependencies.pinned_git(original, 'show', '-s', '--format=%ct')
                env['CYXIA_COSMIC_UPSTREAM_COMMIT'] = source['commit']
                common = ['--manifest-path', str(stage / 'Cargo.toml'), '--locked', '--offline']
                features = ['--no-default-features', '--features', ','.join(static.FEATURES)]
                cargo = str(tools['cargo'])
                metadata_command = [cargo, 'metadata', '--format-version', '1', '--filter-platform',
                                    static.TARGET, *common, *features]
                report['metadata_command'] = metadata_command
                bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
                budget = dict(budget_root=output, scratch_roots=(control,),
                              growth_roots=((cache, base.directory_bytes(cache)),))
                report['sysroot_before'] = base.tree_identity(sysroot / 'sysroot')
                base.run_bounded(metadata_command, control, env, output / 'metadata.json', *bounds,
                                 stderr_log=output / 'metadata.stderr.log', **budget)
                metadata_data = static.read_regular(output / 'metadata.json')
                metadata = json.loads(metadata_data, object_pairs_hook=static.no_duplicates)
                report['metadata_sha256'] = static.sha(metadata_data)
                report['cargo_dependencies'] = static.verify_metadata(metadata, stage, cache, recipe, policy)
                report['package_id'] = component_builder.local_package(metadata, stage, recipe)
                report['resolved_graph_sha256'] = static.canonical_hash(static.normalized_resolution(metadata))
                report['cargo_resolution_verified'] = True
                static.verify_native_archive_search(output, sysroot, recipe, identities,
                                                    report['native_archive_search'], env)
                if not metadata_only:
                    command = [cargo, 'build', '--release', '--target', static.TARGET, '--jobs', str(jobs),
                               '--package', report['package_id'], '--bin', recipe['binary'], *common, *features]
                    report['command'] = command
                    base.run_bounded(command, control, env, output / 'cargo.log', *bounds, **budget)
                static.validate_export(original, cache, stage, report['static_source'], policy_path)
                static.require(static.read_tree(output / 'source') == report['source_tree'],
                               'Preserved static export changed')
                static.require(base.tree_identity(sysroot / 'sysroot') == report['sysroot_before'],
                               'Static notification SDK changed')
                static.require(static.sdk_origin(sysroot, recipe) == sdk_origin,
                               'Static SDK assembly identity changed')
                static.require(static.read_regular(recipe_path) == recipe_data
                               and static.select_profile(resource_path, jobs) == profile
                               and static.producer_sources(__file__) == producers,
                               'Static recipe, resource or producer changed')
                static.require(static.sha(static.read_regular(output / 'metadata.json')) == report['metadata_sha256']
                               and static.verify_metadata(metadata, stage, cache, recipe, policy)
                                   == report['cargo_dependencies'], 'Static dependency or metadata input changed')
                tool_inputs_preserved(identities)
                static.verify_native_archive_search(output, sysroot, recipe, identities,
                                                    report['native_archive_search'], env)
                for item in recipe['native_inputs']:
                    static.require(base.digest(sysroot / item['path']) == item['sha256'], 'Static native input changed')
                report['source_preserved'] = True
                if metadata_only:
                    report['status'] = 'METADATA_VERIFIED_NOT_BUILT'
                else:
                    linked = base.no_symlink_path(output / 'target' / static.TARGET / 'release' / recipe['binary'])
                    static.require(linked.is_file() and linked.is_relative_to(output), 'Missing or escaped static link output')
                    report['link_completed'] = True
                    report['linked_binary'] = {'path': str(linked), 'bytes': linked.stat().st_size,
                                               'sha256': base.digest(linked)}
                    inspection = image.inspect_full_os_elf(linked, profile)
                    static.require(inspection['executable']['sha256'] == report['linked_binary']['sha256'],
                                   'Static ELF changed during admission')
                    final_inspection = publish_candidate(linked, output, recipe, profile, inspection)
                    report.update(status='cross-built', target_linked=True,
                                  image_load_pages=inspection['image_load_pages'],
                                  executable=final_inspection['executable'], image_admission=final_inspection)
        except BaseException as error:
            report.update(status='failed', error=str(error))
            raise
        finally:
            try:
                evidence_error = None
                archive_error = None
                if 'native_archive_search' in report:
                    try:
                        report['native_archive_search_after'] = static.verify_native_archive_search(
                            output, sysroot, recipe, identities, report['native_archive_search'], env)
                        report['native_archive_search_preserved'] = True
                    except Exception as error:
                        archive_error = 'Rustc native archive postcheck failed: ' + str(error)
                        report['native_archive_search_preserved'] = False
                        report['native_archive_check_error'] = archive_error
                        report.update(status='failed')
                        report.setdefault('error', archive_error)
                report['evidence_files'] = {}
                for name in ('metadata.json', 'metadata.stderr.log', 'cargo.log'):
                    path = output / name
                    if path.exists() or path.is_symlink():
                        try:
                            data = static.read_regular(path)
                            report['evidence_files'][name] = {'bytes': len(data), 'sha256': static.sha(data)}
                        except (OSError, ValueError) as error:
                            evidence_error = 'Build evidence changed: ' + str(error)
                            report.update(status='failed', error=evidence_error)
                required_evidence = {'metadata.json', 'metadata.stderr.log'}
                if not metadata_only:
                    required_evidence.add('cargo.log')
                if (report['status'] in ('cross-built', 'METADATA_VERIFIED_NOT_BUILT')
                        and set(report['evidence_files']) != required_evidence):
                    evidence_error = 'Incomplete successful static build evidence inventory'
                    report.update(status='failed', error=evidence_error)
                try:
                    report['producer_sources_after'] = static.producer_sources(__file__)
                    report['producer_sources_preserved'] = report['producer_sources_after'] == producers
                except Exception as error:
                    report['producer_sources_preserved'] = False
                    report['producer_check_error'] = str(error)
                if not report['producer_sources_preserved']:
                    report.update(status='failed', error='Transitive static notification producers changed')
                if not report['producer_sources_preserved'] or evidence_error is not None or archive_error is not None:
                    raise base.CosmicBuildError(report['error'])
                if report['status'] != 'cross-built':
                    discard_publication(output, recipe, report)
                report['elapsed_seconds'] = round(time.monotonic() - started, 3)
                (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
            except BaseException as error:
                report.update(status='failed', target_linked=False)
                report.setdefault('error', str(error))
                discard_publication(output, recipe, report)
                report['elapsed_seconds'] = round(time.monotonic() - started, 3)
                try:
                    (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
                except OSError:
                    # Report I/O must not leave a usable published ELF either.
                    pass
                raise
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--resource-profile', type=Path, default=static.PORT / 'resource-profile.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--source-cache', type=Path, default=base.ports.CACHE)
    parser.add_argument('--cache', type=Path, default=base.CARGO_CACHE)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--host-cc', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--metadata-only', action='store_true', help='validate actual locked/offline metadata without compiling')
    args = parser.parse_args(argv)
    try:
        report = perform_build(args.recipe, args.resource_profile, args.output, args.sysroot,
                               args.cache, args.source_cache, args.jobs, rust_root=args.rust_root,
                               host_cc=args.host_cc, metadata_only=args.metadata_only)
        print(json.dumps({key: report[key] for key in ('status', 'cargo_resolution_verified',
                           'link_completed', 'target_linked', 'notifications_verified')}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print('Static notification build failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
