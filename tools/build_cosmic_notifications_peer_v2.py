#!/usr/bin/env python3
"""Build the complete pinned notifications package with the peer lifecycle fix."""
import argparse
import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile
import time

import build_cosmic_notifications_static_v1 as parent_builder
import cosmic_notifications_peer_v2 as peer
import cosmic_notifications_toolchain as selection
import cosmic_notifications_elf as image
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

static = peer.static
base = static.build


@contextmanager
def restored_control(parent):
    command = parent['command']
    control = Path(command[command.index('--manifest-path') + 1]).parent.parent
    peer.require(control.parent == Path(tempfile.gettempdir()).resolve()
        and control.name.startswith('cyxia-notifications-static-v1-')
        and not control.exists() and not control.is_symlink(),
        'Preserving a non-vacant original temporary workspace')
    control.mkdir()
    try:
        yield control
    finally:
        shutil.rmtree(control)


def build(parent_output, output):
    parent_output, output = map(base.no_symlink_path, (parent_output, output))
    peer.require(not output.exists(), 'Preserving existing peer build')
    parent, validation = peer.validate_parent(parent_output)
    recipe = parent['recipe']
    resource = Path(parent['resource_path'])
    profile = static.select_profile(resource, 2)
    sysroot, cache = Path(parent['sysroot']), Path(parent['cache'])
    for protected in (parent_output, sysroot, cache, peer.PORT):
        peer.require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                     'Peer build overlaps an input')
    producers = static.producer_sources(__file__)
    parent_sha = base.digest(parent_output / 'build-report.json')
    output.mkdir(parents=True)
    started = time.monotonic()
    report = dict(schema_version=1, kind=peer.KIND, status='building', parent_build=str(parent_output),
        parent_report_sha256=parent_sha, parent_validation_sha256=static.canonical_hash(validation),
        policy_sha256=peer.POLICY_SHA256, recipe=recipe, resource_profile=profile,
        resolved_graph_sha256=parent['resolved_graph_sha256'], producers=producers,
        guest_execution=False, full_os_verified=False, cosmic_session_verified=False)
    try:
        with (sysroot / '.build.lock').open('a') as lock, restored_control(parent) as temporary:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            control = Path(temporary).resolve()
            for ancestor in (control, *control.parents):
                peer.require(not (ancestor / 'Cargo.toml').exists()
                    and not any((ancestor / '.cargo' / name).exists() for name in ('config', 'config.toml')),
                    'Inherited Cargo workspace/configuration')
            source = control / 'source'
            report['source_tree'], old_policy = peer.export_source(parent, source)
            # Preserve timestamps only for bytes proven identical to the parent.
            # Keeping the vacant source path and native search path stable lets
            # Cargo reuse the verified GUI dependencies without changing flags.
            preserved_dates = 0
            for name, identity in parent['source_tree']['files'].items():
                selected = source / name
                if base.digest(selected) == identity['sha256']:
                    info = (parent_output / 'source' / name).stat()
                    os.utime(selected, ns=(info.st_atime_ns, info.st_mtime_ns))
                    preserved_dates += 1
            shutil.copytree(source, output / 'source')
            old_target = base.no_symlink_path(parent_output / 'target')
            old_cache = base.tree_identity(old_target)
            peer.require(not any('symlink' in item for item in old_cache['files'].values()),
                         'Only a contained regular-file cache may be cloned')
            clone_command = ['/bin/cp', '-cRp', str(old_target), str(output / 'target')]
            base.run_bounded(clone_command, control, base.clean_environment('/usr/bin:/bin'),
                output / 'cache-clone.log', min(profile['timeout_seconds'], 120),
                profile['min_free_bytes'], profile['max_build_bytes'],
                budget_root=output, scratch_roots=(control,))
            peer.require(base.tree_identity(output / 'target') == old_cache, 'Cache clone bytes differ')
            report['cache_reuse'] = dict(parent_target=str(old_target),
                input_tree_sha256=old_cache['sha256'], clone_command=clone_command,
                clone_log_sha256=base.digest(output / 'cache-clone.log'),
                source_dates_preserved=preserved_dates, parent_preserved=False)
            chosen = parent['toolchain']['selection']
            tools, identities = selection.tools_and_sysroot(sysroot, recipe,
                rust_root=chosen['rust_root'], host_cc=chosen['host_cc'])
            peer.require(identities == parent['toolchain'], 'Peer compiler or SDK selection changed')
            report['toolchain'] = identities
            env = static.cargo_environment(base.cargo_environment(tools, identities, sysroot, output, cache, control))
            flags = env['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')
            current_native = 'native=' + str(output / 'native')
            peer.require(flags.count(current_native) == 1, 'Ambiguous native cache search')
            flags[flags.index(current_native)] = 'native=' + str(parent_output / 'native')
            env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
            report['native_archive_directory'] = str(parent_output)
            report['native_archive_search'] = static.verify_native_archive_search(
                parent_output, sysroot, recipe, identities, parent['native_archive_search'], env)
            env['SOURCE_DATE_EPOCH'] = static.dependencies.pinned_git(
                Path(parent['source_cache']) / parent['component']['directory'], 'show', '-s', '--format=%ct')
            env['CYXIA_COSMIC_UPSTREAM_COMMIT'] = parent['component']['commit']
            common = ['--manifest-path', str(source / 'Cargo.toml'), '--locked', '--offline',
                      '--no-default-features', '--features', ','.join(static.FEATURES)]
            bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
            budget = dict(budget_root=output, scratch_roots=(control,),
                          growth_roots=((cache, base.directory_bytes(cache)),))
            metadata_command = [str(tools['cargo']), 'metadata', '--format-version', '1',
                                '--filter-platform', static.TARGET, *common]
            report['metadata_command'] = metadata_command
            base.run_bounded(metadata_command, control, env, output / 'metadata.json', *bounds,
                             stderr_log=output / 'metadata.stderr.log', **budget)
            metadata = base.load_json(output / 'metadata.json')
            report['cargo_dependencies'] = static.verify_metadata(metadata, source, cache, recipe, old_policy)
            report['package_id'] = parent_builder.component_builder.local_package(metadata, source, recipe)
            peer.require(static.verify_resolution(metadata, old_policy) == parent['resolved_graph_sha256'],
                         'Peer build changed the complete resolved graph')
            command = [str(tools['cargo']), 'build', '--release', '--target', static.TARGET, '--jobs', '2',
                       '--package', report['package_id'], '--bin', recipe['binary'], *common]
            report['command'] = command
            base.run_bounded(command, control, env, output / 'cargo.log', *bounds, **budget)
            peer.validate_source(source, parent['source_tree'])
            peer.validate_source(output / 'source', parent['source_tree'])
            peer.require(base.tree_identity(sysroot / 'sysroot') == parent['sysroot_before'], 'Peer SDK changed')
            peer.require(base.tree_identity(old_target) == old_cache, 'Original target cache changed')
            report['cache_reuse']['parent_preserved'] = True
            peer.require('Compiling cosmic-notifications v' in (output / 'cargo.log').read_text(),
                         'The modified actual root package was not recompiled')
            parent_builder.tool_inputs_preserved(identities)
            static.verify_native_archive_search(parent_output, sysroot, recipe, identities,
                                                 report['native_archive_search'], env)
            linked = output / 'target' / static.TARGET / 'release' / recipe['binary']
            inspection = image.inspect_full_os_elf(linked, profile)
            report['image_admission'] = parent_builder.publish_candidate(linked, output, recipe, profile, inspection)
            report['linked_binary'] = dict(path=str(linked), bytes=linked.stat().st_size, sha256=base.digest(linked))
            peer.require(static.producer_sources(__file__) == producers
                         and base.digest(parent_output / 'build-report.json') == parent_sha,
                         'Peer producers/parent changed during build')
            report['evidence_files'] = {name: base.digest(output / name)
                for name in ('cargo.log', 'metadata.json', 'metadata.stderr.log')}
            report['status'] = 'cross-built'
    except BaseException as error:
        report.update(status='failed', error=str(error))
        parent_builder.discard_publication(output, recipe, report)
        raise
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        report = build(args.parent_build, args.output)
    print(json.dumps({key: report[key] for key in ('status', 'elapsed_seconds', 'linked_binary')}, indent=2))


if __name__ == '__main__':
    main()
