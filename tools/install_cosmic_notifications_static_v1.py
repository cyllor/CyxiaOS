#!/usr/bin/env python3
"""Atomically install a verified static-v1 notification build, without running it.

This consumer is separate from both frozen notification producers and their old
installer. Every validation replays canonical source, vendor archive, metadata,
feature graph, SDK, compiler and FullOsV3 ELF checks. No compiler or guest runs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

if __package__:
    from . import cosmic_notifications_static_v1 as static
    from . import cosmic_notifications_elf as image
    from . import install_cosmic_notifications as legacy
else:
    import cosmic_notifications_static_v1 as static
    import cosmic_notifications_elf as image
    import install_cosmic_notifications as legacy

ROOT = static.ROOT
PROGRAM = 'cosmic-notifications.elf'
RECEIPT = 'cosmic-notifications-static-v1-origin.json'
KIND = 'cosmic-notifications-static-v1'
ORIGIN_KEYS = legacy.ORIGIN_KEYS
RECEIPT_KEYS = {'schema_version', 'kind', 'status', 'origin', 'inputs', 'producers', 'artifacts',
                'guest_execution', 'notifications_verified', 'cosmic_session_verified'}
LOGS = ('metadata.json', 'metadata.stderr.log', 'cargo.log')
MAX_BYTES = 64 * 1024**2
DOC = 'rootfs/usr/share/doc/cosmic-notifications/'
require, BuildError = legacy.require, legacy.BuildError


def license_inputs(exported, policy):
    selected = [('LICENSE.md', DOC + 'LICENSE')]
    for package in policy['registry_inputs']:
        for license_file in package['license_files']:
            source = str(Path(package['destination']) / legacy.common.relative_path(license_file))
            selected.append((source, DOC + package['name'] + '-' + Path(license_file).name))
    result = []
    for source, destination in selected:
        data = static.read_regular(exported / source)
        result.append({'source': source, 'path': destination, **legacy.common.identity(data)})
    require(len({item['path'] for item in result}) == len(result), 'Duplicate static license destination')
    return result


def validate_build(origin):
    """Validate all inputs using the six explicit, canonical origin paths."""
    try:
        require(type(origin) is dict and set(origin) == ORIGIN_KEYS, 'Malformed static notification origin')
        paths = {name: legacy.selected(origin[name], directory=name not in ('recipe', 'resource_profile'))
                 for name in ORIGIN_KEYS}
        output, recipe_path, resource = paths['build_output'], paths['recipe'], paths['resource_profile']
        policy_path = recipe_path.parent / 'source-policy.json'
        policy = static.load_policy(policy_path)
        report = legacy.json_file(output / 'build-report.json')
        expected = {'schema_version': 1, 'kind': KIND, 'status': 'cross-built', 'operation': 'build',
                    'target': static.TARGET, 'architecture': 'x86_64', 'cargo_offline': True,
                    'build_script_network_sandbox': False, 'cargo_resolution_verified': True,
                    'native_archive_search_preserved': True,
                    'source_preserved': True, 'producer_sources_preserved': True,
                    'link_completed': True, 'target_linked': True, 'guest_execution': 'not performed',
                    'cosmic_session_ready': False, 'notifications_verified': False,
                    'cosmic_session_verified': False, 'policy_sha256': static.POLICY_SHA256,
                    'resource_source_sha256': static.RESOURCE_SHA256}
        require(all(type(report.get(key)) is type(value) and report[key] == value for key, value in expected.items())
                and not ({'error', 'producer_check_error', 'native_archive_check_error'} & set(report)),
                'Not a preserved static-v1 notification cross-build')
        for field, key in (('recipe_path', 'recipe'), ('resource_path', 'resource_profile'),
                           ('source_cache', 'source_cache'), ('cache', 'cache'), ('sysroot', 'sysroot')):
            require(report[field] == str(paths[key]), 'Static build origin selection changed: ' + field)
        source = next(item for item in static.build.ports.load_manifest()['components']
                      if item['name'] == 'cosmic-notifications')
        require(report['component'] == source, 'Static notification source selection changed')
        recipe = static.validate_recipe(legacy.json_file(recipe_path), source, policy)
        require(report['recipe'] == recipe, 'Static notification recipe changed')
        hashes = {}
        legacy.bind(recipe_path, report['recipe_sha256'], hashes)
        producers = static.producer_sources(ROOT / 'tools/build_cosmic_notifications_static_v1.py')
        require(report['producer_sources'] == report['producer_sources_after'] == producers,
                'Static notification build producers changed')
        for name, digest in producers.items():
            legacy.bind(ROOT / legacy.common.relative_path(name), digest, hashes)
        supports = static.support_sources(policy_path, policy)
        for name, digest in supports.items():
            legacy.bind(Path(name), digest, hashes)
        exported = legacy.selected(output / 'source', directory=True)
        original = legacy.selected(paths['source_cache'] / source['directory'], directory=True)
        cache = static.build.validate_cache(paths['cache'])
        static.validate_export(original, cache, exported, report['static_source'], policy_path)
        require(report['source_tree'] == report['static_source']['source_tree'], 'Static source identity differs')
        for package in report['static_source']['registry_inputs']:
            legacy.bind(Path(package['archive']), package['archive_sha256'], hashes)
        jobs = legacy.validate_metadata(report, recipe, output, exported, cache)
        metadata = legacy.json_file(output / 'metadata.json')
        graph_sha = static.verify_resolution(metadata, policy)
        require(report['resolved_graph_sha256'] == graph_sha, 'Static resolved graph identity changed')
        command = report['command']
        old_source = Path(command[command.index('--manifest-path') + 1]).parent
        for package in policy['registry_inputs']:
            local = [p for p in metadata['packages'] if p['name'] == package['name']]
            require(len(local) == 1 and local[0].get('source') is None
                    and Path(local[0]['manifest_path']) == old_source / package['destination'] / 'Cargo.toml',
                    'Static vendor manifest selection changed')
        profile = static.select_profile(resource, jobs)
        require(report['resource_profile'] == profile
                and report['profile_sha256'] == hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest(),
                'Static notification profile identity changed')
        libraries = legacy.validate_toolchain(report, recipe, output, paths['sysroot'], hashes)
        native_archives = static.verify_native_archive_search(
            output, paths['sysroot'], recipe, report['toolchain'], report['native_archive_search'])
        static.verify_native_archive_search(output, paths['sysroot'], recipe, report['toolchain'],
                                            report['native_archive_search_after'])
        for name, record in native_archives['files'].items():
            legacy.bind(output / 'native' / name, record['sha256'], hashes)
        sdk_origin = static.sdk_origin(paths['sysroot'], recipe)
        require(report['native_sdk_origin'] == sdk_origin, 'Static SDK assembly identity differs')
        legacy.bind(Path(sdk_origin['path']), sdk_origin['sha256'], hashes)
        binary = legacy.selected(output / PROGRAM)
        linked = legacy.selected(output / 'target' / static.TARGET / 'release/cosmic-notifications')
        require(binary.stat().st_size <= MAX_BYTES and linked.stat().st_size <= MAX_BYTES,
                'Static notification ELF exceeds byte budget')
        inspection = image.inspect_full_os_elf(binary, profile)
        executable = inspection['executable']
        require(report['image_admission'] == inspection and report['executable'] == executable
                and type(report['image_load_pages']) is int
                and report['image_load_pages'] == inspection['image_load_pages']
                and report['linked_binary'] == {'path': str(linked), 'bytes': linked.stat().st_size,
                                               'sha256': static.build.digest(linked)}
                and type(report['linked_binary']['bytes']) is int
                and executable['sha256'] == report['linked_binary']['sha256'],
                'Static notification ELF differs from the real link and admission')
        for path in (binary, linked):
            legacy.bind(path, executable['sha256'], hashes)
        for name, digest in inspection['loader_contract'].items():
            legacy.bind(ROOT / legacy.common.relative_path(name), digest, hashes)
        require(set(report['evidence_files']) == set(LOGS), 'Incomplete static build evidence inventory')
        for name in LOGS:
            data = static.read_regular(output / name)
            require(legacy.common.identity(data) == report['evidence_files'][name],
                    'Static build log or metadata changed: ' + name)
            hashes[str(output / name)] = static.sha(data)
        require(report['metadata_sha256'] == hashes[str(output / 'metadata.json')],
                'Static metadata differs from the pre-build observation')
        for path in (resource, output / 'build-report.json'):
            hashes[str(path)] = static.sha(legacy.common.read_regular(path, MAX_BYTES))
        return {'inputhashes': dict(sorted(hashes.items())), 'executable': executable,
                'image_admission': inspection, 'resource_profile': profile,
                'source_tree_sha256': report['source_tree']['sha256'],
                'static_source_sha256': static.canonical_hash(report['static_source']),
                'cargo_dependencies_sha256': static.canonical_hash(report['cargo_dependencies']),
                'native_archive_search': native_archives,
                'resolved_graph_sha256': graph_sha, 'dependency_count': len(report['cargo_dependencies']),
                'rust_libraries_at_installation': libraries, 'licenses': license_inputs(exported, policy)}
    except (KeyError, TypeError, IndexError, AttributeError, StopIteration) as error:
        raise BuildError('Malformed static notification build evidence') from error


def validate_build_directory(output):
    """Read-only consumer API; report-selected paths still undergo full validation."""
    output = legacy.selected(output, directory=True)
    report = legacy.json_file(output / 'build-report.json')
    try:
        origin = {'build_output': str(output), 'recipe': report['recipe_path'],
                  'resource_profile': report['resource_path'], 'sysroot': report['sysroot'],
                  'source_cache': report['source_cache'], 'cache': report['cache']}
    except KeyError as error:
        raise BuildError('Static build report lacks explicit origin paths') from error
    return {'origin': origin, 'inputs': validate_build(origin)}


def artifacts(inputs):
    result = [{'path': PROGRAM, 'guest_path': '/bin/cosmic-notifications',
               **{key: inputs['executable'][key] for key in ('bytes', 'sha256')}}]
    result.extend({'path': item['path'], 'guest_path': '/' + item['path'].removeprefix('rootfs/'),
                   **{key: item[key] for key in ('bytes', 'sha256')}} for item in inputs['licenses'])
    return result


def validate_inputs(prefix):
    prefix = legacy.selected(prefix, directory=True)
    receipt = legacy.json_file(prefix / RECEIPT)
    require(set(receipt) == RECEIPT_KEYS and type(receipt['schema_version']) is int
            and receipt['schema_version'] == 1 and receipt['kind'] == KIND
            and receipt['status'] == 'INSTALLED_NOT_RUN' and receipt['guest_execution'] == 'not performed'
            and receipt['notifications_verified'] is False and receipt['cosmic_session_verified'] is False,
            'Invalid static notification installation receipt')
    require(receipt['producers'] == static.producer_sources(__file__), 'Static notification installer changed')
    inputs = validate_build(receipt['origin'])
    require(receipt['inputs'] == inputs and receipt['artifacts'] == artifacts(inputs),
            'Static notification installation inputs changed')
    for record in receipt['artifacts']:
        path = prefix / legacy.common.relative_path(record['path'])
        data = legacy.common.read_regular(path, MAX_BYTES)
        require(legacy.common.identity(data) == {key: record[key] for key in ('bytes', 'sha256')},
                'Installed static notification file changed')
        require(path.stat().st_mode & 0o777 == (0o755 if record['path'] == PROGRAM else 0o644),
                'Installed static notification file mode changed')
    require(image.inspect_full_os_elf(prefix / PROGRAM, inputs['resource_profile']) == inputs['image_admission'],
            'Installed static notification image admission changed')
    return {'status': 'VALIDATED_NOT_RUN', 'receipt': receipt, 'guest_execution': 'not performed',
            'notifications_verified': False, 'cosmic_session_verified': False}


def install(build_output, output):
    validated = validate_build_directory(build_output)
    origin, inputs = validated['origin'], validated['inputs']
    output = legacy.common.plain_path(output)
    require(not output.exists(), 'Preserving existing static notification installation')
    for name in ORIGIN_KEYS:
        path = legacy.selected(origin[name], directory=name not in ('recipe', 'resource_profile'))
        require(not output.is_relative_to(path) and not path.is_relative_to(output),
                'Static notification output overlaps an input')
    receipt = {'schema_version': 1, 'kind': KIND, 'status': 'INSTALLED_NOT_RUN',
               'origin': origin, 'inputs': inputs, 'producers': static.producer_sources(__file__),
               'artifacts': artifacts(inputs), 'guest_execution': 'not performed',
               'notifications_verified': False, 'cosmic_session_verified': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        sources = [Path(origin['build_output']) / PROGRAM]
        sources.extend(Path(origin['build_output']) / 'source' / item['source'] for item in inputs['licenses'])
        for record, source in zip(receipt['artifacts'], sources):
            data = legacy.common.read_regular(source, MAX_BYTES)
            require(legacy.common.identity(data) == {key: record[key] for key in ('bytes', 'sha256')},
                    'Static notification input changed during installation')
            target = pending / record['path']; target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            target.chmod(0o755 if record['path'] == PROGRAM else 0o644)
        with (pending / RECEIPT).open('x') as stream:
            json.dump(receipt, stream, indent=2); stream.write('\n')
            stream.flush(); os.fsync(stream.fileno())
        validate_inputs(pending)
        require(not output.exists() and not output.is_symlink(), 'Preserving concurrently created static installation')
        pending.rename(output)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = install(args.build, args.output)
        print(json.dumps({key: receipt[key] for key in ('status', 'artifacts', 'notifications_verified',
                                                        'cosmic_session_verified')}, indent=2))
        return 0
    except (BuildError, ValueError, OSError) as error:
        print('Static notification installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
