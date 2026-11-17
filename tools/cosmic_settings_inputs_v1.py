"""Read-only, complete validation of the retained genuine settings build.

No version probe, Cargo, compiler or target process is invoked. Local metadata
paths are relocated only from the deleted producer stage into retained source.
"""
from __future__ import annotations

import copy
import math
from pathlib import Path

if __package__:
    from . import build_cosmic_settings_linux_v1 as producer
else:
    import build_cosmic_settings_linux_v1 as producer

contract = producer.contract
base, require, BuildError = contract.base, contract.require, contract.BuildError
PROGRAM = producer.PROGRAM


def selected(value, *, directory=False, exists=True):
    require(isinstance(value, (str, Path)), 'Invalid retained settings path')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts, 'Noncanonical retained settings path')
    path = base.no_symlink_path(path)
    if exists:
        require(path.is_dir() if directory else path.is_file(), 'Missing retained settings input: ' + str(path))
    return path


def bind(path, expected, hashes):
    path = selected(path)
    require(base.digest(path) == expected, 'Retained settings input changed: ' + str(path))
    hashes[str(path)] = expected


def metadata_identity(report, output, retained, cache, recipe, policy):
    metadata = contract.read_json(output / 'metadata.json')
    original = selected(report['original_export_root'], exists=False)
    require(metadata.get('workspace_root') == str(original)
            and metadata.get('target_directory') == str(output / 'target'),
            'Settings metadata workspace/target changed')

    def relocate(name, source):
        path = selected(name, exists=False)
        if source is None:
            require(path.is_relative_to(original), 'Local settings dependency escapes the recorded stage')
            return str(selected(retained / path.relative_to(original)))
        contract.common.source_key(source)
        allowed = cache / ('registry/src' if source.startswith('registry+') else 'git/checkouts')
        require(path.is_relative_to(allowed), 'Settings dependency escapes its pinned cache')
        return str(selected(path))

    expected = copy.deepcopy(report['cargo_dependencies'])
    for package in metadata['packages']:
        package['manifest_path'] = relocate(package['manifest_path'], package.get('source'))
        if package.get('source') is None:
            for target in package['targets']:
                if 'src_path' in target:
                    target['src_path'] = relocate(target['src_path'], None)
    for row in expected['packages']:
        row['manifest'] = relocate(row['manifest'], row['source'])
    metadata['workspace_root'] = str(retained)
    actual = contract.metadata_identity(metadata, retained, cache, recipe, policy)
    require(actual == expected and actual['resolution']['package_id'] == report['package_id'],
            'Retained settings dependency sources/features changed')
    return {'resolution': actual['resolution'], 'records_sha256': contract.canonical(actual)}


def license_inputs(retained):
    rows = []
    for source, name in [('LICENSE', 'LICENSE'),
                         ('native-deps/cosmic-comp-config/LICENSE', 'cosmic-comp-config-LICENSE'),
                         ('native-deps/wayland-sys/LICENSE.txt', 'wayland-sys-LICENSE')]:
        data = contract.read_regular(retained / source)
        rows.append({'source_relative': source,
                     'path': 'rootfs/usr/share/doc/cosmic-settings-daemon/' + name,
                     'bytes': len(data), 'sha256': contract.files.sha(data)})
    return rows


def validate_build(output):
    """Return a stable proof for installation/capture, without running tools."""
    try:
        output = selected(output, directory=True)
        report_path = output / 'build-report.json'
        report = contract.read_json(report_path)
        required = {'schema_version': 1, 'kind': contract.KIND, 'status': 'cross-built', 'operation': 'build',
            'target': contract.TARGET, 'architecture': 'x86_64', 'link_completed': True,
            'target_linked': True, 'cargo_resolution_verified': True, 'source_preserved': True,
            'inputs_preserved': True, 'producer_sources_preserved': True, 'cargo_offline': True,
            'build_script_network_sandbox': False, 'guest_execution': 'not performed',
            'settings_verified': False, 'cosmic_session_ready': False, 'cosmic_session_verified': False,
            'policy_sha256': contract.POLICY_SHA256, 'timeout_scope': contract.TIMEOUT_SCOPE}
        require(all(type(report.get(key)) is type(value) and report[key] == value for key, value in required.items())
                and not {'error', 'producer_check_error', 'native_archive_check_error'} & report.keys()
                and report.get('postcheck_errors') == [], 'Not a preserved native settings cross-build')
        require(report['output'] == str(output) and type(report['jobs']) is int, 'Settings output/jobs changed')
        recipe_path = selected(report['recipe_path'])
        profile_path = selected(report['profile_path'])
        source_cache, cache, sysroot = [selected(report[name], directory=True)
                                      for name in ('source_cache', 'cargo_cache', 'sysroot')]
        base.validate_cache(cache)
        policy, recipe, source, profile = contract.contract(recipe_path, profile_path, report['jobs'])
        require(report['recipe'] == recipe and report['component'] == source
                and report['resource_profile'] == profile and report['boundary'] == policy['boundary']
                and report['operation_timeout_seconds'] == profile['timeout_seconds'],
                'Settings build contract differs from the fixed inputs')
        elapsed = report['elapsed_seconds']
        require(type(elapsed) in (int, float) and math.isfinite(elapsed)
                and 0 <= elapsed <= profile['timeout_seconds'], 'Settings operation exceeded its deadline')
        hashes = {str(report_path): base.digest(report_path)}
        bind(recipe_path, report['recipe_sha256'], hashes)
        bind(profile_path, report['profile_sha256'], hashes)
        producers = producer.producer_sources()
        require(report['producer_sources'] == report['producer_sources_after'] == producers
                and report['builder_sha256'] == base.digest(producer.BUILDER), 'Settings producer identity changed')
        for name, checksum in producers.items():
            bind(base.ROOT / base.dependencies.relative_path(name), checksum, hashes)
        retained = selected(output / 'source', directory=True)
        source_tree = contract.verify_export(source_cache, cache, recipe_path, policy, retained, report['source_inputs'])
        require(source_tree == report['source_tree'], 'Retained settings source receipt changed')
        for name, checksum in report['source_inputs']['bindings'].items():
            bind(Path(name), checksum, hashes)
        patches = [{'path': str(recipe_path.parent / row['path']), 'sha256': row['sha256']}
                   for row in recipe['patches']]
        require(report['patches'] == patches, 'Settings patch application receipt changed')
        bind(retained / 'Cargo.lock', recipe['effective_lock_sha256'], hashes)
        sdk_origin = contract.files.sdk_origin(sysroot, recipe)
        require(sdk_origin == report['native_sdk_origin'], 'Settings SDK assembly receipt changed')
        bind(Path(sdk_origin['path']), sdk_origin['sha256'], hashes)
        contract.check_toolchain(report['toolchain'])
        rust_hashes = contract.legacy.validate_toolchain(report, recipe, output, sysroot, hashes)
        rust = contract.rust_libraries(report['toolchain'])
        require(rust == report['rust_libraries_before'] == report['rust_libraries_after']
                and rust_hashes == {name: row['sha256'] for name, row in rust.items()},
                'Official settings target runtime archives changed')
        generated = contract.generated_inputs(output, sysroot, recipe, report['toolchain'])
        require(generated == report['generated_build_inputs'] == report['generated_build_inputs_after']
                and generated['native_search'] == report['native_archive_search'],
                'Generated settings wrappers or copied native archives changed')
        require(set(report['retained_logs']) == set(contract.LOGS), 'Incomplete settings build evidence inventory')
        for name in contract.LOGS:
            data = contract.read_regular(output / name, 64 * 1024**2)
            identity = {'bytes': len(data), 'sha256': contract.files.sha(data)}
            require(identity == report['retained_logs'][name], 'Settings evidence identity changed: ' + name)
            hashes[str(output / name)] = identity['sha256']
        require(report['metadata_sha256'] == hashes[str(output / 'metadata.json')], 'Settings metadata receipt changed')
        metadata = metadata_identity(report, output, retained, cache, recipe, policy)
        cargo = report['toolchain']['tools']['cargo']['path']
        commands = contract.commands(cargo, Path(report['original_export_root']), recipe, report['jobs'], report['package_id'])
        require(report['metadata_command'] == commands[0] and report['command'] == commands[1]
                and 'fetch_command' not in report, 'Settings commands differ from the exact offline build')
        linked = selected(output / 'target' / contract.TARGET / 'release' / recipe['binary'])
        data = contract.read_regular(linked, profile['max_elf_bytes'])
        require(report['linked_binary'] == {'path': str(linked), 'bytes': len(data), 'sha256': contract.files.sha(data)},
                'Raw settings link output changed')
        raw_admission = contract.elf.inspect_full_os_elf(linked, profile)
        require(raw_admission == report['full_os_inspection'], 'Raw settings FullOsV3 admission changed')
        final = selected(output / PROGRAM)
        require(contract.read_regular(final, profile['max_elf_bytes']) == data, 'Published settings ELF differs from raw link')
        admission = contract.elf.inspect_full_os_elf(final, profile)
        require(admission == report['image_admission']
                and admission == {**raw_admission, 'executable': {**raw_admission['executable'], 'file': final.name}}
                and admission['executable'] == report['executable']
                and admission['image_load_pages'] == report['image_load_pages']
                and admission['required_pages'] == report['required_pages'], 'Published settings image admission changed')
        hashes[str(linked)] = hashes[str(final)] = contract.files.sha(data)
        licenses = license_inputs(retained)
        for row in licenses:
            bind(retained / row['source_relative'], row['sha256'], hashes)
        return {'status': 'VALIDATED_NOT_RUN', 'kind': contract.KIND, 'build_output': str(output),
                'program': str(final), 'executable': admission['executable'], 'image_admission': admission,
                'resource_profile': profile, 'source_tree_sha256': source_tree['sha256'],
                'metadata': metadata, 'generated_inputs': generated, 'rust_libraries': rust,
                'hashes': dict(sorted(hashes.items())), 'licenses': licenses, 'boundary': policy['boundary'],
                'input_directories': [str(output), str(source_cache), str(cache), str(sysroot),
                    str(selected(report['toolchain']['selection']['rust_root'], directory=True)),
                    str(recipe_path.parent), str(profile_path.parent)],
                'guest_execution': 'not performed', 'settings_verified': False,
                'cosmic_session_ready': False, 'cosmic_session_verified': False}
    except BuildError:
        raise
    except (contract.legacy.BuildError, OSError, ValueError, KeyError, TypeError, IndexError, StopIteration) as error:
        raise BuildError('Invalid retained settings build: ' + str(error)) from error
