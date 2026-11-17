"""Read-only admission of a preserved genuine native session Linux v1 build.

This consumer never runs Cargo, compilers, version probes or target code. A
successful return binds the bytes available now to a complete build receipt;
guest execution and full-session readiness require separate runtime evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re

try:
    from . import build_cosmic_session_linux_v1 as producer
    from . import install_cosmic_notifications as tools_contract
except ImportError:
    import build_cosmic_session_linux_v1 as producer
    import install_cosmic_notifications as tools_contract

contract, base = producer.contract, producer.base
require, BuildError = contract.require, base.CosmicBuildError
ROOT = contract.ROOT
LOGS = ('metadata.json', 'metadata.stderr.log', 'cargo.log')


def path(value, *, directory=False, exists=True):
    require(isinstance(value, (str, Path)), 'Invalid session input path')
    selected = Path(value)
    require(selected.is_absolute() and '..' not in selected.parts, 'Session input path must be absolute')
    selected = base.no_symlink_path(selected)
    if exists:
        require(selected.is_dir() if directory else selected.is_file(), 'Missing session input: ' + str(selected))
    return selected


def read_json(selected):
    raw = contract.elf._read_regular(path(selected), 64 * 1024**2)
    result = json.loads(raw, object_pairs_hook=base.ports.unique_object)
    require(isinstance(result, dict), 'Session receipt/metadata must be an object')
    return result, hashlib.sha256(raw).hexdigest()


def bind(selected, expected, hashes):
    selected = path(selected)
    require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected)
            and base.digest(selected) == expected, 'Session input identity changed: ' + str(selected))
    hashes[str(selected)] = expected


def metadata_identity(report, recipe, policy, output, retained, cache, old_source):
    metadata, _ = read_json(output / 'metadata.json')
    require(metadata.get('workspace_root') == str(old_source)
            and metadata.get('target_directory') == str(output / 'target'),
            'Session metadata workspace or target directory changed')
    package_id = contract.resolution(metadata, old_source, recipe, policy)
    require(package_id == report['package_id'], 'Selected session package ID changed')

    def remap(name, spec):
        selected = path(name, exists=False)
        if spec is None:
            require(selected.is_relative_to(old_source), 'Local dependency escapes original session export')
            return str(path(retained / selected.relative_to(old_source)))
        contract.common.source_key(spec)
        allowed = cache / ('registry/src' if spec.startswith('registry+') else 'git/checkouts')
        require(selected.is_relative_to(allowed), 'Session dependency escapes the private cache')
        return str(path(selected))

    records = copy.deepcopy(report['cargo_dependencies'])
    for package in metadata['packages']:
        package['manifest_path'] = remap(package['manifest_path'], package.get('source'))
    for record in records:
        record['manifest'] = remap(record['manifest'], record['source'])
    actual = contract.metadata_identity(metadata, retained, cache, recipe, policy)
    require(actual == records, 'Session dependency source identities changed')
    return {'records_sha256': contract.canonical(actual), 'package_count': len(actual),
            'selected_package_id': package_id, 'features': contract.FEATURES,
            'launch_pad_features': policy['launch_pad_features']}


def validate_build(output):
    """Revalidate a completed raw link and its matching FullOs publication."""
    try:
        output = path(output, directory=True)
        receipt = output / 'build-report.json'
        report, receipt_sha256 = read_json(receipt)
        required = {'schema_version': 1, 'kind': contract.KIND, 'status': 'cross-built', 'operation': 'build',
                    'target': contract.TARGET, 'architecture': 'x86_64', 'jobs': 1,
                    'link_completed': True, 'target_linked': True, 'source_preserved': True,
                    'inputs_preserved': True, 'producer_sources_preserved': True, 'cargo_offline': True,
                    'build_script_network_sandbox': False, 'guest_execution': 'not performed',
                    'cosmic_session_ready': False}
        require(all(type(report.get(key)) is type(value) and report[key] == value for key, value in required.items())
                and report.get('postcheck_errors') == [] and 'error' not in report,
                'Not a preserved successful native session build')
        require(path(report['output'], directory=True) == output, 'Detached session receipt is unsupported')
        hashes = {str(receipt): receipt_sha256}
        recipe_path, profile_path = path(report['recipe_path']), path(report['profile_file'])
        policy, recipe, source, profile = contract.contract(recipe_path, profile_path, report['jobs'])
        require(report['component'] == source and report['recipe'] == recipe
                and report['resource_profile'] == profile, 'Session source, recipe or resource profile changed')
        bind(recipe_path, report['recipe_sha256'], hashes)
        bind(profile_path, report['profile_file_sha256'], hashes)
        require(type(report['operation_timeout_seconds']) is int
                and report['operation_timeout_seconds'] == profile['timeout_seconds']
                and report['timeout_scope'] == contract.TIMEOUT_SCOPE
                and type(report['elapsed_seconds']) in (int, float)
                and 0 <= report['elapsed_seconds'] < float('inf'), 'Invalid shared session deadline evidence')
        producers = producer.producer_sources()
        require(report['producer_sources'] == report['producer_sources_after'] == producers,
                'Current session transitive producer closure changed')
        for name, checksum in producers.items():
            bind(ROOT / base.dependencies.relative_path(name), checksum, hashes)
        bind(producer.BUILDER, report['builder_sha256'], hashes)

        source_cache = path(report['source_cache'], directory=True)
        retained = path(output / 'source', directory=True)
        tree = contract.verify_export(source_cache, recipe_path, policy, retained, report['source_inputs'])
        require(tree == report['source_tree'], 'Retained session source receipt changed')
        for name, checksum in report['source_inputs']['bindings'].items():
            bind(name, checksum, hashes)
        require(report['patches'] == [{'path': str(recipe_path.parent / entry['path']), 'sha256': entry['sha256']}
                                      for entry in recipe['patches']], 'Session patch receipt changed')
        old_source = path(report['original_export_root'], exists=False)
        require(old_source.name == 'source' and not old_source.is_relative_to(output)
                and not output.is_relative_to(old_source), 'Invalid original session export root')
        cache = base.validate_cache(path(report['cargo_cache'], directory=True))
        dependencies = metadata_identity(report, recipe, policy, output, retained, cache, old_source)
        metadata_command, build_command = contract.commands(report['toolchain']['tools']['cargo']['path'],
                                      old_source, recipe, report['jobs'], report['package_id'])
        require(report['metadata_command'] == metadata_command and report['command'] == build_command
                and 'fetch_command' not in report, 'Session commands are not the exact locked offline build')
        require(set(report['retained_logs']) == set(LOGS), 'Incomplete or unexpected session log closure')
        require(report['metadata_sha256'] == report['retained_logs']['metadata.json'],
                'Session metadata differs from the resolved build input')
        for name in LOGS:
            bind(output / name, report['retained_logs'][name], hashes)

        sysroot = path(report['sysroot'], directory=True)
        contract.check_toolchain(report['toolchain'])
        # Pure file/ISA inspection only: this helper performs no version probe.
        tools_contract.validate_toolchain(report, recipe, output, sysroot, hashes)
        base.ports.architecture(Path(report['toolchain']['std']['path']), rust_archive=True,
                                target=tools_contract.TARGET)
        base.ports.architecture(Path(report['toolchain']['unwind']['path']), target=tools_contract.TARGET)
        libraries = contract.rust_libraries(report['toolchain'])
        require(libraries == report['rust_libraries_before'], 'Official Rust target archive closure changed')
        library_root = Path(report['toolchain']['std']['path']).parent
        for name, item in libraries.items():
            bind(library_root / name, item['sha256'], hashes)
        generated = contract.generated_inputs(output, report['toolchain'])
        require(generated == report['generated_build_inputs'], 'Generated session linker inputs or wrappers changed')

        linked = path(output / 'target' / recipe['target'] / 'release/cosmic-session')
        binary = path(output / 'cosmic-session.elf')
        raw = contract.elf.inspect_full_os_elf(linked, profile)
        published = contract.elf.inspect_full_os_elf(binary, profile)
        require(raw == report['full_os_inspection'], 'Raw linked session FullOs inspection changed')
        linked_record = {'path': str(linked), 'bytes': linked.stat().st_size, 'sha256': raw['executable']['sha256']}
        require(type(report['linked_binary']['bytes']) is int and report['linked_binary'] == linked_record,
                'Raw linked session identity changed')
        require(report['executable'] == {**published['executable'], 'path': str(binary)}
                and published['executable']['sha256'] == linked_record['sha256']
                and type(report['image_load_pages']) is int
                and type(report['required_pages']) is int
                and report['image_load_pages'] == published['image_load_pages']
                and report['required_pages'] == published['required_pages'],
                'Published session differs from the original admitted link')
        for selected in (linked, binary):
            bind(selected, linked_record['sha256'], hashes)
        for name, checksum in published['loader_contract'].items():
            bind(contract.elf.ROOT / name, checksum, hashes)
        require(base.digest(receipt) == receipt_sha256 and producer.producer_sources() == producers,
                'Session receipt or producer changed during validation')
        identity = {'schema_version': 1, 'receipt_sha256': receipt_sha256, 'inputs': dict(sorted(hashes.items())),
                    'source_inputs_sha256': contract.canonical(report['source_inputs']),
                    'retained_source_sha256': tree['sha256'], 'dependencies': dependencies,
                    'toolchain_sha256': contract.canonical(report['toolchain']),
                    'official_rust_libraries': libraries, 'generated_build_inputs': generated,
                    'sdk_sha256': report['sysroot_before']['sha256'], 'full_os_inspection': published}
        return {'schema_version': 1, 'status': 'SESSION_BUILD_REVALIDATED_NOT_RUN', 'output': str(output),
                'receipt_sha256': receipt_sha256, 'identity': identity, 'identity_sha256': contract.canonical(identity),
                'executable': {**published['executable'], 'path': str(binary), 'file': str(binary)},
                'image_load_pages': published['image_load_pages'], 'required_pages': published['required_pages'],
                'full_os_inspection': published, 'guest_execution': False, 'cosmic_session_ready': False}
    except BuildError:
        raise
    except (tools_contract.BuildError, OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        raise BuildError('Invalid retained native session build: ' + str(error)) from error
