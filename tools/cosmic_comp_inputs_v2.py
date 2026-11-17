"""Read-only consumer of a retained genuine compositor Linux build.

This does not fetch, invoke Cargo/compiler/version probes, publish a program or
claim a running desktop. Only a completed, unchanged build from the explicit
FullOs producer is accepted. Temporary local Cargo paths are relocated solely
to the producer's complete retained source; external dependencies stay put.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

# The frozen os_x86 module imported by the producer uses CLI sibling imports.
# Support this consumer as either tools.cosmic_comp_inputs_v2 or a tools script.
_TOOLS = str(Path(__file__).resolve().parent)
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

if __package__:
    from . import build_cosmic_comp_linux_v2 as producer
    from . import cosmic_notifications_elf as elf
    from . import install_cosmic_notifications as contracts
else:
    import build_cosmic_comp_linux_v2 as producer
    import cosmic_notifications_elf as elf
    import install_cosmic_notifications as contracts

base = producer.base
ROOT = producer.ROOT
BUILDER = Path(producer.__file__).resolve()
BuildError = base.CosmicBuildError
MAX_EVIDENCE_BYTES = 64 * 1024**2
LOGS = ('metadata.json', 'metadata.stderr.log', 'cargo.log')
require = producer.require


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def path(value, *, directory=False, exists=True):
    require(isinstance(value, (str, Path)), 'Invalid compositor input path')
    selected = Path(value)
    require(selected.is_absolute() and '..' not in selected.parts,
            'Compositor input path is not absolute and bounded')
    selected = base.no_symlink_path(selected)
    if exists:
        require(selected.is_dir() if directory else selected.is_file(),
                'Missing retained compositor input: ' + str(selected))
    return selected


def read_json(selected):
    raw = elf._read_regular(path(selected), MAX_EVIDENCE_BYTES)
    value = json.loads(raw, object_pairs_hook=base.ports.unique_object)
    require(isinstance(value, dict), 'Expected compositor JSON object')
    return value, hashlib.sha256(raw).hexdigest()


def bind(selected, expected, hashes):
    selected = path(selected)
    require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected)
            and base.digest(selected) == expected, 'Retained input identity changed: ' + str(selected))
    hashes[str(selected)] = expected


def source_identity(report, recipe, source, original, retained, hashes):
    """Derive every final file from canonical blobs and fixed patch postimages.

    Pinned manifests specify the full ordered before/after chain. Replaying
    their hashes needs no mutable checkout, patch execution or temporary export.
    Files absent from the patch chain must still equal their canonical bytes.
    """
    actual = producer.git_identity(original, producer.COMMIT)
    require(actual == report['canonical_source'], 'Canonical compositor source changed')
    require(base.ports.repository_url(producer.objects.pinned_git(original, 'remote', 'get-url', 'origin'))
            == base.ports.repository_url(source['repository']), 'Original compositor repository changed')
    bind(original / 'Cargo.lock', recipe['source_lock_sha256'], hashes)
    files, modes = {}, {}
    for name, record in actual['files'].items():
        relative = base.dependencies.relative_path(name)
        require(not ('.cargo' in relative.parts and relative.name in ('config', 'config.toml')),
                'Canonical source contains unreviewed Cargo configuration')
        modes[name] = record['mode']
        files[name] = ({'symlink': record['symlink']} if record['mode'] == '120000'
                       else {key: record[key] for key in ('bytes', 'sha256')})
    series_path = path(ROOT / producer.SERIES)
    bind(series_path, producer.SERIES_SHA256, hashes)
    series = producer.series.load_series(series_path)
    require(series['commit'] == source['commit'] == producer.COMMIT
            and base.ports.repository_url(series['repository']) == base.ports.repository_url(source['repository'])
            and series['source_lock_sha256'] == recipe['source_lock_sha256'],
            'Compositor series source contract changed')
    patches = []
    for entry in series['patches']:
        manifest_path = path(ROOT / base.dependencies.relative_path(entry['manifest']))
        patch_path = path(ROOT / base.dependencies.relative_path(entry['patch']))
        bind(manifest_path, entry['manifest_sha256'], hashes)
        manifest, _ = read_json(manifest_path)
        require(manifest.get('schema_version') == 1 and manifest['commit'] == source['commit']
                and base.ports.repository_url(manifest['repository']) == base.ports.repository_url(source['repository']),
                'Compositor patch source changed')
        bind(patch_path, manifest['patch_sha256'], hashes)
        before, after = manifest['before'], manifest['after']
        require(isinstance(before, dict) and before and isinstance(after, dict)
                and before.keys() == after.keys(), 'Malformed patch preimage/postimage closure')
        for name, checksum in before.items():
            base.dependencies.relative_path(name)
            require((name not in files) if checksum is None else
                    (isinstance(checksum, str) and re.fullmatch('[0-9a-f]{64}', checksum)
                     and files.get(name, {}).get('sha256') == checksum),
                    'Canonical patch preimage chain changed: ' + name)
        for name, checksum in after.items():
            if checksum is None:
                files.pop(name, None)
                modes.pop(name, None)
            else:
                require(isinstance(checksum, str) and re.fullmatch('[0-9a-f]{64}', checksum)
                        and modes.get(name, '100644') in ('100644', '100755'),
                        'Unreviewed patch postimage kind: ' + name)
                files[name] = {'sha256': checksum}
                modes.setdefault(name, '100644')
        patches.append({'patch': entry['patch'], 'patch_sha256': manifest['patch_sha256'],
                        'manifest': entry['manifest'], 'manifest_sha256': entry['manifest_sha256'],
                        'changed_paths': sorted(name for name in before if before[name] != after[name])})
    require(report['patches'] == patches and report['series_sha256'] == producer.SERIES_SHA256,
            'Ordered compositor patch receipt changed')
    observed = base.tree_identity(retained)
    require(set(observed['files']) == set(files), 'Retained source has missing or unbound files')
    for name, expected in files.items():
        selected = retained / base.dependencies.relative_path(name)
        actual_file = observed['files'][name]
        require(all(actual_file.get(key) == value for key, value in expected.items()),
                'Retained source differs from canonical patch result: ' + name)
        if 'symlink' not in expected:
            info = selected.lstat()
            require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111) == (modes[name] == '100755'),
                    'Retained source mode differs from canonical export: ' + name)
    require(observed == report['source_tree'], 'Retained source receipt changed')
    bind(retained / 'Cargo.lock', recipe['effective_lock_sha256'], hashes)
    return {'canonical_sha256': actual['sha256'], 'retained_sha256': observed['sha256'],
            'file_count': len(files), 'patches': patches}


def metadata_identity(report, recipe, output, retained, cache, old_source):
    """Recheck real dependency trees after the temporary export was removed."""
    metadata, _ = read_json(output / 'metadata.json')
    preserved = producer.resolution(metadata, old_source)
    require(report.get('preserved_resolution') == preserved, 'Compositor resolution receipt changed')
    require(metadata.get('workspace_root') == str(old_source)
            and metadata.get('target_directory') == str(output / 'target'),
            'Cargo metadata workspace/target differs from the recorded build')
    packages = metadata.get('packages', [])
    roots = [p for p in packages if p.get('source') is None and p.get('name') == 'cosmic-comp'
             and p.get('manifest_path') == str(old_source / 'Cargo.toml')]
    require(len(roots) == 1, 'Metadata lacks the exact local compositor package')
    nodes = [node for node in metadata.get('resolve', {}).get('nodes', []) if node.get('id') == roots[0]['id']]
    require(len(nodes) == 1 and nodes[0].get('features') == ['backend-cyxia'],
            'Resolved compositor backend/features differ from the native recipe')

    def remap(name, spec):
        selected = path(name, exists=False)
        if spec is None:
            require(selected.is_relative_to(old_source), 'Local dependency escapes original export root')
            return str(path(retained / selected.relative_to(old_source)))
        # The producer owns the Git URL/lock interpretation, including Cargo's
        # branch/tag/rev percent-encoding normalization. Do not reinterpret it.
        producer.source_key(spec)
        allowed = cache / ('registry/src' if spec.startswith('registry+') else 'git/checkouts')
        require(selected.is_relative_to(allowed), 'Dependency escapes the recorded private cache')
        return str(path(selected))

    records = copy.deepcopy(report['cargo_dependencies'])
    for package in packages:
        package['manifest_path'] = remap(package['manifest_path'], package.get('source'))
    for record in records:
        record['manifest'] = remap(record['manifest'], record['source'])
    actual = producer.metadata_identity(metadata, retained, cache, recipe)
    require(actual == records, 'Current compositor dependency source identities changed')
    return {'records_sha256': canonical(actual), 'package_count': len(actual),
            'selected_package_id': roots[0]['id'], 'features': nodes[0]['features'],
            'preserved_resolution': preserved}


def commands(report, recipe, output, old_source, hashes):
    cargo = report['toolchain']['tools']['cargo']['path']
    common = ['--manifest-path', str(old_source / 'Cargo.toml'), '--locked', '--offline',
              '--no-default-features', '--features', 'backend-cyxia']
    require(report['metadata_command'] == [cargo, 'metadata', '--format-version', '1',
                '--filter-platform', recipe['target'], *common]
            and report['command'] == [cargo, 'build', '--release', '--target', recipe['target'],
                '--jobs', str(report['jobs']), '--package', 'cosmic-comp', '--bin', 'cosmic-comp', *common]
            and 'fetch_command' not in report,
            'Retained Cargo commands are not the exact offline native compositor build')
    require(set(report['retained_logs']) == set(LOGS), 'Incomplete or unexpected compositor log closure')
    for name in LOGS:
        bind(output / name, report['retained_logs'][name], hashes)


def validate_build(output):
    """Return a stable, recheckable build identity for the runtime capture.

    Evidence here is static provenance/admission only. The caller must still
    prove which bytes the kernel embeds and what genuinely runs in the guest.
    """
    try:
        output = path(output, directory=True)
        receipt = output / 'build-report.json'
        report, receipt_sha256 = read_json(receipt)
        required = {'schema_version': 1, 'kind': producer.KIND,
                    'phase_policy_sha256': producer.POLICY_SHA256,
                    'status': 'cross-built', 'operation': 'build',
                    'target': 'x86_64-unknown-linux-musl', 'architecture': 'x86_64',
                    'link_completed': True, 'target_linked': True, 'source_preserved': True,
                    'producer_sources_preserved': True, 'cargo_offline': True,
                    'build_script_network_sandbox': False, 'guest_execution': 'not performed',
                    'cosmic_session_ready': False}
        require(all(type(report.get(key)) is type(value) and report[key] == value
                    for key, value in required.items()) and 'error' not in report,
                'Not a preserved successful native compositor build')
        require(path(report['output'], directory=True) == output,
                'Detached compositor build receipt is unsupported')
        hashes = {str(receipt): receipt_sha256}
        phase_policy = producer.phase_policy()
        require(report.get('phase_observation_contract') == phase_policy['observation'],
                'Compositor observation contract changed')
        bind(ROOT / producer.POLICY, producer.POLICY_SHA256, hashes)
        recipe_path = path(report['recipe_path'])
        recipe, _ = read_json(recipe_path)
        sources = [item for item in base.ports.load_manifest()['components'] if item['name'] == 'cosmic-comp']
        require(len(sources) == 1 and report['component'] == sources[0], 'Wrong canonical compositor component')
        source = sources[0]
        base.validate_recipe(recipe, source)
        producer.contract(recipe)
        require(recipe == report['recipe'], 'Recorded compositor recipe changed')
        bind(recipe_path, report['recipe_sha256'], hashes)
        producers = contracts.producer_sources(BUILDER)
        require(report['producer_sources'] == report['producer_sources_after'] == producers,
                'Current transitive compositor producer closure changed')
        for name, checksum in producers.items():
            bind(ROOT / base.dependencies.relative_path(name), checksum, hashes)
        bind(BUILDER, report['builder_sha256'], hashes)

        source_cache = path(report['source_cache'], directory=True)
        original = path(source_cache / base.dependencies.relative_path(source['directory']), directory=True)
        retained = path(output / 'source', directory=True)
        source_proof = source_identity(report, recipe, source, original, retained, hashes)
        old_source = path(report['original_export_root'], exists=False)
        require(old_source.name == 'source' and old_source != retained
                and not old_source.is_relative_to(output) and not output.is_relative_to(old_source),
                'Invalid original temporary compositor export root')
        cache = base.validate_cache(path(report['cargo_cache'], directory=True))
        commands(report, recipe, output, old_source, hashes)
        dependencies = metadata_identity(report, recipe, output, retained, cache, old_source)

        profile_path = path(report['profile_file'])
        document, _ = read_json(profile_path)
        profile = producer.full_os_profile(document, recipe, report['jobs'])
        require(profile == report['resource_profile'], 'Compositor FullOs resource profile changed')
        bind(profile_path, report['profile_file_sha256'], hashes)
        require(type(report.get('operation_timeout_seconds')) is int
                and report['operation_timeout_seconds'] == profile['timeout_seconds']
                and report.get('timeout_scope') ==
                    'Shared across export, Cargo commands and validation; publication refuses an expired deadline'
                and type(report.get('elapsed_seconds')) in (int, float)
                and 0 <= report['elapsed_seconds'] < float('inf'), 'Missing finite compositor deadline evidence')
        sysroot = path(report['sysroot'], directory=True)
        require(isinstance(report['toolchain'].get('selection'), dict),
                'Explicit compositor Rust/host compiler selection is required')
        # This reviewed helper only hashes files/archives; it never executes a
        # compiler, target binary or version probe. Its ABI is the same x86 SDK.
        rust_libraries = contracts.validate_toolchain(report, recipe, output, sysroot, hashes)
        base.ports.architecture(Path(report['toolchain']['std']['path']), rust_archive=True,
                                target=contracts.TARGET)
        base.ports.architecture(Path(report['toolchain']['unwind']['path']), target=contracts.TARGET)
        generated_files = {'bin': {'target-pkg-config', 'host-pkg-config'},
                           'native': {'libunwind.a'}}
        if report['toolchain']['tools']['target_cxx']['available'] is False:
            generated_files['bin'].add('unavailable-target-cxx')
        require(set(report['generated_build_inputs']) == {'bin', 'native'},
                'Unexpected generated compositor build inputs')
        for key in ('bin', 'native'):
            require(set(report['generated_build_inputs'][key]['files']) == generated_files[key],
                    'Generated build input closure is incomplete: ' + key)
            require(base.tree_identity(path(output / key, directory=True)) == report['generated_build_inputs'][key],
                    'Generated build wrapper/runtime input changed: ' + key)

        linked = path(output / 'target' / recipe['target'] / 'release/cosmic-comp')
        binary = path(output / 'cosmic-comp.elf')
        linked_inspection = elf.inspect_full_os_elf(linked, profile)
        published = elf.inspect_full_os_elf(binary, profile)
        require(linked_inspection == report['full_os_inspection'], 'Raw linked FullOs inspection changed')
        linked_record = {'path': str(linked), 'bytes': linked.stat().st_size,
                         'sha256': linked_inspection['executable']['sha256']}
        require(report['linked_binary'] == linked_record and type(report['linked_binary']['bytes']) is int,
                'Raw linked compositor bytes differ from their receipt')
        require(report['executable'] == {**published['executable'], 'path': str(binary)}
                and published['executable']['sha256'] == linked_record['sha256']
                and type(report['image_load_pages']) is int
                and report['image_load_pages'] == published['image_load_pages'],
                'Published compositor differs from the admitted original link')
        bind(linked, linked_record['sha256'], hashes)
        bind(binary, linked_record['sha256'], hashes)
        for name, checksum in published['loader_contract'].items():
            bind(elf.ROOT / name, checksum, hashes)
        require(base.digest(receipt) == receipt_sha256
                and contracts.producer_sources(BUILDER) == producers,
                'Compositor receipt or producer changed during validation')
        identity = {'schema_version': 1, 'kind': producer.KIND,
                    'phase_policy_sha256': producer.POLICY_SHA256,
                    'phase_observation_contract': phase_policy['observation'],
                    'receipt_sha256': receipt_sha256,
                    'inputs': dict(sorted(hashes.items())), 'source': source_proof,
                    'dependencies': dependencies, 'toolchain_sha256': canonical(report['toolchain']),
                    'official_rust_libraries_observed_now': rust_libraries,
                    'generated_build_inputs': report['generated_build_inputs'],
                    'full_os_inspection': published}
        return {'schema_version': 1, 'kind': producer.KIND,
                'phase_observation_contract': phase_policy['observation'],
                'status': 'COMPOSITOR_BUILD_REVALIDATED_NOT_RUN',
                'output': str(output), 'receipt_sha256': receipt_sha256,
                'executable': {**published['executable'], 'path': str(binary), 'file': str(binary)},
                'image_load_pages': published['image_load_pages'], 'required_pages': published['required_pages'],
                'full_os_inspection': published, 'identity': identity, 'identity_sha256': canonical(identity),
                'guest_execution': False, 'cosmic_session_ready': False}
    except BuildError:
        raise
    except (contracts.BuildError, OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        raise BuildError('Invalid retained compositor build: ' + str(error)) from error
