#!/usr/bin/env python3
"""Install verified notification link output; never build or run a service.

The published directory contains the real ELF for the kernel's /bin catalog,
its upstream license and an origin receipt. Only the reviewed Cargo-config
removal is supported. A completed installation is explicitly not guest proof.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

if __package__:
    from . import build_cosmic as build
    from . import build_cosmic_component as component_builder
    from . import cosmic_notifications_dependencies as dependencies
    from . import cosmic_notifications_elf as full_os_elf
    from . import cosmic_notifications_source as reviewed
    from . import install_cosmic_config as common
else:
    import build_cosmic as build
    import build_cosmic_component as component_builder
    import cosmic_notifications_dependencies as dependencies
    import cosmic_notifications_elf as full_os_elf
    import cosmic_notifications_source as reviewed
    import install_cosmic_config as common

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = 'cosmic-notifications'
PROGRAM = COMPONENT + '.elf'
RECEIPT = COMPONENT + '-origin.json'
LICENSE = 'rootfs/usr/share/doc/cosmic-notifications/LICENSE'
TARGET = build.ports.user_target('x86_64-unknown-linux-musl')
RECIPE = ROOT / 'ports/cosmic/native-notifications/native-recipe.json'
RESOURCE = ROOT / 'ports/cosmic/recipes/cosmic-notifications-x86_64-resource.json'
MAX_EVIDENCE_BYTES = 64 * 1024**2
LOGS = ('metadata.json', 'metadata.stderr.log', 'cargo.log')
ORIGIN_KEYS = {'build_output', 'recipe', 'resource_profile', 'sysroot', 'source_cache', 'cache'}
FULL_OS_ADMISSION = {'schema_version': 1, 'mode': 'full-os-linked-elf-v1',
                     'original_status': 'failed', 'image_profile': 'full-os-v3'}
LEGACY_LOAD_ERROR = 'Invalid LOAD bounds, alignment or W^X permissions'
RECEIPT_KEYS = {'schema_version', 'status', 'origin', 'inputs', 'producers', 'artifacts',
                'guest_execution', 'notifications_verified', 'cosmic_session_verified'}
require = common.require
BuildError = common.BuildError


def selected(value, *, directory=False):
    require(isinstance(value, (str, Path)), 'Invalid input pathname')
    path = common.plain_path(value)
    require(path.is_dir() if directory else path.is_file(), 'Missing input: ' + str(path))
    return path


def json_file(path):
    data = common.read_regular(path, MAX_EVIDENCE_BYTES)
    value = json.loads(data, object_pairs_hook=common.no_duplicate_keys)
    require(isinstance(value, dict), 'Expected JSON object: ' + str(path))
    return value


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def full_os_origin(origin):
    require(isinstance(origin, dict), 'Malformed notification origin')
    if set(origin) == ORIGIN_KEYS:
        return False
    require(set(origin) == ORIGIN_KEYS | {'admission'}, 'Malformed notification origin')
    admission = origin['admission']
    require(isinstance(admission, dict) and set(admission) == set(FULL_OS_ADMISSION)
            and all(type(admission.get(key)) is type(value) and admission[key] == value
                    for key, value in FULL_OS_ADMISSION.items()), 'Invalid notification admission mode')
    return True


def source_tree(files):
    return {'files': files, 'sha256': canonical_hash(files)}


def bind(path, expected, hashes, *, tool=False):
    # The builder permits ordinary system links for compiler executables. All
    # source, report, SDK-library and install paths must be regular, unaliased.
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Unbound input pathname')
    if not tool:
        path = selected(path)
    require(path.is_file() and isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected)
            and build.digest(path) == expected, 'Input identity changed: ' + str(path))
    hashes[str(path)] = expected


def producer_sources(entry):
    """Read the builder's transitive local-import map without loading native tools.

    This is the same path/hash representation recorded by os_x86.producer_sources;
    importing its command-line module would otherwise require a tools sys.path.
    """
    pending, result = [common.plain_path(entry)], {}
    while pending:
        path = pending.pop()
        key = str(path.relative_to(ROOT))
        if key in result:
            continue
        raw = common.read_regular(path, MAX_EVIDENCE_BYTES)
        result[key] = hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            names = ([item.name for item in node.names] if isinstance(node, ast.Import) else
                     [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for name in names:
                local = ROOT / 'tools' / (name.split('.')[0] + '.py')
                if local.is_file():
                    pending.append(common.plain_path(local))
    return dict(sorted(result.items()))


def validate_source(report, recipe, recipe_path, source, original, exported, hashes):
    require(dependencies.pinned_git(original, 'rev-parse', '--show-toplevel') == str(original)
            and dependencies.pinned_git(original, 'rev-parse', 'HEAD') == source['commit']
            and build.ports.repository_url(dependencies.pinned_git(original, 'remote', 'get-url', 'origin'))
                == build.ports.repository_url(source['repository']), 'Original notification checkout identity changed')
    require(not dependencies.pinned_git(original, 'status', '--porcelain', '--untracked-files=all', '--ignored'),
            'Original notification checkout is not clean')
    declared = dependencies.parse_git_tree(dependencies.pinned_git(original, 'ls-tree', '-rz', 'HEAD'))
    require(all(item['mode'] in ('100644', '100755') for item in declared.values()),
            'Notification source export contains unreviewed links or gitlinks')
    verified = dependencies.validate_checkout_tree(original, declared)
    files = {name: {key: item[key] for key in ('bytes', 'sha256')}
             for name, item in verified['files'].items()}
    bind(original / 'Cargo.lock', recipe['source_lock_sha256'], hashes)
    policy = reviewed.load_policy(recipe, recipe_path, source)
    policy_path = recipe_path.parent / common.relative_path(recipe['source_export_policy']['path'])
    bind(policy_path, recipe['source_export_policy']['sha256'], hashes)
    require(recipe['patches'] == report['patches'] == [] and 'source_series' not in recipe,
            'Notification installation supports only the reviewed config removal, not additional patches')
    require(common.read_regular(original / '.cargo/config.toml') == reviewed.CONFIG
            and common.read_regular(original / '.cargo/config.default') == reviewed.CONFIG,
            'Reviewed notification Cargo configuration changed')
    before = source_tree(files)
    normalized = dict(files)
    removed = normalized.pop('.cargo/config.toml')
    after = source_tree(normalized)
    expected = {'policy': policy, 'exporter_sha256': build.digest(reviewed.__file__),
                'original_tree': before, 'source_tree': after,
                'removed': {'.cargo/config.toml': removed}, 'source_preserved': True}
    require(report['source_normalization'] == expected and report['source_export_policy'] == policy
            and report['reviewed_rust_flags'] == policy['rust_flags']
            and report['reviewed_rustdoc_flags'] == policy['rustdoc_flags'],
            'Notification source-policy receipt changed')
    require(build.tree_identity(exported) == report['source_tree'] == after,
            'Preserved notification export differs from canonical source and reviewed removal')
    bind(exported / 'Cargo.lock', recipe['effective_lock_sha256'], hashes)
    require('LICENSE.md' in normalized, 'Pinned upstream notification license is missing')
    return verified['sha256']


def validate_metadata(report, recipe, output, exported, cache):
    command = report['command']
    require(isinstance(command, list) and all(isinstance(item, str) for item in command)
            and command.count('--manifest-path') == command.count('--jobs') == 1,
            'Malformed notification build command')
    old_manifest = Path(command[command.index('--manifest-path') + 1])
    require(old_manifest.is_absolute() and '..' not in old_manifest.parts
            and old_manifest.name == 'Cargo.toml', 'Invalid recorded temporary manifest path')
    old_source = old_manifest.parent
    metadata = json_file(output / 'metadata.json')
    package_id = component_builder.local_package(metadata, old_source, recipe)
    require(report['package_id'] == package_id, 'Build selected a different local Cargo package')
    require(metadata.get('workspace_root') == str(old_source), 'Metadata workspace differs from temporary source')
    jobs_text = command[command.index('--jobs') + 1]
    require(re.fullmatch('[1-9][0-9]*', jobs_text), 'Invalid build job count')
    common_args = ['--manifest-path', str(old_manifest), '--locked', '--offline']
    features = [] if recipe['default_features'] else ['--no-default-features']
    if recipe['features']:
        features += ['--features', ','.join(recipe['features'])]
    cargo = report['toolchain']['tools']['cargo']['path']
    require(command == [cargo, 'build', '--release', '--target', TARGET.rust_target,
                '--jobs', jobs_text, '--package', package_id, '--bin', COMPONENT, *common_args, *features]
            and report['metadata_command'] == [cargo, 'metadata', '--format-version', '1',
                '--filter-platform', TARGET.rust_target, *common_args, *features],
            'Cargo commands differ from the selected notification recipe')

    def remap(name, spec):
        require(isinstance(name, str), 'Invalid dependency manifest path')
        path = Path(name)
        require(path.is_absolute() and '..' not in path.parts, 'Unbound dependency manifest path')
        if spec is None:
            require(path.is_relative_to(old_source), 'Local dependency escapes recorded temporary source')
            return str(selected(exported / path.relative_to(old_source)))
        require(isinstance(spec, str) and (spec.startswith('registry+') or
                re.fullmatch(r'git\+https://[^\s#]+#[0-9a-f]{40}', spec)), 'Unpinned dependency source')
        allowed = cache / ('registry/src' if spec.startswith('registry+') else 'git/checkouts')
        require(path.is_relative_to(allowed), 'Dependency escapes selected private Cargo cache')
        return str(selected(path))

    # The real builder removes its temporary source directory before returning.
    # Relocate only local manifests under that recorded root; every byte must
    # come from the verified, complete output/source export above.
    records = copy.deepcopy(report['cargo_dependencies'])
    for package in metadata['packages']:
        package['manifest_path'] = remap(package['manifest_path'], package.get('source'))
    for record in records:
        record['manifest'] = remap(record['manifest'], record['source'])
    require(dependencies.verify_metadata(metadata, exported, cache, recipe) == records,
            'Notification dependency identity changed')
    return int(jobs_text)


def validate_toolchain(report, recipe, output, sysroot, hashes):
    toolchain, tools = report['toolchain'], report['toolchain']['tools']
    require(toolchain['target'] == TARGET.rust_target and toolchain['architecture'] == TARGET.architecture,
            'Wrong notification SDK target')
    require(set(tools) == {'rustc', 'cargo', 'target_cc', 'target_cxx', 'target_ar', 'target_ranlib',
                           'host_cc', 'strip', 'pkg_config'}, 'Incomplete compiler identities')
    rustc = Path(tools['rustc']['path'])
    require(rustc.name == 'rustc' and rustc.parent.name == 'bin', 'Invalid Rust toolchain location')
    rust_root = rustc.parent.parent
    selection = toolchain.get('selection')
    if selection is not None:
        require(isinstance(selection, dict) and set(selection) == {'schema_version', 'rust_root', 'host_cc'}
                and type(selection['schema_version']) is int and selection['schema_version'] == 1,
                'Invalid explicit notification toolchain selection')
        require(isinstance(selection['rust_root'], str) and Path(selection['rust_root']).is_absolute()
                and selected(selection['rust_root'], directory=True) == rust_root
                and isinstance(selection['host_cc'], str) and Path(selection['host_cc']).is_absolute()
                and selected(selection['host_cc']) == Path(tools['host_cc']['path']),
                'Explicit toolchain selection differs from recorded tool paths')
        version = toolchain.get('host_cc_version')
        require(isinstance(version, str) and 0 < len(version.encode()) <= 64 * 1024 and version.strip(),
                'Explicit host compiler version observation is missing')
        rust_version = toolchain.get('rustc_version')
        require(isinstance(rust_version, str) and
                [line[6:] for line in rust_version.splitlines() if line.startswith('host: ')] == [toolchain['host']],
                'Rust version observation differs from recorded host')
    else:
        require('host_cc_version' not in toolchain, 'Host compiler observation lacks an explicit selection')
    expected = {'cargo': rust_root / 'bin/cargo', 'target_cc': TARGET.cc(sysroot),
                'target_cxx': sysroot / 'bin/x86_64-linux-musl-cxx',
                'target_ar': sysroot / 'bin/x86_64-linux-musl-ar',
                'target_ranlib': sysroot / 'bin/x86_64-linux-musl-ranlib',
                'strip': rust_root / 'lib/rustlib' / toolchain['host'] / 'bin/llvm-strip'}
    for name, record in tools.items():
        path = Path(record['path'])
        require(path.is_absolute() and '..' not in path.parts and
                (name not in expected or path == expected[name]), 'Recorded compiler selection changed: ' + name)
        if name == 'target_cxx' and record.get('available') is False:
            require(record.get('sha256') is None and not path.exists() and not path.is_symlink(),
                    'Absent target C++ capability changed')
        else:
            require(record.get('available') is True, 'Required compiler was unavailable: ' + name)
            require(os.access(path, os.X_OK), 'Recorded compiler is not executable: ' + name)
            bind(path, record['sha256'], hashes, tool=True)
    library = selected(rust_root / 'lib/rustlib' / TARGET.rust_target / 'lib', directory=True)
    std, unwind = toolchain['std'], toolchain['unwind']
    require(Path(std['path']).parent == library and re.fullmatch(r'libstd-[a-zA-Z0-9]+\.rlib', Path(std['path']).name)
            and len(list(library.glob('libstd-*.rlib'))) == 1
            and Path(unwind['path']) == library / 'self-contained/libunwind.a', 'Wrong target Rust libraries')
    for record in (std, unwind):
        bind(Path(record['path']), record['sha256'], hashes)
    bind(output / 'native/libunwind.a', unwind['sha256'], hashes)
    require(toolchain['native_inputs'] == recipe['native_inputs']
            and toolchain['static_link_inputs'] == build.static_link_inputs(recipe), 'Wrong recorded SDK inputs')
    names = [str(common.relative_path(item['path'])) for item in recipe['native_inputs']]
    required = {'sysroot/usr/lib/' + name for name in
                ('libc.a', TARGET.builtins_archive, 'crt1.o', 'crti.o', 'crtn.o')}
    require(len(names) == len(set(names)) and required <= set(names), 'Missing or duplicate native inputs')
    for item in recipe['native_inputs']:
        path = sysroot / common.relative_path(item['path'])
        bind(path, item['sha256'], hashes)
        if path.suffix == '.a':
            build.ports.architecture(path, target=TARGET)
        elif path.suffix == '.o':
            build.ports.elf_header(path.read_bytes(), (1,), TARGET)
    require(build.tree_identity(sysroot / 'sysroot') == report['sysroot_before'], 'SDK contents changed')
    # These extra libraries are bound at installation time. The original build
    # report records std/unwind; publication cannot invent stronger past proof.
    return {str(path.relative_to(library)): build.digest(selected(path))
            for path in sorted(library.rglob('*')) if path.suffix in ('.rlib', '.a')}


def validate_build(origin):
    try:
        full_os = full_os_origin(origin)
        paths = {name: selected(origin[name], directory=name not in ('recipe', 'resource_profile'))
                 for name in ORIGIN_KEYS}
        output, recipe_path, resource = paths['build_output'], paths['recipe'], paths['resource_profile']
        hashes = {}
        report = json_file(output / 'build-report.json')
        required = {'status': 'cross-built', 'target': TARGET.rust_target, 'architecture': TARGET.architecture,
                    'operation': 'build', 'cargo_offline': True, 'build_script_network_sandbox': False,
                    'guest_execution': 'not performed', 'cosmic_session_ready': False,
                    'link_completed': True, 'target_linked': True, 'source_preserved': True,
                    'producer_sources_preserved': True}
        if full_os:
            required.update(status='failed', target_linked=False, error=LEGACY_LOAD_ERROR)
        require(all(type(report.get(key)) is type(value) and report[key] == value
                    for key, value in required.items()),
                'Not a preserved notifications legacy-window link failure' if full_os else
                'Not a preserved notifications cross-build')
        if full_os:
            require(not ({'executable', 'image_load_pages', 'producer_check_error'} & set(report))
                    and not (output / PROGRAM).exists() and not (output / PROGRAM).is_symlink(),
                    'Legacy-window link failure already contains published build results')
        sources = [item for item in build.ports.load_manifest()['components'] if item['name'] == COMPONENT]
        require(len(sources) == 1 and report['component'] == sources[0], 'Wrong pinned notification component')
        source = sources[0]
        recipe = build.validate_recipe(json_file(recipe_path), source)
        require(report['recipe'] == recipe and recipe['package'] == recipe['binary'] == COMPONENT
                and recipe['target'] == TARGET.rust_target, 'Wrong notification recipe or target')
        bind(recipe_path, report['recipe_sha256'], hashes)
        producer_fields = {'builder_sha256': 'build_cosmic_notifications.py',
                           'common_builder_sha256': 'build_cosmic.py',
                           'source_exporter_sha256': 'cosmic_notifications_source.py',
                           'package_selector_sha256': 'build_cosmic_component.py',
                           'dependency_validator_sha256': 'cosmic_notifications_dependencies.py'}
        producers = producer_sources(ROOT / 'tools/build_cosmic_notifications.py')
        require(report['producer_sources'] == report['producer_sources_after'] == producers,
                'Transitive notification build producers changed')
        for name, digest in producers.items():
            bind(ROOT / common.relative_path(name), digest, hashes)
        for field, filename in producer_fields.items():
            bind(ROOT / 'tools' / filename, report[field], hashes)
        exported = selected(output / 'source', directory=True)
        original = selected(paths['source_cache'] / common.relative_path(source['directory']), directory=True)
        original_hash = validate_source(report, recipe, recipe_path, source, original, exported, hashes)
        cache = build.validate_cache(paths['cache'])
        jobs = validate_metadata(report, recipe, output, exported, cache)
        profile = build.select_profile(json_file(resource), recipe['resource_profile'], jobs, TARGET)
        require(profile == report['resource_profile'] and profile.get('target_runtime_validated') is False
                and hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest() == report['profile_sha256'],
                'Notification resource profile changed')
        libraries = validate_toolchain(report, recipe, output, paths['sysroot'], hashes)
        linked = selected(output / 'target' / TARGET.rust_target / 'release' / COMPONENT)
        binary = linked if full_os else selected(output / PROGRAM)
        require(binary.stat().st_size <= MAX_EVIDENCE_BYTES and linked.stat().st_size <= MAX_EVIDENCE_BYTES,
                'Notification ELF exceeds input bound')
        require(report['linked_binary'] == {
                'path': str(linked), 'bytes': linked.stat().st_size, 'sha256': build.digest(linked)}
                and type(report['linked_binary']['bytes']) is int, 'ELF differs from real link output')
        if full_os:
            inspection = full_os_elf.inspect_full_os_elf(binary, profile)
            require(inspection['legacy_window_exceeded'] is True,
                    'Linked ELF did not exceed the legacy LOAD window')
            executable = inspection['executable']
            for name, digest in inspection['loader_contract'].items():
                bind(ROOT / common.relative_path(name), digest, hashes)
        else:
            executable = build.inspect_elf(binary, TARGET)
            require(executable == report['executable'], 'ELF differs from real link output')
            pages = sum((p['vaddr'] + p['memsz'] + 4095)//4096 - p['vaddr']//4096
                        for p in executable['program_headers'] if p['type'] == 1)
            require(pages == report['image_load_pages'] and executable['bytes'] <= profile['max_elf_bytes']
                    and pages * 4096 + profile['stack_bytes'] <= profile['image_bytes'], 'ELF exceeds resource profile')
        require(executable['sha256'] == report['linked_binary']['sha256'], 'ELF changed during inspection')
        for path in (binary, linked):
            bind(path, executable['sha256'], hashes)
        for path in (resource, output / 'build-report.json', *(output / name for name in LOGS)):
            data = common.read_regular(path, MAX_EVIDENCE_BYTES)
            hashes[str(path)] = hashlib.sha256(data).hexdigest()
        inputs = {'inputhashes': dict(sorted(hashes.items())), 'executable': executable,
                'source_tree_sha256': report['source_tree']['sha256'], 'original_tree_sha256': original_hash,
                'cargo_dependencies_sha256': canonical_hash(report['cargo_dependencies']),
                'dependency_count': len(report['cargo_dependencies']),
                'rust_libraries_at_installation': libraries,
                'license': common.identity(common.read_regular(exported / 'LICENSE.md'))}
        if full_os:
            inputs['admission'] = {**FULL_OS_ADMISSION, 'original_error': LEGACY_LOAD_ERROR,
                'original_report': {'path': str(output / 'build-report.json'),
                                    'sha256': hashes[str(output / 'build-report.json')]},
                'resource_profile': profile, 'inspection': inspection}
        return inputs
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise BuildError('Malformed notification build evidence') from error


def artifacts(inputs):
    return [{'path': PROGRAM, 'guest_path': '/bin/' + COMPONENT,
             **{key: inputs['executable'][key] for key in ('bytes', 'sha256')}},
            {'path': LICENSE, 'guest_path': '/' + LICENSE.removeprefix('rootfs/'), **inputs['license']}]


def validate_inputs(prefix):
    prefix = selected(prefix, directory=True)
    receipt = json_file(prefix / RECEIPT)
    require(set(receipt) == RECEIPT_KEYS and type(receipt['schema_version']) is int
            and receipt['schema_version'] == 1 and receipt['status'] == 'INSTALLED_NOT_RUN'
            and receipt['guest_execution'] == 'not performed' and receipt['notifications_verified'] is False
            and receipt['cosmic_session_verified'] is False, 'Invalid notification installation receipt')
    require(receipt['producers'] == producer_sources(Path(__file__)), 'Notification installer changed')
    inputs = validate_build(receipt['origin'])
    require(receipt['inputs'] == inputs and receipt['artifacts'] == artifacts(inputs),
            'Notification installation inputs or paths changed')
    for record in receipt['artifacts']:
        data = common.read_regular(prefix / common.relative_path(record['path']), MAX_EVIDENCE_BYTES)
        require(common.identity(data) == {key: record[key] for key in ('bytes', 'sha256')},
                'Installed notification file changed')
    require((prefix / PROGRAM).stat().st_mode & 0o777 == 0o755, 'Installed notification ELF is not executable')
    if full_os_origin(receipt['origin']):
        inspection = full_os_elf.inspect_full_os_elf(prefix / PROGRAM, inputs['admission']['resource_profile'])
        expected = copy.deepcopy(inputs['admission']['inspection'])
        expected['executable']['file'] = PROGRAM
        require(inspection == expected, 'Installed notification ELF admission changed')
    else:
        build.inspect_elf(prefix / PROGRAM, TARGET)
    return {'status': 'VALIDATED_NOT_RUN', 'receipt': receipt, 'notifications_verified': False,
            'cosmic_session_verified': False, 'guest_execution': 'not performed'}


def install(build_output, output, *, recipe=RECIPE, resource_profile=RESOURCE, sysroot=None,
            source_cache=None, cache=None, full_os_linked_elf=False):
    require(type(full_os_linked_elf) is bool, 'Invalid notification admission selection')
    origin = {'build_output': build_output, 'recipe': recipe, 'resource_profile': resource_profile,
              'sysroot': sysroot if sysroot is not None else ROOT / 'artifacts/sysroot/x86_64-musl',
              'source_cache': source_cache if source_cache is not None else build.ports.CACHE,
              'cache': cache if cache is not None else build.CARGO_CACHE}
    origin = {name: str(selected(value, directory=name not in ('recipe', 'resource_profile')))
              for name, value in origin.items()}
    output = common.plain_path(output)
    require(not output.exists(), 'Preserving existing notification installation')
    for value in origin.values():
        path = Path(value)
        require(not output.is_relative_to(path) and not path.is_relative_to(output),
                'Notification output overlaps an input')
    if full_os_linked_elf:
        origin['admission'] = dict(FULL_OS_ADMISSION)
    inputs = validate_build(origin)
    producers = producer_sources(Path(__file__))
    receipt = {'schema_version': 1, 'status': 'INSTALLED_NOT_RUN', 'origin': origin,
               'inputs': inputs, 'producers': producers, 'artifacts': artifacts(inputs),
               'guest_execution': 'not performed', 'notifications_verified': False,
               'cosmic_session_verified': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        binary = (Path(origin['build_output']) / 'target' / TARGET.rust_target / 'release' / COMPONENT
                  if full_os_linked_elf else Path(origin['build_output']) / PROGRAM)
        for record, source in zip(receipt['artifacts'],
                (binary, Path(origin['build_output']) / 'source/LICENSE.md')):
            data = common.read_regular(source, MAX_EVIDENCE_BYTES)
            require(common.identity(data) == {key: record[key] for key in ('bytes', 'sha256')},
                    'Notification source changed during installation')
            target = pending / record['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            target.chmod(0o755 if record['path'] == PROGRAM else 0o644)
        with (pending / RECEIPT).open('x') as stream:
            json.dump(receipt, stream, indent=2); stream.write('\n')
            stream.flush(); os.fsync(stream.fileno())
        # Re-read every input and staged file before the one directory rename.
        # The final output never exposes a binary without its validated receipt.
        validate_inputs(pending)
        require(not output.exists() and not output.is_symlink(), 'Preserving concurrently created output')
        pending.rename(output)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--recipe', type=Path, default=RECIPE)
    parser.add_argument('--resource-profile', type=Path, default=RESOURCE)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--source-cache', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--full-os-linked-elf', action='store_true',
                        help='explicitly admit only a preserved legacy-window link failure for full-os-v3')
    args = parser.parse_args(argv)
    try:
        receipt = install(args.build, args.output, recipe=args.recipe, resource_profile=args.resource_profile,
                          sysroot=args.sysroot, source_cache=args.source_cache, cache=args.cache,
                          full_os_linked_elf=args.full_os_linked_elf)
        print(json.dumps({key: receipt[key] for key in ('status', 'artifacts', 'notifications_verified',
                                                       'cosmic_session_verified')}, indent=2))
        return 0
    except (BuildError, OSError, ValueError) as error:
        print('COSMIC notification installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
