"""Read-only provenance checks for real, bounded COSMIC service builds.

No compiler, Cargo, version probe, patch application or guest is executed here.
Origin publication binds logs and the installed Rust library set at publication;
the original builder receipt binds the build-time identities it actually recorded.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import tarfile
import tomllib

try:
    from . import build_cosmic as build
    from . import cosmic_dependencies as dependencies
    from . import cosmic_ports as ports
    from .build_sysroot import inspect_elf
except ImportError:
    import build_cosmic as build
    import cosmic_dependencies as dependencies
    import cosmic_ports as ports
    from build_sysroot import inspect_elf

ROOT = ports.ROOT
HOST_CC = Path('/usr/bin/clang')
RECEIPT = 'cosmic-session-origin.json'
PROGRAM = 'cosmic-session.elf'
LOGS = ('metadata.json', 'metadata.stderr.log', 'cargo.log')
TARGET = ports.user_target('x86_64-unknown-linux-musl')
ORIGIN_KEYS = {'schema_version', 'output', 'report_sha256', 'recipe_path',
               'resource_path', 'resource_sha256', 'source_export', 'logs_sha256',
               'patch_manifests', 'rust_libraries_sha256'}
COMPONENT_SOURCES = {'cosmic-session': 'session', 'cosmic-settings-daemon': 'settings'}


def component_files(component):
    require(component in COMPONENT_SOURCES, 'Unsupported COSMIC service component')
    return component + '.elf', component + '-origin.json'


def require(value, message):
    if not value:
        raise build.CosmicBuildError(message)


def path(value, *, root=None, directory=False):
    requested = Path(value)
    require('..' not in requested.parts, 'Parent traversal in input path')
    if not requested.is_absolute():
        requested = (ROOT if root is None else root) / requested
    selected = build.no_symlink_path(requested)
    if root is not None:
        require(selected.is_relative_to(root), 'Input path escapes its root: ' + str(selected))
    require(selected.is_dir() if directory else selected.is_file(), 'Missing input: ' + str(selected))
    return selected


def artifact(value, *, directory=False):
    requested = Path(value)
    if not requested.is_absolute():
        requested = ROOT / requested
    return path(requested, root=ROOT / 'artifacts', directory=directory)


def checksum(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'Invalid SHA-256')
    return value


def bind(selected, expected, hashes):
    # Toolchain executables may use ordinary system/Homebrew symlinks; their
    # selected pathname and dereferenced bytes are both retained in the receipt.
    require(Path(selected).is_file() and build.digest(selected) == checksum(expected),
            'Input identity changed: ' + str(selected))
    hashes[str(selected)] = expected


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def tracked_files(source):
    """Actual Git-tracked regular files; ignore dependency-cache marker files."""
    require(not build.git(source, 'status', '--porcelain', '--untracked-files=no'),
            'Tracked source is modified: ' + str(source))
    result = {}
    for row in build.git(source, 'ls-tree', '-rz', 'HEAD').split('\0'):
        if not row:
            continue
        identity, name = row.split('\t', 1)
        mode, kind, _ = identity.split()
        require(mode in ('100644', '100755') and kind == 'blob',
                'Source contains a symlink or gitlink')
        relative = dependencies.relative_path(name)
        result[name] = build.digest(path(relative, root=source))
    return result


def validate_registry_inputs(manifest, original, hashes):
    """Verify exported registry origins against the original locked archives."""
    records = manifest.get('registry_inputs', {})
    require(isinstance(records, dict), 'Malformed registry origin map')
    if not records:
        return
    locked = tomllib.loads((original / 'Cargo.lock').read_text())['package']
    for key, record in records.items():
        name, version = record['package'], record['version']
        require(key == name and re.fullmatch(r'[a-zA-Z0-9_-]+', name)
                and re.fullmatch(r'[a-zA-Z0-9.+_-]+', version), 'Invalid registry package identity')
        selected = [p for p in locked if p['name'] == name and p['version'] == version
                    and p.get('source') == record['source']]
        require(len(selected) == 1 and selected[0]['checksum'] == record['checksum']
                == record['archive_sha256'], 'Registry origin differs from original lock')
        cache = ROOT / 'artifacts/cosmic-cargo-cache/registry'
        archive = path(record['archive'], root=ROOT)
        directory = path(record['path'], root=ROOT, directory=True)
        require(archive.is_relative_to(cache / 'cache') and directory.is_relative_to(cache / 'src'),
                'Registry origin escapes private cache')
        require(archive.stat().st_size <= 2 * 1024**2, 'Registry archive exceeds input bound')
        bind(archive, record['archive_sha256'], hashes)
        files = {}; expanded = 0
        with tarfile.open(archive, 'r:*') as packed:
            for member in packed.getmembers():
                relative = dependencies.relative_path(member.name)
                require(relative.parts[0] == name + '-' + version, 'Wrong registry archive prefix')
                if member.isdir():
                    continue
                require(member.isfile() and len(relative.parts) > 1, 'Non-regular registry member')
                filename = str(Path(*relative.parts[1:]))
                expanded += member.size
                require(filename not in files and expanded <= 32 * 1024**2, 'Registry archive inventory bound')
                files[filename] = hashlib.sha256(packed.extractfile(member).read()).hexdigest()
        require(files == record['files'] and hashlib.sha256(json.dumps(files, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest() == record['tree_sha256'],
                'Registry origin inventory differs from locked archive')
        actual = build.tree_identity(directory)['files']
        require(set(actual) - {'.cargo-ok', '.cargo-checksum.json'} == set(files),
                'Registry extraction inventory changed')
        for filename, digest in files.items():
            bind(path(filename, root=directory), digest, hashes)
        checksum_manifest = record.get('checksum_manifest')
        if checksum_manifest is not None:
            require(path(checksum_manifest['path']) == directory / '.cargo-checksum.json',
                    'Wrong registry checksum manifest path')
            bind(directory / '.cargo-checksum.json', checksum_manifest['sha256'], hashes)


def validate_patches(recipe, recipe_path, report, origin, original, exported, hashes):
    require('source_series' not in recipe, 'Session source-series builds are unsupported')
    manifests = origin['patch_manifests']
    require(isinstance(manifests, list) and len(manifests) == len(recipe['patches']),
            'Each session patch needs exactly one bound manifest')
    records = []
    expected = tracked_files(original)
    for patch, manifest_record in zip(recipe['patches'], manifests):
        patch_path = path(dependencies.relative_path(patch['path']), root=recipe_path.parent)
        bind(patch_path, patch['sha256'], hashes)
        records.append({'path': str(patch_path), 'sha256': patch['sha256']})
        require(set(manifest_record) == {'path', 'sha256'}, 'Malformed patch-manifest binding')
        manifest_path = path(manifest_record['path'], root=ROOT)
        bind(manifest_path, manifest_record['sha256'], hashes)
        manifest = build.load_json(manifest_path)
        require(manifest.get('schema_version') == 1 and manifest.get('component') == recipe['component']
                and manifest.get('commit') == recipe['commit']
                and ports.repository_url(manifest.get('repository')) == report['component']['repository']
                and manifest.get('patch_sha256') == patch['sha256']
                and manifest.get('source_lock_sha256') == recipe['source_lock_sha256']
                and manifest.get('effective_lock_sha256') == recipe['effective_lock_sha256'],
                'Patch manifest does not identify the selected session port')
        before, after = manifest.get('before'), manifest.get('after')
        require(isinstance(before, dict) and before and isinstance(after, dict)
                and before.keys() == after.keys(), 'Patch manifest preimages/postimages are incomplete')
        for name in before:
            dependencies.relative_path(name)
            require(expected.get(name) == before[name], 'Patch preimage mismatch: ' + name)
            if after[name] is None:
                expected.pop(name, None)
            else:
                expected[name] = checksum(after[name])
        sources = manifest.get('source_inputs')
        source_key = COMPONENT_SOURCES[recipe['component']]
        require(isinstance(sources, dict) and source_key in sources,
                'Patch manifest lacks source-input identities')
        require(path(sources[source_key]['path'], root=ROOT, directory=True) == original
                and sources[source_key]['commit'] == recipe['commit'],
                'Patch manifest session source differs from epoch checkout')
        for record in sources.values():
            selected = path(record['path'], root=ROOT, directory=True)
            require(build.git(selected, 'rev-parse', 'HEAD') == record['commit']
                    and build.git(selected, 'rev-parse', 'HEAD^{tree}') == record['git_tree'],
                    'Patch source Git identity changed')
            files = tracked_files(selected)
            tree_hash = hashlib.sha256(json.dumps(files, sort_keys=True,
                                                 separators=(',', ':')).encode()).hexdigest()
            require(files == record['files'] and tree_hash == record['tree_sha256'],
                    'Patch source tracked bytes changed')
        support = manifest.get('support_inputs')
        require(isinstance(support, dict) and support, 'Patch manifest lacks support-input identities')
        for name, digest in support.items():
            bind(path(name, root=ROOT), digest, hashes)
        validate_registry_inputs(manifest, original, hashes)
    require(report['patches'] == records, 'Build patch order or identity differs from the recipe')
    actual = build.tree_identity(exported)['files']
    require(all(set(entry) == {'bytes', 'sha256'} for entry in actual.values()),
            'Export contains non-regular source inputs')
    require({name: entry['sha256'] for name, entry in actual.items()} == expected,
            'Export differs from the complete original source and declared patch changes')


def rust_libraries(report):
    library = Path(report['toolchain']['std']['path']).parent
    return {str(item.relative_to(library)): build.digest(path(item))
            for item in sorted(library.rglob('*')) if item.suffix in ('.rlib', '.a')}


def validate_toolchain(report, recipe, output, origin, hashes):
    toolchain = report['toolchain']
    require(toolchain['target'] == TARGET.rust_target and toolchain['architecture'] == TARGET.architecture,
            'Wrong toolchain target')
    sdk = path(ROOT / 'artifacts/sysroot/x86_64-musl', directory=True)
    tools = toolchain['tools']
    require(set(tools) == {'rustc', 'cargo', 'target_cc', 'target_cxx', 'target_ar',
                           'target_ranlib', 'host_cc', 'strip', 'pkg_config'},
            'Incomplete recorded compiler tool set')
    rustc = Path(tools['rustc']['path'])
    require(rustc.name == 'rustc' and rustc.parent.name == 'bin', 'Unexpected Rust toolchain location')
    rust_root = rustc.parent.parent
    expected = {'cargo': rust_root / 'bin/cargo', 'target_cc': TARGET.cc(sdk),
                'target_cxx': sdk / 'bin/x86_64-linux-musl-cxx',
                'target_ar': sdk / 'bin/x86_64-linux-musl-ar',
                'target_ranlib': sdk / 'bin/x86_64-linux-musl-ranlib',
                'host_cc': HOST_CC,
                'strip': rust_root / 'lib/rustlib' / toolchain['host'] / 'bin/llvm-strip'}
    for name, record in tools.items():
        selected = Path(record['path'])
        require(selected.is_absolute() and '..' not in selected.parts, 'Unbound compiler pathname')
        if name in expected:
            require(selected == expected[name], 'Recorded tool selection changed: ' + name)
        if name == 'target_cxx' and record.get('available') is False:
            require(record.get('sha256') is None and not selected.exists() and not selected.is_symlink(),
                    'Absent target C++ capability changed')
        else:
            require(record.get('available') is True, 'Required tool was unavailable: ' + name)
            bind(selected, record['sha256'], hashes)
    libdir = rust_root / 'lib/rustlib' / TARGET.rust_target / 'lib'
    std, unwind = toolchain['std'], toolchain['unwind']
    require(Path(std['path']).parent == libdir and re.fullmatch('libstd-[a-zA-Z0-9]+\\.rlib', Path(std['path']).name)
            and Path(unwind['path']) == libdir / 'self-contained/libunwind.a',
            'Wrong Rust target-library selection')
    require(len(list(libdir.glob('libstd-*.rlib'))) == 1, 'Ambiguous target libstd')
    for record in (std, unwind):
        bind(path(record['path']), record['sha256'], hashes)
    bind(path(output / 'native/libunwind.a'), unwind['sha256'], hashes)
    require(rust_libraries(report) == origin['rust_libraries_sha256'], 'Installed Rust library set changed')
    for name, digest in origin['rust_libraries_sha256'].items():
        bind(path(dependencies.relative_path(name), root=libdir), digest, hashes)
    require(toolchain['native_inputs'] == recipe['native_inputs']
            and toolchain['static_link_inputs'] == build.static_link_inputs(recipe),
            'Recorded native inputs differ from recipe')
    required = {'sysroot/usr/lib/' + name for name in
                ('libc.a', TARGET.builtins_archive, 'crt1.o', 'crti.o', 'crtn.o')}
    require(required <= {item['path'] for item in recipe['native_inputs']}, 'Missing required SDK inputs')
    require(len({item['path'] for item in recipe['native_inputs']}) == len(recipe['native_inputs']),
            'Duplicate native inputs')
    for record in recipe['native_inputs']:
        bind(path(dependencies.relative_path(record['path']), root=sdk), record['sha256'], hashes)
    require(build.tree_identity(sdk / 'sysroot') == report['sysroot_before'], 'Target SDK tree changed')


def validate_metadata(report, recipe, output, exported):
    metadata = build.load_json(output / 'metadata.json')
    command = report['command']
    require(isinstance(command, list) and command.count('--manifest-path') == 1
            and command.count('--jobs') == 1, 'Malformed session build command')
    old_manifest = Path(command[command.index('--manifest-path') + 1])
    require(old_manifest.is_absolute() and old_manifest.name == 'Cargo.toml'
            and '..' not in old_manifest.parts, 'Invalid original source manifest path')
    old_source = old_manifest.parent
    cache = build.validate_cache(path(ROOT / 'artifacts/cosmic-cargo-cache', directory=True))
    records = copy.deepcopy(report['cargo_dependencies'])
    metadata = copy.deepcopy(metadata)

    def remap(name, spec):
        old = Path(name)
        require(old.is_absolute() and '..' not in old.parts, 'Dependency manifest path is not absolute')
        if spec is None:
            require(old.is_relative_to(old_source), 'Local Cargo dependency escapes recorded source')
            return str(path(old.relative_to(old_source), root=exported))
        require(isinstance(spec, str) and (spec.startswith('registry+') or
                re.fullmatch(r'git\+https://[^\s#]+#[0-9a-f]{40}', spec)),
                'Cargo dependency source is not pinned')
        base = cache / ('registry/src' if spec.startswith('registry+') else 'git/checkouts')
        return str(path(old, root=base))

    for package in metadata['packages']:
        package['manifest_path'] = remap(package['manifest_path'], package.get('source'))
    for record in records:
        record['manifest'] = remap(record['manifest'], record['source'])
    require(build.verify_metadata(metadata, exported, cache, recipe) == records,
            'Cargo dependency metadata or source tree changed')
    jobs = int(command[command.index('--jobs') + 1])
    common = ['--manifest-path', str(old_manifest), '--locked', '--offline']
    features = [] if recipe['default_features'] else ['--no-default-features']
    if recipe['features']:
        features += ['--features', ','.join(recipe['features'])]
    cargo = report['toolchain']['tools']['cargo']['path']
    require(command == [cargo, 'build', '--release', '--target', TARGET.rust_target,
                        '--jobs', str(jobs), '--package', recipe['package'], '--bin', recipe['binary'],
                        *common, *features], 'Cargo build command differs from recipe')
    require(report['metadata_command'] == [cargo, 'metadata', '--format-version', '1',
                '--filter-platform', TARGET.rust_target, *common, *features],
            'Cargo metadata command differs from recipe')
    return jobs


def _validate(prefix, origin, component='cosmic-session'):
    program, _ = component_files(component)
    require(isinstance(origin, dict) and set(origin) == ORIGIN_KEYS and origin['schema_version'] == 1,
            'Unsupported cosmic-session origin receipt')
    prefix = artifact(prefix, directory=True)
    output = artifact(origin['output'], directory=True)
    hashes = {}
    report_path = path(output / 'build-report.json')
    bind(report_path, origin['report_sha256'], hashes)
    report = build.load_json(report_path)
    required = {'status': 'cross-built', 'architecture': TARGET.architecture, 'target': TARGET.rust_target,
                'guest_execution': 'not performed', 'cosmic_session_ready': False, 'operation': 'build',
                'link_completed': True, 'target_linked': True, 'cargo_offline': True,
                'build_script_network_sandbox': False, 'source_preserved': True}
    require(all(type(report.get(key)) is type(value) and report[key] == value
                for key, value in required.items()), 'Receipt is not a preserved real session cross-build')
    recipe_path = path(origin['recipe_path'], root=ROOT)
    resource_path = path(origin['resource_path'], root=ROOT)
    bind(recipe_path, report['recipe_sha256'], hashes)
    bind(resource_path, origin['resource_sha256'], hashes)
    component_builder = component == 'cosmic-settings-daemon'
    builder_name = 'build_cosmic_component.py' if component_builder else 'build_cosmic.py'
    bind(path(ROOT / 'tools' / builder_name), report['builder_sha256'], hashes)
    if component_builder:
        bind(path(ROOT / 'tools/build_cosmic.py'), report['common_builder_sha256'], hashes)
    manifest = ports.load_manifest()
    source, original, recipe = build.source_and_recipe(component, recipe_path, manifest,
                                                        ROOT / 'artifacts/cosmic-sources')
    require(report['component'] == source and report['recipe'] == recipe
            and recipe['package'] == recipe['binary'] == component
            and recipe['target'] == TARGET.rust_target, 'Wrong session source or recipe identity')
    exported = artifact(origin['source_export'], directory=True)
    require(build.tree_identity(exported) == report['source_tree'], 'Preserved source export changed')
    bind(path(exported / 'Cargo.lock'), recipe['effective_lock_sha256'], hashes)
    validate_patches(recipe, recipe_path, report, origin, Path(original['path']), exported, hashes)
    require(isinstance(origin['logs_sha256'], dict) and set(origin['logs_sha256']) == set(LOGS),
            'Origin must bind all Cargo metadata and log files')
    for name in LOGS:
        bind(path(output / name), origin['logs_sha256'][name], hashes)
    metadata_report = report
    if component_builder:
        if __package__:
            from .build_cosmic_component import local_package
        else:
            from build_cosmic_component import local_package
        command = report['command']
        require(command.count('--manifest-path') == command.count('--package') == 1,
                'Malformed exact-package command')
        old_source = Path(command[command.index('--manifest-path') + 1]).parent
        selected = local_package(build.load_json(output / 'metadata.json'), old_source, recipe)
        require(report['package_id'] == selected == command[command.index('--package') + 1],
                'Build selected a different Cargo package ID')
        # Reuse the ordinary dependency/command validator after separately
        # validating the exact ID against the actual recorded root manifest.
        metadata_report = copy.deepcopy(report)
        metadata_report['command'][command.index('--package') + 1] = recipe['package']
    jobs = validate_metadata(metadata_report, recipe, output, exported)
    profile = build.select_profile(build.load_json(resource_path), recipe['resource_profile'], jobs, TARGET)
    require(profile == report['resource_profile'] and canonical_hash(profile) == report['profile_sha256'],
            'Resource profile changed')
    validate_toolchain(report, recipe, output, origin, hashes)
    original_elf = path(output / program)
    linked = path(output / 'target' / TARGET.rust_target / 'release' / component)
    require(report['linked_binary'] == {'path': str(linked), 'bytes': linked.stat().st_size,
                                        'sha256': build.digest(linked)}, 'Original link output changed')
    executable = inspect_elf(original_elf, TARGET)
    require(executable == report['executable']
            and executable['sha256'] == report['linked_binary']['sha256'], 'Published ELF differs from link output')
    pages = sum((p['vaddr'] + p['memsz'] + 4095)//4096 - p['vaddr']//4096
                for p in executable['program_headers'] if p['type'] == 1)
    require(pages == report['image_load_pages'] and executable['bytes'] <= profile['max_elf_bytes']
            and pages * 4096 + profile['stack_bytes'] <= profile['image_bytes'], 'ELF exceeds build resource bounds')
    copied = path(prefix / program)
    for selected in (original_elf, linked, copied):
        bind(selected, executable['sha256'], hashes)
    inspect_elf(copied, TARGET)
    return {'status': 'VALIDATED_NOT_RUN', 'origin': origin, 'report': report,
            'output': str(output), 'validated_output': str(prefix), 'inputhashes': dict(sorted(hashes.items())),
            'source_tree_sha256': report['source_tree']['sha256'], 'dependency_count': len(report['cargo_dependencies']),
            'guest_execution': 'not performed by receipt validation', 'cosmic_session_ready': False}


def validate_inputs(prefix, *, component='cosmic-session'):
    """Validate a curated executable and its origin without executing native tools."""
    prefix = artifact(prefix, directory=True)
    _, receipt = component_files(component)
    origin_path = path(prefix / receipt)
    result = _validate(prefix, build.load_json(origin_path), component)
    result['inputhashes'][str(origin_path)] = build.digest(origin_path)
    return result


def record_origin(output, recipe, resource, source_export, prefix, *, patch_manifests=(),
                  component='cosmic-session'):
    """Validate then create one fresh receipt; caller copies the real ELF first."""
    output = artifact(output, directory=True)
    prefix = artifact(prefix, directory=True)
    _, receipt = component_files(component)
    receipt_path = prefix / receipt
    require(not receipt_path.exists() and not receipt_path.is_symlink(), 'Preserving existing session origin receipt')
    recipe, resource = path(recipe, root=ROOT), path(resource, root=ROOT)
    source_export = artifact(source_export, directory=True)
    report_path = path(output / 'build-report.json')
    report = build.load_json(report_path)
    origin = {'schema_version': 1, 'output': str(output), 'report_sha256': build.digest(report_path),
              'recipe_path': str(recipe), 'resource_path': str(resource),
              'resource_sha256': build.digest(resource), 'source_export': str(source_export),
              'logs_sha256': {name: build.digest(path(output / name)) for name in LOGS},
              'patch_manifests': [{'path': str(path(item, root=ROOT)), 'sha256': build.digest(path(item, root=ROOT))}
                                  for item in patch_manifests],
              'rust_libraries_sha256': rust_libraries(report)}
    _validate(prefix, origin, component)
    with receipt_path.open('x') as stream:
        stream.write(json.dumps(origin, indent=2) + '\n')
    return origin
