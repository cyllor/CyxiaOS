#!/usr/bin/env python3
"""Offline, bounded link of the real pinned COSMIC configuration libraries.

The original compositor build linked but failed ELF admission. Reusing its
verified libraries does not promote that build or claim a working COSMIC session.
Only ``build`` invokes rustc, under the shared native lease and into fresh artifacts.
``validate`` also supports a byte-identical receipt and ELF in a curated directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

if __package__:
    from .build_sysroot import BuildError, inspect_elf
    from .build_cosmic import clean_environment, run_bounded, CosmicBuildError
    from .native_session import native_lease, idle_native_host, DEFAULT_NATIVE_LOCK
    from .target_profile import profile_for
else:
    from build_sysroot import BuildError, inspect_elf
    from build_cosmic import clean_environment, run_bounded, CosmicBuildError
    from native_session import native_lease, idle_native_host, DEFAULT_NATIVE_LOCK
    from target_profile import profile_for

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts'
MANIFEST = ROOT / 'ports/cosmic/config/library-inputs.json'
SOURCE = ROOT / 'ports/cosmic/config/client.rs'
DEFAULT_COSMIC_BUILD = ARTIFACTS / 'v017-dbus-20261115-r1/cosmic-build'
DEFAULT_SDK = ARTIFACTS / 'sysroot/x86_64-musl'
TARGET = 'x86_64-unknown-linux-musl'
SEARCH_ROOTS = ('target/' + TARGET + '/release/deps', 'target/release/deps', 'native')
EXTERN_NAMES = ('cosmic_config', 'cosmic_settings_config')
EXECUTABLE = 'cosmic-config.elf'
RECEIPT = 'cosmic-config-build-report.json'
TIMEOUT_SECONDS = 120
MIN_FREE_BYTES = 1024 ** 3
MAX_OUTPUT_BYTES = 128 * 1024 ** 2
MAX_JSON_BYTES = 8 * 1024 ** 2
NATIVE_NAMES = ('libc.a', 'libclang_rt.builtins-x86_64.a', 'libxkbcommon.a',
                'crt1.o', 'crti.o', 'crtn.o')


def require(condition, message):
    if not condition:
        raise BuildError(message)


def plain_path(path):
    path = Path(path).absolute()
    require('..' not in path.parts, 'Path traversal is forbidden: ' + str(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)),
            'Symlink input/output is forbidden: ' + str(path))
    return path


def relative_path(value):
    require(isinstance(value, str) and '\x00' not in value and '\\' not in value,
            'Invalid relative input path')
    path = PurePosixPath(value)
    require(bool(path.parts) and not path.is_absolute() and '..' not in path.parts
            and str(path) == value, 'Unsafe relative input path')
    return str(path)


def file_identity(path):
    path = plain_path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'Input is not a regular file: ' + str(path))
        sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    current = path.stat(follow_symlinks=False)
    fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(fingerprint(before) == fingerprint(after) == fingerprint(current),
            'Input changed while hashing: ' + str(path))
    return {'bytes': before.st_size, 'sha256': sha256}


def file_hash(path):
    return file_identity(path)['sha256']


def file_map(directory, *, allow_internal_links=False):
    directory = plain_path(directory)
    require(directory.is_dir(), 'Missing input directory: ' + str(directory))
    result = {}
    for path in sorted(directory.rglob('*')):
        key = str(path.relative_to(directory))
        if path.is_symlink():
            require(allow_internal_links, 'Symlink in input tree: ' + str(path))
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(directory) and (resolved.is_file() or resolved.is_dir()),
                    'SDK symlink escapes its tree: ' + str(path))
            result[key] = {'symlink': os.readlink(path)}
        elif path.is_file():
            result[key] = file_identity(path)
        else:
            require(path.is_dir(), 'Unsupported input tree entry: ' + str(path))
    return result


def map_hash(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify_tree(directory, expected, *, allow_internal_links=False):
    actual = file_map(directory, allow_internal_links=allow_internal_links)
    require(actual == expected, 'Input search tree changed: ' + str(directory))
    return actual


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path):
    identity = file_identity(path)
    require(identity['bytes'] <= MAX_JSON_BYTES, 'JSON input exceeds byte budget')
    data = Path(path).read_bytes()
    require(hashlib.sha256(data).hexdigest() == identity['sha256'], 'JSON changed while reading')
    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as error:
        raise BuildError('Invalid JSON input: ' + str(path)) from error


def load_manifest(path=MANIFEST):
    manifest = read_json(path)
    require(manifest.get('schema_version') == 1 and manifest.get('target') == TARGET,
            'Unsupported COSMIC library manifest')
    require(manifest.get('reuse') == 'pinned-compiled-libraries-from-failed-compositor-admission',
            'Library reuse must be explicit')
    require(set(manifest.get('search_roots', {})) == set(SEARCH_ROOTS), 'Unexpected library search roots')
    require(set(manifest['search_roots']['native']) == {'libunwind.a'},
            'Native Rust search root must expose only official unwind')
    require(set(manifest.get('externs', {})) == set(EXTERN_NAMES), 'Unexpected direct library set')
    for root, files in manifest['search_roots'].items():
        relative_path(root)
        require(isinstance(files, dict) and bool(files), 'Empty library search root')
        for name, identity in files.items():
            relative_path(name)
            require(isinstance(identity, dict) and set(identity) == {'bytes', 'sha256'} and
                    isinstance(identity['bytes'], int) and identity['bytes'] >= 0 and
                    re.fullmatch('[0-9a-f]{64}', identity['sha256']), 'Invalid library file identity')
    for path in manifest['externs'].values(): relative_path(path)
    require(manifest.get('lock', {}).get('path') == 'artifacts/cosmic-sources/cosmic-comp-epoch/Cargo.lock',
            'Unexpected upstream lock path')
    sdk = manifest.get('sdk', {})
    require(set(sdk.get('native_inputs', {})) == {'sysroot/usr/lib/' + name for name in NATIVE_NAMES},
            'Unexpected SDK native input closure')
    hashes = [manifest.get('build_report_sha256'), manifest.get('metadata_sha256'),
              manifest['lock'].get('sha256'), sdk.get('report_sha256'),
              sdk.get('sysroot_sha256'), sdk.get('bin_sha256'), *sdk['native_inputs'].values()]
    require(all(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h) for h in hashes),
            'Invalid pinned input digest')
    toolchain = manifest.get('toolchain', {})
    rustc = plain_path(toolchain.get('rustc', ''))
    require(rustc.name == 'rustc' and rustc.parent.name == 'bin' and
            toolchain.get('host') == 'aarch64-apple-darwin', 'Unexpected Rust toolchain layout')
    rustlib = rustc.parent.parent / 'lib/rustlib'
    require(set(toolchain.get('trees', {})) == {
        str(rustlib / TARGET / 'lib'), str(rustlib / toolchain['host'] / 'lib')},
        'Unexpected Rust standard library roots')
    required_tools = {str(rustc), '/usr/bin/clang',
                      str(rustlib / toolchain['host'] / 'bin/rust-lld'), str(Path(sys.executable).resolve())}
    required_tools.update(str(p) for p in (rustc.parent.parent / 'lib').glob('*.dylib'))
    require(set(toolchain.get('files', {})) == required_tools, 'Unexpected Rust/link tool closure')
    require(all(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h)
                for h in [*toolchain['files'].values(), *toolchain['trees'].values()]),
            'Invalid toolchain digest')
    return manifest


def original_outcome(report):
    require(report.get('status') == 'failed' and report.get('link_completed') is True and
            report.get('target_linked') is False and report.get('target') == TARGET and
            report.get('architecture') == 'x86_64' and
            report.get('error') == 'Invalid LOAD bounds, alignment or W^X permissions' and
            report.get('resource_profile', {}).get('max_elf_bytes') == 16 * 1024 ** 2 and
            report.get('resource_profile', {}).get('image_bytes') == 16 * 1024 ** 2,
            'Original compositor receipt is not the pinned failed admission')
    return {key: report[key] for key in ('status', 'link_completed', 'target_linked', 'error')}


def resolve_externs(cosmic_build, expected):
    require(set(expected) == set(EXTERN_NAMES), 'Unexpected direct library set')
    result = {}
    directory = plain_path(cosmic_build) / SEARCH_ROOTS[0]
    for name in EXTERN_NAMES:
        relative = relative_path(expected[name])
        candidates = list(directory.glob('lib' + name + '-*.rlib'))
        require(len(candidates) == 1, 'Ambiguous or missing direct rlib: ' + name)
        path = plain_path(candidates[0])
        require(str(path.relative_to(cosmic_build)) == relative, 'Direct library path changed: ' + name)
        file_hash(path)
        result[name] = str(path)
    return result


def dependency_records(metadata, original):
    """Use Cargo's retained resolved graph without invoking Cargo or any build script."""
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    starts = [p['id'] for p in packages.values() if p['name'] in ('cosmic-config', 'cosmic-settings-config')]
    require(len(starts) == 2, 'Missing or ambiguous COSMIC source packages')
    pending, seen = list(starts), set()
    while pending:
        current = pending.pop()
        if current in seen: continue
        seen.add(current)
        pending.extend(nodes[current]['dependencies'])
    records = []
    for package in sorted((packages[i] for i in seen), key=lambda p: p['id']):
        matches = [r for r in original['cargo_dependencies']
                   if (r['name'], r['version'], r['source'], r['manifest']) ==
                   (package['name'], package['version'], package['source'], package['manifest_path'])]
        require(len(matches) == 1, 'Missing/ambiguous original source record: ' + package['id'])
        record = matches[0]
        source = plain_path(record['manifest']).parent
        require(source.is_relative_to(ROOT / 'artifacts/cosmic-cargo-cache'), 'Dependency source outside pinned cache')
        require(map_hash(file_map(source)) == record['source_tree_sha256'],
                'Current dependency source changed: ' + record['name'])
        records.append(record)
    return records


def producer_identity():
    paths = [Path(__file__).resolve(), SOURCE]
    paths += [ROOT / 'tools' / name for name in (
        'build_sysroot.py', 'build_cosmic.py', 'target_profile.py', 'native_session.py',
        'desktop_ports.py', 'cosmic_ports.py', 'cosmic_dependencies.py')]
    return {str(path): file_hash(path) for path in paths}


def capture_inputs(cosmic_build, sdk, manifest=MANIFEST):
    cosmic_build, sdk, manifest = map(plain_path, (cosmic_build, sdk, manifest))
    pinned = load_manifest(manifest)
    original_path = cosmic_build / 'build-report.json'
    require(file_hash(original_path) == pinned['build_report_sha256'], 'Original build-report changed')
    original = read_json(original_path)
    outcome = original_outcome(original)
    metadata_path = cosmic_build / 'metadata.json'
    require(file_hash(metadata_path) == pinned['metadata_sha256'], 'Retained dependency metadata changed')
    searches = {root: verify_tree(cosmic_build / root, pinned['search_roots'][root]) for root in SEARCH_ROOTS}
    externs = resolve_externs(cosmic_build, pinned['externs'])
    records = dependency_records(read_json(metadata_path), original)
    lock = ROOT / relative_path(pinned['lock']['path'])
    require(file_hash(lock) == pinned['lock']['sha256'] == original['recipe']['effective_lock_sha256'],
            'Current source Cargo.lock changed')
    toolchain = pinned['toolchain']
    rustc = plain_path(toolchain['rustc'])
    require(str(rustc) == original['toolchain']['tools']['rustc']['path'] and
            file_hash(rustc) == original['toolchain']['tools']['rustc']['sha256'], 'Original Rust compiler changed')
    for path, expected in toolchain['files'].items():
        require(file_hash(path) == expected, 'Rust/link tool changed: ' + path)
    for path, expected in toolchain['trees'].items():
        require(map_hash(file_map(path)) == expected, 'Rust standard library tree changed: ' + path)
    for kind in ('std', 'unwind'):
        source = original['toolchain'][kind]
        require(file_hash(source['path']) == source['sha256'], 'Original Rust ' + kind + ' changed')
    require(searches['native']['libunwind.a']['sha256'] == original['toolchain']['unwind']['sha256'],
            'Native unwind differs from official Rust target unwind')
    target = profile_for('x86_64')
    sdk_report_path = sdk / 'build-report.json'
    require(file_hash(sdk_report_path) == pinned['sdk']['report_sha256'], 'SDK producer receipt changed')
    sdk_report = read_json(sdk_report_path)
    target.require_report(sdk_report)
    sdk_tree = file_map(sdk / 'sysroot', allow_internal_links=True)
    sdk_bin = file_map(sdk / 'bin')
    require(map_hash(sdk_tree) == pinned['sdk']['sysroot_sha256'] and
            map_hash(sdk_bin) == pinned['sdk']['bin_sha256'], 'Read-only SDK identity changed')
    native = {}
    original_native = {entry['path']: entry['sha256'] for entry in original['toolchain']['native_inputs']}
    for relative, expected in pinned['sdk']['native_inputs'].items():
        path = sdk / relative_path(relative)
        require(original_native.get(relative) == expected, 'SDK native pin differs from library producer: ' + relative)
        require(file_hash(path) == expected, 'SDK native input changed: ' + relative)
        native[relative] = target.inspect_archive(path) if path.suffix == '.a' else file_identity(path)
    require(native['sysroot/usr/lib/libc.a']['sha256'] == sdk_report['libc_sha256'], 'SDK libc producer differs')
    # The fixed SDK wrapper embeds these paths; rejecting relocation prevents a
    # selected copy from silently linking the old SDK instead of the selected one.
    cc = target.cc(sdk)
    wrapper = cc.read_text()
    require(str(sdk / 'sysroot/usr/lib') in wrapper and str(sdk / 'bin/ld.lld') in wrapper,
            'SDK compiler wrapper refers to a different SDK')
    return {'cosmic_build': str(cosmic_build), 'sdk': str(sdk),
            'manifest': {'path': str(manifest), 'sha256': file_hash(manifest)},
            'original_build_report_sha256': pinned['build_report_sha256'], 'original_build_outcome': outcome,
            'library_reuse': pinned['reuse'], 'search_roots': searches, 'externs': externs,
            'metadata_sha256': pinned['metadata_sha256'], 'dependency_records': records,
            'lock': {'path': str(lock), 'sha256': file_hash(lock)},
            'rustc': str(rustc), 'toolchain_root': str(rustc.parent.parent), 'toolchain': toolchain,
            'source': str(SOURCE), 'producer_sha256': producer_identity(),
            'sdk_report_sha256': pinned['sdk']['report_sha256'], 'sdk_tree': sdk_tree,
            'sdk_bin': sdk_bin, 'native_inputs': native}


def validate_output(output, cosmic_build, sdk):
    output = plain_path(output)
    require(output.is_relative_to(plain_path(ARTIFACTS)) and output != ARTIFACTS,
            'Output must be inside repository artifacts')
    require(not output.exists(), 'Output must be fresh; existing evidence is never overwritten')
    for source in map(plain_path, (cosmic_build, sdk, ROOT / 'artifacts/cosmic-cargo-cache',
                                  ROOT / 'artifacts/cosmic-sources')):
        require(not output.is_relative_to(source) and not source.is_relative_to(output),
                'Output must not overlap read-only input trees')
    return output


def link_command(inputs, output):
    cosmic, sdk = Path(inputs['cosmic_build']), Path(inputs['sdk'])
    command = [inputs['rustc'], inputs['source'], '--edition=2024', '--target', TARGET,
               '--sysroot', inputs['toolchain_root'], '-C', 'panic=abort', '-C', 'opt-level=2',
               '-C', 'link-self-contained=no', '-C', 'relocation-model=static',
               '-C', 'target-feature=+crt-static', '-C', 'linker=' + str(sdk / 'bin/x86_64-linux-musl-cc')]
    for root in SEARCH_ROOTS:
        command += ['-L', ('native=' if root == 'native' else 'dependency=') + str(cosmic / root)]
    command += ['-L', 'native=' + str(sdk / 'sysroot/usr/lib'), '-l', 'static=xkbcommon',
                '-o', str(output / (EXECUTABLE + '.pending'))]
    for name in EXTERN_NAMES: command += ['--extern', name + '=' + inputs['externs'][name]]
    return command


def write_report(output, report):
    pending = output / (RECEIPT + '.pending')
    pending.write_text(json.dumps(report, indent=2) + '\n')
    pending.replace(output / RECEIPT)


def link_environment(output):
    env = clean_environment(str(Path(sys.executable).parent) + ':/usr/bin:/bin:/usr/sbin:/sbin')
    env['TMPDIR'] = str(output / 'tmp')
    return env


def build(output, cosmic_build=DEFAULT_COSMIC_BUILD, sdk=DEFAULT_SDK, *, manifest=MANIFEST,
          native_lock=DEFAULT_NATIVE_LOCK):
    output = validate_output(output, cosmic_build, sdk)
    with native_lease(native_lock):
        idle_native_host()
        validate_output(output, cosmic_build, sdk)
        before = capture_inputs(cosmic_build, sdk, manifest)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'tmp').mkdir()
        report = {'schema_version': 1, 'status': 'building', 'architecture': 'x86_64', 'target': TARGET,
                  'output': str(output), 'inputs_before': before, 'input_preserved': False,
                  'guest_execution': 'not performed', 'cosmic_session_ready': False,
                  'native_lock': str(plain_path(native_lock)), 'network_requested': False,
                  'limits': {'timeout_seconds': TIMEOUT_SECONDS, 'min_free_bytes': MIN_FREE_BYTES,
                             'max_output_bytes': MAX_OUTPUT_BYTES}}
        write_report(output, report)
        try:
            command = link_command(before, output)
            report['command'] = command
            env = link_environment(output)
            report['environment'] = env
            run_bounded(command, ROOT, env, output / 'link.log', TIMEOUT_SECONDS,
                        MIN_FREE_BYTES, MAX_OUTPUT_BYTES, budget_root=output)
            pending = output / (EXECUTABLE + '.pending')
            file_hash(pending)
            inspect_elf(pending, profile_for('x86_64'))
            report['inputs_after'] = capture_inputs(cosmic_build, sdk, manifest)
            require(report['inputs_after'] == before, 'Pinned inputs changed during config client link')
            pending.replace(output / EXECUTABLE)
            report.update(status='cross-built', input_preserved=True,
                          executable=inspect_elf(output / EXECUTABLE, profile_for('x86_64')),
                          link_log_sha256=file_hash(output / 'link.log'))
            write_report(output, report)
            return report
        except BaseException as error:
            report.update(status='failed', error=str(error))
            write_report(output, report)
            raise


def validate_inputs(directory, *, receipt=RECEIPT):
    requested = plain_path(directory)
    require(receipt == RECEIPT, 'Unexpected receipt name')
    receipt_path = requested / receipt
    receipt_hash = file_hash(receipt_path)
    report = read_json(receipt_path)
    require(report.get('schema_version') == 1 and report.get('status') == 'cross-built' and
            report.get('architecture') == 'x86_64' and report.get('target') == TARGET and
            report.get('input_preserved') is True and report.get('cosmic_session_ready') is False and
            report.get('guest_execution') == 'not performed' and report.get('network_requested') is False,
            'Receipt does not describe the bounded cross-build contract')
    origin = plain_path(report['output'])
    require(origin.is_relative_to(ARTIFACTS) and origin != ARTIFACTS, 'Original output is outside artifacts')
    require(file_hash(origin / RECEIPT) == receipt_hash, 'Curated copy must retain the exact original receipt')
    before = report['inputs_before']
    current = capture_inputs(before['cosmic_build'], before['sdk'], before['manifest']['path'])
    require(current == before == report.get('inputs_after'), 'Build input identity changed')
    require(report.get('command') == link_command(before, origin), 'Receipt link command changed')
    require(report.get('environment') == link_environment(origin), 'Receipt compiler environment changed')
    require(report.get('limits') == {'timeout_seconds': TIMEOUT_SECONDS, 'min_free_bytes': MIN_FREE_BYTES,
                                     'max_output_bytes': MAX_OUTPUT_BYTES}, 'Receipt resource limits changed')
    require(file_hash(origin / 'link.log') == report['link_log_sha256'], 'Link log changed')
    original = origin / EXECUTABLE
    require(file_hash(original) == report['executable']['sha256'] and
            inspect_elf(original, profile_for('x86_64')) == report['executable'], 'Original executable changed')
    copied = requested / EXECUTABLE
    require(file_hash(copied) == report['executable']['sha256'], 'Curated executable changed')
    inspect_elf(copied, profile_for('x86_64'))
    return {'receipt_sha256': receipt_hash, 'output': str(origin), 'validated_output': str(requested),
            'artifacts': {str(copied): report['executable']['sha256']}, 'report': report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inventory', 'build', 'validate'), nargs='?', default='inventory')
    parser.add_argument('--cosmic-build', type=Path, default=DEFAULT_COSMIC_BUILD)
    parser.add_argument('--sdk', type=Path, default=DEFAULT_SDK)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'inventory':
            print(json.dumps({'target': TARGET, 'source': str(SOURCE), 'manifest': str(MANIFEST),
                              'cosmic_build': str(args.cosmic_build), 'sdk': str(args.sdk),
                              'operation': 'read-only-inventory', 'reuse': 'real pinned compiled COSMIC libraries'}))
        elif args.operation == 'validate':
            require(args.output is not None, 'validate requires --output')
            result = validate_inputs(args.output)
            print(json.dumps({key: value for key, value in result.items() if key != 'report'}, indent=2))
        else:
            require(args.output is not None, 'build requires an explicit fresh --output inside artifacts')
            build(args.output, args.cosmic_build, args.sdk, native_lock=args.native_lock)
            print(args.output / RECEIPT)
        return 0
    except (BuildError, CosmicBuildError, OSError, ValueError, KeyError, TypeError) as error:
        print('COSMIC config build: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
