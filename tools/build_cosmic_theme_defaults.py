#!/usr/bin/env python3
"""Source-bound, offline link of the pinned COSMIC built-in theme exporter.

The caller owns the shared native lease. Only the explicit build operation
executes rustc; inventory and validate never invoke a compiler or guest.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

if __package__:
    from . import build_cosmic_config as common
    from . import cosmic_session_inputs as session
    from .build_cosmic import CosmicBuildError, resource_check, run_bounded
    from .build_sysroot import BuildError, inspect_elf
    from .native_session import idle_native_host
    from .target_profile import profile_for
else:
    import build_cosmic_config as common
    import cosmic_session_inputs as session
    from build_cosmic import CosmicBuildError, resource_check, run_bounded
    from build_sysroot import BuildError, inspect_elf
    from native_session import idle_native_host
    from target_profile import profile_for

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts'
SOURCE = ROOT / 'ports/cosmic/theme-defaults/client.rs'
README = SOURCE.with_name('README.md')
DEFAULT_BUILD = ARTIFACTS / 'v017-cosmic-settings-20261115-r1/build-native-04'
DEFAULT_SETTINGS_PREFIX = ARTIFACTS / 'v017-cosmic-settings-20261115-r1/sysroot-settings-01'
SDK = ARTIFACTS / 'sysroot/x86_64-musl'
TARGET = common.TARGET
SEARCH_ROOTS = common.SEARCH_ROOTS
EXTERNS = ('cosmic_config', 'cosmic_theme')
LIBCOSMIC_COMMIT = '5a8bd9482a35ae94c1e54edf77b331c6b970f170'
EXECUTABLE = 'theme-defaults.elf'
RECEIPT = 'cosmic-theme-defaults-build-report.json'
LIMITS = {'jobs': 1, 'timeout_seconds': 120, 'min_free_bytes': 1024 ** 3,
          'max_output_bytes': 256 * 1024 ** 2}
require = common.require


def producer_identity():
    files = [Path(__file__).resolve(), SOURCE, README]
    files += [ROOT / 'tools' / name for name in (
        'build_cosmic_config.py', 'cosmic_session_inputs.py', 'build_cosmic_component.py',
        'build_cosmic.py', 'build_sysroot.py', 'cosmic_dependencies.py', 'cosmic_ports.py',
        'desktop_ports.py', 'target_profile.py', 'native_session.py')]
    return {str(path): common.file_identity(path) for path in files}


def resolve_externs(build):
    directory = common.plain_path(build) / SEARCH_ROOTS[0]
    result = {}
    for name in EXTERNS:
        candidates = sorted(directory.glob('lib' + name + '-*.rlib'))
        require(len(candidates) == 1, 'Missing or ambiguous target rlib: ' + name)
        selected = common.plain_path(candidates[0])
        result[name] = {'path': str(selected), **common.file_identity(selected)}
    return result


def tool_identity(selected):
    selected = Path(selected)
    require(selected.is_absolute() and '..' not in selected.parts, 'Invalid tool path')
    resolved = selected.resolve(strict=True)
    return {'resolved': str(resolved), **common.file_identity(resolved)}


def capture_inputs(settings_prefix):
    proof = session.validate_inputs(settings_prefix, component='cosmic-settings-daemon')
    build = common.plain_path(proof['output'])
    require(build == common.plain_path(DEFAULT_BUILD), 'Expected the actual build-native-04 libraries')
    original = proof['report']
    pinned_source = 'git+https://github.com/pop-os/libcosmic#' + LIBCOSMIC_COMMIT
    for name in ('cosmic-config', 'cosmic-theme'):
        records = [row for row in original['cargo_dependencies'] if row['name'] == name]
        require(len(records) == 1 and records[0]['source'] == pinned_source,
                'Direct library is not the selected pinned libcosmic source: ' + name)
    searches = {name: common.file_map(build / name) for name in SEARCH_ROOTS}
    require(set(searches['native']) == {'libunwind.a'}, 'Unexpected native search inputs')
    require(searches['native']['libunwind.a']['sha256'] == original['toolchain']['unwind']['sha256'],
            'Native unwind differs from the validated Rust target library')
    externs = resolve_externs(build)
    toolchain = original['toolchain']
    rustc = common.plain_path(toolchain['tools']['rustc']['path'])
    rust_root = rustc.parent.parent
    target = profile_for('x86_64')
    sdk_report = SDK / 'build-report.json'
    target.require_report(common.read_json(sdk_report))
    native = {row['path']: common.file_identity(SDK / common.relative_path(row['path']))
              for row in toolchain['native_inputs']}
    require(all(native[row['path']]['sha256'] == row['sha256']
                for row in toolchain['native_inputs']), 'Validated native SDK input changed')
    wrapper = target.cc(SDK).read_text()
    require(str(SDK / 'sysroot/usr/lib') in wrapper and str(SDK / 'bin/ld.lld') in wrapper,
            'SDK wrapper selects another SDK')
    tools = {row['path'] for row in toolchain['tools'].values() if row['available']}
    tools.update((str(Path(sys.executable).resolve()), str(SDK / 'bin/ld.lld'),
                  str(rust_root / 'lib/rustlib' / toolchain['host'] / 'bin/rust-lld')))
    tools.update(str(path) for path in (rust_root / 'lib').glob('*.dylib'))
    rust_trees = {str(rust_root / 'lib/rustlib' / name / 'lib'):
                  common.file_map(rust_root / 'lib/rustlib' / name / 'lib')
                  for name in (TARGET, toolchain['host'])}
    return {'settings_prefix': str(common.plain_path(settings_prefix)),
            'settings_proof': proof, 'cosmic_build': str(build), 'sdk': str(SDK),
            'search_roots': searches, 'externs': externs, 'rustc': str(rustc),
            'toolchain_root': str(rust_root), 'tool_files': {p: tool_identity(p) for p in sorted(tools)},
            'rust_trees': rust_trees, 'sdk_report': common.file_identity(sdk_report),
            'sdk_sysroot': common.file_map(SDK / 'sysroot', allow_internal_links=True),
            'sdk_bin': common.file_map(SDK / 'bin'), 'native_inputs': native,
            'source': common.file_identity(SOURCE), 'producer': producer_identity()}


def artifact_destination(value, protected):
    selected = common.plain_path(value)
    require(selected.is_relative_to(common.plain_path(ARTIFACTS)) and selected != ARTIFACTS,
            'Destination must be inside repository artifacts')
    require(not selected.exists(), 'Destination must be fresh: ' + str(selected))
    for tree in protected:
        tree = common.plain_path(tree)
        require(not selected.is_relative_to(tree) and not tree.is_relative_to(selected),
                'Destination overlaps an input or output tree')
    return selected


def destinations(output, prefix, settings_prefix):
    protected = (DEFAULT_BUILD, SDK, settings_prefix, ARTIFACTS / 'cosmic-cargo-cache',
                 ARTIFACTS / 'cosmic-sources')
    output = artifact_destination(output, protected)
    prefix = artifact_destination(prefix, (*protected, output))
    return output, prefix


def link_command(inputs, output):
    build, sdk = Path(inputs['cosmic_build']), Path(inputs['sdk'])
    # These are the established build_cosmic_config.link_command flags. The
    # direct extern closure changes to cosmic-theme and cosmic-config only.
    command = [inputs['rustc'], str(output / 'client.rs'), '--edition=2024', '--target', TARGET,
               '--sysroot', inputs['toolchain_root'], '-C', 'panic=abort', '-C', 'opt-level=2',
               '-C', 'link-self-contained=no', '-C', 'relocation-model=static',
               '-C', 'target-feature=+crt-static',
               '-C', 'linker=' + str(sdk / 'bin/x86_64-linux-musl-cc')]
    for name in SEARCH_ROOTS:
        command += ['-L', ('native=' if name == 'native' else 'dependency=') + str(build / name)]
    command += ['-L', 'native=' + str(sdk / 'sysroot/usr/lib'), '-l', 'static=xkbcommon',
                '-o', str(output / (EXECUTABLE + '.pending'))]
    for name in EXTERNS:
        command += ['--extern', name + '=' + inputs['externs'][name]['path']]
    return command


def write_report(output, report):
    pending = output / (RECEIPT + '.pending')
    pending.write_text(json.dumps(report, indent=2) + '\n')
    pending.replace(output / RECEIPT)


def build(output, prefix, settings_prefix=DEFAULT_SETTINGS_PREFIX):
    output, prefix = destinations(output, prefix, settings_prefix)
    idle_native_host()
    before = capture_inputs(settings_prefix)
    output, prefix = destinations(output, prefix, settings_prefix)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'tmp').mkdir()
    shutil.copyfile(SOURCE, output / 'client.rs')
    require(common.file_identity(output / 'client.rs') == before['source'], 'Exported source changed')
    report = {'schema_version': 1, 'status': 'building', 'target': TARGET, 'architecture': 'x86_64',
              'output': str(output), 'prefix': str(prefix), 'inputs_before': before,
              'input_preserved': False, 'limits': LIMITS, 'native_lease': 'held by caller',
              'network_requested': False, 'guest_execution': 'not performed',
              'generated_assets_verified': False, 'cosmic_session_ready': False}
    write_report(output, report)
    try:
        command = link_command(before, output)
        environment = common.link_environment(output)
        report.update(command=command, environment=environment)
        write_report(output, report)
        run_bounded(command, ROOT, environment, output / 'link.log', LIMITS['timeout_seconds'],
                    LIMITS['min_free_bytes'], LIMITS['max_output_bytes'], budget_root=output)
        pending = output / (EXECUTABLE + '.pending')
        inspect_elf(pending, profile_for('x86_64'))
        report['inputs_after'] = capture_inputs(settings_prefix)
        require(report['inputs_after'] == before, 'Source-bound inputs changed during exporter link')
        require(common.file_identity(output / 'client.rs') == before['source'], 'Exported source changed')
        pending.replace(output / EXECUTABLE)
        report.update(status='cross-built', input_preserved=True,
                      executable=inspect_elf(output / EXECUTABLE, profile_for('x86_64')),
                      link_log=common.file_identity(output / 'link.log'))
        write_report(output, report)
        # Curated publication is one fresh-directory rename after ELF admission
        # and all input rechecks. A failed compile never creates this prefix.
        staged = output / 'curated.pending'
        staged.mkdir()
        for name in (EXECUTABLE, RECEIPT):
            shutil.copyfile(output / name, staged / name)
            require(common.file_identity(staged / name) == common.file_identity(output / name),
                    'Curated copy differs from verified output')
        resource_check(output, LIMITS['min_free_bytes'], LIMITS['max_output_bytes'])
        prefix.parent.mkdir(parents=True, exist_ok=True)
        require(not prefix.exists() and not prefix.is_symlink(), 'Curated destination appeared')
        staged.rename(prefix)
        return report
    except BaseException as error:
        report.update(status='failed', error=str(error))
        write_report(output, report)
        raise


def validate_inputs(prefix):
    prefix = common.plain_path(prefix)
    require(prefix.is_relative_to(ARTIFACTS) and prefix != ARTIFACTS, 'Prefix outside artifacts')
    receipt = prefix / RECEIPT
    report = common.read_json(receipt)
    required = {'schema_version': 1, 'status': 'cross-built', 'target': TARGET, 'architecture': 'x86_64',
                'input_preserved': True, 'native_lease': 'held by caller', 'network_requested': False,
                'guest_execution': 'not performed', 'generated_assets_verified': False,
                'cosmic_session_ready': False}
    require(all(type(report.get(key)) is type(value) and report[key] == value
                for key, value in required.items()), 'Receipt is not a verified exporter cross-build')
    output = common.plain_path(report['output'])
    require(output.is_relative_to(ARTIFACTS) and output != ARTIFACTS, 'Origin outside artifacts')
    require(common.file_identity(output / RECEIPT) == common.file_identity(receipt),
            'Curated receipt differs from original')
    before = report['inputs_before']
    require(before == report.get('inputs_after') == capture_inputs(before['settings_prefix']),
            'Source-bound inputs changed since exporter link')
    require(common.file_identity(output / 'client.rs') == before['source'], 'Exported source changed')
    require(report.get('command') == link_command(before, output), 'Compiler argv changed')
    require(report.get('environment') == common.link_environment(output), 'Compiler environment changed')
    require(report.get('limits') == LIMITS, 'Build limits changed')
    require(common.file_identity(output / 'link.log') == report.get('link_log'), 'Link log changed')
    for selected in (output / EXECUTABLE, prefix / EXECUTABLE):
        inspected = inspect_elf(selected, profile_for('x86_64'))
        inspected['file'] = str(output / EXECUTABLE)
        require(inspected == report['executable'],
                'Exporter ELF differs from admitted output')
    return {'status': 'VALIDATED_NOT_RUN', 'output': str(output), 'validated_output': str(prefix),
            'receipt_sha256': common.file_hash(receipt), 'executable': report['executable']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inventory', 'build', 'validate'), nargs='?', default='inventory')
    parser.add_argument('--settings-prefix', type=Path, default=DEFAULT_SETTINGS_PREFIX)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--prefix', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'inventory':
            result = {'target': TARGET, 'source': str(SOURCE), 'libcosmic_commit': LIBCOSMIC_COMMIT,
                      'settings_prefix': str(args.settings_prefix), 'library_build': str(DEFAULT_BUILD),
                      'limits': LIMITS, 'operation': 'read-only-inventory', 'guest_execution': 'not performed'}
        elif args.operation == 'validate':
            require(args.prefix is not None, 'validate requires --prefix')
            result = validate_inputs(args.prefix)
        else:
            require(args.output is not None and args.prefix is not None,
                    'build requires fresh --output and --prefix; caller must hold the native lease')
            result = build(args.output, args.prefix, args.settings_prefix)
            result = {key: result[key] for key in ('status', 'output', 'prefix', 'guest_execution')}
        print(json.dumps(result, indent=2))
        return 0
    except (BuildError, CosmicBuildError, OSError, ValueError, KeyError, TypeError) as error:
        print('COSMIC theme defaults: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
