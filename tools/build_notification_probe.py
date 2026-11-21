#!/usr/bin/env python3
"""Build a genuine libdbus notification client from immutable target inputs.

Requires the retained output of build_dbus.py and the exact SDK used there.
Revalidates its upstream/source/ABI/command evidence before and after linking.
No fetch, installation into either input, service substitute, or guest run.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

if __package__:
    from . import build_dbus
    from .build_cosmic import CosmicBuildError, no_symlink_path, run_bounded
    from .build_pipe_capacity_probe import file_identity, sdk_identity, tool_identity
    from .build_sysroot import ROOT, Builder as GenericBuilder, BuildError, inspect_elf, toolchain
    from .native_session import idle_native_host, native_lease
    from .target_profile import profile_for
else:
    import build_dbus
    from build_cosmic import CosmicBuildError, no_symlink_path, run_bounded
    from build_pipe_capacity_probe import file_identity, sdk_identity, tool_identity
    from build_sysroot import ROOT, Builder as GenericBuilder, BuildError, inspect_elf, toolchain
    from native_session import idle_native_host, native_lease
    from target_profile import profile_for

SOURCE = ROOT / 'user/ported/notification_probe.c'
POLICY = ROOT / 'ports/cosmic/native-notifications/source-policy.json'
EXECUTABLE = 'notification-probe.elf'
RECEIPT = 'build-report.json'
NATIVE_LOCK = ROOT / 'artifacts/v017-cosmic-completion-20261116/native-session.lock'
TIMEOUT_SECONDS = 120
MIN_FREE_BYTES = 1024 ** 3
MAX_OUTPUT_BYTES = 64 * 1024 ** 2
SERVER_IDENTITY = {'name': 'cosmic-notifications', 'vendor': 'System76',
                   'version': '1.10.0', 'spec_version': '1.2',
                   'commit': '1e4c1f11fdcae273d6954fd0bfc54749a6145267'}


def require(value, message):
    if not value:
        raise BuildError(message)


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def producer_sources(entry):
    """Hash the local import closure without importing a guest/OS entry point."""
    pending, result = [no_symlink_path(entry)], {}
    while pending:
        path = pending.pop()
        key = path.relative_to(ROOT).as_posix()
        if key in result:
            continue
        identity = file_identity(path)
        require(identity['bytes'] <= 2 * 1024 ** 2, 'Producer source exceeds its read budget')
        with path.open('rb') as stream:
            raw = stream.read(2 * 1024 ** 2 + 1)
        require(len(raw) == identity['bytes'] and
                hashlib.sha256(raw).hexdigest() == identity['sha256'], 'Producer changed while reading')
        result[key] = identity['sha256']
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module] if node.module else [item.name for item in node.names]
            else:
                continue
            for name in names:
                local = ROOT / 'tools' / (name.split('.')[0] + '.py')
                if local.is_file():
                    pending.append(no_symlink_path(local))
    return dict(sorted(result.items()))


def producer_identity():
    identity = file_identity(POLICY)
    policy = json.loads(POLICY.read_text())
    require(policy.get('component') == 'cosmic-notifications' and
            policy.get('commit') == SERVER_IDENTITY['commit'],
            'Notification probe identity requires its reviewed upstream version')
    return {'python': producer_sources(__file__), 'source': file_identity(SOURCE),
            'notification_source_policy': identity}


def dbus_identity(directory, sdk, target):
    # This is the original strict validator, including source archives/trees,
    # licenses, all tool/config/log hashes, complete preserved SDK, target
    # archives, executables, headers and reviewed real session-bus policy.
    proof = build_dbus.validate_build(directory)
    report = proof['report']
    target.require_report(report)
    require(Path(proof['output']) == directory and Path(proof['validated_output']) == directory,
            'Use the original retained D-Bus build output, not a detached receipt')
    require(report['architecture'] == target.architecture and Path(report['sdk']['path']) == sdk,
            'D-Bus library and notification client must use the same target SDK')
    stage = directory / 'stage'
    archives = {}
    for name in ('libdbus-1.a', 'libexpat.a'):
        path = stage / 'usr/lib' / name
        archive = target.inspect_archive(path)
        component = 'dbus' if name == 'libdbus-1.a' else 'expat'
        require(archive == report[component]['archive'], 'D-Bus link archive differs from its receipt')
        archives[name] = archive
    for relative in ('usr/include/dbus-1.0/dbus/dbus.h',
                     'usr/lib/dbus-1.0/include/dbus/dbus-arch-deps.h'):
        require(file_identity(stage / relative)['sha256'] == report['stage_files'][relative],
                'D-Bus target header differs from its receipt')
    return {'path': str(directory), 'receipt': file_identity(directory / 'dbus-build-report.json'),
            'validation_sha256': json_digest(proof), 'target_archives': archives,
            'stage_files': report['stage_files'], 'session': report['session']}


def validate_output(output, *inputs):
    output = no_symlink_path(output)
    require(not output.exists(), 'Output must be fresh; existing evidence is never overwritten')
    for directory in inputs:
        require(not output.is_relative_to(directory) and not directory.is_relative_to(output),
                'Output must be separate from both read-only SDK and D-Bus inputs')
    return output


class Builder(GenericBuilder):
    """Use the existing compiler runner shape with an explicit total budget."""
    def __init__(self, output, tools, target):
        super().__init__(output, tools, 1, target)
        self.deadline = time.monotonic() + TIMEOUT_SECONDS

    def run(self, command, log, cwd=None):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'Notification client build deadline exceeded')
        command = [str(item) for item in command]
        self.commands.append(command)
        try:
            run_bounded(command, cwd or self.output, self.env, self.output / 'logs' / log,
                        remaining, MIN_FREE_BYTES, MAX_OUTPUT_BYTES, budget_root=self.output)
        except CosmicBuildError as error:
            raise BuildError(str(error)) from error


def build(output, sysroot, dbus_build, architecture='x86_64', *, native_lock=NATIVE_LOCK, panel_clear=False):
    target = profile_for(architecture)
    sdk = no_symlink_path(sysroot).resolve(strict=True)
    dbus = no_symlink_path(dbus_build).resolve(strict=True)
    require(sdk.is_dir() and dbus.is_dir(), 'SDK and D-Bus inputs must be real directories')
    output = validate_output(output, sdk, dbus)
    lock = no_symlink_path(native_lock)
    require(not lock.is_relative_to(sdk) and not lock.is_relative_to(dbus),
            'Shared native lease cannot modify a read-only input')
    lock.parent.mkdir(parents=True, exist_ok=True)
    with native_lease(lock):
        idle_native_host()
        output = validate_output(output, sdk, dbus)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'logs').mkdir()
        report = {'schema_version': 1, 'status': 'FAILED', 'architecture': target.architecture,
                  'target': target.c_target, 'target_profile': target.identity(),
                  'source_root': str(ROOT), 'source': str(SOURCE),
                  'expected_server': SERVER_IDENTITY, 'capture_window_ms': 0 if panel_clear else 5000,
                  'panel_clear': panel_clear,
                  'guest_execution': False, 'notifications_verified': False,
                  'render_verified': False, 'cosmic_session_verified': False,
                  'native_lock': str(lock),
                  'limits': {'timeout_seconds': TIMEOUT_SECONDS, 'min_free_bytes': MIN_FREE_BYTES,
                             'max_output_bytes': MAX_OUTPUT_BYTES}}
        try:
            report['producer_inputs'] = producer_identity()
            report['sdk'] = sdk_identity(sdk, target)
            report['dbus'] = dbus_identity(dbus, sdk, target)
            tools = toolchain()
            report['toolchain'] = tool_identity(tools)
            builder = Builder(output, tools, target)
            report['commands'] = builder.commands
            builder.run([tools['clang'], '--version'], 'clang-version.log')
            builder.run([tools['rust-lld'], '-flavor', 'gnu', '--version'], 'linker-version.log')
            report['tool_versions'] = {name: (output / 'logs' / log).read_text()
                for name, log in [('clang', 'clang-version.log'), ('rust-lld', 'linker-version.log')]}
            stage = dbus / 'stage'
            library = sdk / 'sysroot/usr/lib'
            obj = output / 'notification-probe.o'
            temporary = output / (EXECUTABLE + '.tmp')
            mode = ['-DNOTIFICATION_PROBE_PANEL_CLEAR=1'] if panel_clear else []
            builder.run([tools['clang'], *target.clang_args, '-nostdinc', '-isystem',
                         sdk / 'sysroot/usr/include', '-I', stage / 'usr/include/dbus-1.0',
                         '-I', stage / 'usr/lib/dbus-1.0/include', '-std=c11', '-O2',
                         '-ffp-contract=off', '-fno-stack-protector', '-fno-pie',
                         '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror',
                         *mode, '-c', SOURCE, '-o', obj], 'compile.log')
            builder.run([tools['rust-lld'], '-flavor', 'gnu', '-m', target.linker_emulation,
                         '--image-base=0x01000000', '-z', 'max-page-size=4096', '-z', 'separate-code',
                         '-static', '--no-pie', '--build-id=sha1', '--gc-sections',
                         '-o', temporary, library / 'crt1.o', library / 'crti.o', obj,
                         '--start-group', stage / 'usr/lib/libdbus-1.a', stage / 'usr/lib/libexpat.a',
                         library / 'libc.a', library / target.builtins_archive, '--end-group',
                         library / 'crtn.o'], 'link.log')
            inspected = inspect_elf(temporary, target)
            require(producer_identity() == report['producer_inputs'], 'Client source or producer changed')
            require(sdk_identity(sdk, target) == report['sdk'], 'Read-only SDK changed')
            require(dbus_identity(dbus, sdk, target) == report['dbus'], 'D-Bus source/build inputs changed')
            require(tool_identity(tools) == report['toolchain'], 'Compiler or linker changed')
            program = output / EXECUTABLE
            temporary.chmod(0o755)
            temporary.replace(program)
            inspected['file'] = str(program)
            report['probe'] = inspected
            report['status'] = 'BUILT_NOT_RUN'
        except BaseException as error:
            report['error'] = str(error)
            raise
        finally:
            report['logs'] = build_dbus.file_map(output / 'logs')
            receipt = output / (RECEIPT + '.tmp')
            receipt.write_text(json.dumps(report, indent=2) + '\n')
            receipt.replace(output / RECEIPT)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--dbus-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--arch', choices=('x86_64', 'aarch64'), default='x86_64')
    parser.add_argument('--native-lock', type=Path, default=NATIVE_LOCK)
    parser.add_argument('--panel-clear', action='store_true', help='Wait for the real UI to close the notification')
    args = parser.parse_args(argv)
    try:
        build(args.output, args.sysroot, args.dbus_build, args.arch, native_lock=args.native_lock,
              panel_clear=args.panel_clear)
        print(args.output.resolve() / RECEIPT)
        return 0
    except (BuildError, CosmicBuildError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('notification-probe: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
