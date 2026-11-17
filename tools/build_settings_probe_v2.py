#!/usr/bin/env python3
"""Build the real settings/Wayland-readiness client from retained native inputs.

The existing settings client source and every production service stay unchanged.
Version 2 independently binds returned watcher connections to the daemon PID,
preserves the original wire/filesystem checks, and diagnoses failed method calls. Building is not guest
execution, service verification, a rendered frame, or a normal COSMIC session.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

if __package__:
    from . import build_notification_probe as base
    from . import cosmic_notifications_elf as elf
else:
    import build_notification_probe as base
    import cosmic_notifications_elf as elf

ROOT = base.ROOT
SOURCE = ROOT / 'user/ported/settings_probe_v2.c'
ORIGINAL_SOURCE = ROOT / 'user/ported/settings_probe.c'
PREVIOUS_SOURCE = ROOT / 'user/ported/settings_probe_v1.c'
POLICY = ROOT / 'ports/cosmic/native-settings-linux-v1/source-policy.json'
SOURCE_SHA256 = '80127ec4321c02bc39ca5c3bb2176461f60bf2211af29e5e5114ce02bd002053'
PREVIOUS_SOURCE_SHA256 = 'd6fb3501686f785ba2d5cccdba915fa457e32b4f55340c9784433c93801520ac'
ORIGINAL_SOURCE_SHA256 = 'c7bd300de2065fb55c4956983053388bb602855da02986ab8b32a0e30045379c'
POLICY_SHA256 = '9491dd501e250ad58f380e2b7c3e0c4d0074c97a86bf01d51bd68e945e562672'
EXECUTABLE = 'settings-probe.elf'
OBJECT = 'settings-probe.o'
RECEIPT = 'build-report.json'
KIND = 'cosmic-settings-probe-v2'
NATIVE_LOCK = base.NATIVE_LOCK
TIMEOUT_SECONDS = base.TIMEOUT_SECONDS
MIN_FREE_BYTES = base.MIN_FREE_BYTES
MAX_OUTPUT_BYTES = base.MAX_OUTPUT_BYTES
FULL_OS = {'image_bytes': 64 * 1024**2, 'max_elf_bytes': 64 * 1024**2,
           'stack_bytes': 2 * 1024**2, 'target_runtime_validated': False}
SERVER_IDENTITY = {'component': 'cosmic-settings-daemon', 'version': '1.10.0',
                   'commit': '9e4ae69fc175191f15789d35423806ea0f093c9d',
                   'service': 'com.system76.CosmicSettingsDaemon',
                   'object': '/com/system76/CosmicSettingsDaemon'}
CLIENT_CONTRACT = {'prepare_argument': 'prepare', 'socket': '/run/user/0/wayland-1',
                   'wayland_connect_timeout_ms': 30000, 'owner_timeout_ms': 30000,
                   'method_timeout_ms': 10000, 'changed_timeout_ms': 15000,
                   'theme_timeout_ms': 30000, 'wayland_protocol_verified': False,
                   'protocol_version': 2, 'watcher_unique_scope': 'per-returned-watch-name',
                   'watcher_pid_equals_main_service': True, 'watcher_pid_excludes_client': True,
                   'watcher_stable_before_and_after_changed': True,
                   'main_owner_stability_independent': True,
                   'changed_marker_fields': ['watcher_unique', 'watcher_name', 'watcher_pid',
                                             'service_pid', 'client_pid'],
                   'error_diagnostic_fields': ['member', 'destination', 'request_serial',
                                               'elapsed_ms', 'timeout_ms', 'errno', 'name', 'message'],
                   'upstream_policy_is_current_daemon_build_proof': False}
require, BuildError = base.require, base.BuildError


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def read(path, limit=2 * 1024**2):
    return elf._read_regular(base.no_symlink_path(path), limit)


def identify(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def producer_identity():
    require(base.no_symlink_path(__file__) == ROOT / 'tools/build_settings_probe_v2.py',
            'Use the reviewed installed settings probe producer')
    source, original, previous, policy_raw = read(SOURCE), read(ORIGINAL_SOURCE), read(PREVIOUS_SOURCE), read(POLICY)
    require(identify(source)['sha256'] == SOURCE_SHA256
            and identify(original)['sha256'] == ORIGINAL_SOURCE_SHA256
            and identify(previous)['sha256'] == PREVIOUS_SOURCE_SHA256
            and identify(policy_raw)['sha256'] == POLICY_SHA256,
            'Settings client source, preserved originals, or fixed upstream reference changed')
    policy = json.loads(policy_raw, object_pairs_hook=unique_object)
    require(all(policy.get(key) == SERVER_IDENTITY[key] for key in ('component', 'version', 'commit')),
            'Settings client requires its reviewed real upstream daemon')
    return {'python': base.producer_sources(__file__), 'source': identify(source),
            'original_source': identify(original), 'previous_v1_source': identify(previous),
            'settings_upstream_policy_reference': identify(policy_raw),
            'upstream_policy_is_current_daemon_build_proof': False}


def commands(output, sdk, dbus, tools, target):
    """Actual compiler/linker argv; the independent consumer reconstructs it."""
    stage, library = dbus / 'stage', sdk / 'sysroot/usr/lib'
    obj = output / OBJECT
    return [[tools['clang'], '--version'],
            [tools['rust-lld'], '-flavor', 'gnu', '--version'],
            [tools['clang'], *target.clang_args, '-nostdinc', '-isystem', sdk / 'sysroot/usr/include',
             '-I', stage / 'usr/include/dbus-1.0', '-I', stage / 'usr/lib/dbus-1.0/include',
             '-std=c11', '-O2', '-ffp-contract=off', '-fno-stack-protector', '-fno-pie',
             '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror',
             '-c', SOURCE, '-o', obj],
            [tools['rust-lld'], '-flavor', 'gnu', '-m', target.linker_emulation,
             '--image-base=0x01000000', '-z', 'max-page-size=4096', '-z', 'separate-code',
             '-static', '--no-pie', '--build-id=sha1', '--gc-sections', '-o',
             output / (EXECUTABLE + '.tmp'), library / 'crt1.o', library / 'crti.o', obj,
             '--start-group', stage / 'usr/lib/libdbus-1.a', stage / 'usr/lib/libexpat.a',
             library / 'libc.a', library / target.builtins_archive, '--end-group', library / 'crtn.o']]


def build(output, sysroot, dbus_build, *, native_lock=NATIVE_LOCK):
    target = base.profile_for('x86_64')
    sdk, dbus = [base.no_symlink_path(path).resolve(strict=True) for path in (sysroot, dbus_build)]
    require(sdk.is_dir() and dbus.is_dir(), 'SDK and D-Bus inputs must be actual directories')
    protected = [sdk, dbus, ROOT / 'tools', ROOT / 'user', ROOT / 'ports', ROOT / 'kernel', ROOT / 'crates']
    output = base.validate_output(output, *protected)
    lock = base.no_symlink_path(native_lock)
    require(lock == NATIVE_LOCK and all(not lock.is_relative_to(path) for path in protected),
            'Use the original shared native lease outside read-only inputs')
    lock.parent.mkdir(parents=True, exist_ok=True)
    with base.native_lease(lock):
        base.idle_native_host()
        output = base.validate_output(output, *protected)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'logs').mkdir()
        report = {'schema_version': 1, 'kind': KIND, 'status': 'FAILED', 'output': str(output),
                  'architecture': target.architecture, 'target': target.c_target,
                  'target_profile': target.identity(), 'source_root': str(ROOT), 'source': str(SOURCE),
                  'expected_server': SERVER_IDENTITY, 'client_contract': CLIENT_CONTRACT,
                  'guest_execution': False, 'settings_verified': False, 'render_verified': False,
                  'cosmic_session_verified': False, 'cosmic_session_ready': False,
                  'full_cosmic_complete': False, 'native_lock': str(lock),
                  'limits': {'timeout_seconds': TIMEOUT_SECONDS, 'min_free_bytes': MIN_FREE_BYTES,
                             'max_output_bytes': MAX_OUTPUT_BYTES}}
        try:
            report['producer_inputs'] = producer_identity()
            report['sdk'] = base.sdk_identity(sdk, target)
            report['dbus'] = base.dbus_identity(dbus, sdk, target)
            tools = base.toolchain()
            report['toolchain'] = base.tool_identity(tools)
            builder = base.Builder(output, tools, target)
            report['commands'] = builder.commands
            for command, log in zip(commands(output, sdk, dbus, tools, target),
                                    ('clang-version.log', 'linker-version.log', 'compile.log', 'link.log')):
                builder.run(command, log)
            report['tool_versions'] = {name: read(output / 'logs' / filename, 64 * 1024).decode()
                for name, filename in [('clang', 'clang-version.log'), ('rust-lld', 'linker-version.log')]}
            temporary = output / (EXECUTABLE + '.tmp')
            inspected = base.inspect_elf(temporary, target)
            admitted = elf.inspect_full_os_elf(temporary, FULL_OS)
            require(producer_identity() == report['producer_inputs'], 'Settings client producer changed')
            require(base.sdk_identity(sdk, target) == report['sdk'], 'Read-only SDK changed')
            require(base.dbus_identity(dbus, sdk, target) == report['dbus'], 'D-Bus source/build inputs changed')
            require(base.tool_identity(tools) == report['toolchain'], 'Compiler or linker changed')
            program = output / EXECUTABLE
            temporary.chmod(0o755)
            temporary.replace(program)
            inspected['file'] = str(program)
            admitted['executable']['file'] = program.name
            report['probe'], report['image_admission'] = inspected, admitted
            report['object'] = base.file_identity(output / OBJECT)
            report['status'] = 'BUILT_NOT_RUN'
        except BaseException as error:
            report['error'] = str(error)
            raise
        finally:
            report['logs'] = base.build_dbus.file_map(output / 'logs')
            receipt = output / (RECEIPT + '.tmp')
            receipt.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
            receipt.replace(output / RECEIPT)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sysroot', 'dbus-build', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--native-lock', type=Path, default=NATIVE_LOCK)
    args = parser.parse_args(argv)
    try:
        build(args.output, args.sysroot, args.dbus_build, native_lock=args.native_lock)
        print(args.output.resolve() / RECEIPT)
        return 0
    except (BuildError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('settings-probe-v2: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
