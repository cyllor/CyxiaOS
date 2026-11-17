"""Read-only independent admission of the preserved real settings client.

This invokes no compiler, version process, guest or network. The original strict
SDK/D-Bus readers bind native sources, headers, archives and compiler identities.
Wire replies, socket readiness and normal-session execution remain unverified.
"""
from __future__ import annotations

import json
from pathlib import Path

if __package__:
    from . import build_settings_probe_v2 as producer
else:
    import build_settings_probe_v2 as producer

base, elf = producer.base, producer.elf
require, BuildError = producer.require, producer.BuildError
PROGRAM = producer.EXECUTABLE
REPORT_KEYS = {'schema_version', 'kind', 'status', 'output', 'architecture', 'target', 'target_profile',
    'source_root', 'source', 'expected_server', 'client_contract', 'guest_execution', 'settings_verified',
    'render_verified', 'cosmic_session_verified', 'cosmic_session_ready', 'full_cosmic_complete',
    'native_lock', 'limits', 'producer_inputs', 'sdk', 'dbus', 'toolchain', 'commands', 'tool_versions',
    'probe', 'image_admission', 'object', 'logs'}


def exact(actual, expected):
    # JSON preserves integer-vs-float spelling; Python's 1 == True must not
    # silently weaken a reviewed boolean, version, limit or image-page field.
    return json.dumps(actual, sort_keys=True, separators=(',', ':'), allow_nan=False) == \
        json.dumps(expected, sort_keys=True, separators=(',', ':'), allow_nan=False)


def selected(value, *, directory=False):
    require(isinstance(value, (str, Path)), 'Invalid settings probe path')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts, 'Noncanonical settings probe path')
    path = base.no_symlink_path(path)
    require(path.is_dir() if directory else path.is_file(), 'Missing settings probe input: ' + str(path))
    return path


def validate_build(output):
    output = selected(output, directory=True)
    receipt_path = output / producer.RECEIPT
    raw = producer.read(receipt_path)
    report = json.loads(raw, object_pairs_hook=producer.unique_object)
    target = base.profile_for('x86_64')
    expected_target = json.loads(json.dumps(target.identity(), allow_nan=False))
    require(type(report) is dict and set(report) == REPORT_KEYS
            and type(report['schema_version']) is int and report['schema_version'] == 1
            and report['kind'] == producer.KIND and report['status'] == 'BUILT_NOT_RUN'
            and report['output'] == str(output) and report['source_root'] == str(producer.ROOT)
            and report['source'] == str(producer.SOURCE)
            and report['architecture'] == 'x86_64' and report['target'] == target.c_target
            and exact(report['target_profile'], expected_target)
            and exact(report['expected_server'], producer.SERVER_IDENTITY)
            and exact(report['client_contract'], producer.CLIENT_CONTRACT)
            and report['native_lock'] == str(producer.NATIVE_LOCK)
            and exact(report['limits'], {'timeout_seconds': producer.TIMEOUT_SECONDS,
                                    'min_free_bytes': producer.MIN_FREE_BYTES,
                                    'max_output_bytes': producer.MAX_OUTPUT_BYTES})
            and all(report[key] is False for key in ('guest_execution', 'settings_verified',
                'render_verified', 'cosmic_session_verified', 'cosmic_session_ready', 'full_cosmic_complete')),
            'Not a preserved independently admissible settings client build')
    target.require_report(report)
    source_identity = producer.producer_identity()
    require(exact(report['producer_inputs'], source_identity), 'Settings probe source/producer identity changed')
    sdk = selected(report['sdk']['path'], directory=True)
    dbus = selected(report['dbus']['path'], directory=True)
    require(exact(report['sdk'], base.sdk_identity(sdk, target)), 'Settings probe SDK changed')
    require(exact(report['dbus'], base.dbus_identity(dbus, sdk, target)), 'Settings probe D-Bus inputs changed')
    tools = {name: row['path'] for name, row in report['toolchain'].items()}
    require(exact(base.tool_identity(tools), report['toolchain']), 'Settings probe compiler/linker changed')
    # Reconstruct independently of producer.commands; no argument may disappear,
    # select another source, add a library, or alter static/W^X/page boundaries.
    stage, library, obj = dbus / 'stage', sdk / 'sysroot/usr/lib', output / producer.OBJECT
    commands = [[tools['clang'], '--version'], [tools['rust-lld'], '-flavor', 'gnu', '--version'],
        [tools['clang'], *target.clang_args, '-nostdinc', '-isystem', sdk / 'sysroot/usr/include',
         '-I', stage / 'usr/include/dbus-1.0', '-I', stage / 'usr/lib/dbus-1.0/include',
         '-std=c11', '-O2', '-ffp-contract=off', '-fno-stack-protector', '-fno-pie',
         '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror',
         '-c', producer.SOURCE, '-o', obj],
        [tools['rust-lld'], '-flavor', 'gnu', '-m', target.linker_emulation,
         '--image-base=0x01000000', '-z', 'max-page-size=4096', '-z', 'separate-code',
         '-static', '--no-pie', '--build-id=sha1', '--gc-sections', '-o',
         output / (PROGRAM + '.tmp'), library / 'crt1.o', library / 'crti.o', obj,
         '--start-group', stage / 'usr/lib/libdbus-1.a', stage / 'usr/lib/libexpat.a',
         library / 'libc.a', library / target.builtins_archive, '--end-group', library / 'crtn.o']]
    require(report['commands'] == [[str(arg) for arg in row] for row in commands],
            'Settings probe compile/link commands changed')
    require(report['logs'] == base.build_dbus.file_map(output / 'logs'), 'Settings probe logs changed')
    versions = {name: producer.read(output / 'logs' / filename, 64 * 1024).decode()
                for name, filename in [('clang', 'clang-version.log'), ('rust-lld', 'linker-version.log')]}
    require(report['tool_versions'] == versions, 'Settings probe compiler version logs changed')
    program = selected(output / PROGRAM)
    require(program.stat().st_mode & 0o7777 == 0o755, 'Settings probe file mode changed')
    require(exact(report['probe'], base.inspect_elf(program, target)), 'Settings probe actual static ELF changed')
    admitted = elf.inspect_full_os_elf(program, producer.FULL_OS)
    require(exact(report['image_admission'], admitted), 'Settings probe loader/admission identity changed')
    require(exact(report['object'], base.file_identity(selected(obj))), 'Settings probe actual linked object changed')
    executable = {'path': str(program), **base.file_identity(program), 'mode': 0o755}
    require(producer.read(receipt_path) == raw and producer.producer_identity() == source_identity,
            'Settings probe receipt or sources changed during validation')
    result = {'schema_version': 1, 'kind': producer.KIND, 'status': 'SETTINGS_PROBE_BUILD_REVALIDATED_NOT_RUN',
              'client_contract': json.loads(json.dumps(producer.CLIENT_CONTRACT, allow_nan=False)),
              'output': str(output), 'receipt_sha256': producer.identify(raw)['sha256'],
              'producer_sources': source_identity, 'executable': executable,
              'resource_profile': producer.FULL_OS, 'image_admission': admitted,
              'required_pages': admitted['required_pages'], 'image_load_pages': admitted['image_load_pages'],
              'dbus_build': str(dbus), 'sdk': str(sdk), 'guest_execution': False,
              'settings_verified': False, 'cosmic_session_ready': False, 'full_cosmic_complete': False}
    result['identity_sha256'] = base.json_digest(result)
    return result
