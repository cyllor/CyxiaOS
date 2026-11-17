#!/usr/bin/env python3
"""Build the real pipe-capacity probe in a fresh directory from a read-only SDK.

Uses the existing generic compiler runner, target profiles and static ELF gate.
Does not change the shared probe registry, fetch inputs, or execute target code.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

if __package__:
    from .build_sysroot import ROOT, Builder, BuildError, digest, inspect_elf, toolchain
    from .native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
    from .target_profile import profile_for
else:
    from build_sysroot import ROOT, Builder, BuildError, digest, inspect_elf, toolchain
    from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
    from target_profile import profile_for

SOURCE = ROOT / 'user/ported/pipe_capacity_probe.c'
EXECUTABLE = 'pipe-capacity-probe.elf'
RECEIPT = 'build-report.json'


def require(condition, message):
    if not condition:
        raise BuildError(message)


def file_identity(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), 'Missing or linked input: ' + str(path))
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), 'Input must be a regular file: ' + str(path))
    result = {'bytes': before.st_size, 'sha256': digest(path)}
    after = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                              value.st_mtime_ns, value.st_ctime_ns)
    require(identity(before) == identity(after), 'Input changed while hashing: ' + str(path))
    return result


def header_identity(directory):
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir(), 'Missing SDK headers')
    directory = directory.resolve(strict=True)
    result = {}
    for path in sorted(directory.rglob('*')):
        name = path.relative_to(directory).as_posix()
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(directory) and
                    (resolved.is_file() or resolved.is_dir()), 'SDK header link escapes include tree')
            result[name] = {'symlink': os.readlink(path),
                            'resolved': resolved.relative_to(directory).as_posix()}
        elif path.is_file():
            result[name] = file_identity(path)
        else:
            require(path.is_dir(), 'Unsupported SDK header entry: ' + str(path))
    require(bool(result), 'SDK include tree is empty')
    return result


def sdk_identity(prefix, target):
    report_path = prefix / 'build-report.json'
    report_identity = file_identity(report_path)
    report = json.loads(report_path.read_text())
    target.require_report(report)
    require(report.get('status') == 'cross-built', 'SDK was not successfully cross-built')
    library = prefix / 'sysroot/usr/lib'
    names = ['crt1.o', 'crti.o', 'crtn.o', 'libc.a', target.builtins_archive]
    files = {}
    for name in names:
        path = library / name
        require(path.resolve(strict=True).is_relative_to(prefix), 'SDK native input escapes its prefix')
        files['sysroot/usr/lib/' + name] = file_identity(path)
        if name.endswith('.o'):
            header = path.read_bytes()[:20]
            require(len(header) == 20 and header[:7] == b'\x7fELF\x02\x01\x01' and
                    struct.unpack_from('<HH', header, 16) == (1, target.machine),
                    'SDK startup object has the wrong target: ' + name)
    archives = {name: target.inspect_archive(library / name)
                for name in ('libc.a', target.builtins_archive)}
    require(archives['libc.a']['sha256'] == report.get('libc_sha256'),
            'SDK libc differs from its producer receipt')
    require(archives[target.builtins_archive]['sha256'] == report.get('builtins_sha256'),
            'SDK compiler builtins differ from their producer receipt')
    headers = prefix / 'sysroot/usr/include'
    require(headers.resolve(strict=True).is_relative_to(prefix), 'SDK headers escape their prefix')
    return {'path': str(prefix), 'build_report': report_identity,
            'native_inputs': files, 'archives': archives,
            'headers': header_identity(headers)}


def producer_identity():
    paths = [Path(__file__).resolve(), SOURCE]
    paths += [ROOT / 'tools' / name for name in (
        'build_sysroot.py', 'target_profile.py', 'desktop_ports.py', 'native_session.py')]
    return {str(path): file_identity(path) for path in paths}


def tool_identity(tools):
    result = {}
    for name in ('clang', 'rust-lld'):
        path = Path(tools[name]).absolute()
        resolved = path.resolve(strict=True)
        result[name] = {'path': str(path), 'resolved': str(resolved), **file_identity(resolved)}
    return result


def validate_output(output, prefix):
    output = Path(output)
    require(not output.exists() and not output.is_symlink(),
            'Output must be fresh; existing evidence is never overwritten')
    output = output.resolve()
    require(not output.is_relative_to(prefix) and not prefix.is_relative_to(output),
            'Output must be separate from the read-only SDK')
    return output


def build(output, sysroot, architecture='x86_64', *, native_lock=DEFAULT_NATIVE_LOCK):
    target = profile_for(architecture)
    prefix = Path(sysroot).resolve(strict=True)
    require(prefix.is_dir(), 'SDK prefix must be a directory')
    output = validate_output(output, prefix)
    native_lock = Path(native_lock).absolute()
    require(not native_lock.resolve().is_relative_to(prefix), 'Native lock must be outside the SDK')
    native_lock.parent.mkdir(parents=True, exist_ok=True)
    with native_lease(native_lock):
        idle_native_host()
        output = validate_output(output, prefix)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'logs').mkdir()
        report = {'schema_version': 1, 'status': 'FAILED', 'architecture': target.architecture,
                  'target': target.c_target, 'target_profile': target.identity(),
                  'source_root': str(ROOT), 'source': str(SOURCE),
                  'guest_execution': False, 'native_acceptance': False}
        try:
            report['producer_inputs'] = producer_identity()
            report['source_sha256'] = report['producer_inputs'][str(SOURCE)]['sha256']
            report['sdk'] = sdk_identity(prefix, target)
            tools = toolchain()
            report['toolchain'] = tool_identity(tools)
            builder = Builder(output, tools, 1, target)
            report['commands'] = builder.commands
            builder.run([tools['clang'], '--version'], 'clang-version.log')
            builder.run([tools['rust-lld'], '-flavor', 'gnu', '--version'], 'linker-version.log')
            report['tool_versions'] = {
                'clang': (output / 'logs/clang-version.log').read_text(),
                'rust-lld': (output / 'logs/linker-version.log').read_text()}
            library = prefix / 'sysroot/usr/lib'
            obj = output / 'pipe-capacity-probe.o'
            temporary = output / (EXECUTABLE + '.tmp')
            builder.run([tools['clang'], *target.clang_args, '-nostdinc', '-isystem',
                         str(prefix / 'sysroot/usr/include'), '-O2', '-ffp-contract=off',
                         '-fno-stack-protector', '-fno-pie', '-Wall', '-Wextra', '-Werror',
                         '-c', str(SOURCE), '-o', str(obj)], 'compile.log')
            builder.run([tools['rust-lld'], '-flavor', 'gnu', '-m', target.linker_emulation,
                         '--image-base=0x01000000', '-z', 'max-page-size=4096', '-z',
                         'separate-code', '-static', '--no-pie', '--build-id=sha1',
                         '-o', str(temporary), str(library / 'crt1.o'), str(library / 'crti.o'),
                         str(obj), '--start-group', str(library / 'libc.a'),
                         str(library / target.builtins_archive), '--end-group',
                         str(library / 'crtn.o')], 'link.log')
            inspected = inspect_elf(temporary, target)
            require(producer_identity() == report['producer_inputs'], 'Producer or source changed during build')
            require(sdk_identity(prefix, target) == report['sdk'], 'SDK inputs changed during build')
            require(tool_identity(tools) == report['toolchain'], 'Compiler or linker changed during build')
            program = output / EXECUTABLE
            temporary.replace(program)
            inspected['file'] = str(program)
            report['probe'] = inspected
            report['status'] = 'BUILT_NOT_RUN'
        except Exception as error:
            report['error'] = str(error)
            raise
        finally:
            receipt = output / (RECEIPT + '.tmp')
            receipt.write_text(json.dumps(report, indent=2) + '\n')
            receipt.replace(output / RECEIPT)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sysroot', type=Path, required=True, help='Existing SDK prefix containing build-report.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--arch', choices=('x86_64', 'aarch64'), default='x86_64')
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    args = parser.parse_args(argv)
    try:
        build(args.output, args.sysroot, args.arch, native_lock=args.native_lock)
        print(args.output.resolve() / RECEIPT)
        return 0
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('pipe-capacity-probe: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
