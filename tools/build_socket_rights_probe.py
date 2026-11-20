#!/usr/bin/env python3
"""Add a real musl socket-FD regression to a manifest-bound existing catalog."""
import argparse
from pathlib import Path
import subprocess

import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, native_lease, idle_native_host


def build(base_build, sdk, output):
    base_build, sdk, output = map(lambda p: Path(p).resolve(), (base_build, sdk, output))
    manifest = pc.read_json(base_build / 'build-manifest.json')
    parent = Path(manifest['sysroot'])
    original = os_x86.catalog_inputs(parent)
    pc.require(manifest['status'] == 'BUILT_NOT_RUN' and original == manifest['external_inputs'],
               'Socket regression parent catalog changed')
    pc.require(not output.exists() and all(not output.is_relative_to(p)
        and not p.is_relative_to(output) for p in (parent, sdk, base_build)), 'Unsafe/existing output')
    source = pc.ROOT / 'user/ported/socket_rights_probe.c'
    programs = {'socket-rights-probe': source, 'scm-probe': pc.ROOT / 'user/ported/scm_probe.c'}
    compiler = sdk / 'bin/x86_64-linux-musl-cc'
    libraries = [sdk / 'sysroot/usr/lib' / name for name in ('libc.a', 'crt1.o', 'crti.o', 'crtn.o')]
    inputs = {str(p): pc.sha(p) for p in (*programs.values(), pc.ROOT / 'user/ported/cyxia_spawn.h',
                                        compiler, *libraries, sdk / 'runtime-sdk-origin.json')}
    pc.require(not any(name + '.elf' in original for name in programs),
               'Socket regression would overwrite an existing input')
    subprocess.run(['/bin/cp', '-cRp', str(parent), str(output)], check=True)
    commands = {}
    for name, source in programs.items():
        command = [str(compiler), '-O2', '-Wall', '-Wextra', '-Werror', str(source),
                   '-o', str(output / (name + '.elf'))]
        with (output / (name + '-link.log')).open('w') as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        (output / (name + '.source.c')).write_bytes(source.read_bytes())
        commands[name] = command
    pc.require(all(pc.sha(Path(path)) == sha for path, sha in inputs.items())
               and os_x86.catalog_inputs(parent) == original, 'Socket regression input changed')
    actual = os_x86.catalog_inputs(output)
    binaries = {name + '.elf': pc.sha(output / (name + '.elf')) for name in programs}
    pc.require(actual == {**original, **binaries},
               'Socket regression changed an original catalog input')
    pc.write_json(output / 'socket-rights-probe-origin.json', dict(
        status='SOCKET_REGRESSION_LINKED_NOT_RUN', parent_build=str(base_build),
        parent_manifest_sha256=pc.sha(base_build / 'build-manifest.json'), inputs=inputs,
        original_inputs=original, commands=commands, binaries=binaries,
        producers=os_x86.producer_sources(__file__), full_os_verified=False,
        cosmic_session_verified=False))
    print('Real socket regression linked; all original catalog inputs preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        build(args.base_build, args.sdk, args.output)


if __name__ == '__main__':
    main()
