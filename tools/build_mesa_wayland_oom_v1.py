#!/usr/bin/env python3
"""Compile one genuine Mesa translation unit and replace its archive member.

Original SDK, Rust dependencies and historical build outputs remain immutable.
The explicit object is also suitable for linking ahead of Rust's bundled native
archive: the linker must then leave the original translation unit unselected.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import time

import cosmic_time_applet_v2 as clock
import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

PORT = pc.ROOT / 'ports/cosmic/native-mesa-wayland-oom-v1'
PATCH = pc.ROOT / 'ports/cosmic/patches/mesa-26.2.3-wayland-swrast-allocation.patch'
SOURCE = Path('src/egl/drivers/dri2/platform_wayland.c')
MEMBER = 'drivers_dri2_platform_wayland.c.o'


def archive_members(path):
    raw = path.read_bytes()
    pc.require(raw[:8] == b'!<arch>\n', 'Expected a regular target archive')
    position, names, members = 8, b'', {}
    while position < len(raw):
        header = raw[position:position + 60]
        pc.require(len(header) == 60 and header[58:] == b'`\n', 'Invalid archive member header')
        size = int(header[48:58])
        name = header[:16].decode().strip()
        data = raw[position + 60:position + 60 + size]
        pc.require(len(data) == size, 'Truncated archive member')
        position += 60 + size + (size & 1)
        if name == '//':
            names = data
            continue
        if name.startswith('#1/'):
            length = int(name[3:])
            name, data = data[:length].rstrip(b'\0').decode(), data[length:]
        elif name.startswith('/') and name[1:].isdigit():
            offset = int(name[1:])
            end = names.index(b'/\n', offset)
            name = names[offset:end].decode()
        else:
            name = name.removesuffix('/')
        if not name or name.startswith(('__.SYMDEF', '/SYM64')):
            continue
        pc.require(name not in members, 'Duplicate native archive member: ' + name)
        members[name] = data
    pc.require(position == len(raw), 'Unexpected archive trailing bytes')
    return members


def member_hashes(path):
    return {name: hashlib.sha256(data).hexdigest() for name, data in archive_members(path).items()}


def verify(output):
    report = pc.read_json(output / 'repair-origin.json')
    pc.require(report['status'] == 'COMPILED_NATIVE_OBJECT_NOT_RUN'
        and all(pc.sha(Path(p)) == digest for p, digest in report['inputs'].items()),
        'Mesa repair inputs changed')
    pc.require(all(pc.sha(output / p) == digest for p, digest in report['outputs'].items()),
               'Mesa repair outputs changed')
    pc.require(all(pc.sha(output / 'producer-sources' / p) == digest
        for p, digest in report['producers'].items()), 'Mesa repair producer snapshot changed')
    before = member_hashes(Path(report['original_archive']))
    after = member_hashes(output / 'libEGL.a')
    pc.require(before.keys() == after.keys() and
        [name for name in before if before[name] != after[name]] == [MEMBER]
        and after[MEMBER] == pc.sha(output / MEMBER), 'Repair changed unrelated EGL members')
    return report


def build(sdk, output):
    pc.require(not output.exists(), 'Preserving an existing Mesa repair')
    source = sdk / 'mesa-native-port/mesa-26.2.3' / SOURCE
    compilation = sdk / 'mesa-native-port/build/compile_commands.json'
    original_archive = sdk / 'mesa-native-port/build/src/egl/libEGL.a'
    policy = pc.read_json(PORT / 'source-policy.json')
    pc.require(pc.sha(source) == policy['upstream_sha256'] == pc.sha(PORT / 'upstream/platform_wayland.c'),
               'Retained original Mesa translation unit changed')
    recipe = clock.contract()[1]
    inputs = {str(p): pc.sha(p) for p in (source, compilation, PORT / 'source-policy.json', PATCH)}
    for row in [*recipe['native_inputs'], recipe['native_sdk_origin']]:
        pc.require(pc.sha(sdk / row['path']) == row['sha256'], 'Pinned SDK input changed')
        inputs[str(sdk / row['path'])] = row['sha256']
    entries = [r for r in pc.read_json(compilation) if r['file'].endswith('/platform_wayland.c')]
    pc.require(len(entries) == 1, 'Missing unique original Wayland compile command')
    row = entries[0]
    directory = Path(row['directory'])
    pc.require(directory == sdk / 'mesa-native-port/build'
        and (directory / row['file']).resolve() == source, 'Compile command source mismatch')
    arguments = shlex.split(row['command'])
    compiler = sdk / 'bin/x86_64-linux-musl-cc'
    ar = sdk / 'bin/x86_64-linux-musl-ar'
    pc.require(Path(arguments[0]) == compiler, 'Unexpected target compiler')
    inputs.update({str(p): pc.sha(p) for p in (compiler, ar)})
    output.mkdir(parents=True)
    producers = os_x86.producer_sources(__file__)
    for name, digest in producers.items():
        snapshot = output / 'producer-sources' / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pc.ROOT / name, snapshot)
        pc.require(pc.sha(snapshot) == digest, 'Mesa repair producer changed')
    patched = output / SOURCE
    patched.parent.mkdir(parents=True)
    shutil.copyfile(source, patched)
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
                   cwd=output, check=True, capture_output=True)
    args, index = [], 0
    while index < len(arguments):
        arg = arguments[index]
        if arg in ('-MF', '-MQ', '-o', '-c'):
            index += 2
        elif arg == '-MD':
            index += 1
        else:
            args.append(arg)
            index += 1
    args += ['-iquote', str(source.parent)]
    dependencies = subprocess.run(args + ['-M', '-MT', 'native', str(patched)],
        cwd=directory, check=True, capture_output=True, text=True, timeout=60)
    (output / 'dependencies.d').write_text(dependencies.stdout)
    headers = shlex.split(dependencies.stdout.replace('\\\n', ' ').split(':', 1)[1])
    for name in headers:
        path = (directory / name).resolve()
        inputs[str(path)] = pc.sha(path)
    command = args + ['-o', str(output / MEMBER), '-c', str(patched)]
    with (output / 'compile.log').open('w') as log:
        subprocess.run(command, cwd=directory, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    raw = (output / MEMBER).read_bytes()
    pc.require(raw[:4] == b'\x7fELF' and struct.unpack_from('<HH', raw, 16) == (1, 62),
               'Repair is not a genuine x86_64 relocatable object')
    old = archive_members(original_archive)
    pc.require(MEMBER in old, 'Original EGL object is missing')
    (output / 'original-wayland.o').write_bytes(old[MEMBER])
    nm = Path('/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/llvm-nm')
    inputs[str(nm)] = pc.sha(nm)
    symbol_sets = []
    for obj in ('original-wayland.o', MEMBER):
        result = subprocess.run([str(nm), '-g', '--defined-only', '--format=posix', str(output / obj)],
                                check=True, capture_output=True, text=True)
        symbol_sets.append(sorted(' '.join(line.split()[:2]) for line in result.stdout.splitlines()))
    pc.require(symbol_sets[0] == symbol_sets[1], 'Mesa repair changed native public symbols')
    shutil.copyfile(original_archive, output / 'libEGL.a')
    subprocess.run([str(ar), 'rD', str(output / 'libEGL.a'), str(output / MEMBER)], check=True)
    pc.require(all(pc.sha(Path(p)) == digest for p, digest in inputs.items()), 'Compile inputs changed')
    report = dict(status='COMPILED_NATIVE_OBJECT_NOT_RUN', original_archive=str(original_archive),
        inputs=inputs, original_compile_command=row, command=command,
        public_symbols=symbol_sets[1], original_members=member_hashes(original_archive),
        outputs={name: pc.sha(output / name) for name in
                 (MEMBER, 'libEGL.a', str(SOURCE), 'original-wayland.o', 'dependencies.d', 'compile.log')},
        producers=producers, full_os_verified=False, cosmic_session_verified=False)
    pc.write_json(output / 'repair-origin.json', report)
    verify(output)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sysroot', type=Path, default=pc.ROOT / 'artifacts/sysroot/x86_64-musl')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sdk, output = map(clock.base.no_symlink_path, (args.sysroot, args.output))
    pc.require(not output.is_relative_to(sdk) and not sdk.is_relative_to(output), 'Output overlaps SDK')
    started = time.monotonic()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        report = build(sdk, output)
    print(json.dumps(dict(status=report['status'], elapsed_seconds=round(time.monotonic() - started, 3),
                         object_sha256=report['outputs'][MEMBER], inputs=len(report['inputs']))))


if __name__ == '__main__':
    main()
