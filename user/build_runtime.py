#!/usr/bin/env python3
"""Build and inspect six source-bound user images; no guest execution claim.

Run only with the controller's compiler grant. The CLI acquires the shared
native lease; callers already holding it may call build() directly.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_sources import code_source_map
from doctor import env as tool_environment
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

ROLES = ('prototype-runtime', 'prototype-learning', 'prototype-governance',
         'prototype-task', 'prototype-client', 'prototype-cluster')
ARCHES = {'aarch64': (183, 4, 'aarch64-unknown-none-softfloat', 'aarch64-unknown-none'),
          'x86_64': (62, 1, 'x86_64-unknown-none', 'x86_64-unknown-none')}
# Exact existing address/permission budgets, independent of target machine bytes.
WINDOWS = {'prototype-runtime': (0x80000, 0xa0000, False, 512 * 1024),
           'prototype-learning': (0x80000, 0x100000, False, 512 * 1024),
           'prototype-governance': (0x80000, 0x100000, False, 512 * 1024),
           'prototype-task': (0x10000, 0x11000, False, 512 * 1024),
           'prototype-client': (0x10000, 0x14000, False, 512 * 1024),
           'prototype-cluster': (0x1000000, 0x1e00000, True, 8 * 1024 * 1024)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_image(data, role, arch):
    """Inspect actual emitted ELF bytes, including permissions and backing."""
    require(arch in ARCHES and role in WINDOWS, 'unsupported image architecture/role')
    machine, alignment, _, _ = ARCHES[arch]
    base, limit, writable, cap = WINDOWS[role]
    require(64 <= len(data) <= cap and data[:7] == b'\x7fELF\x02\x01\x01', 'invalid ELF header/size')
    kind, actual_machine, version, entry, phoff = struct.unpack_from('<HHIQQ', data, 16)
    ehsize, phsize, count = struct.unpack_from('<HHH', data, 52)
    require((kind, actual_machine, version, ehsize, phsize) == (2, machine, 1, 64, 56),
            'ELF type/machine/version mismatch')
    require(0 < count <= 8 and phoff + count * 56 <= len(data), 'invalid ELF program table')
    ranges, executable_entry = [], False
    for index in range(count):
        kind, flags, offset, address, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + index * 56)
        if kind in (0, 4, 6, 0x6474e551):
            continue
        require(kind == 1, 'unsupported dynamic/interpreter/TLS segment')
        allowed = (4, 5, 6) if writable else (4, 5)
        require(flags in allowed and 0 < memsz and filesz <= memsz, 'invalid segment permission/size')
        require(base <= address < limit and address + memsz <= limit and
                address % 4096 == offset % 4096 == 0 and align == 4096 and
                offset + filesz <= len(data), 'invalid segment mapping/backing')
        end = (address + memsz + 4095) // 4096 * 4096
        require(all(end <= start or address >= old_end for start, old_end in ranges), 'overlapping mapped segments')
        ranges.append((address, end))
        executable_entry |= flags == 5 and address <= entry < address + filesz and entry % alignment == 0
    require(executable_entry, 'entry is not aligned file-backed executable code')
    return dict(machine=machine, entry=entry, bytes=len(data), segments=len(ranges),
                sha256=hashlib.sha256(data).hexdigest())


def identity_snapshot(directory):
    directory = Path(directory).resolve(strict=True)
    require(not directory.is_relative_to(ROOT), 'private identities must remain outside source checkout')
    names = ('cert.der', 'key.der', 'own.pub', 'local.pin', 'peer.pub', 'peer.pin')
    values = {name: (directory / name).read_bytes() for name in names}
    require(all(values.values()), 'empty TLS identity input')
    require(all(len(values[name]) == 32 for name in names[2:]), 'invalid public identity length')
    require(hashlib.sha256(values['own.pub']).digest() == values['local.pin'] and
            hashlib.sha256(values['peer.pub']).digest() == values['peer.pin'] and
            values['local.pin'] != values['peer.pin'], 'TLS public identity/pin mismatch')
    return directory, values


def run_logged(command, environment, output, name):
    result = subprocess.run(command, cwd=ROOT, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    log = output / (name + '.log')
    log.write_bytes(result.stdout)
    log.chmod(0o600)
    require(result.returncode == 0, f'image build failed; inspect {log}')


def build(arch, output, identity):
    """Caller owns the unified native lease and has frozen the source checkout."""
    require(arch in ARCHES, 'unsupported user architecture')
    output = Path(output).expanduser()
    require(not output.exists() and not output.is_symlink(), 'output must be a fresh directory')
    output = output.resolve()
    identity, private = identity_snapshot(identity)
    before = code_source_map()
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    environment = tool_environment()
    environment.pop('CARGO_ENCODED_RUSTFLAGS', None)
    environment.pop('RUSTFLAGS', None)
    environment.update(CARGO_TARGET_DIR=str(output / 'target'), CARGO_NET_OFFLINE='true',
                       CYXIA_CLUSTER_IDENTITY=str(identity))
    _, _, arithmetic_target, cluster_target = ARCHES[arch]
    rustc = environment.get('RUSTC', 'rustc')
    cargo = environment.get('CARGO', 'cargo')
    helper_files = (ROOT / 'tools/build_sources.py', ROOT / 'tools/doctor.py', ROOT / 'tools/native_session.py')
    helpers = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in helper_files}
    versions = {}
    for name, command in [('rustc', [rustc, '--version', '--verbose']), ('cargo', [cargo, '--version'])]:
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=15)
        require(result.returncode == 0, f'cannot identify {name}')
        versions[name] = result.stdout.strip()
    commands, images = [], {}
    for role in ROLES:
        source = ROOT / 'user' / role
        image = output / (role + '.elf')
        if role == 'prototype-cluster':
            command = [str(source / 'tools/build.sh'), '--arch', arch]
            produced = output / 'target' / cluster_target / 'release/cyxia-prototype-cluster'
        elif role in ('prototype-learning', 'prototype-governance'):
            command = [cargo, 'rustc', '--locked', '--offline', '--release', '--target', arithmetic_target,
                       '--manifest-path', str(source / 'Cargo.toml'), '--', '-C', 'relocation-model=static',
                       '-C', 'strip=debuginfo',
                       '-C', 'link-arg=--build-id=none', '-C', 'link-arg=-zmax-page-size=4096',
                       '-C', 'link-arg=-T' + str(source / 'linker.ld')]
            produced = output / 'target' / arithmetic_target / 'release' / role
        else:
            command = [rustc, str(source / 'main.rs'), '--edition=2024', '--target', arithmetic_target,
                       '--crate-name', role.replace('-', '_'), '-C', 'opt-level=2', '-C', 'panic=abort',
                       '-C', 'strip=debuginfo',
                       '-C', 'overflow-checks=yes', '-C', 'relocation-model=static',
                       '-C', 'link-arg=--build-id=none', '-C', 'link-arg=-zmax-page-size=4096',
                       '-C', 'link-arg=-T' + str(source / 'linker.ld'), '-o', str(image)]
            if arch == 'x86_64':
                command += ['-C', 'code-model=small', '-C', 'no-redzone=yes']
            produced = image
        commands.append(dict(role=role, argv=command))
        run_logged(command, environment, output, role)
        if produced != image:
            shutil.copyfile(produced, image)
        image.chmod(0o600)
        images[role] = validate_image(image.read_bytes(), role, arch)
        images[role]['file'] = image.name
    cluster = (output / 'prototype-cluster.elf').read_bytes()
    require(all(private[name] in cluster for name in ('cert.der', 'key.der', 'peer.pub', 'peer.pin')),
            'emitted cluster image does not contain its exact provisioned TLS inputs')
    # Billing private material belongs to the kernel, never to any user image.
    billing = identity / 'billing.seed'
    if billing.exists():
        seed = billing.read_bytes()
        require(len(seed) == 32 and all(seed not in (output / (role + '.elf')).read_bytes() for role in ROLES),
                'a user image contains the kernel billing private seed')
    require(identity_snapshot(identity)[1] == private, 'identity changed while building')
    require(code_source_map() == before, 'source changed while building; retain failed output')
    require(all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name, digest in helpers.items()),
            'build helper changed while building; retain failed output')
    report = dict(version=1, status='BUILT_NOT_RUN', architecture=arch,
                  sources=before, helpers=helpers, tools=versions, images=images, commands=commands,
                  node_id=private['local.pin'].hex(), peer_node_id=private['peer.pin'].hex(),
                  identity_sha256={name: hashlib.sha256(data).hexdigest() for name, data in private.items()},
                  scope='Six user ELF images inspected; no guest execution or runtime acceptance.')
    manifest = output / 'user-images.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    manifest.chmod(0o600)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=tuple(ARCHES), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        build(args.arch, args.output, args.identity)


if __name__ == '__main__':
    main()
