#!/usr/bin/env python3
"""Build and launch the explicit 2 GiB x86 PC runtime profile.

The original os_x86 builder and its one-GiB manifests remain unchanged. This
profile couples QEMU RAM, the loader limit, direct maps and physical-page guards.
"""
from __future__ import annotations
import argparse
import ast
import os
from pathlib import Path
import subprocess
import x86_64 as pc
from build_sources import code_source_map, build_cache_context
from native_session import native_lease, idle_native_host, DEFAULT_NATIVE_LOCK

ROOT = pc.ROOT
VERSION = 3
RUSTFLAGS = ['-C', 'relocation-model=static', '-C', 'code-model=large',
             '-C', 'no-redzone=yes', '-C', 'lto=off']
DESKTOP_FEATURES = frozenset(('large-memory', 'full-os', 'cosmic-desktop', 'cosmic-session', 'cosmic-core-services-v1', 'cosmic-time-applet-v1', 'rust-reactor-probe', 'rust-egl-probe',
    'mesa-probe', 'smithay-probe', 'smithay-wayland-probe', 'smithay-xdg-probe',
    'smithay-multi-probe', 'smithay-interactive-probe', 'smithay-resize-probe',
    'smithay-dynamic-probe', 'wayland-shm-probe', 'abi-trace'))

def select_features(*, graphics=False, ported=False, extras=()):
    extras = sorted(set(extras))
    pc.require(set(extras) <= DESKTOP_FEATURES, 'unsupported formal OS feature')
    pc.require(not extras or ported, 'desktop features require the ported catalog')
    pc.require(not any(f not in ('large-memory', 'full-os') for f in extras) or graphics,
               'desktop compositor features require graphics')
    return ['os-runtime', 'ram-2g'] + (['graphics'] if graphics else []) + (['ported'] if ported else []) + extras

def catalog_inputs(prefix):
    """Bind bytes which the kernel build can embed, excluding mutable SDK caches."""
    prefix = Path(prefix)
    pc.require(prefix.is_dir() and not prefix.is_symlink() and prefix.resolve() == prefix.absolute(),
               'invalid or linked OS sysroot')
    pending = [p for p in prefix.glob('*.elf') if not p.name.endswith('.symbols.elf')]
    rootfs = prefix / 'rootfs'
    if rootfs.exists() or rootfs.is_symlink(): pending.append(rootfs)
    result = {}; total = 0
    while pending:
        path = pending.pop()
        pc.require(not path.is_symlink(), 'linked OS image/asset')
        if path.is_dir():
            pending.extend(path.iterdir()); continue
        pc.require(path.is_file(), 'OS catalog input is not a regular file')
        raw = pc.bounded_bytes(path, 64 * 1024 * 1024)
        total += len(raw)
        pc.require(total <= 256 * 1024 * 1024 and len(result) < 1024, 'OS input catalog budget')
        result[str(path.relative_to(prefix))] = pc.sha_bytes(raw)
    pc.require('probe.elf' in result, 'missing real ported probe ELF')
    return dict(sorted(result.items()))

def cache_sources(sources, features, prefix, inputs):
    return {**sources, '@os-build-config': pc.digest_map(dict(features=features, sysroot=prefix)),
            **{'@os-input/' + name: digest for name, digest in inputs.items()}}

def build_argv(cargo, profile, features):
    pc.require(profile in ('dev', 'release'), 'unsupported OS build profile')
    command = [cargo, 'build', '--locked', '--offline', '-p', 'cyxia-kernel',
               '--bin', 'cyxia-kernel', '--target', pc.TARGET, '--no-default-features',
               '--features', ','.join(features)]
    return command + (['--release'] if profile == 'release' else [])

def build_environment(cache, cc, prefix):
    environment = pc.build_environment(cache)
    pc.require(not any(name.startswith('CYXIA_') and (name.endswith('_ELF') or
               name in ('CYXIA_SYSROOT', 'CYXIA_CC')) for name in environment),
               'use explicit OS build inputs instead of ambient image/compiler overrides')
    environment['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(RUSTFLAGS)
    environment['CYXIA_CC'] = cc
    if prefix is not None: environment['CYXIA_SYSROOT'] = prefix
    return environment

def producer_sources(entry=None):
    """Bind the selected producer and its transitive local Python imports."""
    pending = [Path(entry or __file__).resolve()]
    result = {}
    while pending:
        path = pending.pop()
        key = str(path.relative_to(ROOT))
        if key in result: continue
        raw = path.read_bytes(); result[key] = pc.sha_bytes(raw)
        for node in ast.walk(ast.parse(raw)):
            names = ([i.name for i in node.names] if isinstance(node, ast.Import) else
                     [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for name in names:
                local = ROOT / 'tools' / (name.split('.')[0] + '.py')
                if local.is_file(): pending.append(local)
    return dict(sorted(result.items()))

def build(output, *, profile='dev', graphics=False, ported=False, extras=(), sysroot=None,
          cargo='cargo', cc='clang', native_lock=DEFAULT_NATIVE_LOCK):
    pc.require(profile in ('dev', 'release'), 'unsupported OS build profile')
    features = select_features(graphics=graphics, ported=ported, extras=extras)
    pc.require(ported or sysroot is None, 'sysroot requires ported images')
    prefix = str(Path(sysroot or ROOT / 'artifacts/sysroot/x86_64-musl').absolute()) if ported else None
    with native_lease(pc.prepare_native_lock(native_lock)):
        idle_native_host()
        output = pc.fresh_output(output)
        sources = code_source_map(ROOT); producer = producer_sources()
        inputs = catalog_inputs(prefix) if ported else {}
        cache = build_cache_context(ROOT / 'target' / 'x86-os', ROOT,
                                    cache_sources(sources, features, prefix, inputs))
        cargo = pc.executable(cargo); rustc = pc.executable('rustc')
        cc = pc.executable(cc)
        environment = build_environment(cache, cc, prefix)
        command = build_argv(cargo, profile, features)
        versions, binaries = pc.compiler_tools(cargo, rustc)
        with (output / 'build.log').open('wb') as log:
            result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=900)
        pc.require(result.returncode == 0, f'OS build failed: {output / "build.log"}')
        elf = Path(cache['effective']) / pc.TARGET / ('debug' if profile == 'dev' else 'release') / 'cyxia-kernel'
        pc.require(elf.resolve(strict=True).is_relative_to(Path(cache['effective']).resolve()),
                   'OS artifact outside selected Cargo cache')
        raw = pc.bounded_bytes(elf, 256 * 1024 * 1024)
        flat = pc.boot_image(raw, runtime=True)
        (output / 'kernel.elf').write_bytes(raw); (output / 'boot.bin').write_bytes(flat)
        pc.require(code_source_map(ROOT) == sources and producer_sources() == producer,
                   'source changed during compilation; artifacts are unbound development outputs')
        pc.require((catalog_inputs(prefix) if ported else {}) == inputs,
                   'OS user images/assets changed during compilation')
        manifest = dict(version=VERSION, status='BUILT_NOT_RUN', target=pc.TARGET,
                        profile=profile, features=features, rustflags=RUSTFLAGS,
                        source_root=str(ROOT), sources=sources, source_sha256=pc.digest_map(sources),
                        producer_sources=producer, tool_versions=versions, compiler_binaries=binaries,
                        cargo=dict(path=cargo, sha256=pc.sha(cargo)), rustc=dict(path=rustc, sha256=pc.sha(rustc)),
                        cc=dict(path=cc, sha256=pc.sha(cc), version=pc.version(cc)),
                        sysroot=prefix, external_inputs=inputs,
                        build_argv=command, cache=cache, ram_mib=2048, cpus=4,
                        elf=pc.inspect_elf(raw, runtime=True),
                        artifacts={'kernel.elf': pc.sha_bytes(raw), 'boot.bin': pc.sha_bytes(flat)},
                        full_os_verified=False, cosmic_session_verified=False)
        pc.write_json(output / 'build-manifest.json', manifest)
        return manifest

def validate_build(directory, *, cc='clang'):
    directory = Path(directory).resolve(strict=True)
    manifest = pc.read_json(directory / 'build-manifest.json')
    pc.require(manifest.get('version') == VERSION and manifest.get('target') == pc.TARGET
               and manifest.get('status') == 'BUILT_NOT_RUN' and manifest.get('rustflags') == RUSTFLAGS
               and manifest.get('ram_mib') == 2048 and manifest.get('cpus') == 4,
               'unsupported OS build contract')
    features = manifest.get('features')
    pc.require(isinstance(features, list) and all(isinstance(f, str) for f in features), 'OS features missing')
    pc.require(features == select_features(graphics='graphics' in features, ported='ported' in features,
               extras=[f for f in features if f not in ('os-runtime', 'ram-2g', 'graphics', 'ported')]), 'OS feature mismatch')
    pc.require(manifest.get('source_root') == str(ROOT) and manifest.get('full_os_verified') is False
               and manifest.get('cosmic_session_verified') is False, 'unsupported OS verification claim')
    sources = code_source_map(ROOT)
    pc.require(manifest.get('sources') == sources and manifest.get('source_sha256') == pc.digest_map(sources),
               'OS source identity mismatch')
    pc.require(manifest.get('producer_sources') == producer_sources(), 'OS producer identity mismatch')
    prefix = manifest.get('sysroot')
    pc.require(isinstance(prefix, str) if 'ported' in features else prefix is None, 'OS sysroot contract')
    inputs = catalog_inputs(prefix) if prefix else {}
    pc.require(manifest.get('external_inputs') == inputs, 'OS embedded input identity mismatch')
    cache = build_cache_context(ROOT / 'target' / 'x86-os', ROOT, cache_sources(sources, features, prefix, inputs))
    pc.require(manifest.get('cache') == cache, 'OS cache identity mismatch')
    cargo = pc.executable('cargo'); rustc = pc.executable('rustc')
    for name, path in [('cargo', cargo), ('rustc', rustc)]:
        pc.require(manifest.get(name) == dict(path=path, sha256=pc.sha(path)), 'OS compiler executable mismatch')
    versions, binaries = pc.compiler_tools(cargo, rustc)
    pc.require(manifest.get('tool_versions') == versions and manifest.get('compiler_binaries') == binaries,
               'OS compiler toolchain mismatch')
    cc_path = pc.executable(cc)
    pc.require(manifest.get('cc') == dict(path=cc_path, sha256=pc.sha(cc_path), version=pc.version(cc_path)),
               'OS C compiler mismatch')
    build_environment(cache, cc_path, prefix)
    pc.require(manifest.get('build_argv') == build_argv(cargo, manifest.get('profile'), features), 'OS build argv mismatch')
    raw = pc.bounded_bytes(directory / 'kernel.elf', 256 * 1024 * 1024)
    flat = pc.boot_image(raw, runtime=True)
    pc.require(pc.bounded_bytes(directory / 'boot.bin', 512 * 1024 * 1024) == flat, 'OS load image mismatch')
    pc.require(manifest.get('elf') == pc.inspect_elf(raw, runtime=True) and
               manifest.get('artifacts') == {'kernel.elf': pc.sha_bytes(raw), 'boot.bin': pc.sha_bytes(flat)},
               'OS ELF identity mismatch')
    return manifest

def launch_argv(qemu, image, *, accel='tcg', display='none', disk=None, qmp=None):
    pc.require(display in ('none', 'cocoa', 'gtk', 'sdl'), 'unsupported display')
    command = [str(qemu), '-machine', 'pc-i440fx-10.2', '-cpu', 'qemu64',
               '-smp', 'cpus=4,sockets=1,cores=4,threads=1', '-m', '2048M',
               '-accel', pc.accelerator(accel), '-display', display,
               '-vga', 'none',
               '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=4',
               '-object', 'rng-random,id=rng0,filename=/dev/urandom',
               '-device', 'virtio-rng-pci,rng=rng0,disable-legacy=on',
               '-device', 'virtio-gpu-pci,disable-legacy=on',
               '-device', 'virtio-keyboard-pci,disable-legacy=on',
               '-device', 'virtio-mouse-pci,disable-legacy=on',
               '-nic', 'none', '-kernel', str(image)]
    if disk is not None:
        disk = Path(disk).resolve(strict=True)
        pc.require(disk.is_file() and ',' not in str(disk), 'invalid dedicated OS disk')
        command += ['-drive', f'if=none,id=osdisk,format=raw,file={disk}',
                    '-device', 'virtio-blk-pci,drive=osdisk,disable-legacy=on']
    if qmp is not None:
        pc.require(',' not in str(qmp), 'invalid QMP path')
        command += ['-qmp', f'unix:{qmp},server=on,wait=off']
    return command

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    b = commands.add_parser('build'); b.add_argument('--output', type=Path, required=True)
    b.add_argument('--profile', choices=['dev', 'release'], default='dev')
    b.add_argument('--graphics', action='store_true')
    b.add_argument('--ported', action='store_true'); b.add_argument('--sysroot', type=Path)
    b.add_argument('--feature', choices=sorted(DESKTOP_FEATURES), action='append', default=[])
    b.add_argument('--cc', default='clang')
    r = commands.add_parser('run'); r.add_argument('--build', type=Path, required=True)
    r.add_argument('--disk', type=Path); r.add_argument('--qemu', default='qemu-system-x86_64')
    r.add_argument('--cc', default='clang', help='explicit compiler used to produce this build')
    r.add_argument('--accel', choices=['tcg', 'kvm'], default='tcg')
    r.add_argument('--display', choices=['none', 'cocoa', 'gtk', 'sdl'], default='none')
    args = parser.parse_args()
    if args.command == 'build':
        build(args.output, profile=args.profile, graphics=args.graphics, ported=args.ported,
              extras=args.feature, sysroot=args.sysroot, cc=args.cc)
        print(args.output / 'kernel.elf')
    else:
        validate_build(args.build, cc=args.cc)
        with native_lease(pc.prepare_native_lock(DEFAULT_NATIVE_LOCK)):
            idle_native_host()
            subprocess.run(launch_argv(pc.executable(args.qemu), args.build / 'boot.bin',
                           accel=args.accel, display=args.display, disk=args.disk), check=True)

if __name__ == '__main__': main()
