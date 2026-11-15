#!/usr/bin/env python3
"""Prepare/build a fresh pinned x86 QEMU; never modifies an existing emulator.

prepare is offline unless --fetch-dependencies explicitly permits the three
manifest URLs. build serializes through the same lease as ARM native activity.
All build outputs are under the fresh /private/tmp destination. No native timing
claim follows from compilation. System package/tool versions are recorded;
bit-for-bit reproducibility across arbitrary host toolchains is not claimed.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from x86_accounting import (HERE, UPSTREAM_COMMIT, PATCH, attest_source,
                            command, load_manifest, require, sha)

sys.path.insert(0, str(HERE.parent))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

REPOSITORY = 'https://github.com/qemu/qemu.git'


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def fresh_destination(path):
    path = Path(path).absolute()
    require(not path.exists() and not path.is_symlink(), 'destination must be fresh')
    require(path.parent.is_dir() and path.parent.resolve() == path.parent,
            'destination parent must exist without symlinks')
    require(path.is_relative_to(Path('/private/tmp')), 'fresh QEMU tree must be under /private/tmp')
    return path


def clone_exact(origin, destination, commit):
    command(['git', 'clone', '--no-hardlinks', '--no-checkout', origin, destination], timeout=300)
    command(['git', '-C', destination, 'checkout', '--detach', commit], timeout=120)
    require(command(['git', '-C', destination, 'rev-parse', 'HEAD']).strip() == commit,
            'cloned source revision differs')


def dependency_tree(path):
    """Bind all dependency source and applied Meson overlays, excluding .git."""
    result = {}
    for file in sorted(Path(path).rglob('*')):
        if '.git' in file.relative_to(path).parts:
            continue
        require(not file.is_symlink(), 'linked dependency source')
        if file.is_file():
            result[str(file.relative_to(path))] = sha(file)
    require(result, 'empty dependency checkout')
    return result


def prepare(base_source, destination, *, dependency_cache=None, fetch_dependencies=False):
    manifest = load_manifest()
    base = Path(base_source).resolve(strict=True)
    require(command(['git', '-C', base, 'rev-parse', 'HEAD']).strip() == UPSTREAM_COMMIT,
            'base source is not pinned QEMU 10.2.2')
    destination = fresh_destination(destination)
    clone_exact(base, destination, UPSTREAM_COMMIT)
    command(['git', '-C', destination, 'apply', '--check', PATCH])
    command(['git', '-C', destination, 'apply', PATCH])
    proof = attest_source(destination)
    dependencies = {}
    for name, pin in manifest['dependencies'].items():
        target = destination / 'subprojects' / name
        require(not target.exists(), 'unexpected existing dependency in pristine checkout')
        cached = Path(dependency_cache) / name if dependency_cache else None
        if cached is not None and (cached / '.git').exists():
            clone_exact(cached.resolve(strict=True), target, pin['commit'])
        else:
            require(fetch_dependencies, 'missing pinned dependency: ' + name + '; provide --dependency-cache or --fetch-dependencies')
            target.mkdir()
            command(['git', '-C', target, 'init'])
            command(['git', '-C', target, 'remote', 'add', 'origin', pin['url']])
            command(['git', '-C', target, 'fetch', '--depth=1', 'origin', pin['commit']], timeout=300)
            command(['git', '-C', target, 'checkout', '--detach', 'FETCH_HEAD'])
        require(command(['git', '-C', target, 'rev-parse', 'HEAD']).strip() == pin['commit'],
                'dependency revision differs: ' + name)
        overlay = destination / 'subprojects/packagefiles' / name
        if overlay.is_dir():
            shutil.copytree(overlay, target, dirs_exist_ok=True)
        dependencies[name] = dict(**pin, files=dependency_tree(target))
    receipt = dict(schema_version=1, status='PREPARED_NOT_BUILT', source=proof,
                   base_origin=str(base), upstream_url=REPOSITORY, dependencies=dependencies,
                   builder_sha256=sha(Path(__file__)))
    write_json(destination / 'x86-accounting-prepare.json', receipt)
    return receipt


def tool(name, args=('--version',)):
    selected = shutil.which(name)
    require(selected is not None, 'required build tool missing: ' + name)
    path = Path(selected).resolve(strict=True)
    return dict(path=str(path), sha256=sha(path), version=command([path, *args], timeout=10).strip())


def build(source, *, jobs=2, native_lock=DEFAULT_NATIVE_LOCK):
    require(type(jobs) is int and 1 <= jobs <= 4, 'build jobs must be in 1..4')
    source = Path(source).resolve(strict=True)
    require(source.is_relative_to(Path('/private/tmp')), 'build source must be the fresh /private/tmp tree')
    proof = attest_source(source)
    preparation = json.loads((source / 'x86-accounting-prepare.json').read_text())
    require(preparation.get('status') == 'PREPARED_NOT_BUILT' and preparation.get('source') == proof
            and preparation.get('builder_sha256') == sha(Path(__file__)), 'preparation receipt differs')
    manifest = load_manifest()
    require(set(preparation.get('dependencies', {})) == set(manifest['dependencies']), 'dependency set differs')
    for name, pin in manifest['dependencies'].items():
        entry = preparation['dependencies'][name]
        target = source / 'subprojects' / name
        require(entry.get('url') == pin['url'] and entry.get('commit') == pin['commit']
                and command(['git', '-C', target, 'rev-parse', 'HEAD']).strip() == pin['commit']
                and dependency_tree(target) == entry.get('files'), 'prepared dependency changed: ' + name)
    # No hidden compiler substitution/flags or dependency download during build.
    controls = ('CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
                'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'MESON_ARGS')
    require(not any(os.environ.get(k) for k in controls), 'ambient compiler/build override is unsupported')
    build_dir = source / 'build'
    require(not build_dir.exists() and not build_dir.is_symlink(), 'build directory must be fresh')
    configure = [str(source / 'configure'), '--target-list=x86_64-softmmu',
                 '--without-default-features', '--enable-tcg', '--enable-pixman',
                 '--disable-docs', '--disable-werror', '--disable-download']
    make = ['make', '-j' + str(jobs), 'qemu-system-x86_64']
    with native_lease(native_lock):
        idle_native_host()
        identities = {name: tool(name) for name in ('cc', 'make', 'ninja', 'meson', 'pkg-config', 'python3')}
        packages = {name: command(['pkg-config', '--modversion', name]).strip()
                    for name in ('glib-2.0', 'pixman-1')}
        build_dir.mkdir()
        for name, argv in (('configure', configure), ('build', make)):
            with (source / ('x86-accounting-' + name + '.log')).open('wb') as log:
                subprocess.run(argv, cwd=build_dir, check=True, stdout=log,
                               stderr=subprocess.STDOUT, timeout=3600)
        binary = build_dir / 'qemu-system-x86_64'
        require(binary.is_file(), 'build did not produce x86 system emulator')
        require(attest_source(source) == proof, 'source changed during build')
        receipt = dict(schema_version=1, status='BUILT_NOT_RUN', source=proof,
            builder_sha256=sha(Path(__file__)), prepare_receipt_sha256=sha(source / 'x86-accounting-prepare.json'),
            binary_sha256=sha(binary), configure_argv=configure, build_argv=make,
            toolchain=identities, packages=packages, dependencies=preparation['dependencies'],
            logs={name: sha(source / ('x86-accounting-' + name + '.log')) for name in ('configure', 'build')})
        write_json(source / 'x86-accounting-build.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    prep = commands.add_parser('prepare')
    prep.add_argument('--base-source', required=True, type=Path)
    prep.add_argument('--destination', required=True, type=Path)
    prep.add_argument('--dependency-cache', type=Path)
    prep.add_argument('--fetch-dependencies', action='store_true',
                      help='explicitly fetch only the three exact manifest URLs/revisions')
    compile_parser = commands.add_parser('build')
    compile_parser.add_argument('--source', required=True, type=Path)
    compile_parser.add_argument('--jobs', type=int, default=2)
    compile_parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    args = parser.parse_args()
    if args.action == 'prepare':
        result = prepare(args.base_source, args.destination, dependency_cache=args.dependency_cache,
                         fetch_dependencies=args.fetch_dependencies)
    else:
        result = build(args.source, jobs=args.jobs, native_lock=args.native_lock)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
