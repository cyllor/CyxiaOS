#!/usr/bin/env python3
"""Build pinned upstream Wayland for CyxiaOS; never execute an ARM program.

Inventory is read-only. `build` verifies cached sources unless --fetch is explicit.
The scanner and its Expat dependency are native host tools in a separate prefix;
client/server libraries use only the existing static AArch64 musl target sysroot.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from build_sysroot import (ROOT, DEFAULT_OUTPUT, BUILD_TOOLS, Builder, BuildError,
                          toolchain, clean_env, unpack, digest, inspect_elf,
                          validate_packages)
from build_gtk_foundation import archive_architecture
import desktop_ports
from target_profile import profile_for

MANIFEST = ROOT / 'ports/cosmic/wayland-source.json'
EXPAT_MANIFEST = ROOT / 'ports/libc/openbox-fonts.json'
HOST = DEFAULT_OUTPUT / 'wayland-host-tools'
REPORT = DEFAULT_OUTPUT / 'wayland-build-report.json'


def packages():
    wayland = json.loads(MANIFEST.read_text())
    expat = next(p for p in json.loads(EXPAT_MANIFEST.read_text())['packages']
                 if p['name'] == 'expat')
    validate_packages([wayland, expat])
    return wayland, expat


def source(builder, package, fetch):
    record = (desktop_ports.fetch(package, desktop_ports.DEFAULT_CACHE, online=True,
                                  max_bytes=8 * 1024 * 1024) if fetch else
              desktop_ports.verify(package, desktop_ports.DEFAULT_CACHE,
                                   max_bytes=8 * 1024 * 1024))
    directory = builder.output / 'wayland-source'
    directory.mkdir(exist_ok=True)
    path = unpack(package, record, directory)
    license_dir = builder.output / 'licenses' / ('wayland-' + package['name'])
    license_dir.mkdir(exist_ok=True)
    shutil.copyfile(path / package['license_file'], license_dir / package['license_file'])
    return path, {'source': record, 'license_sha256': digest(license_dir / package['license_file'])}


def fresh(directory):
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir()


def native_environment(builder):
    builder.env = clean_env()
    # Do not inherit a target pkg-config prefix, target Rust flags, or DESTDIR.
    for key in list(builder.env):
        if key.startswith('PKG_CONFIG') or key in ('DESTDIR', 'RUSTFLAGS'):
            builder.env.pop(key)
    builder.env.update(CC=builder.tools['clang'],
                       PATH=str(BUILD_TOOLS / 'bin') + os.pathsep + builder.env.get('PATH', ''),
                       PKG_CONFIG_LIBDIR=str((builder.output / "wayland-host-tools") / 'lib/pkgconfig'),
                       PKG_CONFIG_PATH='')


def build_host(builder, wayland_source, expat_source):
    native_environment(builder)
    directory = builder.output / 'wayland-host-expat-build'
    fresh(directory)
    builder.run([str(expat_source / 'configure'), '--prefix=' + str((builder.output / "wayland-host-tools")),
                 '--disable-shared', '--enable-static', '--without-xmlwf',
                 '--without-examples', '--without-tests', '--without-docbook'],
                'wayland-host-expat-setup.log', directory)
    builder.run([builder.tools['make'], '-j' + str(builder.jobs)],
                'wayland-host-expat-build.log', directory)
    builder.run([builder.tools['make'], 'install'], 'wayland-host-expat-install.log', directory)
    directory = builder.output / 'wayland-host-build'
    fresh(directory)
    meson = str(BUILD_TOOLS / 'bin/meson')
    options = ['--prefix=' + str((builder.output / "wayland-host-tools")), '--libdir=lib', '--wrap-mode=nofallback',
               '-Dbuildtype=release', '-Ddefault_library=static', '-Dlibraries=false',
               '-Dscanner=true', '-Dtests=false', '-Ddocumentation=false', '-Ddtd_validation=false']
    builder.run([meson, 'setup', str(directory), str(wayland_source), *options],
                'wayland-host-setup.log')
    builder.run([meson, 'compile', '-C', str(directory), '-j', str(builder.jobs)],
                'wayland-host-build.log')
    builder.run([meson, 'install', '-C', str(directory)], 'wayland-host-install.log')
    scanner = builder.output / "wayland-host-tools" / 'bin/wayland-scanner'
    version = subprocess.check_output([str(scanner), '--version'], env=builder.env,
                                      stderr=subprocess.STDOUT, text=True).strip()
    return {'path': str(scanner), 'sha256': digest(scanner), 'version': version,
            'expat_sha256': digest(builder.output / "wayland-host-tools" / 'lib/libexpat.a'), 'options': options}


def build_target(builder, wayland_source):
    builder.env = clean_env()
    builder.target_environment()
    builder.env.pop('DESTDIR', None)
    builder.env['PATH'] = str(BUILD_TOOLS / 'bin') + os.pathsep + builder.env.get('PATH', '')
    target = builder.output / 'sysroot'
    pkg = shutil.which('pkg-config')
    if not pkg:
        raise BuildError('pkg-config is required')
    builder.env['PKG_CONFIG'] = str(builder.shell_wrapper('wayland-target-pkg-config', [pkg, '--static']))
    host_pkg = builder.shell_wrapper('wayland-host-pkg-config',
        ['env', '-u', 'PKG_CONFIG_SYSROOT_DIR', '-u', 'PKG_CONFIG_PATH',
         'PKG_CONFIG_LIBDIR=' + str((builder.output / "wayland-host-tools") / 'lib/pkgconfig'), pkg, '--static'])
    cross = builder.output / 'wayland-cross.ini'
    cross.write_text('[binaries]\n' +
        'c = ' + repr(builder.env['CC']) + '\n' +
        'ar = ' + repr(builder.tools['llvm-ar']) + '\n' +
        'strip = ' + repr(builder.tools['llvm-strip']) + '\n' +
        'pkg-config = ' + repr(builder.env['PKG_CONFIG']) + '\n' +
        builder.target.meson_machine() +
        '[properties]\nneeds_exe_wrapper = true\nsys_root = ' + repr(str(target)) + '\n' +
        'pkg_config_libdir = ' + repr(builder.env['PKG_CONFIG_LIBDIR'].split(os.pathsep)) + '\n')
    native = builder.output / 'wayland-native.ini'
    native.write_text('[binaries]\nc = ' + repr(builder.tools['clang']) + '\n' +
                      'pkg-config = ' + repr(str(host_pkg)) + '\n')
    directory = builder.output / 'wayland-target-build'
    fresh(directory)
    meson = str(BUILD_TOOLS / 'bin/meson')
    options = ['--prefix=/usr', '--libdir=lib', '--wrap-mode=nofallback',
               '--cross-file=' + str(cross), '--native-file=' + str(native),
               '-Dbuildtype=release', '-Ddefault_library=static', '-Db_staticpic=false',
               '-Dlibraries=true', '-Dscanner=false', '-Dtests=false',
               '-Ddocumentation=false', '-Ddtd_validation=false',
               '-Dc_args=-ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables']
    builder.run([meson, 'setup', str(directory), str(wayland_source), *options],
                'wayland-target-setup.log')
    builder.run([meson, 'compile', '-C', str(directory), '-j', str(builder.jobs)],
                'wayland-target-build.log')
    builder.env['DESTDIR'] = str(target)
    try:
        builder.run([meson, 'install', '-C', str(directory)], 'wayland-target-install.log')
    finally:
        builder.env.pop('DESTDIR', None)
    return {'options': options, 'archives': {
        name: archive_architecture(target / 'usr/lib' / name, builder.target) for name in
        ('libwayland-client.a', 'libwayland-server.a', 'libwayland-cursor.a', 'libwayland-egl.a')}}


def build_libffi(builder, fetch):
    """Reuse the pinned libffi source/recipe needed by genuine Wayland calls."""
    manifest = ROOT / 'ports/libc/openbox-foundation.json'
    package = next(item for item in json.loads(manifest.read_text())['packages'] if item['name'] == 'libffi')
    validate_packages([package])
    directory, record = source(builder, package, fetch)
    builder.target_environment()
    build_dir = builder.output / 'wayland-libffi-build'
    fresh(build_dir)
    options = ['--prefix=/usr', '--host=' + builder.target.c_target,
               '--disable-shared', '--enable-static', '--disable-multi-os-directory',
               '--disable-docs', '--disable-exec-static-tramp']
    builder.run([str(directory / 'configure'), *options], 'wayland-libffi-setup.log', build_dir)
    builder.run([builder.tools['make'], '-j' + str(builder.jobs)], 'wayland-libffi-build.log', build_dir)
    builder.run([builder.tools['make'], 'install', 'DESTDIR=' + str(builder.output / 'sysroot')],
                'wayland-libffi-install.log', build_dir)
    return dict(source=record, manifest_sha256=digest(manifest), options=options,
                archive=builder.target.inspect_archive(builder.output / 'sysroot/usr/lib/libffi.a'))


def link_probe(builder):
    flags = shlex.split(subprocess.check_output(
        [builder.env['PKG_CONFIG'], '--static', '--cflags', '--libs',
         'wayland-client', 'wayland-server'], env=builder.env, text=True))
    path = ROOT / 'user/ported/wayland_probe.c'
    temporary = builder.output / 'wayland-probe.elf.tmp'
    builder.run([builder.env['CC'], '-Os', '-ffunction-sections', '-fdata-sections',
                 '-Wall', '-Wextra', '-Werror', '-Wl,--gc-sections',
                 str(path), *flags, '-o', str(temporary)], 'wayland-probe-link.log')
    layout = inspect_elf(temporary, builder.target)
    shutil.copyfile(temporary, builder.output / 'wayland-probe.symbols.elf')
    builder.run([builder.tools['llvm-strip'], '--strip-all', str(temporary)], 'wayland-probe-strip.log')
    probe = inspect_elf(temporary, builder.target)
    temporary.replace(builder.output / 'wayland-probe.elf')
    probe['file'] = str(builder.output / 'wayland-probe.elf')
    return {'probe': probe, 'symbol_image_sha256': layout['sha256'], 'source_sha256': digest(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inventory', 'build'), nargs='?', default='inventory')
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--bootstrap-libffi', action='store_true', help='Build the existing pinned libffi dependency first')
    parser.add_argument('--arch', choices=('aarch64', 'x86_64'), default='aarch64')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    selected_target = profile_for(args.arch)
    output = (args.output or selected_target.default_output(ROOT)).resolve()
    report_path = output / "wayland-build-report.json"
    host = output / "wayland-host-tools"
    try:
        wayland, expat = packages()
        if args.fetch and args.command != 'build':
            raise BuildError('--fetch requires build')
        if not 1 <= args.jobs <= 16:
            raise BuildError('--jobs must be in 1..16')
        if args.command == 'inventory':
            print(json.dumps({'wayland': wayland, 'host_expat': expat,
                              'output': str(output), 'network': False,
                              'guest_execution': 'not performed'}, indent=2))
            return 0
        if shutil.disk_usage(output).free < 512 * 1024 * 1024:
            raise BuildError('At least 512 MiB free disk required')
        prerequisites = [output / 'sysroot/usr/lib/libc.a', BUILD_TOOLS / 'bin/meson']
        if not args.bootstrap_libffi:
            prerequisites.append(output / 'sysroot/usr/lib/libffi.a')
        for path in prerequisites:
            if not path.is_file():
                raise BuildError('Missing prerequisite: ' + str(path))
        with (output / '.build.lock').open('w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise BuildError('Another sysroot build is active') from error
            report_path.unlink(missing_ok=True)
            builder = Builder(output, toolchain(), args.jobs, selected_target)
            report = {'status': 'building', 'architecture': selected_target.architecture, 'target_triple': selected_target.rust_target, 'manifest_sha256': digest(MANIFEST),
                      'expat_manifest_sha256': digest(EXPAT_MANIFEST),
                      'builder_sha256': digest(Path(__file__)), 'toolchain': builder.tools,
                      'commands': builder.commands, 'guest_execution': 'not performed',
                      'limitations': ['No compositor or COSMIC desktop is built.',
                                      'No wl_shm, EGL rendering or GPU acceleration is claimed.']}
            try:
                if args.bootstrap_libffi:
                    report['libffi_producer'] = build_libffi(builder, args.fetch)
                wl_source, wl_record = source(builder, wayland, args.fetch)
                expat_source, expat_record = source(builder, expat, args.fetch)
                report['sources'] = [wl_record, expat_record]
                report['native_scanner'] = build_host(builder, wl_source, expat_source)
                report['target'] = build_target(builder, wl_source)
                report.update(link_probe(builder))
                report['target_libffi_sha256'] = digest(output / 'sysroot/usr/lib/libffi.a')
                report['target_libc_sha256'] = digest(output / 'sysroot/usr/lib/libc.a')
                report['status'] = 'cross-built'
            except Exception as error:
                report['status'], report['error'] = 'failed', str(error)
                raise
            finally:
                report_path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'report': str(report_path),
                          'probe': report['probe'], 'guest_execution': 'not performed'}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('wayland: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
