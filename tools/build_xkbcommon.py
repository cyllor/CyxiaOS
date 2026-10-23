#!/usr/bin/env python3
"""Build genuine libxkbcommon core for static AArch64 musl, without running it.

Inventory is read-only. `build --fetch` permits pinned source downloads; ordinary
`build` requires the verified cache. Native Bison lives in an isolated prefix.
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

MANIFEST = ROOT / 'ports/cosmic/xkbcommon-source.json'
HOST = DEFAULT_OUTPUT / 'xkbcommon-host-tools'
REPORT = DEFAULT_OUTPUT / 'xkbcommon-build-report.json'


def source(builder, package, fetch):
    record = (desktop_ports.fetch(package, desktop_ports.DEFAULT_CACHE, online=True,
                                  max_bytes=8 * 1024 * 1024) if fetch else
              desktop_ports.verify(package, desktop_ports.DEFAULT_CACHE,
                                   max_bytes=8 * 1024 * 1024))
    directory = builder.output / 'xkbcommon-source'
    directory.mkdir(exist_ok=True)
    path = unpack(package, record, directory)
    license_dir = builder.output / 'licenses' / ('xkbcommon-' + package['name'])
    license_dir.mkdir(exist_ok=True)
    shutil.copyfile(path / package['license_file'], license_dir / package['license_file'])
    return path, {'source': record, 'license_sha256': digest(license_dir / package['license_file'])}


def fresh(directory):
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir()


def build_bison(builder, directory):
    builder.env = clean_env()
    for key in list(builder.env):
        if key.startswith('PKG_CONFIG') or key == 'DESTDIR':
            builder.env.pop(key)
    builder.env['CC'] = builder.tools['clang']
    host_build = builder.output / 'xkbcommon-bison-build'
    fresh(host_build)
    builder.run([str(directory / 'configure'), '--prefix=' + str(HOST), '--disable-nls'],
                'xkbcommon-bison-setup.log', host_build)
    builder.run([builder.tools['make'], '-j' + str(builder.jobs)],
                'xkbcommon-bison-build.log', host_build)
    builder.run([builder.tools['make'], 'install'], 'xkbcommon-bison-install.log', host_build)
    bison = HOST / 'bin/bison'
    version = subprocess.check_output([str(bison), '--version'], env=builder.env,
                                      text=True).splitlines()[0]
    return {'path': str(bison), 'sha256': digest(bison), 'version': version}


def build_library(builder, source_dir):
    builder.env = clean_env()
    builder.target_environment()
    builder.env.pop('DESTDIR', None)
    builder.env['PATH'] = os.pathsep.join((str(HOST / 'bin'), str(BUILD_TOOLS / 'bin'),
                                         builder.env.get('PATH', '')))
    target = builder.output / 'sysroot'
    builder.env['PKG_CONFIG'] = str(builder.shell_wrapper('xkbcommon-target-pkg-config',
                                                         [shutil.which('pkg-config'), '--static']))
    cross = builder.output / 'xkbcommon-cross.ini'
    cross.write_text('[binaries]\n' +
        'c = ' + repr(builder.env['CC']) + '\n' +
        'ar = ' + repr(builder.tools['llvm-ar']) + '\n' +
        'strip = ' + repr(builder.tools['llvm-strip']) + '\n' +
        'pkg-config = ' + repr(builder.env['PKG_CONFIG']) + '\n' +
        "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\ncpu = 'cortex-a53'\nendian = 'little'\n" +
        '[properties]\nneeds_exe_wrapper = true\nsys_root = ' + repr(str(target)) + '\n' +
        'pkg_config_libdir = ' + repr(builder.env['PKG_CONFIG_LIBDIR'].split(os.pathsep)) + '\n')
    directory = builder.output / 'xkbcommon-target-build'
    fresh(directory)
    meson = str(BUILD_TOOLS / 'bin/meson')
    options = ['--prefix=/usr', '--libdir=lib', '--wrap-mode=nofallback',
               '--cross-file=' + str(cross), '-Dbuildtype=release',
               '-Ddefault_library=static', '-Db_staticpic=false',
               '-Denable-x11=false', '-Denable-wayland=false', '-Denable-docs=false',
               '-Denable-xkbregistry=false', '-Denable-tools=false',
               '-Denable-bash-completion=false',
               '-Dxkb-config-root=/usr/share/X11/xkb',
               '-Dc_args=-ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables']
    builder.run([meson, 'setup', str(directory), str(source_dir), *options],
                'xkbcommon-target-setup.log')
    # Upstream has no disable-tests option. Build only its actual core library;
    # install without the default all-target rebuild (which would build tests).
    builder.run([meson, 'compile', '-C', str(directory), '-j', str(builder.jobs), 'xkbcommon'],
                'xkbcommon-target-build.log')
    builder.env['DESTDIR'] = str(target)
    try:
        builder.run([meson, 'install', '-C', str(directory), '--no-rebuild'], 'xkbcommon-target-install.log')
    finally:
        builder.env.pop('DESTDIR', None)
    return {'options': options, 'archive': archive_architecture(target / 'usr/lib/libxkbcommon.a')}


def link_probe(builder):
    flags = shlex.split(subprocess.check_output(
        [builder.env['PKG_CONFIG'], '--static', '--cflags', '--libs', 'xkbcommon'],
        env=builder.env, text=True))
    path = ROOT / 'user/ported/xkbcommon_probe.c'
    temporary = builder.output / 'xkbcommon-probe.elf.tmp'
    builder.run([builder.env['CC'], '-Os', '-ffunction-sections', '-fdata-sections',
                 '-Wall', '-Wextra', '-Werror', '-Wl,--gc-sections',
                 str(path), *flags, '-o', str(temporary)], 'xkbcommon-probe-link.log')
    layout = inspect_elf(temporary)
    shutil.copyfile(temporary, builder.output / 'xkbcommon-probe.symbols.elf')
    builder.run([builder.tools['llvm-strip'], '--strip-all', str(temporary)], 'xkbcommon-probe-strip.log')
    probe = inspect_elf(temporary)
    temporary.replace(builder.output / 'xkbcommon-probe.elf')
    probe['file'] = str(builder.output / 'xkbcommon-probe.elf')
    return {'probe': probe, 'symbol_image_sha256': layout['sha256'], 'probe_source_sha256': digest(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inventory', 'build'), nargs='?', default='inventory')
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--reuse-host-tools', action='store_true',
                        help='Reuse native Bison only after checking its saved build provenance and binary hash')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    try:
        package = json.loads(MANIFEST.read_text())
        bison = package['host_tools'][0]
        validate_packages([package, bison])
        if (args.fetch or args.reuse_host_tools) and args.command != 'build':
            raise BuildError('--fetch and --reuse-host-tools require build')
        if not 1 <= args.jobs <= 16:
            raise BuildError('--jobs must be in 1..16')
        if args.command == 'inventory':
            print(json.dumps({'source': package, 'output': str(DEFAULT_OUTPUT),
                              'network': False, 'guest_execution': 'not performed'}, indent=2))
            return 0
        if shutil.disk_usage(DEFAULT_OUTPUT).free < 512 * 1024 * 1024:
            raise BuildError('At least 512 MiB free disk required')
        for path in (DEFAULT_OUTPUT / 'sysroot/usr/lib/libc.a', BUILD_TOOLS / 'bin/meson'):
            if not path.is_file():
                raise BuildError('Missing prerequisite: ' + str(path))
        with (DEFAULT_OUTPUT / '.build.lock').open('w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise BuildError('Another sysroot build is active') from error
            reused_bison = None
            if args.reuse_host_tools:
                previous = json.loads(REPORT.read_text())
                native = previous['native_bison']
                if (previous['manifest_sha256'] != digest(MANIFEST)
                        or previous['sources'][1]['source']['sha256'] != bison['expected_sha256']
                        or native['version'] != 'bison (GNU Bison) 3.8.2'
                        or native['sha256'] != digest(HOST / 'bin/bison')):
                    raise BuildError('Native Bison provenance or binary changed; rebuild without --reuse-host-tools')
                saved = HOST / 'bison-build-provenance.json'
                # Keep the original host build record when subsequent target
                # builds reuse it, rather than overwriting its provenance chain.
                if 'provenance_sha256' in native:
                    if native['provenance_sha256'] != digest(saved):
                        raise BuildError('Original native Bison build record changed')
                else:
                    shutil.copyfile(REPORT, saved)
                reused_bison = {**native, 'reused': True, 'provenance_sha256': digest(saved)}
            REPORT.unlink(missing_ok=True)
            builder = Builder(DEFAULT_OUTPUT, toolchain(), args.jobs)
            report = {'status': 'building', 'manifest_sha256': digest(MANIFEST),
                      'builder_sha256': digest(Path(__file__)), 'toolchain': builder.tools,
                      'commands': builder.commands, 'guest_execution': 'not performed',
                      'scope': 'static core keymap/state library; embedded fixture, not full desktop layouts'}
            try:
                xkb_source, xkb_record = source(builder, package, args.fetch)
                bison_source, bison_record = source(builder, bison, args.fetch)
                report['sources'] = [xkb_record, bison_record]
                report['native_bison'] = reused_bison or build_bison(builder, bison_source)
                report['target'] = build_library(builder, xkb_source)
                report.update(link_probe(builder))
                report['target_libc_sha256'] = digest(DEFAULT_OUTPUT / 'sysroot/usr/lib/libc.a')
                report['status'] = 'cross-built'
            except Exception as error:
                report['status'], report['error'] = 'failed', str(error)
                raise
            finally:
                REPORT.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'report': str(REPORT),
                          'probe': report['probe'], 'guest_execution': 'not performed'}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('xkbcommon: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
