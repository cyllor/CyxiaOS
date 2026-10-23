#!/usr/bin/env python3
"""Build pinned GTK3 prerequisites into CyxiaOS's static ARM musl sysroot.

Inventory is read-only. Building holds the shared sysroot lock, verifies every
source archive, and never runs a target program. Successful compilation is not
evidence of guest threading, dynamic loading, accessibility, or GTK support.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess

from build_sysroot import (Builder, BuildError, ROOT, DEFAULT_OUTPUT, BUILD_TOOLS,
                          toolchain, unpack, digest, validate_packages, inspect_elf)
import desktop_ports

MANIFEST = ROOT / 'ports/libc/gtk-foundation.json'
OUTPUTS = {
    'libpng': ['libpng16.a'], 'libjpeg-turbo': ['libjpeg.a'],
    'cairo': ['libcairo.a', 'libcairo-gobject.a'],
    'gdk-pixbuf': ['libgdk_pixbuf-2.0.a'], 'atk': ['libatk-1.0.a'],
    'pango': ['libpangocairo-1.0.a', 'libpango-1.0.a'],
    'libXfixes': ['libXfixes.a'], 'libXrandr': ['libXrandr.a'],
    'libXi': ['libXi.a'], 'libepoxy': ['libepoxy.a'],
    'gtk': ['libgtk-3.a', 'libgdk-3.a'],
}
OPTIONS = {
    'cairo': ['-Dpng=enabled', '-Dfontconfig=enabled', '-Dfreetype=enabled',
              '-Dxlib=enabled', '-Dxcb=enabled', '-Dzlib=enabled', '-Dglib=enabled',
              '-Dtests=disabled', '-Dgtk_doc=false', '-Dspectre=disabled',
              '-Dlzo=disabled', '-Dsymbol-lookup=disabled', '-Dgtk2-utils=disabled'],
    'gdk-pixbuf': ['-Dpng=enabled', '-Djpeg=enabled', '-Dgif=enabled',
                   '-Dtiff=disabled', '-Dothers=enabled', '-Dbuiltin_loaders=all',
                   '-Dintrospection=disabled', '-Dgtk_doc=false', '-Dman=false',
                   '-Dtests=false', '-Dinstalled_tests=false', '-Dgio_sniffing=false'],
    'atk': ['-Ddocs=false', '-Dintrospection=false'],
    'libepoxy': ['-Ddocs=false', '-Dtests=false', '-Degl=no', '-Dglx=yes', '-Dx11=true'],
    'pango': ['-Ddocumentation=false', '-Dman-pages=false', '-Dintrospection=disabled',
              '-Dbuild-testsuite=false', '-Dbuild-examples=false', '-Dlibthai=disabled',
              '-Dcairo=enabled', '-Dxft=enabled', '-Dfontconfig=enabled',
              '-Dfreetype=enabled', '-Dc_args=-D__CYXIA_SINGLE_THREAD_FONTCONFIG__'],
    'gtk': ['-Dx11_backend=true', '-Dwayland_backend=false', '-Dbroadway_backend=false',
            '-Dquartz_backend=false', '-Dwin32_backend=false', '-Dintrospection=false',
            '-Dgtk_doc=false', '-Dman=false', '-Dtests=false', '-Dexamples=false',
            '-Ddemos=false', '-Dprint_backends=', '-Dcolord=no', '-Dxinerama=no',
            '-Dbuiltin_immodules=all', '-Datk_bridge=false',
            '-Dcyxia_single_thread_compose=true',
            '-Dc_args=-ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables'],
}


def archive_architecture(path):
    """Inspect every archive object, rather than assuming its filename is ARM."""
    data = path.read_bytes()
    if data[:8] != b'!<arch>\n':
        raise BuildError(f'Not a regular static archive: {path}')
    offset, count = 8, 0
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise BuildError(f'Invalid archive header: {path}')
        size = int(header[48:58].strip())
        body = data[offset + 60:offset + 60 + size]
        name = header[:16].strip()
        if name not in (b'/', b'//', b'/SYM64/'):
            if len(body) < 20 or body[:6] != b'\x7fELF\x02\x01':
                raise BuildError(f'Archive member is not ELF64 LE: {path}: {name!r}')
            kind, machine = struct.unpack_from('<HH', body, 16)
            if (kind, machine) != (1, 183):
                raise BuildError(f'Archive member is not AArch64 ET_REL: {path}: {name!r}')
            count += 1
        offset += 60 + size + size % 2
    if count == 0 or offset != len(data):
        raise BuildError(f'Empty or truncated archive: {path}')
    return {'sha256': digest(path), 'bytes': path.stat().st_size,
            'aarch64_object_count': count}


def link_probe(builder):
    flags = shlex.split(subprocess.check_output(
        [builder.env['PKG_CONFIG'], '--static', '--cflags', '--libs', 'gtk+-3.0'],
        env=builder.env, text=True))
    source_file = ROOT / 'user/ported/gtk_probe.c'
    temporary = builder.output / 'gtk-probe.elf.tmp'
    builder.run([builder.env['CC'], '-Os', '-g', '-Wall', '-Wextra', '-Werror',
                 '-Wl,--gc-sections', str(source_file), *flags, '-o', str(temporary)], 'gtk-probe-link.log')
    builder.run([builder.tools['llvm-strip'], '--strip-debug', str(temporary)], 'gtk-probe-strip.log')
    # Check unresolved strong symbols before removing the symbol table. Preserve
    # that inspectable image separately from the compact boot-catalog artifact.
    checked_layout = inspect_elf(temporary)
    symbols = builder.output / 'gtk-probe.symbols.elf'
    shutil.copyfile(temporary, symbols)
    builder.run([builder.tools['llvm-strip'], '--strip-all', str(temporary)], 'gtk-probe-compact.log')
    report = {'probe': inspect_elf(temporary), 'probe_source_sha256': digest(source_file),
              'symbol_image': {'file': str(symbols), 'sha256': checked_layout['sha256']},
              'commands': builder.commands, 'guest_execution': 'not performed'}
    temporary.replace(builder.output / 'gtk-probe.elf')
    report['probe']['file'] = str(builder.output / 'gtk-probe.elf')
    return report


def build(fetch=False, only=None, jobs=8):
    out, target = DEFAULT_OUTPUT, DEFAULT_OUTPUT / 'sysroot'
    manifest = json.loads(MANIFEST.read_text())
    validate_packages(manifest['packages'])
    builder = Builder(out, toolchain(), jobs)
    builder.target_environment()
    builder.env['PATH'] = str(BUILD_TOOLS / 'bin') + os.pathsep + builder.env.get('PATH', '')
    builder.env['PKG_CONFIG'] = str(builder.shell_wrapper(
        'gtk-pkg-config-static', [shutil.which('pkg-config'), '--static']))
    builder.env['CXX'] = str(out / 'bin/aarch64-linux-musl-cxx')
    host_tools = {}
    for name in ('glib-compile-resources', 'glib-compile-schemas', 'glib-genmarshal',
                 'glib-mkenums', 'gdbus-codegen'):
        program = shutil.which(name)
        if not program:
            raise BuildError('Required native build tool missing: ' + name)
        host_tools[name] = program
    cross = out / 'gtk-foundation-cross.ini'
    cross.write_text('[binaries]\n' +
        'c = ' + repr(builder.env['CC']) + '\ncpp = ' + repr(builder.env['CXX']) + '\n' +
        'ar = ' + repr(builder.tools['llvm-ar']) + '\nstrip = ' + repr(builder.tools['llvm-strip']) + '\n' +
        'pkg-config = ' + repr(builder.env['PKG_CONFIG']) + '\n' +
        ''.join(name + ' = ' + repr(program) + '\n' for name, program in host_tools.items()) +
        "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\ncpu = 'cortex-a53'\nendian = 'little'\n" +
        '[properties]\nneeds_exe_wrapper = true\nsys_root = ' + repr(str(target)) + '\n' +
        'pkg_config_libdir = ' + repr(builder.env['PKG_CONFIG_LIBDIR'].split(os.pathsep)) + '\n')
    source_root = out / 'gtk-source'
    source_root.mkdir(exist_ok=True)
    meson = str(BUILD_TOOLS / 'bin/meson')
    triplet = subprocess.check_output(['sh', str(out / 'source/xorgproto-2024.1/config.guess')], text=True).strip()
    report_path = out / ('gtk-foundation-' + (only or 'all') + '-report.json')
    report = {'status': 'building', 'target': 'aarch64-linux-musl', 'packages': [],
              'commands': builder.commands, 'manifest_sha256': digest(MANIFEST),
              'toolchain': builder.tools, 'native_codegen_tools': host_tools,
              'guest_execution': 'not performed',
              'limitations': ['Static libraries only; no guest dynamic loader or general pthread implementation.',
                              'ATK is an in-process API only; no AT-SPI session bus or accessibility bridge.',
                              'GTK printing backends are disabled; input modules are built in.',
                              'Epoxy GLX dispatch is compiled; no OpenGL provider is installed or claimed.',
                              'GdkPixbuf uses built-in loaders, including XPM required by libwnck fallback icons; TIFF and GIO MIME sniffing disabled.',
                              'GTK Compose tables load synchronously on the caller; general GTask workers are not supported.',
                              'Pango retains the explicit synchronous Fontconfig port used by Openbox.']}
    try:
        for package in manifest['packages']:
            name = package['name']
            if only and only != name:
                continue
            print('Building ' + name, flush=True)
            record = (desktop_ports.fetch(package, ROOT / 'artifacts/desktop-sources', online=True, max_bytes=64 * 1024 * 1024)
                      if fetch else desktop_ports.verify(package, ROOT / 'artifacts/desktop-sources', max_bytes=64 * 1024 * 1024))
            source = unpack(package, record, source_root)
            licenses = out / 'licenses' / name
            licenses.mkdir(exist_ok=True)
            for license_name in [package['license_file'], 'COPYING-LGPL-2.1', 'COPYING-MPL-1.1', 'README.ijg']:
                if (source / license_name).is_file():
                    shutil.copyfile(source / license_name, licenses / license_name)
            directory = out / ('gtk-' + name + '-build')
            if directory.exists():
                shutil.rmtree(directory)
            if name == 'libpng' or name.startswith('libX'):
                directory.mkdir()
                extra = (['--disable-tools', '--disable-tests', '--enable-arm-neon=no']
                         if name == 'libpng' else ['--disable-docs', '--disable-specs', '--without-xmlto', '--without-fop'])
                builder.env['xorg_cv_malloc0_returns_null'] = 'no'
                builder.run([str(source / 'configure'), '--prefix=/usr', '--host=aarch64-linux-musl',
                             '--build=' + triplet, '--disable-shared', '--enable-static',
                             *extra], 'gtk-' + name + '-configure.log', directory)
                builder.run([builder.tools['make'], '-j' + str(jobs)], 'gtk-' + name + '-build.log', directory)
                builder.run([builder.tools['make'], 'install', 'DESTDIR=' + str(target)], 'gtk-' + name + '-install.log', directory)
            elif name == 'libjpeg-turbo':
                cmake = str(BUILD_TOOLS / 'bin/cmake')
                builder.run([cmake, '-S', str(source), '-B', str(directory), '-G', 'Ninja',
                             '-DCMAKE_SYSTEM_NAME=Linux', '-DCMAKE_SYSTEM_PROCESSOR=aarch64',
                             '-DCMAKE_C_COMPILER=' + builder.env['CC'], '-DCMAKE_AR=' + builder.tools['llvm-ar'],
                             '-DCMAKE_RANLIB=' + builder.env['RANLIB'], '-DCMAKE_BUILD_TYPE=MinSizeRel',
                             '-DCMAKE_INSTALL_PREFIX=/usr', '-DCMAKE_INSTALL_LIBDIR=lib',
                             '-DENABLE_SHARED=OFF', '-DENABLE_STATIC=ON', '-DWITH_TURBOJPEG=OFF',
                             '-DWITH_SIMD=OFF', '-DCMAKE_POSITION_INDEPENDENT_CODE=OFF'], 'gtk-jpeg-setup.log')
                builder.run([cmake, '--build', str(directory), '-j', str(jobs)], 'gtk-jpeg-build.log')
                builder.env['DESTDIR'] = str(target)
                builder.run([cmake, '--install', str(directory)], 'gtk-jpeg-install.log')
                del builder.env['DESTDIR']
            else:
                port_patch = {'gdk-pixbuf': 'gdk-pixbuf-static-loaders.patch',
                              'gtk': 'gtk-optional-atspi-bridge.patch'}.get(name)
                if port_patch:
                    patch = ROOT / 'ports/libc/patches' / port_patch
                    builder.run(['patch', '-p1', '-i', str(patch)], 'gtk-' + name + '-port-patch.log', source)
                    report[name + '_port_patch_sha256'] = digest(patch)
                if name == 'gtk':
                    patch = ROOT / 'ports/libc/patches/gtk-allow-no-print-backends.patch'
                    builder.run(['patch', '-p1', '-i', str(patch)], 'gtk-print-port-patch.log', source)
                    report['gtk_print_port_patch_sha256'] = digest(patch)
                    patch = ROOT / 'ports/libc/patches/gtk-cyxia-static-single-thread.patch'
                    builder.run(['patch', '-p1', '-i', str(patch)], 'gtk-static-port-patch.log', source)
                    report['gtk_static_port_patch_sha256'] = digest(patch)
                if name == 'pango':
                    patch = ROOT / 'ports/libc/patches/pango-cyxia-synchronous-fontconfig.patch'
                    builder.run(['patch', '-p1', '-i', str(patch)], 'gtk-pango-port-patch.log', source)
                    report['pango_port_patch_sha256'] = digest(patch)
                builder.run([meson, 'setup', str(directory), str(source), '--cross-file', str(cross),
                             '--prefix=/usr', '--libdir=lib', '--buildtype=minsize',
                             '--default-library=static', '--wrap-mode=nodownload', *OPTIONS[name]], 'gtk-' + name + '-setup.log')
                builder.run([meson, 'compile', '-C', str(directory), '-j', str(jobs)], 'gtk-' + name + '-build.log')
                builder.env['DESTDIR'] = str(target)
                builder.run([meson, 'install', '-C', str(directory)], 'gtk-' + name + '-install.log')
                del builder.env['DESTDIR']
            for archive in (target / 'usr/lib').glob('*.la'):
                archive.unlink()
            outputs = {filename: archive_architecture(target / 'usr/lib' / filename) for filename in OUTPUTS[name]}
            if name == 'gtk':
                probe_report = link_probe(builder)
                report.update(probe_report)
                (out / 'gtk-probe-build-report.json').write_text(json.dumps(probe_report, indent=2) + '\n')
            report['packages'].append({'name': name, 'version': package['version'], 'source': record,
                                       'outputs': outputs, 'licenses': {p.name: digest(p) for p in licenses.iterdir() if p.is_file()}})
            report_path.write_text(json.dumps(report, indent=2) + '\n')
        report['status'] = 'cross-built'
    except Exception as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    return report_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['inventory', 'build', 'probe'], default='inventory', nargs='?')
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--only', choices=list(OUTPUTS))
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()
    if args.command == 'inventory':
        print(MANIFEST.read_text())
    else:
        if not 1 <= args.jobs <= 32:
            parser.error('--jobs must be in 1..32')
        with (DEFAULT_OUTPUT / '.build.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.command == 'probe':
                builder = Builder(DEFAULT_OUTPUT, toolchain(), args.jobs)
                builder.target_environment()
                report = link_probe(builder)
                output = DEFAULT_OUTPUT / 'gtk-probe-build-report.json'
                output.write_text(json.dumps(report, indent=2) + '\n')
                print(output)
            else:
                print(build(args.fetch, args.only, args.jobs))
