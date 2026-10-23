#!/usr/bin/env python3
"""Build real, pinned LXPanel GTK3 with statically linked built-in plugins."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_sysroot import (ROOT, DEFAULT_OUTPUT, BUILD_TOOLS, Builder, BuildError,
                          toolchain, unpack, digest, inspect_elf)
from build_gtk_foundation import archive_architecture
from build_pcmanfm import source_record, extract_git, target_environment, install_assets

MANIFEST = ROOT / 'ports/libc/lxpanel-foundation.json'
STAGES = ('libwnck', 'keybinder', 'lxpanel')


def verify_static_resources(path, nm):
    symbols = subprocess.check_output([nm, '--defined-only', str(path)], text=True)
    if not any(line.split()[-1:] == ['libwnck_get_resource'] for line in symbols.splitlines()):
        raise BuildError('LXPanel static link omitted libwnck embedded icon resources')
    return {'libwnck_get_resource': 'retained'}


def build(builder, only, fetch):
    target_environment(builder)
    out, target = DEFAULT_OUTPUT, DEFAULT_OUTPUT / 'sysroot'
    manifest = json.loads(MANIFEST.read_text())
    packages = {p['name']: p for p in manifest['packages']}
    packages['lxpanel'] = next(p for p in json.loads(
        (ROOT / manifest['lxpanel_source_manifest']).read_text())['packages'] if p['name'] == 'lxpanel')
    triplet = subprocess.check_output(['sh', str(out / 'source/xorgproto-2024.1/config.guess')], text=True).strip()
    cross = out / 'lxpanel-cross.ini'
    cross.write_text('[binaries]\n' +
        'c = ' + repr(builder.env['CC']) + '\n' +
        'ar = ' + repr(builder.tools['llvm-ar']) + '\n' +
        'strip = ' + repr(builder.tools['llvm-strip']) + '\n' +
        'pkg-config = ' + repr(builder.env['PKG_CONFIG']) + '\n' +
        ''.join(name + ' = ' + repr(shutil.which(name)) + '\n' for name in
                ('glib-compile-resources', 'glib-genmarshal', 'glib-mkenums')) +
        "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\ncpu = 'cortex-a53'\nendian = 'little'\n" +
        '[properties]\nneeds_exe_wrapper = true\nsys_root = ' + repr(str(target)) + '\n' +
        'pkg_config_libdir = ' + repr(builder.env['PKG_CONFIG_LIBDIR'].split(os.pathsep)) + '\n')
    records = []
    for name in STAGES:
        if only and name != only:
            continue
        print('Building ' + name, flush=True)
        package = packages[name]
        record = source_record(package, fetch)
        if name == 'libwnck':
            source_root = out / 'lxpanel-source'
            source_root.mkdir(exist_ok=True)
            source = unpack(package, record, source_root)
        else:
            source = extract_git(record, out / ('lxpanel-' + name + '-source'))
        patches = []
        patch_name = {'libwnck': 'libwnck-static-build.patch',
                      'keybinder': 'keybinder-optional-introspection.patch',
                      'lxpanel': 'lxpanel-vpath-headers.patch'}.get(name)
        if patch_name:
            patch = ROOT / 'ports/libc/patches' / patch_name
            builder.run(['patch', '-p1', '-i', str(patch)], 'lxpanel-' + name + '-patch.log', source)
            patches.append({'file': str(patch.relative_to(ROOT)), 'sha256': digest(patch)})
        directory = out / ('lxpanel-' + name + '-build')
        if directory.exists():
            shutil.rmtree(directory)
        if name == 'libwnck':
            meson = str(BUILD_TOOLS / 'bin/meson')
            options = ['--prefix=/usr', '--libdir=lib', '--buildtype=minsize',
                       '--default-library=static', '--cross-file=' + str(cross),
                       '-Dintrospection=disabled', '-Dgtk_doc=false', '-Dinstall_tools=false',
                       '-Dstartup_notification=disabled',
                       '-Dc_args=-ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables']
            builder.run([meson, 'setup', str(directory), str(source), *options], 'lxpanel-libwnck-setup.log')
            builder.run([meson, 'compile', '-C', str(directory), '-j', str(builder.jobs)], 'lxpanel-libwnck-build.log')
            builder.env['DESTDIR'] = str(target)
            try:
                builder.run([meson, 'install', '-C', str(directory)], 'lxpanel-libwnck-install.log')
            finally:
                del builder.env['DESTDIR']
        else:
            (source / 'm4').mkdir(exist_ok=True)
            if name == 'keybinder':
                # Upstream autogen.sh creates this generated distribution file.
                (source / 'ChangeLog').touch()
                builder.run([str(out / 'pcmanfm-host-tools/bin/gtkdocize'), '--copy'],
                            'lxpanel-keybinder-gtkdocize.log', source)
            builder.run(['autoreconf', '-fiv'], 'lxpanel-' + name + '-autoreconf.log', source)
            directory.mkdir()
            options = ['--prefix=/usr', '--sysconfdir=/etc', '--host=aarch64-linux-musl',
                       '--build=' + triplet, '--disable-shared', '--enable-static']
            if name == 'keybinder':
                options += ['--disable-gtk-doc', '--disable-introspection']
            else:
                options += ['--enable-gtk3', '--disable-plugins-loading', '--with-plugins=none',
                            '--disable-alsa', '--disable-indicator-support']
            builder.run([str(source / 'configure'), *options], 'lxpanel-' + name + '-setup.log', directory)
            builder.run([builder.tools['make'], '-j' + str(builder.jobs)], 'lxpanel-' + name + '-build.log', directory)
            builder.run([builder.tools['make'], 'install', 'DESTDIR=' + str(target)], 'lxpanel-' + name + '-install.log', directory)
        for archive in (target / 'usr/lib').glob('*.la'):
            archive.unlink()
        license_dir = out / 'licenses' / name
        license_dir.mkdir(exist_ok=True)
        shutil.copyfile(source / 'COPYING', license_dir / 'COPYING')
        result = {'name': name, 'source': record, 'patches': patches, 'configure_options': options,
                  'license_sha256': digest(license_dir / 'COPYING'), 'guest_execution': 'not performed'}
        if name == 'lxpanel':
            temporary = out / 'lxpanel.elf.tmp'
            shutil.copyfile(target / 'usr/bin/lxpanel', temporary)
            builder.run([builder.tools['llvm-strip'], '--strip-debug', str(temporary)], 'lxpanel-strip.log')
            result['symbol_image'] = inspect_elf(temporary)
            result['static_resources'] = verify_static_resources(temporary, builder.tools['llvm-nm'])
            shutil.copyfile(temporary, out / 'lxpanel.symbols.elf')
            result['symbol_image']['file'] = str(out / 'lxpanel.symbols.elf')
            builder.run([builder.tools['llvm-strip'], '--strip-all', str(temporary)], 'lxpanel-compact.log')
            result['executable'] = inspect_elf(temporary)
            temporary.replace(out / 'lxpanel.elf')
            result['executable']['file'] = str(out / 'lxpanel.elf')
        else:
            archive = 'libwnck-3.a' if name == 'libwnck' else 'libkeybinder-3.0.a'
            result['archive'] = archive_architecture(target / 'usr/lib' / archive)
        (out / ('lxpanel-' + name + '-report.json')).write_text(json.dumps(result, indent=2) + '\n')
        records.append(result)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inventory', 'build', 'verify', 'install-assets'), nargs='?', default='inventory')
    parser.add_argument('--only', choices=STAGES)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()
    if args.command == 'inventory':
        print(MANIFEST.read_text())
        return
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be in 1..32')
    with (DEFAULT_OUTPUT / '.build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'install-assets':
            print(install_assets(ROOT / 'ports/desktop/lxpanel-rootfs.json', DEFAULT_OUTPUT / 'rootfs',
                                 DEFAULT_OUTPUT / 'lxpanel-assets-report.json'))
            return
        if args.command == 'verify':
            report = {'status': 'cross-built-and-statically-verified',
                      'guest_execution': 'not performed',
                      'symbol_image': inspect_elf(DEFAULT_OUTPUT / 'lxpanel.symbols.elf'),
                      'static_resources': verify_static_resources(DEFAULT_OUTPUT / 'lxpanel.symbols.elf', toolchain()['llvm-nm']),
                      'executable': inspect_elf(DEFAULT_OUTPUT / 'lxpanel.elf'),
                      'archives': {name: archive_architecture(DEFAULT_OUTPUT / 'sysroot/usr/lib' / name)
                                   for name in ('libwnck-3.a', 'libkeybinder-3.0.a')},
                      'asset_manifest_sha256': digest(ROOT / 'ports/desktop/lxpanel-rootfs.json'),
                      'verification_tool_sha256': digest(Path(__file__))}
            path = DEFAULT_OUTPUT / 'lxpanel-verified-report.json'
            path.write_text(json.dumps(report, indent=2) + '\n')
            print(path)
            return
        builder = Builder(DEFAULT_OUTPUT, toolchain(), args.jobs)
        report = {'status': 'building', 'commands': builder.commands, 'manifest_sha256': digest(MANIFEST),
                  'builder_sha256': digest(Path(__file__)),
                  'source_manifest_sha256': digest(ROOT / 'ports/desktop/manifest.json'),
                  'shared_builder_sha256': digest(ROOT / 'tools/build_pcmanfm.py'),
                  'guest_execution': 'not performed'}
        try:
            report['packages'] = build(builder, args.only, args.fetch)
            report['status'] = 'cross-built'
        except Exception as error:
            report.update(status='failed', error=str(error))
            raise
        finally:
            report_path = DEFAULT_OUTPUT / ('lxpanel-' + (args.only or 'all') + '-build-report.json')
            report_path.write_text(json.dumps(report, indent=2) + '\n')
        print(report_path)


if __name__ == '__main__':
    main()
