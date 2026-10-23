#!/usr/bin/env python3
"""Cross-build Openbox prerequisites. Default inventory, no implicit retrieval.

The foundation stage installs static libffi, PCRE2 and GLib into the isolated
CyxiaOS target sysroot. It does not claim Openbox or GTK runtime compatibility.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
from build_sysroot import Builder, ROOT, DEFAULT_OUTPUT, BUILD_TOOLS, toolchain, unpack, inspect_elf, digest
import desktop_ports


def foundation(fetch=False, only=None, cyxia_spawn=False):
    out = DEFAULT_OUTPUT
    target = out / 'sysroot'
    builder = Builder(out, toolchain(), 8)
    builder.target_environment()
    builder.env['PATH'] = str(BUILD_TOOLS/'bin') + os.pathsep + builder.env.get('PATH', '')
    manifest = json.loads((ROOT/'ports/libc/openbox-foundation.json').read_text())
    triplet = subprocess.check_output(['sh', str(out/'source/xorgproto-2024.1/config.guess')], text=True).strip()
    records = []
    patches = []
    for package in manifest['packages'][:3]:
        if only and package['name'] != only:
            continue
        package = dict(package, depends_on=[], source_commit=None)
        cache = ROOT/'artifacts/desktop-sources'
        record = (desktop_ports.fetch(package, cache, online=True, max_bytes=32*1024*1024)
                  if fetch else desktop_ports.verify(package, cache, max_bytes=32*1024*1024))
        records.append(record)
        source = unpack(package, record, out/'source')
        name = package['name']
        license_dir = out/'licenses'/name
        license_dir.mkdir(exist_ok=True)
        shutil.copyfile(source/package['license_file'], license_dir/package['license_file'])
        build = out/(name+'-build')
        if build.exists(): shutil.rmtree(build)
        if name == 'glib':
            patch = ROOT / 'ports/libc/patches/glib-cyxia-spawn.patch'
            builder.run(['patch', '-p1', '-i', str(patch)], 'glib-cyxia-spawn-patch.log', source)
            patches.append({'file': str(patch.relative_to(ROOT)), 'sha256': digest(patch),
                            'enabled': cyxia_spawn})
            cross = out/'glib-cross.ini'
            cross.write_text('[binaries]\n' +
                'c = '+repr(builder.env['CC'])+'\n' +
                'ar = '+repr(builder.tools['llvm-ar'])+'\n' +
                'strip = '+repr(builder.tools['llvm-strip'])+'\n' +
                'pkg-config = '+repr(builder.env['PKG_CONFIG'])+'\n' +
                "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\ncpu = 'cortex-a53'\nendian = 'little'\n"+
                '[properties]\nneeds_exe_wrapper = true\nsys_root = '+repr(str(target))+'\n'+
                'pkg_config_libdir = '+repr(builder.env['PKG_CONFIG_LIBDIR'].split(os.pathsep))+'\n'+
                # musl/AAPCS64 properties, not guessed guest services.
                'have_c99_vsnprintf = true\nhave_c99_snprintf = true\nhave_unix98_printf = true\n'+
                'growing_stack = false\nhave_proc_self_cmdline = false\n')
            meson = str(BUILD_TOOLS/'bin/meson')
            builder.run([meson,'setup',str(build),str(source),'--cross-file',str(cross),
                '--prefix=/usr','--libdir=lib','--buildtype=minsize','--default-library=static','--wrap-mode=nodownload',
                '-Dtests=false','-Dinstalled_tests=false','-Dnls=disabled','-Dselinux=disabled',
                '-Dxattr=false','-Dlibmount=disabled','-Dman-pages=disabled','-Ddtrace=disabled',
                '-Dsystemtap=disabled','-Dsysprof=disabled','-Ddocumentation=false',
                '-Dlibelf=disabled','-Dintrospection=disabled',
                '-Dcyxia_spawn=' + ('true' if cyxia_spawn else 'false')],name+'-setup.log')
            builder.run([meson,'compile','-C',str(build),'-j','8'],name+'-build.log')
            builder.env['DESTDIR'] = str(target)
            builder.run([meson,'install','-C',str(build)],name+'-install.log')
            del builder.env['DESTDIR']
        else:
            build.mkdir()
            options=['--prefix=/usr','--host=aarch64-linux-musl','--build='+triplet,
                     '--disable-shared','--enable-static']
            if name == 'libffi': options += ['--disable-multi-os-directory','--disable-docs','--disable-exec-static-tramp']
            if name == 'pcre2': options += ['--disable-pcre2grep','--disable-tests','--disable-jit']
            builder.run([str(source/'configure'),*options],name+'-configure.log',build)
            builder.run([builder.tools['make'],'-j8'],name+'-make.log',build)
            builder.run([builder.tools['make'],'install','DESTDIR='+str(target)],name+'-install.log',build)
            for archive in (target/'usr/lib').glob('*.la'): archive.unlink()
    report=dict(sources=records,commands=builder.commands,patches=patches,
                cyxia_spawn=cyxia_spawn,guest_execution='not performed',
                scope='Openbox library foundation; window manager and font closure remain incomplete')
    (out/'openbox-foundation-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def window_manager(fetch=False):
    """Link upstream Openbox against the previously built target libraries."""
    out = DEFAULT_OUTPUT
    builder = Builder(out, toolchain(), 8)
    builder.target_environment()
    builder.env['PKG_CONFIG'] = str(builder.shell_wrapper(
        'pkg-config-static', [shutil.which('pkg-config'), '--static']))
    builder.env['LD'] = str(out/'bin/ld.lld')
    builder.env['LIBS'] = subprocess.check_output(
        [builder.env['PKG_CONFIG'], '--libs', 'x11', 'xt', 'xext'],
        env=builder.env, text=True).strip()
    package = json.loads((ROOT/'ports/libc/openbox-foundation.json').read_text())['packages'][-1]
    cache = ROOT/'artifacts/desktop-sources'
    record = (desktop_ports.fetch(package, cache, online=True, max_bytes=32*1024*1024)
              if fetch else desktop_ports.verify(package, cache, max_bytes=32*1024*1024))
    source = unpack(package, record, out/'source')
    # The 2015 release's GNU platform recognizer predates Apple Silicon.
    # Reuse the helpers from the already pinned X.Org protocol source.
    for helper in ('config.guess', 'config.sub'):
        shutil.copyfile(out/'source/xorgproto-2024.1'/helper, source/helper)
    licenses = out/'licenses/openbox'
    licenses.mkdir(exist_ok=True)
    shutil.copyfile(source/'COPYING', licenses/'COPYING')
    directory = out/'openbox-build'
    if directory.exists(): shutil.rmtree(directory)
    directory.mkdir()
    triplet = subprocess.check_output(['sh', str(out/'source/xorgproto-2024.1/config.guess')], text=True).strip()
    builder.run([str(source/'configure'), '--host=aarch64-linux-musl', '--build='+triplet,
        '--prefix=/usr', '--sysconfdir=/etc', '--disable-shared', '--enable-static',
        '--x-includes='+str(out/'sysroot/usr/include'),
        '--x-libraries='+str(out/'sysroot/usr/lib'),
        '--disable-nls', '--disable-startup-notification', '--disable-xcursor',
        '--disable-imlib2', '--disable-librsvg'], 'openbox-configure.log', directory)
    builder.run([builder.tools['make'], '-j8', 'openbox/openbox'], 'openbox-make.log', directory)
    temporary = out/'openbox.elf.tmp'
    shutil.copyfile(directory/'openbox/openbox', temporary)
    builder.run([builder.tools['llvm-strip'], '--strip-debug', str(temporary)], 'openbox-strip.log')
    layout = inspect_elf(temporary)
    temporary.replace(out/'openbox.elf')
    install_assets(out)
    report = dict(sources=[record], elf=layout, commands=builder.commands,
                  scope='Upstream Openbox static ARM image; guest execution not performed')
    (out/'openbox-build-report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def install_assets(out=DEFAULT_OUTPUT):
    source = ROOT/'user/ported/openbox'
    assets = {
        'etc/passwd': source/'passwd',
        'etc/group': source/'group',
        'etc/xdg/openbox/rc.xml': source/'rc.xml',
        'etc/xdg/openbox/menu.xml': source/'menu.xml',
        'etc/fonts/fonts.conf': source/'fonts.conf',
        'usr/share/themes/Cyxia/openbox-3/themerc': source/'themerc',
        'usr/share/fonts/Roboto-Regular.ttf': out/'source/harfbuzz-12.3.2/perf/fonts/Roboto-Regular.ttf',
    }
    # The font is an unmodified file in the verified HarfBuzz source archive.
    manifest = json.loads((ROOT/'ports/libc/openbox-fonts.json').read_text())
    package = next(p for p in manifest['packages'] if p['name'] == 'harfbuzz')
    record = desktop_ports.verify(package, ROOT/'artifacts/desktop-sources', max_bytes=32*1024*1024)
    verified = unpack(package, record, out/'source')
    assets['usr/share/fonts/Roboto-Regular.ttf'] = verified/'perf/fonts/Roboto-Regular.ttf'
    for target, original in assets.items():
        destination = out/'rootfs'/target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
    licenses = out/'licenses/Roboto'
    licenses.mkdir(exist_ok=True)
    shutil.copyfile(source/'Roboto-LICENSE.txt', licenses/'LICENSE')
    (licenses/'NOTICE').write_text('Roboto Regular: Copyright 2011 Google Inc. All Rights Reserved.\n'
        'Unmodified perf/fonts/Roboto-Regular.ttf from the pinned HarfBuzz 12.3.2 source archive.\n'
        'The embedded font name table identifies the Apache License 2.0.\n')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['inventory','foundation','build','install-assets'],default='inventory',nargs='?')
    parser.add_argument('--fetch',action='store_true')
    parser.add_argument('--only', choices=['libffi', 'pcre2', 'glib'],
                        help='Build only one foundation dependency')
    parser.add_argument('--cyxia-spawn', action='store_true',
                        help='Enable the real private CyxiaOS catalog-process spawn backend in GLib')
    args=parser.parse_args()
    if args.command != 'foundation' and (args.only or args.cyxia_spawn):
        parser.error('--only and --cyxia-spawn apply to foundation')
    if args.command == 'inventory': print((ROOT/'ports/libc/openbox-foundation.json').read_text())
    else:
        with (DEFAULT_OUTPUT/'.build.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = (foundation(args.fetch, args.only, args.cyxia_spawn)
                      if args.command == 'foundation' else
                      install_assets() if args.command == 'install-assets' else window_manager(args.fetch))
            print(json.dumps(result,indent=2))
