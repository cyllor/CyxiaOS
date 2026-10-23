#!/usr/bin/env python3
"""Build the pinned Openbox font/XML prerequisites in the target sysroot.

No target program is run on macOS. Header-only C++ uses the installed Clang
libc++ headers with availability annotations disabled for the Linux persona;
no macOS binary library is linked. This is not a general C++ runtime port.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
from build_sysroot import Builder, ROOT, DEFAULT_OUTPUT, BUILD_TOOLS, toolchain, unpack, digest
import desktop_ports


def build(fetch=False, only=None):
    out=DEFAULT_OUTPUT; target=out/'sysroot'
    builder=Builder(out,toolchain(),8);builder.target_environment()
    builder.env['PATH']=str(BUILD_TOOLS/'bin')+os.pathsep+builder.env.get('PATH','')
    builder.env['PKG_CONFIG']=str(builder.shell_wrapper('pkg-config-static',[shutil.which('pkg-config'),'--static']))
    sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip())
    headers=sdk/'usr/include/c++/v1'
    if not (headers/'atomic').is_file(): raise RuntimeError('Clang libc++ headers are required')
    # Retarget compiler-provided template headers; never use Darwin ABI config
    # or link a host C++ library. Any required runtime symbol must resolve in
    # the target sysroot or the static link fails.
    configuration = out/'target-cxx-config'
    configuration.mkdir(exist_ok=True)
    site=(headers/'__config_site').read_text()
    for old,new in [('_LIBCPP_HAS_MUSL_LIBC 0','_LIBCPP_HAS_MUSL_LIBC 1'),
                    ('_LIBCPP_HAS_THREAD_API_PTHREAD 0','_LIBCPP_HAS_THREAD_API_PTHREAD 1'),
                    ('_LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS 1','_LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS 0'),
                    ('#define _LIBCPP_PSTL_BACKEND_LIBDISPATCH','#define _LIBCPP_PSTL_BACKEND_SERIAL')]:
        site=site.replace(old,new)
    (configuration/'__config_site').write_text(site)
    cxx=builder.shell_wrapper('aarch64-linux-musl-cxx',[builder.env['CC'],'-std=c++17','-nostdinc++',
            '-I'+str(configuration),'-I'+str(headers),'-D_LIBCPP_DISABLE_AVAILABILITY','-fno-exceptions','-fno-rtti'])
    builder.env['CXX']=str(cxx)
    cross=out/'openbox-fonts-cross.ini'
    cross.write_text('[binaries]\nc = '+repr(builder.env['CC'])+'\ncpp = '+repr(str(cxx))+'\n'+
        'ar = '+repr(builder.tools['llvm-ar'])+'\nstrip = '+repr(builder.tools['llvm-strip'])+'\n'+
        'pkg-config = '+repr(builder.env['PKG_CONFIG'])+'\n'+
        "[host_machine]\nsystem = 'linux'\ncpu_family = 'aarch64'\ncpu = 'cortex-a53'\nendian = 'little'\n"+
        '[properties]\nneeds_exe_wrapper = true\nsys_root = '+repr(str(target))+'\n'+
        'pkg_config_libdir = '+repr(builder.env['PKG_CONFIG_LIBDIR'].split(os.pathsep))+'\n')
    records=[]
    manifest=json.loads((ROOT/'ports/libc/openbox-fonts.json').read_text())
    triplet=subprocess.check_output(['sh',str(out/'source/xorgproto-2024.1/config.guess')],text=True).strip()
    for package in manifest['packages']:
        name=package['name']
        if only and name != only: continue
        cache=ROOT/'artifacts/desktop-sources'
        record=(desktop_ports.fetch(package,cache,online=True,max_bytes=32*1024*1024) if fetch
                else desktop_ports.verify(package,cache,max_bytes=32*1024*1024))
        records.append(record);source=unpack(package,record,out/'source')
        licenses=out/'licenses'/name;licenses.mkdir(exist_ok=True)
        shutil.copyfile(source/package['license_file'],licenses/package['license_file'])
        directory=out/(name+'-build')
        if directory.exists(): shutil.rmtree(directory)
        if name in ('fontconfig','harfbuzz','pango'):
            if name == 'pango':
                builder.run(['patch', '-p1', '-i', str(ROOT/'ports/libc/patches/pango-cyxia-synchronous-fontconfig.patch')], 'pango-port-patch.log', source)
            options={
                'fontconfig':['-Ddoc=disabled','-Dnls=disabled','-Dtests=disabled','-Dtools=disabled','-Dcache-build=disabled','-Dxml-backend=expat','-Ddefault-fonts-dirs=/usr/share/fonts'],
                'harfbuzz':['-Dglib=disabled','-Dgobject=disabled','-Dcairo=disabled','-Dchafa=disabled','-Dicu=disabled','-Dfreetype=enabled','-Dtests=disabled','-Ddocs=disabled','-Dutilities=disabled','-Dintrospection=disabled'],
                'pango':['-Ddocumentation=false','-Dman-pages=false','-Dintrospection=disabled','-Dbuild-testsuite=false','-Dbuild-examples=false','-Dlibthai=disabled','-Dcairo=disabled','-Dxft=enabled','-Dfontconfig=enabled','-Dfreetype=enabled'],
            }[name]
            if name == 'pango': options += ['-Dc_args=-D__CYXIA_SINGLE_THREAD_FONTCONFIG__']
            meson=str(BUILD_TOOLS/'bin/meson')
            builder.run([meson,'setup',str(directory),str(source),'--cross-file',str(cross),
                '--prefix=/usr','--libdir=lib','--buildtype=minsize','--default-library=static','--wrap-mode=nodownload',*options],name+'-setup.log')
            builder.run([meson,'compile','-C',str(directory),'-j','8'],name+'-build.log')
            builder.env['DESTDIR']=str(target)
            builder.run([meson,'install','-C',str(directory)],name+'-install.log')
            del builder.env['DESTDIR']
        else:
            directory.mkdir()
            options=['--prefix=/usr','--host=aarch64-linux-musl','--build='+triplet,'--disable-shared','--enable-static']
            if name=='expat': options += ['--without-docbook','--without-xmlwf','--without-examples','--without-tests']
            if name=='fribidi': options += ['--disable-docs','--disable-deprecated']
            if name=='libxml2': options += ['--without-python','--without-lzma','--without-iconv','--without-zlib']
            builder.run([str(source/'configure'),*options],name+'-configure.log',directory)
            builder.run([builder.tools['make'],'-j8'],name+'-make.log',directory)
            builder.run([builder.tools['make'],'install','DESTDIR='+str(target)],name+'-install.log',directory)
            for archive in (target/'usr/lib').glob('*.la'): archive.unlink()
    report=dict(sources=records,commands=builder.commands,cxx_headers=str(headers),
                cxx_config_sha256=digest(configuration/'__config_site'),
                pango_port_patch_sha256=digest(ROOT/'ports/libc/patches/pango-cyxia-synchronous-fontconfig.patch'),
                pango_threading='synchronous fontconfig on the AI-scheduled single guest thread',
                scope='Cross-build only; Openbox/GTK guest runtime not verified')
    (out/('openbox-fonts-'+(only or 'all')+'-report.json')).write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['inventory','build'],default='inventory',nargs='?')
    p.add_argument('--fetch',action='store_true')
    p.add_argument('--only',choices=['expat','fontconfig','fribidi','harfbuzz','libXrender','libXft','libxml2','pango'])
    a=p.parse_args()
    if a.command=='inventory': print((ROOT/'ports/libc/openbox-fonts.json').read_text())
    else:
        with (DEFAULT_OUTPUT/'.build.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(build(a.fetch,a.only),indent=2))
