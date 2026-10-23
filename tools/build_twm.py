#!/usr/bin/env python3
"""Build the upstream TWM integration window manager against the target sysroot.

TWM is an interim X11 integration target; LXDE/Openbox remains the planned
desktop. No target binary is executed by this tool. Default is inventory.
"""
import argparse
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
from build_sysroot import Builder, ROOT, DEFAULT_OUTPUT, toolchain, unpack, digest, inspect_elf
import desktop_ports

SOURCES = [
    ("libICE", "1.1.2", "974e4ed414225eb3c716985df9709f4da8d22a67a2890066bc6dfc89ad298625", "2024-December/003568"),
    ("libSM", "1.2.6", "be7c0abdb15cbfd29ac62573c1c82e877f9d4047ad15321e7ea97d1e43d835be", "2025-March/003592"),
    ("libXt", "1.3.1", "e0a774b33324f4d4c05b199ea45050f87206586d81655f8bef4dba434d931288", "2024-November/003560"),
    ("libXext", "1.3.6", "edb59fa23994e405fdc5b400afdf5820ae6160b94f35e3dc3da4457a16e89753", "2024-February/003454"),
    ("libXmu", "1.3.1", "81a99e94c4501e81c427cbaa4a11748b584933e94b7a156830c3621256857bc4", "2026-January/003668"),
    ("twm", "1.0.13.1", "a52534755aa8b492c884e52fa988bac84ab4d54641954679b9aaf08e323df2c5", "2025-May/003600"),
]

def packages():
    return [dict(name=name, version=version, expected_sha256=sha, source_commit=None,
                 depends_on=[], archive_root=f"{name}-{version}", license_file="COPYING",
                 source_url=f"https://xorg.freedesktop.org/archive/individual/{'app' if name == 'twm' else 'lib'}/{name}-{version}.tar.xz",
                 hash_source=f"https://lists.freedesktop.org/archives/xorg-announce/{announcement}.html")
            for name, version, sha, announcement in SOURCES]

def build(fetch=False):
    out = DEFAULT_OUTPUT
    builder = Builder(out, toolchain(), 8)
    builder.target_environment()
    # musl malloc(0) returns an allocation; target binaries cannot run on macOS.
    builder.env['xorg_cv_malloc0_returns_null'] = 'no'
    target = out / "sysroot"
    records = []
    triplet = subprocess.check_output(["sh", str(out / "source/xorgproto-2024.1/config.guess")], text=True).strip()
    for package in packages():
        name = package['name']
        cache = ROOT / 'artifacts/desktop-sources'
        record = (desktop_ports.fetch(package, cache, online=True, max_bytes=8*1024*1024)
                  if fetch else desktop_ports.verify(package, cache, max_bytes=8*1024*1024))
        records.append(record)
        source = unpack(package, record, out / 'source')
        licenses = out / 'licenses' / name
        licenses.mkdir(exist_ok=True)
        shutil.copyfile(source / 'COPYING', licenses / 'COPYING')
        directory = out / (name + '-build')
        if directory.exists(): shutil.rmtree(directory)
        directory.mkdir()
        options = ['--prefix=/usr', '--host=aarch64-linux-musl', '--build='+triplet,
                   '--disable-shared', '--enable-static', '--disable-docs',
                   '--disable-specs', '--without-xmlto', '--without-fop']
        if name == 'libICE': options += ['--disable-tcp-transport', '--disable-ipv6']
        if name == 'libSM': options += ['--without-libuuid']
        # Link only target libraries, including static private dependencies.
        builder.env['PKG_CONFIG'] = str(builder.shell_wrapper('pkg-config-static', [shutil.which('pkg-config'), '--static']))
        builder.run([str(source/'configure'), *options], name+'-configure.log', directory)
        builder.run([builder.tools['make'], '-j8'], name+'-make.log', directory)
        if name != 'twm':
            builder.run([builder.tools['make'], 'install', 'DESTDIR='+str(target)], name+'-install.log', directory)
            for archive in (target/'usr/lib').glob('*.la'): archive.unlink()
        else:
            binary = directory / 'src/twm'
            if not binary.is_file(): binary = directory / 'twm'
            temporary = out / 'twm.elf.tmp'
            shutil.copyfile(binary, temporary)
            builder.run([builder.tools['llvm-strip'], '--strip-debug', str(temporary)], 'twm-strip.log')
            layout = inspect_elf(temporary)
            temporary.replace(out/'twm.elf')
    config = target.parent / "rootfs/etc/X11/twm/system.twmrc"
    config.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "user/ported/twm/system.twmrc", config)
    report = dict(sources=records, elf=layout, commands=builder.commands,
                  scope='Interim upstream X11 window manager; not LXDE/Openbox acceptance',
                  guest_execution='not performed')
    (out/'twm-build-report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['inventory', 'build'], default='inventory', nargs='?')
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    if args.command == 'inventory': print(json.dumps(packages(), indent=2))
    else:
        with (DEFAULT_OUTPUT/'.build.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(build(args.fetch), indent=2))
