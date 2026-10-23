#!/usr/bin/env python3
"""Cross-build pinned libfm/menu-cache/PCManFM; never run target programs."""
import argparse
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

from build_sysroot import (ROOT, DEFAULT_OUTPUT, BUILD_TOOLS, Builder, BuildError,
                          toolchain, unpack, digest, inspect_elf, clean_env)
from build_gtk_foundation import archive_architecture
import desktop_ports

MANIFEST = ROOT / 'ports/libc/pcmanfm-foundation.json'
SOURCE_MANIFEST = ROOT / 'ports/desktop/manifest.json'
CACHE = ROOT / 'artifacts/desktop-sources'
HOST = DEFAULT_OUTPUT / 'pcmanfm-host-tools'
OUTPUTS = {'libfm-extra': ['libfm-extra.a'], 'menu-cache': ['libmenu-cache.a'],
           'libfm': ['libfm-extra.a', 'libfm.a', 'libfm-gtk3.a'], 'lxmenu-data': [], 'pcmanfm': []}


def source_record(package, fetch):
    if fetch:
        return desktop_ports.fetch(package, CACHE, online=True, max_bytes=64 * 1024 * 1024)
    return desktop_ports.verify(package, CACHE, max_bytes=64 * 1024 * 1024)


def extract_git(record, directory):
    """Extract the verified rootless git archive, rejecting escaping paths/links."""
    archive = Path(record['directory']) / 'source.tar'
    if digest(archive) != record['sha256']:
        raise BuildError('Git archive changed after verification')
    with tempfile.TemporaryDirectory(prefix='.pcmanfm-extract-', dir=DEFAULT_OUTPUT) as temporary:
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            if sum(m.size for m in members) > 64 * 1024 * 1024:
                raise BuildError('Git source exceeds extraction budget')
            for member in members:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or '..' in path.parts or not path.parts or
                        not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                    raise BuildError('Unsafe git archive path: ' + member.name)
                if member.issym() or member.islnk():
                    link = PurePosixPath(member.linkname)
                    resolved = PurePosixPath(posixpath.normpath(posixpath.join(
                        str(path.parent) if member.issym() else '', member.linkname)))
                    if link.is_absolute() or '..' in resolved.parts:
                        raise BuildError('Unsafe git archive link: ' + member.name)
            bundle.extractall(temporary, members=members, filter='data')
        if not (Path(temporary) / 'COPYING').is_file():
            raise BuildError('Git source license is missing')
        if directory.exists():
            shutil.rmtree(directory)
        shutil.copytree(temporary, directory, symlinks=True)
    return directory


def bootstrap_host(builder, manifest, fetch):
    builder.env = clean_env()
    builder.env['PATH'] = os.pathsep.join((str(HOST / 'bin'), str(BUILD_TOOLS / 'bin'), builder.env.get('PATH', '')))
    python = str(BUILD_TOOLS / 'bin/python')
    if subprocess.run([python, '-c', 'import pygments; assert pygments.__version__ == "2.19.2"'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        if not fetch:
            raise BuildError('Missing pinned host Pygments; use host-tools --fetch')
        builder.run([python, '-m', 'pip', 'install', '--require-hashes', '--only-binary=:all:',
                     '-r', str(ROOT / 'ports/libc/pcmanfm-host-tools.lock')], 'pcmanfm-host-python.log')
    root = DEFAULT_OUTPUT / 'pcmanfm-host-source'
    root.mkdir(exist_ok=True)
    records = []
    for package in manifest['host_tools']:
        record = source_record(package, fetch)
        source = unpack(package, record, root)
        name = package['name']
        directory = DEFAULT_OUTPUT / ('pcmanfm-host-' + name + '-build')
        if directory.exists():
            shutil.rmtree(directory)
        if name == 'intltool':
            directory.mkdir()
            builder.run([str(source / 'configure'), '--prefix=' + str(HOST)], 'pcmanfm-intltool-setup.log', directory)
            builder.run([builder.tools['make'], '-j' + str(builder.jobs)], 'pcmanfm-intltool-build.log', directory)
            builder.run([builder.tools['make'], 'install'], 'pcmanfm-intltool-install.log', directory)
        else:
            meson = str(BUILD_TOOLS / 'bin/meson')
            builder.run([meson, 'setup', str(directory), str(source), '--prefix=' + str(HOST),
                         '-Dyelp_manual=false', '-Dtests=false'], 'pcmanfm-gtkdoc-setup.log')
            builder.run([meson, 'compile', '-C', str(directory)], 'pcmanfm-gtkdoc-build.log')
            builder.run([meson, 'install', '-C', str(directory)], 'pcmanfm-gtkdoc-install.log')
        licenses = DEFAULT_OUTPUT / 'licenses' / ('host-' + name)
        licenses.mkdir(exist_ok=True)
        shutil.copyfile(source / 'COPYING', licenses / 'COPYING')
        records.append({'source': record, 'license_sha256': digest(licenses / 'COPYING')})
    return records


def target_environment(builder):
    builder.target_environment()
    builder.env['PATH'] = os.pathsep.join((str(HOST / 'bin'), str(BUILD_TOOLS / 'bin'), builder.env.get('PATH', '')))
    builder.env['ACLOCAL_PATH'] = os.pathsep.join((str(HOST / 'share/aclocal'), '/opt/homebrew/share/aclocal'))
    builder.env['LIBTOOLIZE'] = shutil.which('glibtoolize') or shutil.which('libtoolize')
    builder.env['PKG_CONFIG'] = str(builder.shell_wrapper('pcmanfm-pkg-config-static', [shutil.which('pkg-config'), '--static']))
    builder.env['CFLAGS'] = '-Os -g -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables'
    builder.env['LDFLAGS'] = '-Wl,--gc-sections'


def build(builder, manifest, only, fetch, cyxia_spawn=False):
    target_environment(builder)
    packages = {p['name']: p for p in json.loads(SOURCE_MANIFEST.read_text())['packages']}
    target = DEFAULT_OUTPUT / 'sysroot'
    base_cflags = builder.env['CFLAGS']
    triplet = subprocess.check_output(['sh', str(DEFAULT_OUTPUT / 'source/xorgproto-2024.1/config.guess')], text=True).strip()
    completed = []
    for stage in manifest['stages']:
        name = stage['name']
        if only and name != only:
            continue
        # menu-cache 1.1.0's headers contain C tentative definitions in several
        # translation units; preserve that release's original common semantics.
        builder.env['CFLAGS'] = base_cflags + (' -fcommon' if name == 'menu-cache' else '')
        if cyxia_spawn and stage['source_package'] == 'libfm':
            builder.env['CFLAGS'] += ' -D__CYXIA_CATALOG_SPAWN__'
        print('Building ' + name, flush=True)
        package = packages[stage['source_package']]
        record = source_record(package, fetch)
        source = extract_git(record, DEFAULT_OUTPUT / ('pcmanfm-' + name + '-source'))
        patches = []
        if stage['source_package'] == 'libfm':
            for filename in ('libfm-vpath-generated-headers.patch', 'libfm-optional-modules.patch',
                             'libfm-static-pkgconfig.patch', 'libfm-cyxia-spawn.patch'):
                patch = ROOT / 'ports/libc/patches' / filename
                builder.run(['patch', '-p1', '-i', str(patch)], 'pcmanfm-' + name + '-' + filename + '.log', source)
                patches.append({'file': str(patch), 'sha256': digest(patch)})
        if stage['source_package'] == 'menu-cache':
            patch = ROOT / 'ports/libc/patches/menu-cache-missing-service-error.patch'
            builder.run(['patch', '-p1', '-i', str(patch)], 'pcmanfm-menu-cache-service-patch.log', source)
            patches.append({'file': str(patch), 'sha256': digest(patch)})
        if stage['source_package'] in ('libfm', 'menu-cache'):
            (source / 'm4').mkdir(exist_ok=True)
            builder.run([str(HOST / 'bin/gtkdocize'), '--copy'], 'pcmanfm-' + name + '-gtkdocize.log', source)
        builder.run(['autoreconf', '-fiv'], 'pcmanfm-' + name + '-autoreconf.log', source)
        directory = DEFAULT_OUTPUT / ('pcmanfm-' + name + '-build')
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir()
        options = ['--prefix=/usr', '--host=aarch64-linux-musl', '--build=' + triplet,
                   *(['--disable-shared', '--enable-static'] if name not in ('pcmanfm', 'lxmenu-data') else [])]
        if name in ('libfm-extra', 'libfm'):
            options += ['--disable-old-actions', '--disable-udisks', '--disable-exif', '--disable-gtk-doc', '--disable-demo', '--disable-modules']
            options += ['--with-extra-only'] if name == 'libfm-extra' else ['--with-gtk=3']
        elif name == 'menu-cache':
            options += ['--disable-gtk-doc']
        elif name == 'pcmanfm':
            options += ['--with-gtk=3']
        builder.run([str(source / 'configure'), *options], 'pcmanfm-' + name + '-setup.log', directory)
        builder.run([builder.tools['make'], '-j' + str(builder.jobs)], 'pcmanfm-' + name + '-build.log', directory)
        builder.run([builder.tools['make'], 'install', 'DESTDIR=' + str(target)], 'pcmanfm-' + name + '-install.log', directory)
        for archive in (target / 'usr/lib').glob('*.la'):
            archive.unlink()
        licenses = DEFAULT_OUTPUT / 'licenses' / package['name']
        licenses.mkdir(exist_ok=True)
        shutil.copyfile(source / 'COPYING', licenses / 'COPYING')
        result = {'name': name, 'source': record, 'license_sha256': digest(licenses / 'COPYING'),
                  'patches': patches,
                  'configure_options': options, 'cflags': builder.env['CFLAGS'], 'ldflags': builder.env['LDFLAGS'],
                  'guest_execution': 'not performed',
                  'outputs': {a: archive_architecture(target / 'usr/lib' / a) for a in OUTPUTS[name]}}
        if name == 'pcmanfm':
            temp = DEFAULT_OUTPUT / 'pcmanfm.elf.tmp'
            shutil.copyfile(target / 'usr/bin/pcmanfm', temp)
            builder.run([builder.tools['llvm-strip'], '--strip-debug', str(temp)], 'pcmanfm-strip.log')
            inspect_elf(temp)
            shutil.copyfile(temp, DEFAULT_OUTPUT / 'pcmanfm.symbols.elf')
            builder.run([builder.tools['llvm-strip'], '--strip-all', str(temp)], 'pcmanfm-compact.log')
            result['executable'] = inspect_elf(temp)
            temp.replace(DEFAULT_OUTPUT / 'pcmanfm.elf')
            result['executable']['file'] = str(DEFAULT_OUTPUT / 'pcmanfm.elf')
        completed.append(result)
        (DEFAULT_OUTPUT / ('pcmanfm-' + name + '-report.json')).write_text(json.dumps(result, indent=2) + '\n')
    return completed


def verify_outputs():
    """Audit installed outputs and resource syntax without executing target code."""
    out = DEFAULT_OUTPUT
    target = out / 'sysroot'
    result = {'status': 'cross-built-and-statically-verified', 'guest_execution': 'not performed',
              'runtime_blockers': ['Real pthread/clone and GThreadPool/GTask support are required for local directory windows.',
                                   'Guest resource deployment, file operation acceptance and persistent storage remain separate gates.'],
              'libraries': {name: archive_architecture(target / 'usr/lib' / name)
                            for name in ('libfm-extra.a', 'libmenu-cache.a', 'libfm.a', 'libfm-gtk3.a')},
              'executable': inspect_elf(out / 'pcmanfm.elf'),
              'symbol_image': inspect_elf(out / 'pcmanfm.symbols.elf'),
              'helpers': {name: inspect_elf(target / 'usr/libexec/menu-cache' / name)
                          for name in ('menu-cache-gen', 'menu-cached')},
              'resources': {}, 'verification_tool_sha256': digest(Path(__file__))}
    for folder in ('usr/share/libfm', 'usr/share/pcmanfm', 'etc/xdg/menus', 'usr/share/desktop-directories'):
        for path in sorted((target / folder).rglob('*')):
            if path.is_file():
                if path.suffix in ('.ui', '.menu'):
                    ET.parse(path)
                result['resources']['/' + str(path.relative_to(target))] = {
                    'bytes': path.stat().st_size, 'sha256': digest(path)}
    path = out / 'pcmanfm-verified-report.json'
    path.write_text(json.dumps(result, indent=2) + '\n')
    return path


def install_assets(manifest_path, rootfs, report_path):
    """Validate the entire pinned asset set before atomically replacing files."""
    manifest = json.loads(manifest_path.read_text())
    records, targets = [], set()
    for entry in manifest['files']:
        relative = PurePosixPath(entry['source'])
        target = PurePosixPath(entry['target'])
        if relative.is_absolute() or '..' in relative.parts:
            raise BuildError('Unsafe resource source: ' + entry['source'])
        if (not target.is_absolute() or '..' in target.parts or
                target.parts[1:2] not in (('etc',), ('usr',)) or
                str(target) != entry['target'] or len(str(target).encode()) >= 96):
            raise BuildError('Unsafe or overlong resource target: ' + entry['target'])
        if str(target) in targets:
            raise BuildError('Duplicate resource target: ' + str(target))
        targets.add(str(target))
        source = ROOT / relative
        if not source.resolve().is_relative_to(ROOT.resolve()) or not source.is_file():
            raise BuildError('Resource source is missing or escapes project: ' + str(source))
        if source.stat().st_size != entry['bytes'] or digest(source) != entry['sha256']:
            raise BuildError('Resource content differs from manifest: ' + str(source))
        if source.suffix == '.ui':
            ET.parse(source)
        destination = rootfs / str(target).lstrip('/')
        if not destination.resolve().is_relative_to(rootfs.resolve()):
            raise BuildError('Resource destination escapes rootfs: ' + str(destination))
        records.append((source, destination, entry))
    if (len(records) != manifest['file_count'] or
            sum(entry['bytes'] for _, _, entry in records) != manifest['total_bytes']):
        raise BuildError('Resource manifest totals disagree')
    for source, destination, entry in records:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix='.' + destination.name, dir=destination.parent,
                                         delete=False) as temporary:
            temporary.write(source.read_bytes())
            temporary_name = Path(temporary.name)
        temporary_name.chmod(0o644)
        temporary_name.replace(destination)
        if digest(destination) != entry['sha256']:
            raise BuildError('Installed resource differs from manifest: ' + str(destination))
    report_path.write_text(json.dumps({'status': 'assets-installed',
        'manifest_sha256': digest(manifest_path), 'files': manifest['files'],
        'guest_execution': 'not performed by resource installer'}, indent=2) + '\n')
    return report_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['inventory', 'host-tools', 'build', 'verify', 'install-assets'], default='inventory', nargs='?')
    parser.add_argument('--only', choices=list(OUTPUTS))
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--cyxia-spawn', action='store_true',
                        help='Build libfm with explicit CyxiaOS catalog-process launching')
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    if args.command == 'inventory':
        print(json.dumps(manifest, indent=2))
        return
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be in 1..32')
    with (DEFAULT_OUTPUT / '.build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'verify':
            print(verify_outputs())
            return
        if args.command == 'install-assets':
            print(install_assets(ROOT / 'ports/desktop/pcmanfm-rootfs.json',
                                 DEFAULT_OUTPUT / 'rootfs',
                                 DEFAULT_OUTPUT / 'pcmanfm-assets-report.json'))
            return
        builder = Builder(DEFAULT_OUTPUT, toolchain(), args.jobs)
        report = {'status': 'building', 'commands': builder.commands,
                  'manifest_sha256': digest(MANIFEST), 'source_manifest_sha256': digest(SOURCE_MANIFEST),
                  'builder_sha256': digest(Path(__file__)),
                  'host_python_lock_sha256': digest(ROOT / 'ports/libc/pcmanfm-host-tools.lock'),
                  'guest_execution': 'not performed', 'target': 'aarch64-linux-musl'}
        try:
            if args.command == 'host-tools':
                report['host_tools'] = bootstrap_host(builder, manifest, args.fetch)
                report['status'] = 'host-tools-built'
            else:
                report['packages'] = build(builder, manifest, args.only, args.fetch, args.cyxia_spawn)
                report['cyxia_spawn'] = args.cyxia_spawn
                report['status'] = 'cross-built'
        except Exception as error:
            report.update(status='failed', error=str(error))
            raise
        finally:
            path = DEFAULT_OUTPUT / ('pcmanfm-' + (args.only or args.command) + '-build-report.json')
            path.write_text(json.dumps(report, indent=2) + '\n')
        print(path)


if __name__ == '__main__':
    main()
