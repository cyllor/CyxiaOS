#!/usr/bin/env python3
"""Cross-build pinned pixman into an explicitly selected prepared musl SDK.

Inventory is read-only; build uses verified cached sources unless --fetch is
explicit. Only pixman headers/archive/pkg-config metadata are installed. No
target program is executed. The caller owns any native build lease.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

if __package__:
    from .build_sysroot import (ROOT, BUILD_TOOLS, Builder as SysrootBuilder, BuildError,
                               clean_env, digest, inspect_elf, unpack, validate_packages)
    from .build_cosmic import run_bounded, CosmicBuildError
    from . import desktop_ports
    from .target_profile import profile_for
else:
    from build_sysroot import (ROOT, BUILD_TOOLS, Builder as SysrootBuilder, BuildError,
                              clean_env, digest, inspect_elf, unpack, validate_packages)
    from build_cosmic import run_bounded, CosmicBuildError
    import desktop_ports
    from target_profile import profile_for

MANIFEST = ROOT / 'ports/cosmic/pixman-source.json'
SOURCE_MANIFEST = ROOT / 'ports/libc/pixman-source.json'
INSTALL_FILES = frozenset(('usr/lib/libpixman-1.a', 'usr/lib/pkgconfig/pixman-1.pc',
                           'usr/include/pixman-1/pixman.h',
                           'usr/include/pixman-1/pixman-version.h'))
MIN_FREE_BYTES = 1024 ** 3
MAX_NEW_BYTES = 512 * 1024 ** 2
BUILD_TIMEOUT_SECONDS = 900
PROBE = r'''#include <pixman.h>
#include <stddef.h>
#include <stdint.h>
_Static_assert(sizeof(pixman_color_t) == 8, "pixman color ABI");
_Static_assert(sizeof(pixman_box32_t) == 16, "pixman region ABI");
_Static_assert(offsetof(pixman_box32_t, x2) == 8, "pixman coordinate ABI");
_Static_assert(sizeof(pixman_transform_t) == 36, "pixman matrix ABI");
int main(void) {
    uint32_t pixels[4] = {0};
    pixman_color_t color = {0xffff, 0, 0, 0xffff};
    pixman_region32_t region;
    pixman_region32_init_rect(&region, 0, 0, 2, 2);
    pixman_image_t *src = pixman_image_create_solid_fill(&color);
    pixman_image_t *dst = pixman_image_create_bits(PIXMAN_a8r8g8b8, 2, 2, pixels, 8);
    if (!src || !dst) return 1;
    if (!pixman_image_set_clip_region32(dst, &region)) return 2;
    pixman_image_composite32(PIXMAN_OP_SRC, src, NULL, dst, 0, 0, 0, 0, 0, 0, 2, 2);
    pixman_image_unref(src);
    pixman_image_unref(dst);
    pixman_region32_fini(&region);
    return pixman_version() == PIXMAN_VERSION && pixels[0] == 0xffff0000U ? 0 : 3;
}
'''


class Builder(SysrootBuilder):
    """All native commands share one wall-clock and output-growth budget."""
    def __init__(self, output, tools, jobs, target='aarch64'):
        super().__init__(output, tools, jobs, target)
        self.initial_bytes = output_bytes(output)
        self.min_free_bytes = MIN_FREE_BYTES
        self.max_new_bytes = MAX_NEW_BYTES
        self.deadline = time.monotonic() + BUILD_TIMEOUT_SECONDS
        self.scratch = output / 'pixman-tmp'
        if self.scratch.is_symlink():
            raise BuildError('Pixman scratch directory cannot be a symlink')
        self.scratch.mkdir(exist_ok=True)

    def check_limits(self, additional_bytes=0):
        if time.monotonic() >= self.deadline:
            raise BuildError('Pixman build deadline exceeded')
        if shutil.disk_usage(self.output).free - additional_bytes < self.min_free_bytes:
            raise BuildError('Pixman build has insufficient free space')
        added = max(0, output_bytes(self.output) - self.initial_bytes)
        if added + additional_bytes > self.max_new_bytes:
            raise BuildError('Pixman build exceeded its new-data byte budget')
        return added

    def run(self, command, log, cwd=None):
        self.check_limits()
        self.env['TMPDIR'] = str(self.scratch)
        self.commands.append(command)
        try:
            run_bounded(command, cwd or self.output, self.env, self.output / 'logs' / log,
                        self.deadline - time.monotonic(), self.min_free_bytes,
                        self.initial_bytes + self.max_new_bytes, budget_root=self.output)
        except CosmicBuildError as error:
            raise BuildError(str(error)) from error
        self.check_limits()

    def capture(self, command, log):
        self.run(command, log)
        return (self.output / 'logs' / log).read_text()


def discover_toolchain(builder):
    # Keep the shared discovery helper, but bound its rustc subprocesses in the
    # same process group and deadline as compilation and linking.
    script = ('import json, sys; sys.path.insert(0, ' + repr(str(ROOT / 'tools')) + '); '
              'from build_sysroot import toolchain; print(json.dumps(toolchain()))')
    return json.loads(builder.capture([sys.executable, '-c', script], 'pixman-toolchain.log'))


def load_source(path=None):
    config = json.loads(MANIFEST.read_text())
    if (config.get('schema_version') != 1 or
            config.get('source_manifest') != 'ports/libc/pixman-source.json'):
        raise BuildError('Unsupported pixman source reference')
    package = json.loads((path or SOURCE_MANIFEST).read_text())
    validate_packages([package])
    if package['name'] != 'pixman' or package.get('depends_on') != []:
        raise BuildError('Only standalone pinned pixman is supported')
    return package


def sdk_identity(output, target):
    report_path = output / 'build-report.json'
    report = json.loads(report_path.read_text())
    target.require_report(report)
    lib = output / 'sysroot/usr/lib'
    libc = target.inspect_archive(lib / 'libc.a')
    if libc['sha256'] != report.get('libc_sha256'):
        raise BuildError('SDK libc identity differs from its producer report')
    return {'report_sha256': digest(report_path), 'libc': libc,
            'builtins': target.inspect_archive(lib / target.builtins_archive),
            'compiler_driver_sha256': digest(target.cc(output))}


def protected_archives(output):
    return {str(path.relative_to(output)): digest(path)
            for path in sorted((output / 'sysroot').rglob('*.a'))
            if path != output / 'sysroot/usr/lib/libpixman-1.a'}


def target_environment(builder):
    builder.env = clean_env()
    for key in list(builder.env):
        if (key.startswith(('PKG_CONFIG', 'RUST', 'CARGO', 'LD_', 'DYLD_')) or
                key in ('DESTDIR', 'LIBS', 'CONFIG_SITE', 'CMAKE_TOOLCHAIN_FILE')):
            builder.env.pop(key)
    builder.target_environment()
    builder.env['PATH'] = str(BUILD_TOOLS / 'bin') + os.pathsep + builder.env.get('PATH', '')
    pkg = builder.env['PKG_CONFIG']
    builder.env['PKG_CONFIG'] = str(builder.shell_wrapper('pixman-target-pkg-config', [pkg, '--static']))
    cross = builder.output / 'pixman-cross.ini'
    cross.write_text('[binaries]\n' +
        'c = ' + repr(builder.env['CC']) + '\n' +
        'ar = ' + repr(builder.tools['llvm-ar']) + '\n' +
        'pkg-config = ' + repr(builder.env['PKG_CONFIG']) + '\n' +
        builder.target.meson_machine() +
        '[properties]\nneeds_exe_wrapper = true\nsys_root = ' + repr(str(builder.output / 'sysroot')) + '\n' +
        'pkg_config_libdir = ' + repr(builder.env['PKG_CONFIG_LIBDIR'].split(os.pathsep)) + '\n')
    return cross


def source(builder, package, fetch, cache):
    record = (desktop_ports.fetch(package, cache, online=True, max_bytes=8 * 1024 ** 2)
              if fetch else desktop_ports.verify(package, cache, max_bytes=8 * 1024 ** 2))
    archive = Path(record['directory']) / 'source.archive'
    with archive.open('rb') as stream:
        sha512 = hashlib.file_digest(stream, 'sha512').hexdigest()
    if package.get('expected_sha512') and sha512 != package['expected_sha512']:
        raise BuildError('Source archive differs from the upstream SHA512 pin')
    directory = builder.output / 'pixman-source'
    directory.mkdir(exist_ok=True)
    path = unpack(package, record, directory)
    license_dir = builder.output / 'licenses/pixman'
    license_dir.mkdir(parents=True, exist_ok=True)
    license_file = license_dir / package['license_file']
    shutil.copyfile(path / package['license_file'], license_file)
    return path, {'source': record, 'archive_sha512': sha512,
                  'license_sha256': digest(license_file)}


def fresh(directory):
    if directory.is_symlink():
        raise BuildError('Build directory cannot be a symlink: ' + str(directory))
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir()


def install_staged(stage, sysroot, target, *, budget):
    paths = list(stage.rglob('*'))
    if any(path.is_symlink() for path in paths):
        raise BuildError('Pixman installation contains a symlink')
    files = {str(path.relative_to(stage)) for path in paths if path.is_file()}
    if files != INSTALL_FILES:
        raise BuildError('Unexpected pixman installation files: ' + repr(sorted(files)))
    archive = target.inspect_archive(stage / 'usr/lib/libpixman-1.a')
    # Validate every destination before copying any file. Package installation
    # cannot follow an existing link outside the selected SDK.
    for relative in files:
        destination = sysroot / relative
        parents = tuple(destination.parents)[:len(Path(relative).parts)]
        if any(path.is_symlink() for path in (destination, *parents)):
            raise BuildError('Pixman destination contains a symlink: ' + str(destination))
    # Installation duplicates the staged payload. Reserve its complete size
    # before the first SDK write, even when replacing a previous pixman build.
    budget.check_limits(sum((stage / relative).stat().st_size for relative in files))
    for relative in sorted(files):
        destination = sysroot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stage / relative, destination)
    return {'archive': archive, 'installed_files': {
        relative: digest(sysroot / relative) for relative in sorted(files)}}


def build_library(builder, source_dir):
    cross = target_environment(builder)
    directory = builder.output / 'pixman-target-build'
    stage = builder.output / 'pixman-install'
    fresh(directory)
    fresh(stage)
    meson = str(BUILD_TOOLS / 'bin/meson')
    # Same dependency-free static recipe as build_sysroot's X-server bootstrap,
    # without that recipe's X11 prerequisites or additional library builds.
    options = ['--prefix=/usr', '--libdir=lib', '--wrap-mode=nofallback',
               '--cross-file=' + str(cross), '-Dbuildtype=release',
               '-Ddefault_library=static', '-Db_staticpic=false',
               '-Dtests=disabled', '-Ddemos=disabled', '-Dgtk=disabled',
               '-Dlibpng=disabled', '-Da64-neon=disabled',
               '-Dc_args=-ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables']
    builder.run([meson, 'setup', str(directory), str(source_dir), *options], 'pixman-setup.log')
    builder.run([meson, 'compile', '-C', str(directory), '-j', str(builder.jobs)], 'pixman-build.log')
    builder.env['DESTDIR'] = str(stage)
    try:
        builder.run([meson, 'install', '-C', str(directory), '--no-rebuild'], 'pixman-install.log')
    finally:
        builder.env.pop('DESTDIR', None)
    return {'options': options, **install_staged(stage, builder.output / 'sysroot',
                                                builder.target, budget=builder)}


def link_probe(builder):
    flags = shlex.split(builder.capture(
        [builder.env['PKG_CONFIG'], '--static', '--cflags', '--libs', 'pixman-1'],
        'pixman-pkg-config.log'))
    path = builder.output / 'pixman-probe.c'
    path.write_text(PROBE)
    probe_path = builder.output / 'pixman-probe.elf'
    builder.run([builder.env['CC'], '-Os', '-Wall', '-Wextra', '-Werror',
                 '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
                 str(path), *flags, '-o', str(probe_path)], 'pixman-probe-link.log')
    probe = inspect_elf(probe_path, builder.target)
    return {'probe': probe, 'probe_source_sha256': digest(path), 'pkg_config_flags': flags,
            'probe_execution': 'not performed; ABI assertions and static link only'}


def output_bytes(output):
    return sum(path.stat().st_size for path in output.rglob('*')
               if path.is_file() and not path.is_symlink())


def check_budget(output, initial_bytes):
    if shutil.disk_usage(output).free < MIN_FREE_BYTES:
        raise BuildError('At least 1 GiB free disk required')
    added = max(0, output_bytes(output) - initial_bytes)
    if added > MAX_NEW_BYTES:
        raise BuildError('Pixman output exceeds the 512 MiB new-data budget')
    return added


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inventory', 'build'), nargs='?', default='inventory')
    parser.add_argument('--arch', choices=('aarch64', 'x86_64'), default='aarch64')
    parser.add_argument('--output', type=Path, help='Prepared SDK prefix; required for build')
    parser.add_argument('--cache', type=Path, default=desktop_ports.DEFAULT_CACHE)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args(argv)
    target = profile_for(args.arch)
    output = (args.output or target.default_output(ROOT)).resolve()
    try:
        package = load_source()
        if args.fetch and args.command != 'build':
            raise BuildError('--fetch requires build')
        if not 1 <= args.jobs <= 16:
            raise BuildError('--jobs must be in 1..16')
        if args.command == 'inventory':
            print(json.dumps({'source': package, 'output': str(output),
                              'architecture': target.architecture, 'target_triple': target.rust_target,
                              'network': False, 'guest_execution': 'not performed'}, indent=2))
            return 0
        if args.output is None:
            raise BuildError('--output is required for build; select an isolated prepared SDK')
        sdk = sdk_identity(output, target)
        meson = BUILD_TOOLS / 'bin/meson'
        if not meson.is_file():
            raise BuildError('Missing project-local Meson: ' + str(meson))
        initial_bytes = output_bytes(output)
        check_budget(output, initial_bytes)
        with (output / '.build.lock').open('w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise BuildError('Another SDK build is active') from error
            for name in ('logs', 'bin', 'licenses'):
                (output / name).mkdir(exist_ok=True)
            builder = Builder(output, {}, args.jobs, target)
            before = protected_archives(output)
            report = {'status': 'building', 'architecture': target.architecture,
                      'target_triple': target.rust_target, 'sdk': sdk,
                      'manifest_sha256': digest(MANIFEST), 'source_manifest_sha256': digest(SOURCE_MANIFEST),
                      'producer_sha256': {str(path): digest(path) for path in
                          (Path(__file__).resolve(), ROOT / 'tools/build_sysroot.py',
                           ROOT / 'tools/target_profile.py', ROOT / 'tools/desktop_ports.py',
                           ROOT / 'tools/build_cosmic.py')},
                      'limits': {'timeout_seconds': BUILD_TIMEOUT_SECONDS,
                                 'min_free_bytes': builder.min_free_bytes,
                                 'max_new_bytes': builder.max_new_bytes,
                                 'initial_output_bytes': builder.initial_bytes},
                      'commands': builder.commands, 'guest_execution': 'not performed',
                      'scope': 'Static pixman library and ABI/link probe; no guest or COSMIC session proof'}
            report_path = output / 'pixman-build-report.json'
            try:
                builder.tools = discover_toolchain(builder)
                report['toolchain'] = {name: {'path': path, 'sha256': digest(Path(path))}
                                      for name, path in {**builder.tools, 'meson': str(meson)}.items()}
                source_dir, record = source(builder, package, args.fetch, args.cache)
                report['source'] = record
                builder.check_limits()
                report['target'] = build_library(builder, source_dir)
                report.update(link_probe(builder))
                after = protected_archives(output)
                if before != after:
                    raise BuildError('Preexisting non-pixman SDK archives changed')
                report['preserved_archives'] = after
                report['new_output_bytes'] = builder.check_limits()
                report['status'] = 'cross-built'
            except Exception as error:
                report['status'], report['error'] = 'failed', str(error)
                raise
            finally:
                report_path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'report': str(report_path),
                          'archive': report['target']['archive'], 'probe': report['probe'],
                          'guest_execution': 'not performed'}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('pixman: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
