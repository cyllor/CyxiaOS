#!/usr/bin/env python3
"""Build genuine static Linux input libraries in a separate, bounded SDK.

This supplies linkable libraries and UAPI headers. It does not implement or
certify Linux device, sysfs, netlink or Wacom support in the CyxiaOS kernel.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
import cosmic_ports as port_check

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / 'ports/cosmic/native-input-sdk-v1'
RUST = Path('/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unpack(archive, destination, kernel=False):
    require(not destination.exists(), 'Preserving extracted source')
    destination.mkdir()
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        roots = {Path(m.name).parts[0] for m in members if Path(m.name).parts}
        require(len(roots) == 1, 'Ambiguous source archive root')
        if kernel:
            families = ('include/', 'scripts/', 'arch/x86/', 'LICENSES/')
            files = {'Makefile', 'Kbuild', 'Kconfig', 'COPYING'}
            members = [m for m in members if '/'.join(Path(m.name).parts[1:]) in files
                or '/'.join(Path(m.name).parts[1:]).startswith(families)]
        stream.extractall(destination, members=members, filter='data')
    return destination / roots.pop()


def build(output, original, archives):
    output, original, archives = [Path(p).absolute() for p in (output, original, archives)]
    require(not output.exists() and not output.is_relative_to(original)
            and not original.is_relative_to(output), 'Preserving original native SDK')
    for path in (output, original, archives):
        require(path.resolve() == path and not path.is_symlink(), 'Linked native SDK path')
    pins = json.loads((PORT / 'sources.json').read_text())
    require(pins['target'] == 'x86_64-unknown-linux-musl', 'Input SDK target')
    for name, identity in pins['sources'].items():
        require(sha(archives / name) == identity['sha256'], 'Input source archive changed: ' + name)
    baseline_recipe = json.loads((ROOT / 'ports/cosmic/native-time-applet-v2/native-recipe.json').read_text())
    original_hashes = {row['path']: sha(original / row['path']) for row in baseline_recipe['native_inputs']}
    require(all(original_hashes[row['path']] == row['sha256'] for row in baseline_recipe['native_inputs']),
            'Original compiler SDK inputs changed')
    output.mkdir(); work = output / 'native-input-port'; work.mkdir(); logs = work / 'logs'; logs.mkdir()
    started = time.monotonic(); deadline = started + 1800
    commands = []; report = dict(status='BUILDING', target=pins['target'], sources=pins,
        source_manifest_sha256=sha(PORT / 'sources.json'), producer_sha256=sha(__file__),
        parent=str(original), original_native_inputs=original_hashes, commands=commands,
        bounds=dict(timeout_seconds=1800, jobs=2, max_bytes=6 * 1024**3, min_free_bytes=1024**3),
        device_runtime_verified=False, guest_execution=False,
        optional_backend=dict(libwacom=False, reason='no Wacom hardware backend in this target SDK'))

    def run(argv, cwd, environment, label):
        require(time.monotonic() < deadline, 'Input SDK deadline')
        require(shutil.disk_usage(output).free >= 1024**3, 'Input SDK free-space budget')
        commands.append(dict(argv=[str(x) for x in argv], cwd=str(cwd), log=label))
        with (logs / (label + '.log')).open('wb') as log:
            result = subprocess.run([str(x) for x in argv], cwd=cwd, env=environment,
                stdout=log, stderr=subprocess.STDOUT, timeout=max(1, deadline - time.monotonic()))
        require(result.returncode == 0, 'Input SDK command failed: ' + label)
        if label == 'linux-uapi':
            require('sed:' not in (logs / (label + '.log')).read_text(errors='replace'),
                    'Linux UAPI filter reported a sed failure')
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file() and not p.is_symlink())
        require(size <= 6 * 1024**3, 'Input SDK disk budget')

    try:
        shutil.copytree(original / 'sysroot', output / 'sysroot', symlinks=True)
        shutil.copytree(original / 'bin', output / 'bin', symlinks=True)
        shutil.copyfile(original / 'runtime-sdk-origin.json', output / 'runtime-sdk-origin.json')
        for relative in original_hashes:
            target = output / relative
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(original / relative, target)
        compiler = output / 'bin/x86_64-linux-musl-cc'
        compiler.write_text(compiler.read_text().replace(str(original), str(output)))
        compiler.chmod(0o755)
        environment = dict(os.environ)
        for name in tuple(environment):
            if name.startswith(('PKG_CONFIG', 'CARGO_', 'RUST')) or name in (
                    'CC', 'CXX', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'LIBRARY_PATH',
                    'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET'):
                environment.pop(name)
        environment.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
            CC=str(compiler), AR=str(output / 'bin/x86_64-linux-musl-ar'),
            RANLIB=str(output / 'bin/x86_64-linux-musl-ranlib'),
            STRIP=str(RUST / 'lib/rustlib/aarch64-apple-darwin/bin/llvm-strip'),
            CFLAGS='-O2 -fPIC', PKG_CONFIG='/opt/homebrew/bin/pkg-config',
            PKG_CONFIG_LIBDIR=str(output / 'sysroot/usr/lib/pkgconfig'),
            PKG_CONFIG_SYSROOT_DIR=str(output / 'sysroot'), PKG_CONFIG_PATH='',
            GIT_CEILING_DIRECTORIES=str(work), LC_ALL='C')
        sources = work / 'sources'; sources.mkdir()
        extracted = {}
        for name in pins['sources']:
            extracted[name] = unpack(archives / name, sources / name, kernel=name.startswith('linux-'))
        make_source = extracted['make-4.4.1.tar.gz']; make_build = work / 'make-build'; make_build.mkdir()
        host = dict(environment, CC='/usr/bin/clang', AR='/usr/bin/ar', RANLIB='/usr/bin/ranlib', CFLAGS='-O2')
        run([make_source / 'configure', '--prefix=' + str(work / 'host-tools'), '--disable-nls'],
            make_build, host, 'make-configure')
        run(['/usr/bin/make', '-j2'], make_build, host, 'make-build')
        run(['/usr/bin/make', 'install'], make_build, host, 'make-install')
        make = work / 'host-tools/bin/make'
        kernel = extracted['linux-6.18.tar.xz']
        header_filter = kernel / 'scripts/headers_install.sh'
        original_filter = header_filter.read_text()
        marker = '/WITH Linux-syscall-note/!p}'
        require(original_filter.count(marker) == 1, 'Linux UAPI portable SPDX guard preimage')
        portable_filter = original_filter.replace(marker, '/WITH Linux-syscall-note/!p;}')
        header_filter.write_text(portable_filter)
        report['uapi_filter_patch'] = dict(before=hashlib.sha256(original_filter.encode()).hexdigest(),
            after=hashlib.sha256(portable_filter.encode()).hexdigest(),
            purpose='POSIX command delimiter; preserves the original SPDX rejection check on BSD and GNU sed')
        run([make, '-j2', 'ARCH=x86', 'HOSTCC=/usr/bin/clang',
            'INSTALL_HDR_PATH=' + str(output / 'sysroot/usr'), 'headers_install'],
            kernel, environment, 'linux-uapi')
        for archive, label, options in (
            ('eudev-3.2.15.tar.gz', 'eudev', ['--disable-programs', '--disable-blkid',
                '--disable-kmod', '--disable-selinux', '--disable-manpages']),
            ('libevdev-1.13.4.tar.xz', 'libevdev', ['--disable-tests', '--disable-documentation']),
            ('mtdev-1.1.7.tar.bz2', 'mtdev', []),
        ):
            source = extracted[archive]; directory = work / (label + '-build'); directory.mkdir()
            run([source / 'configure', '--host=x86_64-linux-musl', '--build=aarch64-apple-darwin',
                 '--prefix=/usr', '--libdir=/usr/lib', '--disable-shared', '--enable-static',
                 '--disable-dependency-tracking', *options], directory, environment, label + '-configure')
            run([make, '-j2'], directory, environment, label + '-build')
            run([make, 'DESTDIR=' + str(output / 'sysroot'), 'install'],
                directory, environment, label + '-install')
        source = extracted['libinput-1.29.0.tar.gz']
        original_meson = (source / 'meson.build').read_text()
        old = "lib_libinput = shared_library('input',"
        require(original_meson.count(old) == 1, 'libinput static linkage patch preimage')
        adapted = original_meson.replace(old, "lib_libinput = static_library('input',", 1)
        for line in ('\t\tversion : libinput_so_version,\n', '\t\tlink_args : version_flag,\n',
                     '\t\tlink_depends : mapfile,\n'):
            require(adapted.count(line) == 1, 'libinput shared-only metadata changed')
            adapted = adapted.replace(line, '', 1)
        (source / 'meson.build').write_text(adapted)
        report['libinput_meson_patch'] = dict(before=hashlib.sha256(original_meson.encode()).hexdigest(),
                                            after=hashlib.sha256(adapted.encode()).hexdigest())
        cross = work / 'cross.ini'
        cross.write_text("[binaries]\nc = '" + str(compiler) + "'\nar = '" + environment['AR'] +
            "'\nstrip = '" + environment['STRIP'] + "'\npkg-config = '/opt/homebrew/bin/pkg-config'\n"
            "[host_machine]\nsystem = 'linux'\ncpu_family = 'x86_64'\ncpu = 'x86_64'\nendian = 'little'\n"
            "[properties]\nneeds_exe_wrapper = true\nsys_root = '" + str(output / 'sysroot') +
            "'\npkg_config_libdir = ['" + str(output / 'sysroot/usr/lib/pkgconfig') + "']\n")
        directory = work / 'libinput-build'
        run(['/opt/homebrew/bin/meson', 'setup', str(directory), str(source), '--cross-file', str(cross),
             '--prefix=/usr', '--libdir=lib', '--buildtype=release', '-Ddefault_library=static',
             '-Dlibwacom=false', '-Ddebug-gui=false', '-Dtests=false', '-Ddocumentation=false'],
            work, environment, 'libinput-configure')
        run(['/opt/homebrew/bin/ninja', '-C', str(directory), '-j2', 'libinput.a'],
            work, environment, 'libinput-build')
        shutil.copyfile(directory / 'libinput.a', output / 'sysroot/usr/lib/libinput.a')
        shutil.copyfile(source / 'src/libinput.h', output / 'sysroot/usr/include/libinput.h')
        shutil.copyfile(directory / 'meson-private/libinput.pc', output / 'sysroot/usr/lib/pkgconfig/libinput.pc')
        libraries = {}
        for name in ('input', 'udev', 'evdev', 'mtdev'):
            relative = 'sysroot/usr/lib/lib' + name + '.a'
            port_check.architecture(output / relative, target='x86_64')
            libraries[relative] = dict(sha256=sha(output / relative), bytes=(output / relative).stat().st_size)
        smoke = work / 'static-link.c'
        smoke.write_text('#include <stdint.h>\n#include <libudev.h>\n'
            '#include <libinput.h>\n#include <libevdev/libevdev.h>\n'
            'static uintptr_t volatile api[] = {(uintptr_t)udev_new, (uintptr_t)libevdev_new, '
            '(uintptr_t)libinput_path_create_context};\n'
            'int main(void) { uintptr_t value=0; for (unsigned i=0;i<3;i++) value ^= api[i]; return value==0; }\n')
        smoke_output = work / 'static-link.elf'
        run([compiler, '-O2', '-I' + str(output / 'sysroot/usr/include/libevdev-1.0'), smoke,
             '-Wl,--start-group', *(output / name for name in libraries), '-lm',
             '-Wl,--end-group', '-o', smoke_output], work, environment, 'static-link')
        # architecture() admits archive members and shared objects, whereas
        # this probe deliberately produces a static ET_EXEC executable.
        port_check.elf_header(smoke_output.read_bytes(), (2,), target='x86_64')
        require(all(sha(original / p) == digest and sha(output / p) == digest
                    for p, digest in original_hashes.items()), 'Original static SDK bytes changed')
        report.update(status='NATIVE_INPUT_SDK_BUILT_NOT_RUN', libraries=libraries,
            static_link_probe=dict(sha256=sha(smoke_output), bytes=smoke_output.stat().st_size,
                                   executed=False),
            compiler_sha256=sha(compiler), output=str(output), original_inputs_preserved=True,
            elapsed_seconds=round(time.monotonic() - started, 3))
        producers = {}
        for relative in ('tools/build_cosmic_input_sdk_v1.py', 'tools/cosmic_ports.py',
                         'tools/target_profile.py', 'tools/native_session.py',
                         'ports/cosmic/native-input-sdk-v1/sources.json'):
            snapshot = output / 'producer-sources' / relative
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, snapshot)
            producers[relative] = sha(snapshot)
        require(producers['tools/build_cosmic_input_sdk_v1.py'] == report['producer_sha256'],
                'Input SDK producer changed during build')
        report['producers'] = producers
    except BaseException as error:
        report.update(status='FAILED', error=repr(error), elapsed_seconds=round(time.monotonic() - started, 3))
        raise
    finally:
        (output / 'native-input-sdk-origin.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--original', type=Path, default=ROOT / 'artifacts/sysroot/x86_64-musl')
    parser.add_argument('--archives', type=Path, default=ROOT / 'artifacts/native-input-source-archives')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = build(args.output, args.original, args.archives)
    print(json.dumps({key: result[key] for key in ('status', 'elapsed_seconds', 'libraries')}, indent=2))


if __name__ == '__main__':
    main()
