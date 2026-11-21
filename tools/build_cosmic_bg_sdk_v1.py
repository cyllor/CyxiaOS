#!/usr/bin/env python3
"""Extend the existing musl SDK with the pinned static AVIF decoder."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import build_cosmic as base
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

ROOT = base.ROOT
PORT = ROOT / 'ports/cosmic/native-bg-v1'
DECODER = PORT / 'dav1d.json'
ARCHIVE = 'sysroot/usr/lib/libdav1d.a'
PKG_CONFIG = 'sysroot/usr/lib/pkgconfig/dav1d.pc'
LICENSE = 'dav1d-COPYING'
RECEIPT = 'dav1d-sdk-origin.json'
TARGET = 'x86_64-unknown-linux-musl'


def build(output, parent, sources):
    output, parent, sources = map(base.no_symlink_path, (output, parent, sources))
    if output.exists() or output.is_relative_to(parent) or output.is_relative_to(sources):
        raise base.CosmicBuildError('Use a fresh SDK output outside the source inputs')
    pin = base.load_json(DECODER)
    source = base.inspect_source(sources, pin)
    output.mkdir(parents=True)
    for name in ('bin', 'sysroot'):
        subprocess.run(['/bin/cp', '-cRp', str(parent / name), str(output / name)], check=True)
    bin_dir = output / 'bin'
    cc = bin_dir / 'x86_64-linux-musl-cc'
    cc.write_text(cc.read_text().replace(str(parent), str(output)))
    with tempfile.TemporaryDirectory(prefix='cyxia-dav1d-', dir='/private/tmp') as temporary:
        work = Path(temporary)
        stage, target = work / 'source', work / 'build'
        base.export_source(Path(source['path']), stage)
        cross = output / 'dav1d-cross.ini'
        cross.write_text(
            f"[binaries]\nc = '{cc}'\nar = '{bin_dir / 'x86_64-linux-musl-ar'}'\n"
            f"ranlib = '{bin_dir / 'x86_64-linux-musl-ranlib'}'\n"
            "[host_machine]\nsystem = 'linux'\ncpu_family = 'x86_64'\ncpu = 'x86_64'\n"
            "endian = 'little'\n[properties]\nneeds_exe_wrapper = true\n"
        )
        meson = '/opt/homebrew/bin/meson'
        commands = [
            [meson, 'setup', str(target), str(stage), '--cross-file', str(cross),
             '--prefix=/usr', '--libdir=lib', '--wrap-mode=nofallback', '--buildtype=release',
             '-Ddefault_library=static', '-Denable_asm=false', '-Denable_tools=false', '-Denable_tests=false'],
            [meson, 'compile', '-C', str(target), '-j', '2'],
            [meson, 'install', '-C', str(target), '--no-rebuild', '--destdir', str(output / 'sysroot')],
        ]
        env = base.clean_environment('/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
        env['SOURCE_DATE_EPOCH'] = base.git(Path(source['path']), 'show', '-s', '--format=%ct')
        for name, command in zip(('configure', 'compile', 'install'), commands):
            base.run_bounded(command, work, env, output / f'dav1d-{name}.log',
                             300, 256 * 1024**2, 512 * 1024**2,
                             budget_root=output, scratch_roots=(work,))
        shutil.copyfile(stage / 'COPYING', output / LICENSE)
        if base.inspect_source(sources, pin) != source:
            raise base.CosmicBuildError('dav1d source changed while building')
    base.ports.architecture(output / ARCHIVE, target='x86_64')
    files = (ARCHIVE, PKG_CONFIG, LICENSE, 'dav1d-cross.ini', 'bin/x86_64-linux-musl-cc')
    report = dict(status='DAV1D_SDK_BUILT', target=TARGET, source=source, parent=str(parent),
                  commands=commands, files={name: base.digest(output / name) for name in files})
    (output / RECEIPT).write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--parent', type=Path, default=ROOT / 'artifacts/v017-cosmic-input-sdk-v3')
    parser.add_argument('--sources', type=Path, default=ROOT / 'artifacts/cosmic-native-sources')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        report = build(args.output, args.parent, args.sources)
    print(json.dumps({'status': report['status'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
