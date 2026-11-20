#!/usr/bin/env python3
"""Link a real Wayland-EGL client against the exact panel native SDK."""
import argparse
import json
from pathlib import Path
import subprocess

import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease


def build(base_build, panel_build, output, *, source=None, repair=None, hold_memfd_backing=False):
    base_build, panel_build, output = map(lambda p: Path(p).resolve(), (base_build, panel_build, output))
    manifest = pc.read_json(base_build / 'build-manifest.json')
    parent = Path(manifest['sysroot'])
    original = os_x86.catalog_inputs(parent)
    panel = json.loads(pc.bounded_bytes(panel_build / 'build-report.json', 32 * 1024**2))
    sdk = Path(panel['sysroot'])
    pc.require(manifest['status'] == 'BUILT_NOT_RUN' and original == manifest['external_inputs']
               and panel['status'] == 'cross-built', 'Unverified diagnostic parents')
    pc.require(not output.exists() and all(not output.is_relative_to(p)
               and not p.is_relative_to(output) for p in (base_build, panel_build, parent, sdk)),
               'Preserving existing/overlapping diagnostic inputs')
    inputs = {str(sdk / row['path']): row['sha256'] for row in panel['recipe']['native_inputs']}
    inputs[str(sdk / 'runtime-sdk-origin.json')] = panel['recipe']['native_sdk_origin']['sha256']
    default_source = pc.ROOT / 'user/ported/wayland_egl_probe.c'
    source = Path(source).resolve() if source else default_source
    compiler = sdk / 'bin/x86_64-linux-musl-cc'
    inputs.update({str(source): pc.sha(source), str(compiler): pc.sha(compiler)})
    if source != default_source:
        inputs[str(default_source)] = pc.sha(default_source)
    if repair is not None:
        import build_mesa_wayland_oom_v1 as mesa
        repair = Path(repair).resolve()
        mesa.verify(repair)
        inputs.update({str(p): pc.sha(p) for p in (repair / 'libEGL.a', repair / 'repair-origin.json')})
    headers = sdk / 'mesa-native-port/mesa-26.2.3/include'
    for directory in ('EGL', 'KHR', 'GLES3', 'GLES2'):
        inputs.update({str(p): pc.sha(p) for p in (headers / directory).glob('*.h')})
    scanner = sdk / 'wayland-host-tools/bin/wayland-scanner'
    registry = pc.ROOT / 'artifacts/cosmic-comp-cache/registry/src/index.crates.io-1949cf8c6b5b557f'
    protocols = {
        'layer-shell': registry / 'wayland-protocols-wlr-0.3.12/wlr-protocols/unstable/wlr-layer-shell-unstable-v1.xml',
        'xdg-shell': registry / 'wayland-protocols-0.32.13/protocols/stable/xdg-shell/xdg-shell.xml'}
    inputs.update({str(p): pc.sha(p) for p in (scanner, *protocols.values())})
    pc.require(all(pc.sha(Path(p)) == digest for p, digest in inputs.items()), 'Panel native SDK changed')
    output.mkdir(parents=True)
    for name, path in protocols.items():
        for mode, suffix in (('client-header', '.h'), ('private-code', '.c')):
            subprocess.run([str(scanner), mode, str(path), str(output / (name + suffix))], check=True)
    subprocess.run(['/bin/cp', '-cRp', str(parent / 'rootfs'), str(output / 'rootfs')], check=True)
    for name in ('probe.elf', 'cosmic-comp.elf', 'dbus-daemon.elf'):
        subprocess.run(['/bin/cp', '-c', '-p', str(parent / name), str(output / name)], check=True)
    command = [str(compiler), '-O2', '-ffunction-sections', '-fdata-sections',
               '-Wl,--gc-sections', '-Wall', '-Wextra', '-Werror',
               '-I' + str(sdk / 'sysroot/usr/include'), '-I' + str(headers), '-I' + str(output),
               str(source), str(output / 'layer-shell.c'), str(output / 'xdg-shell.c'), '-Wl,--start-group']
    if source != default_source:
        command += ['-I' + str(source.parent)]
    if hold_memfd_backing:
        pc.require(source != default_source, 'Reference-retention wrapper requires its diagnostic source')
        command += ['-Wl,--wrap=memfd_create']
    archives = [str(sdk / name) for name in panel['recipe']['static_link_inputs']]
    if repair is not None:
        old = str(sdk / 'mesa-native-port/build/src/egl/libEGL.a')
        pc.require(archives.count(old) == 1, 'Expected one original EGL archive')
        archives = [str(repair / 'libEGL.a') if name == old else name for name in archives]
    command += archives
    command += ['-Wl,--end-group', '-lm', '-lpthread', '-ldl', '-o', str(output / 'wayland-egl-probe.elf')]
    (output / 'link-command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (output / 'link.log').open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    (output / 'wayland-egl-probe.source.c').write_bytes(source.read_bytes())
    pc.require(all(pc.sha(Path(p)) == digest for p, digest in inputs.items())
               and os_x86.catalog_inputs(parent) == original, 'Diagnostic input changed during link')
    selected = os_x86.catalog_inputs(output)
    pc.require(sum((output / name).stat().st_size for name in selected) <= 96 * 1024**2,
               'Isolated diagnostic exceeds the existing 96 MiB limit')
    pc.write_json(output / 'wayland-egl-probe-origin.json', dict(
        status='WAYLAND_EGL_DIAGNOSTIC_LINKED_NOT_RUN', inputs=inputs, selected_inputs=selected,
        base_build=str(base_build), panel_build=str(panel_build),
        parent_manifest_sha256=pc.sha(base_build / 'build-manifest.json'),
        panel_report_sha256=pc.sha(panel_build / 'build-report.json'),
        repair=str(repair) if repair else None,
        hold_memfd_backing=hold_memfd_backing,
        producers=os_x86.producer_sources(__file__), full_os_verified=False,
        cosmic_session_verified=False))
    print('Linked genuine panel SDK EGL diagnostic with original compositor and assets')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--panel-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--repair', type=Path)
    parser.add_argument('--hold-memfd-backing', action='store_true')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        build(args.base_build, args.panel_build, args.output, source=args.source, repair=args.repair,
              hold_memfd_backing=args.hold_memfd_backing)


if __name__ == '__main__':
    main()
