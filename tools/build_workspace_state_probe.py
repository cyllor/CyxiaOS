#!/usr/bin/env python3
"""Build a read-only observer of the real COSMIC workspace protocols."""
import argparse
from pathlib import Path
import shutil
import subprocess

import cosmic_workspace_applets_v1 as applets
import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, require = applets.base, applets.require
SPEC = applets.PORT / 'workspace-probe.json'


def validate(output):
    output = base.no_symlink_path(output)
    report = base.load_json(output / 'workspace-probe-origin.json')
    require(report['status'] == 'WORKSPACE_OBSERVER_BUILT_NOT_RUN'
            and report['protocols'] == base.load_json(SPEC)['protocols'], 'Workspace observer contract changed')
    for path, digest in report['inputs'].items():
        require(base.digest(Path(path)) == digest, 'Workspace observer input changed: ' + path)
    for path, digest in report['evidence'].items():
        require(base.digest(output / path) == digest, 'Workspace observer evidence changed: ' + path)
    for path, digest in report['producers'].items():
        require(base.digest(output / 'producer-sources' / path) == digest, 'Workspace observer producer changed')
    inspection = applets.parent.parent.elf.inspect_full_os_elf(output / 'workspace-state-probe.elf', applets.contract()[3])
    require(inspection == report['image_admission'], 'Workspace observer executable changed')
    require(applets.parent.parent.elf.inspect_full_os_elf(output / 'workspace-window-probe.elf', applets.contract()[3])
            == report['window_image_admission'], 'Workspace diagnostic window changed')
    return report


def build(output, sdk):
    output, sdk = map(base.no_symlink_path, (output, sdk))
    require(not output.exists() and not output.is_relative_to(sdk) and not sdk.is_relative_to(output),
            'Preserving observer output and SDK')
    _, recipe, _, profile, _ = applets.contract()
    extra = applets.additional_link_inputs(sdk, recipe)
    protocols = base.load_json(SPEC)['protocols']
    scanner = base.ROOT / 'artifacts/sysroot/x86_64-musl/wayland-host-tools/bin/wayland-scanner'
    compiler = sdk / 'bin/x86_64-linux-musl-cc'
    source = base.ROOT / 'user/ported/workspace_state_probe.c'
    window = base.ROOT / 'user/ported/workspace_window_probe.c'
    inputs = {str(p): base.digest(p) for p in (source, window, scanner, compiler, SPEC)}
    inputs.update({str(sdk / row['path']): row['sha256'] for row in recipe['native_inputs']})
    headers = sdk / 'sysroot/usr/include'
    inputs.update({str(p): base.digest(p) for p in headers.glob('wayland-*.h')})
    inputs.update({str(base.ROOT / row['path']): row['sha256'] for row in protocols})
    require(all(base.digest(Path(p)) == digest for p, digest in inputs.items()), 'Observer native inputs changed')
    output.mkdir(parents=True)
    producers = os_x86.producer_sources(__file__)
    for name in producers:
        path = output / 'producer-sources' / name
        path.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(base.ROOT / name, path)
    commands = []
    environment = base.clean_environment('/usr/bin:/bin:/opt/homebrew/bin')
    def run(command, label):
        commands.append([str(p) for p in command])
        with (output / (label + '.log')).open('wb') as log:
            subprocess.run(commands[-1], env=environment, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=30)
    for row in protocols:
        for mode, suffix in (('client-header', '.h'), ('private-code', '.c')):
            run([scanner, mode, base.ROOT / row['path'], output / (row['name'] + suffix)], row['name'] + '-' + mode)
    shutil.copyfile(source, output / source.name)
    run([compiler, '-O2', '-Wall', '-Wextra', '-Werror', '-ffunction-sections', '-fdata-sections',
         '-Wl,--gc-sections', '-I' + str(output), source,
         *(output / (row['name'] + '.c') for row in protocols),
         sdk / 'sysroot/usr/lib/libwayland-client.a', sdk / 'sysroot/usr/lib/libffi.a',
         '-lm', '-lpthread', '-o', output / 'workspace-state-probe.elf'], 'link')
    shutil.copyfile(window, output / window.name)
    run([compiler, '-O2', '-Wall', '-Wextra', '-Werror', '-ffunction-sections', '-fdata-sections',
         '-Wl,--gc-sections', '-I' + str(output), window, output / 'xdg-shell.c',
         sdk / 'sysroot/usr/lib/libwayland-client.a', sdk / 'sysroot/usr/lib/libffi.a',
         '-lm', '-lpthread', '-o', output / 'workspace-window-probe.elf'], 'window-link')
    require(all(base.digest(Path(p)) == digest for p, digest in inputs.items())
            and applets.additional_link_inputs(sdk, recipe) == extra
            and os_x86.producer_sources(__file__) == producers, 'Observer inputs changed during compilation')
    inspection = applets.parent.parent.elf.inspect_full_os_elf(output / 'workspace-state-probe.elf', profile)
    base_data = dict(status='WORKSPACE_OBSERVER_BUILT_NOT_RUN', protocols=protocols, inputs=inputs,
                     image_admission=inspection,
                     window_image_admission=applets.parent.parent.elf.inspect_full_os_elf(output / 'workspace-window-probe.elf', profile),
                     commands=commands, producers=producers,
                     guest_execution=False, full_os_verified=False, cosmic_session_verified=False)
    base_data['evidence'] = {p.name: base.digest(p) for p in output.iterdir() if p.is_file()}
    pc.write_json(output / 'workspace-probe-origin.json', base_data)
    return validate(output)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sysroot', required=True, type=Path)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = build(args.output, args.sysroot)
    print(result['status'])


if __name__ == '__main__':
    main()
