#!/usr/bin/env python3
"""Build the real musl memfd metadata/page-bound regression in a small catalog."""
import argparse
from pathlib import Path
import shutil
import subprocess

import cosmic_time_applet_v2 as clock
import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, default=pc.ROOT / 'artifacts/sysroot/x86_64-musl')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    catalog, sdk, output = map(clock.base.no_symlink_path, (args.catalog, args.sysroot, args.output))
    pc.require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
               for p in (catalog, sdk)), 'Probe output overlaps an input')
    recipe = clock.contract()[1]
    source = pc.ROOT / 'user/ported/shared_object_probe.c'
    compiler = sdk / 'bin/x86_64-linux-musl-cc'
    inputs = {str(p): pc.sha(p) for p in (source, compiler, catalog / 'probe.elf')}
    inputs.update({str(sdk / row['path']): row['sha256'] for row in recipe['native_inputs']})
    inputs[str(sdk / recipe['native_sdk_origin']['path'])] = recipe['native_sdk_origin']['sha256']
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        pc.require(all(pc.sha(Path(p)) == sha for p, sha in inputs.items()), 'Genuine musl SDK changed')
        output.mkdir(parents=True)
        command = [str(compiler), '-O2', '-Wall', '-Wextra', '-Werror', str(source),
                   '-o', str(output / 'notifications-peer-probe.elf')]
        with (output / 'link.log').open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
        shutil.copyfile(catalog / 'probe.elf', output / 'probe.elf')
        pc.require(all(pc.sha(Path(p)) == sha for p, sha in inputs.items()), 'Probe input changed')
        pc.write_json(output / 'shared-object-origin.json', dict(inputs=inputs, command=command,
            selected_inputs=os_x86.catalog_inputs(output), producers=os_x86.producer_sources(__file__),
            full_os_verified=False, cosmic_session_verified=False))


if __name__ == '__main__':
    main()
