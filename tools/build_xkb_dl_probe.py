#!/usr/bin/env python3
"""Link the real clock's XKB crate into a small native regression catalog."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from cosmic_cargo_artifact import selected_rlib
import os_x86
import x86_64 as pc
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease


def build(clock, catalog, output):
    clock, catalog, output = map(lambda p: Path(p).resolve(), (clock, catalog, output))
    report = json.loads(pc.bounded_bytes(clock / 'build-report.json', 32 * 1024**2))
    pc.require(report['status'] == 'cross-built' and not output.exists()
        and pc.sha(clock / 'cosmic-applet-time.elf') == report['linked_binary']['sha256'],
        'Actual clock binary changed or diagnostic output exists')
    sdk = Path(report['sysroot'])
    selected = selected_rlib(clock, report, 'xkbcommon_dl')
    dependencies = selected.parent
    source = pc.ROOT / 'user/ported/xkb_dl_probe.rs'
    rustc = Path(report['toolchain']['tools']['rustc']['path'])
    compiler = sdk / 'bin/x86_64-linux-musl-cc'
    inputs = {str(p): pc.sha(p) for p in (source, rustc, compiler, selected)}
    for row in report['recipe']['native_inputs']:
        pc.require(pc.sha(sdk / row['path']) == row['sha256'], 'Genuine SDK archive changed')
        inputs[str(sdk / row['path'])] = row['sha256']
    output.mkdir(parents=True)
    original = os_x86.catalog_inputs(catalog)
    subprocess.run(['/bin/cp', '-cRp', str(catalog / 'rootfs'), str(output / 'rootfs')], check=True)
    shutil.copyfile(catalog / 'probe.elf', output / 'probe.elf')
    command = [str(rustc), '--edition=2024', '--target', report['recipe']['target'],
        '-C', 'panic=abort', '-C', 'opt-level=2', '-C', 'link-self-contained=no',
        '-C', 'relocation-model=static', '-C', 'target-feature=+crt-static',
        '-C', 'linker=' + str(compiler), '-L', 'dependency=' + str(dependencies),
        '-L', 'dependency=' + str(clock / 'target/release/deps'),
        '-L', 'native=' + str(clock / 'native'), '--extern', 'xkbcommon_dl=' + str(selected),
        '-C', 'link-arg=-Wl,--start-group']
    command += [value for name in report['recipe']['static_link_inputs']
                for value in ('-C', 'link-arg=' + str(sdk / name))]
    command += ['-C', 'link-arg=-Wl,--end-group', str(source), '-o',
                str(output / 'notifications-peer-probe.elf')]
    with (output / 'link.log').open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
    pc.require(all(pc.sha(Path(p)) == digest for p, digest in inputs.items())
               and os_x86.catalog_inputs(catalog) == original, 'XKB diagnostic input changed')
    pc.write_json(output / 'xkb-dl-origin.json', dict(clock_build=str(clock),
        clock_report_sha256=pc.sha(clock / 'build-report.json'), inputs=inputs, command=command,
        selected_rlib=str(selected), selected_inputs=os_x86.catalog_inputs(output),
        producers=os_x86.producer_sources(__file__), full_os_verified=False))
    print('Linked actual clock XKB crate regression')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clock-build', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        build(args.clock_build, args.catalog, args.output)


if __name__ == '__main__':
    main()
