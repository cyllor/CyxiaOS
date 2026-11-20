#!/usr/bin/env python3
"""Independently validate a real GUI relink and preserve all other catalog inputs."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import build_mesa_wayland_oom_v1 as mesa
import cosmic_panel_allocation_v2 as panel
import cosmic_time_applet_v2 as clock
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, require = panel.base, panel.require


def validate(build):
    report = base.load_json(build / 'build-report.json')
    require(report['kind'] == 'cosmic-mesa-wayland-relink-v1' and report['status'] == 'cross-built'
            and report['cargo_offline'] and report['parent_cache_preserved'], 'Incomplete native GUI relink')
    parent_build = Path(report['parent_build'])
    parent_report = base.load_json(parent_build / 'build-report.json')
    require(base.digest(parent_build / 'build-report.json') == report['parent_report_sha256'], 'Parent receipt changed')
    fix = panel if report['component']['name'] == 'cosmic-panel' else clock
    policy, recipe, component, profile, _ = fix.contract()
    require(report['component'] == component and report['recipe'] == recipe
            and report['resource_profile'] == profile, 'Genuine source/features or resource profile changed')
    for name, digest in report['producers'].items():
        require(base.digest(build / 'producer-sources' / name) == digest, 'Archived relink producer changed')
    for name, digest in report['evidence_files'].items():
        require(base.digest(build / name) == digest, 'Relink evidence changed')
    source, inputs = build / 'source', report['source_inputs']
    require(fix.verify_export(source, inputs) == report['source_tree'] == parent_report['source_tree'],
            'Complete retained Rust source changed')
    metadata = base.load_json(build / 'metadata.json')
    cache = next(Path(p['manifest_path']).parents[4] for p in metadata['packages']
                 if (p.get('source') or '').startswith('registry+'))
    require(fix.original_inputs(base.ROOT / 'artifacts/cosmic-sources',
            base.ROOT / 'artifacts/cosmic-native-sources', cache) == inputs, 'Canonical sources changed')
    stage = report['original_export_root']
    rebound = json.loads(json.dumps(metadata).replace(stage, str(source)))
    expected = json.loads(json.dumps(report['cargo_dependencies']).replace(stage, str(source)))
    identity = fix.parent.metadata_identity if fix is panel else fix.metadata_identity
    require(identity(rebound, source, cache, recipe, policy) == expected, 'Full locked dependency graph changed')
    sdk = Path(parent_report['sysroot'])
    selection = report['toolchain']['selection']
    _, toolchain = fix.parent.common.selection.tools_and_sysroot(sdk, recipe,
        rust_root=selection['rust_root'], host_cc=selection['host_cc'])
    require(toolchain == report['toolchain'] and base.tree_identity(sdk / 'sysroot') == report['sdk_tree'],
            'Original SDK/compiler changed')
    repair = Path(report['repair'])
    require(base.digest(repair / 'repair-origin.json') == report['repair_report_sha256'], 'Native repair receipt changed')
    repaired = mesa.verify(repair)
    obj = repair / mesa.MEMBER
    invocation = base.load_json(build / 'link-invocation.json')
    require(invocation['actual_arguments'][0] == str(obj)
            and invocation['native_object_sha256'] == repaired['outputs'][mesa.MEMBER], 'Repaired C object not selected')
    mapping = (build / 'native-link.map').read_text()
    require(str(obj) in mapping and not any(mesa.MEMBER in line
            and ('.rlib(' in line or 'libEGL.a(' in line) for line in mapping.splitlines()), 'Old C object linked')
    executable = build / (recipe['binary'] + '.elf')
    require(base.digest(executable) == report['linked_binary']['sha256'], 'Published ELF differs')
    actual = fix.parent.elf.inspect_full_os_elf(executable, profile)
    expected = report['image_admission']
    require(actual == {**expected, 'executable': {**expected['executable'], 'file': executable.name}},
            'FullOs ELF admission changed')
    return report


def assemble(build, base_build, output):
    report = validate(build)
    manifest = base.load_json(base_build / 'build-manifest.json')
    original = Path(manifest['sysroot'])
    require(manifest['status'] == 'BUILT_NOT_RUN'
            and os_x86.catalog_inputs(original) == manifest['external_inputs'], 'Original catalog changed')
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
            for p in (build, base_build, original, Path(report['repair']))), 'Catalog output overlaps an input')
    subprocess.run(['/bin/cp', '-cRp', str(original), str(output)], check=True)
    name = report['recipe']['binary'] + '.elf'
    require(name in manifest['external_inputs'], 'Relink must replace an existing genuine program')
    shutil.copyfile(build / name, output / name)
    notice = 'rootfs/usr/share/doc/mesa-wayland-swrast-allocation/LICENSE'
    require(notice not in manifest['external_inputs'], 'Repair notice would overwrite an input')
    target = output / notice
    target.parent.mkdir(parents=True)
    target.write_text((mesa.PORT / 'upstream/platform_wayland.c').read_text().split('*/', 1)[0] + '*/\n')
    expected = {**manifest['external_inputs'], name: base.digest(output / name), notice: base.digest(target)}
    require(os_x86.catalog_inputs(output) == expected
            and os_x86.catalog_inputs(original) == manifest['external_inputs'], 'Unrelated catalog input changed')
    total = sum((output / p).stat().st_size for p in expected)
    require(total <= 192 * 1024**2, 'Catalog exceeds its existing explicit clock ROM profile')
    record = dict(status='GENUINE_MESA_GUI_RELINK_CATALOG_NOT_RUN', inputs=expected,
        original_inputs=manifest['external_inputs'], build=str(build), base_build=str(base_build),
        build_report_sha256=base.digest(build / 'build-report.json'), raw_bytes=total,
        producers=os_x86.producer_sources(__file__), full_os_verified=False, cosmic_session_verified=False)
    (output / 'mesa-wayland-relink-origin.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], raw_bytes=total, replaced=name), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        assemble(*map(base.no_symlink_path, (args.build, args.base_build, args.output)))


if __name__ == '__main__':
    main()
