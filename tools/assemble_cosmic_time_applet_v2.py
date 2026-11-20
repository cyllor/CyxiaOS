#!/usr/bin/env python3
"""Add the real upstream clock and its original desktop/icon/license to a catalog."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import cosmic_time_applet_v2 as clock
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, parent, require = clock.base, clock.parent, clock.require
ASSETS = {
    'cosmic-applet-time/data/com.system76.CosmicAppletTime.desktop':
        'usr/share/applications/com.system76.CosmicAppletTime.desktop',
    'cosmic-applet-time/data/icons/scalable/apps/com.system76.CosmicAppletTime-symbolic.svg':
        'usr/share/icons/hicolor/scalable/apps/com.system76.CosmicAppletTime-symbolic.svg',
    'LICENSE': 'usr/share/doc/cosmic-applet-time/LICENSE',
    'native-deps/xkbcommon-dl/LICENSE': 'usr/share/doc/cosmic-applet-time/xkbcommon-dl-LICENSE',
}


def validate(build):
    build = base.no_symlink_path(build)
    policy, recipe, _, profile, _ = clock.contract()
    report = base.load_json(build / 'build-report.json')
    require(report['status'] == 'cross-built' and report['kind'] == 'cosmic-time-applet-v2'
            and report['recipe'] == recipe and report['resource_profile'] == profile
            and report['source_policy_sha256'] == base.digest(clock.PORT / 'source-policy.json')
            and report['cargo_offline'] is True and report['sdk_preserved'] is True
            and report['input_sources_preserved'] is True,
            'Clock is not a complete admitted offline build')
    # A historical binary remains independently verifiable after unrelated OS
    # tools gain a new image feature. Bind the exact archived producer bytes;
    # do not execute them or claim they equal a subsequently edited tool.
    for name, digest in report['producers'].items():
        require(base.digest(build / 'producer-sources' / name) == digest,
                'Clock producer snapshot changed: ' + name)
    for name, digest in report['evidence_files'].items():
        require(base.digest(build / name) == digest, 'Clock build evidence changed: ' + name)
    inputs = report['source_inputs']
    source = build / 'source'
    require(clock.verify_export(source, inputs) == report['source_tree'], 'Retained full clock source changed')
    metadata = base.load_json(build / 'metadata.json')
    registry_package = next(p for p in metadata['packages'] if (p.get('source') or '').startswith('registry+'))
    cache = Path(registry_package['manifest_path']).parents[4]
    require(clock.original_inputs(Path(inputs['originals']['applets']['path']).parent,
                                 base.ROOT / 'artifacts/cosmic-native-sources', cache) == inputs,
            'Clock canonical source/native bindings changed')
    original_stage = report['original_export_root']
    rebound = json.loads(json.dumps(metadata).replace(original_stage, str(source)))
    expected = json.loads(json.dumps(report['cargo_dependencies']).replace(original_stage, str(source)))
    require(clock.metadata_identity(rebound, source, cache, recipe, policy) == expected,
            'Complete clock locked dependency closure changed')
    sysroot = Path(report['sysroot'])
    selected = report['toolchain']['selection']
    _, identity = parent.common.selection.tools_and_sysroot(sysroot, recipe,
        rust_root=selected['rust_root'], host_cc=selected['host_cc'])
    require(identity == report['toolchain'] and base.tree_identity(sysroot / 'sysroot') == report['sdk_tree']
            and base.digest(sysroot / recipe['native_sdk_origin']['path']) == recipe['native_sdk_origin']['sha256']
            and parent.native_search(build, sysroot, recipe, identity) == report['native_archive_search'],
            'Clock actual compiler or genuine native SDK changed')
    executable = build / 'cosmic-applet-time.elf'
    require(base.digest(executable) == report['linked_binary']['sha256'], 'Clock published ELF changed')
    actual = parent.elf.inspect_full_os_elf(executable, profile)
    original = report['image_admission']
    require(actual == {**original, 'executable': {**original['executable'], 'file': executable.name}},
            'Clock static FullOs ELF admission changed')
    return report


def assemble(build, base_build, output):
    build, base_build, output = map(base.no_symlink_path, (build, base_build, output))
    report = validate(build)
    manifest = base.load_json(base_build / 'build-manifest.json')
    original = Path(manifest['sysroot'])
    require(manifest['status'] == 'BUILT_NOT_RUN'
            and os_x86.catalog_inputs(original) == manifest['external_inputs'], 'Parent core catalog changed')
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
            for p in (build, base_build, original, Path(report['sysroot']), clock.PORT)),
            'Clock catalog overlaps existing inputs')
    subprocess.run(['/bin/cp', '-cRp', str(original), str(output)], check=True)
    added = {}
    for source, target in ASSETS.items():
        relative = 'rootfs/' + target
        require(relative not in manifest['external_inputs'], 'Clock asset would replace an existing input')
        selected = output / relative
        selected.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(build / 'source' / source, selected)
        selected.chmod(0o644)
        added[relative] = base.digest(selected)
    # These real fonts are embedded by libcosmic::app::preload_fonts. Carry
    # their upstream notices with the applet even though no font asset is added.
    cosmic = [p for p in report['cargo_dependencies']['packages'] if p['name'] == 'libcosmic']
    require(len(cosmic) == 1, 'Missing unique genuine libcosmic license source')
    cosmic_root = Path(cosmic[0]['manifest']).parent
    for source, target in {
        'LICENSE': 'libcosmic-LICENSE',
        'res/open-sans/LICENSE': 'OpenSans-LICENSE',
        'res/noto/LICENSE': 'NotoSansMono-LICENSE',
    }.items():
        relative = 'rootfs/usr/share/doc/cosmic-applet-time/' + target
        require(relative not in manifest['external_inputs'], 'Clock notice would replace an input')
        shutil.copyfile(cosmic_root / source, output / relative)
        (output / relative).chmod(0o644)
        added[relative] = base.digest(output / relative)
    name = 'cosmic-applet-time.elf'
    require(name not in manifest['external_inputs'], 'Clock executable would replace an input')
    shutil.copyfile(build / name, output / name)
    (output / name).chmod(0o755)
    added[name] = base.digest(output / name)
    expected = {**manifest['external_inputs'], **added}
    require(os_x86.catalog_inputs(output) == expected
            and os_x86.catalog_inputs(original) == manifest['external_inputs'],
            'Clock assembly changed other core/default/diagnostic inputs')
    total = sum((output / name).stat().st_size for name in expected)
    require(total <= 192 * 1024**2, 'Complete clock catalog exceeds its explicit ROM profile')
    record = dict(status='GENUINE_CLOCK_CATALOG_ASSEMBLED_NOT_RUN',
        build=str(build), build_report_sha256=base.digest(build / 'build-report.json'),
        base_build=str(base_build), base_manifest_sha256=base.digest(base_build / 'build-manifest.json'),
        original_inputs=manifest['external_inputs'], additions=added, inputs=expected, raw_bytes=total,
        upstream_commit=clock.COMMIT, producers=os_x86.producer_sources(__file__),
        full_os_verified=False, cosmic_session_verified=False, applet_verified=False)
    (output / 'cosmic-time-applet-origin.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], raw_bytes=total,
                         clock_sha256=report['linked_binary']['sha256']), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        assemble(args.build, args.base_build, args.output)


if __name__ == '__main__':
    main()
