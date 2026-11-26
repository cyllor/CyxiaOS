#!/usr/bin/env python3
"""Revalidate and install two genuine controls into a preserved COSMIC catalog."""
import argparse
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

import cosmic_workspace_applets_v1 as applets
import os_x86
import build_workspace_state_probe as observer
import build_cosmic_applet_host_v1 as hosts
import relink_cosmic_workspace_applets_v1 as repaired_applets
import cosmic_applet_object_profile_v1 as objects
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, require = applets.base, applets.require
backend = applets.parent.parent
MAX_BYTES = 256 * 1024**2
MAX_ENTRIES = 256
ASSETS = {
    'cosmic-applet-workspaces/data/com.system76.CosmicAppletWorkspaces.desktop':
        'usr/share/applications/com.system76.CosmicAppletWorkspaces.desktop',
    'cosmic-applet-workspaces/data/icons/scalable/apps/com.system76.CosmicAppletWorkspaces.svg':
        'usr/share/icons/hicolor/scalable/apps/com.system76.CosmicAppletWorkspaces.svg',
    'cosmic-applet-tiling/data/com.system76.CosmicAppletTiling.desktop':
        'usr/share/applications/com.system76.CosmicAppletTiling.desktop',
    'cosmic-applet-tiling/data/icons/scalable/apps/com.system76.CosmicAppletTiling-symbolic.svg':
        'usr/share/icons/hicolor/scalable/apps/com.system76.CosmicAppletTiling-symbolic.svg',
    'cosmic-applet-tiling/data/icons/scalable/apps/com.system76.CosmicAppletTiling.On.svg':
        'usr/share/icons/hicolor/scalable/apps/com.system76.CosmicAppletTiling.On.svg',
    'cosmic-applet-tiling/data/icons/scalable/apps/com.system76.CosmicAppletTiling.Off.svg':
        'usr/share/icons/hicolor/scalable/apps/com.system76.CosmicAppletTiling.Off.svg',
}


def validate(build, *, contract_module=applets):
    applets = contract_module
    build = base.no_symlink_path(build)
    policy, recipe, _, profile, _ = applets.contract()
    report = base.load_json(build / 'build-report.json')
    require(report['status'] == 'cross-built' and report['kind'] == applets.KIND
            and report['recipe'] == recipe and report['resource_profile'] == profile
            and report['source_policy_sha256'] == base.digest(applets.PORT / 'source-policy.json')
            and report['cargo_offline'] is True and report['sdk_preserved'] is True
            and report['input_sources_preserved'] is True,
            'Not a complete successful workspace applet build')
    require(set(report['binaries']) == set(applets.PROGRAMS), 'Partial applet publication')
    for name, digest in report['producers'].items():
        require(base.digest(build / 'producer-sources' / name) == digest, 'Archived applet producer changed')
    for name, digest in report['evidence_files'].items():
        require(base.digest(build / name) == digest, 'Applet build evidence changed')
    inputs = report['source_inputs']; source = build / 'source'
    require(applets.verify_export(source, inputs) == report['source_tree'], 'Retained applet source changed')
    metadata = base.load_json(build / 'metadata.json')
    registry = next(p for p in metadata['packages'] if (p.get('source') or '').startswith('registry+'))
    cache = Path(registry['manifest_path']).parents[4]
    require(applets.original_inputs(Path(inputs['originals']['applets']['path']).parent,
            base.ROOT / 'artifacts/cosmic-native-sources', cache) == inputs, 'Canonical applet inputs changed')
    old = report['original_export_root']
    rebound = json.loads(json.dumps(metadata).replace(old, str(source)))
    expected = json.loads(json.dumps(report['cargo_dependencies']).replace(old, str(source)))
    require(applets.metadata_identity(rebound, source, cache, recipe, policy) == expected,
            'Complete applet dependency closure changed')
    sysroot = Path(report['sysroot']); selected = report['toolchain']['selection']
    _, actual = backend.common.selection.tools_and_sysroot(sysroot, recipe,
        rust_root=selected['rust_root'], host_cc=selected['host_cc'])
    require(actual == report['toolchain'] and base.tree_identity(sysroot / 'sysroot') == report['sdk_tree']
            and base.digest(sysroot / recipe['native_sdk_origin']['path']) == recipe['native_sdk_origin']['sha256']
            and backend.native_search(build, sysroot, recipe, actual) == report['native_archive_search'],
            'Applet compiler or native SDK changed')
    require(applets.additional_link_inputs(sysroot, recipe) == report['additional_native_inputs'],
            'Additional applet native SDK changed')
    if hasattr(applets, 'verify_native_environment'):
        require(applets.verify_native_environment(build, report['toolchain'], sysroot,
                report['native_environment']) == report['native_build_probes'], 'Native target symbol probe changed')
    for name in applets.PROGRAMS:
        record = report['binaries'][name]
        executable = build / (name + '.elf')
        linked = build / 'target' / applets.parent.TARGET / 'release' / name
        require(base.digest(executable) == base.digest(linked) == record['linked_binary']['sha256']
                and stat.S_IMODE(executable.stat().st_mode) == 0o755,
                'Published applet differs from the genuine raw link: ' + name)
        admitted = backend.elf.inspect_full_os_elf(executable, profile)
        original = record['image_admission']
        require(admitted == {**original, 'executable': {**original['executable'], 'file': executable.name}},
                'Applet FullOs ELF admission changed: ' + name)
    return report


def _assemble(build, base_build, output, probe=None, host_builds=(), applet_relink=None):
    build, base_build, output = map(base.no_symlink_path, (build, base_build, output))
    report = validate(build)
    probe_report = observer.validate(probe) if probe else None
    host_reports = {}
    for path in host_builds:
        host = hosts.validate(path)
        require(host['host'] not in host_reports, 'Duplicate native host build')
        host_reports[host['host']] = (Path(path), host)
    require(not host_builds or set(host_reports) == {'session', 'panel'} and len(host_builds) == 2,
            'Both genuine 128-FD hosts are required together')
    repaired = repaired_applets.validate(applet_relink) if applet_relink else None
    require(not host_reports or repaired is not None, 'Production applet catalog requires repaired genuine applets')
    require(repaired is None or Path(repaired['parent']) == build, 'Repaired applets use another parent build')
    manifest = base.load_json(base_build / 'build-manifest.json')
    original = base.no_symlink_path(Path(manifest['sysroot']))
    require(manifest['status'] == 'BUILT_NOT_RUN' and manifest['ram_mib'] == 1024
            and os_x86.catalog_inputs(original) == manifest['external_inputs'],
            'Parent one-GiB input catalog changed')
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
        for p in (build, base_build, original, Path(report['sysroot']), applets.PORT)),
        'Applet catalog overlaps existing inputs')
    # Keep clonefile on Darwin without requiring its private cp option on
    # other POSIX hosts. Catalog validation and publication stay unchanged.
    copy_flags = '-cRp' if sys.platform == 'darwin' else '-Rp'
    subprocess.run(['/bin/cp', copy_flags, str(original), str(output)], check=True)
    added = {}
    replaced = {}
    for kind, (directory, host_report) in host_reports.items():
        name = hosts.hosts.NAMES[kind] + '.elf'; target = output / name
        require(name in manifest['external_inputs'], 'Missing original host input')
        shutil.copyfile(directory / name, target); target.chmod(0o755)
        replaced[name] = dict(before=manifest['external_inputs'][name], after=base.digest(target),
                              build=str(directory), report_sha256=base.digest(directory / 'build-report.json'))
    for name in applets.PROGRAMS:
        target = output / (name + '.elf')
        require(not target.exists(), 'Refuse to overwrite an existing applet')
        shutil.copyfile(Path(applet_relink or build) / (name + '.elf'), target); target.chmod(0o755)
        added[target.relative_to(output).as_posix()] = base.digest(target)
    if probe_report is not None:
        for name in ('workspace-state-probe.elf', 'workspace-window-probe.elf'):
            target = output / name
            require(not target.exists(), 'Preserving existing workspace diagnostic')
            shutil.copyfile(Path(probe) / name, target); target.chmod(0o755)
            added[name] = base.digest(target)
    assets = dict(ASSETS)
    for name in applets.PROGRAMS:
        # The same original GPL license applies to both upstream programs.
        destination = output / 'rootfs/usr/share/doc' / name / 'LICENSE'
        require(not destination.exists(), 'Refuse to replace an existing license')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(build / 'source/LICENSE', destination); destination.chmod(0o644)
        added[destination.relative_to(output).as_posix()] = base.digest(destination)
    for row in report['recipe']['additional_native_licenses']:
        destination = output / 'rootfs' / row['destination']
        require(not destination.exists(), 'Refuse to replace an existing native license')
        source = Path(report['sysroot']) / row['path']
        require(base.digest(source) == row['sha256'], 'Native license input changed')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination); destination.chmod(0o644)
        added[destination.relative_to(output).as_posix()] = base.digest(destination)
    for source, relative in assets.items():
        destination = output / 'rootfs' / relative
        require(not destination.exists(), 'Refuse to replace an existing desktop asset')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(build / 'source' / source, destination); destination.chmod(0o644)
        added[destination.relative_to(output).as_posix()] = base.digest(destination)
    if host_reports:
        popup = dict(kind='cosmic-panel-popup-input-v1', source_policy_sha256=base.digest(objects.POPUP_POLICY))
        require(host_reports['panel'][1].get('popup_input') == popup, 'Reviewed popup input host required')
        bus = output / objects.BUS
        require(base.digest(bus) == 'df221c94857a9d18738818d67b28446fab11614236f979e7acf60ae971ec9ebb',
                'Preserving the reviewed original session bus configuration')
        replaced[objects.BUS] = dict(before=base.digest(bus), after=base.digest(objects.BUS_SOURCE),
                                    scope='bounded session bus connection profile')
        shutil.copyfile(objects.BUS_SOURCE, bus); bus.chmod(0o644)
        contract = dict(profile='cosmic-applets-objects-v1', fds_per_process=128,
            open_descriptions=512, unix_endpoints=128, unix_connections=64, shared_objects=32, shared_mappings_per_process=32,
            session_bus_connections=32, session_bus_sha256=base.digest(bus),
            panel_popup_input='cosmic-panel-popup-input-v1',
            panel_popup_source_policy_sha256=base.digest(objects.POPUP_POLICY),
            host_source_policy_sha256=base.digest(hosts.hosts.PORT / 'source-policy.json'),
            hosts={hosts.hosts.NAMES[kind] + '.elf': row['after'] for kind, row in
                   ((kind, replaced[hosts.hosts.NAMES[kind] + '.elf']) for kind in host_reports)})
        path = output / 'rootfs/usr/share/cyxia/cosmic-applets-v1.json'
        require(not path.exists(), 'Preserving existing object contract')
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(contract, sort_keys=True, indent=2) + '\n')
        added[path.relative_to(output).as_posix()] = base.digest(path)
    index = output / 'rootfs/usr/share/icons/hicolor/index.theme'
    require(not index.exists(), 'Preserving an existing icon theme index')
    index.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(applets.PORT / 'hicolor-index.theme', index); index.chmod(0o644)
    added[index.relative_to(output).as_posix()] = base.digest(index)
    current = os_x86.catalog_inputs(output)
    require(current == {**manifest['external_inputs'], **added, **{name: row['after'] for name, row in replaced.items()}},
            'Unrelated catalog input changed')
    total = sum((output / name).stat().st_size for name in current)
    require(total <= MAX_BYTES and len(current) <= MAX_ENTRIES, 'Workspace applet ROM catalog budget')
    require(os_x86.catalog_inputs(original) == manifest['external_inputs'], 'Parent catalog mutated')
    receipt = dict(status='WORKSPACE_APPLETS_INSTALLED_NOT_RUN', kind=applets.KIND,
        build=str(build), build_report_sha256=base.digest(build / 'build-report.json'),
        base_build=str(base_build), base_manifest_sha256=base.digest(base_build / 'build-manifest.json'),
        upstream_commit=applets.parent.COMMIT, files=current, original_inputs=manifest['external_inputs'],
        added=added, raw_catalog_bytes=total, max_catalog_bytes=MAX_BYTES,
        replaced=replaced,
        producers=os_x86.producer_sources(__file__), full_os_verified=False, cosmic_session_verified=False,
        guest_execution=False)
    if probe_report is not None:
        receipt['workspace_observer'] = dict(build=str(probe),
            receipt_sha256=base.digest(Path(probe) / 'workspace-probe-origin.json'))
    if repaired is not None:
        receipt['applet_mesa_relink'] = dict(build=str(applet_relink), receipt_sha256=base.digest(Path(applet_relink) / 'relink-report.json'))
    (output / 'cosmic-workspace-applets-origin.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def assemble(build, base_build, output, probe=None, host_builds=(), applet_relink=None):
    output = base.no_symlink_path(output)
    require(not output.exists(), 'Preserving existing catalog output')
    with tempfile.TemporaryDirectory(prefix='.cosmic-workspace-applets-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'catalog'
        receipt = _assemble(build, base_build, stage, probe, host_builds, applet_relink)
        require(not output.exists(), 'Catalog output appeared during assembly')
        stage.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workspace-probe', type=Path)
    parser.add_argument('--host-build', type=Path, action='append', required=True)
    parser.add_argument('--applet-relink', type=Path)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = assemble(args.build, args.base_build, args.output, args.workspace_probe, args.host_build, args.applet_relink)
    print(json.dumps({key: result[key] for key in ('status', 'raw_catalog_bytes', 'added')}, indent=2))


if __name__ == '__main__':
    main()
