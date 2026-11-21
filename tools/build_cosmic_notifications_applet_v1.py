#!/usr/bin/env python3
"""Build and install the genuine Epoch COSMIC notification center offline."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import assemble_cosmic_workspace_applets_v1 as workspace_catalog
import build_notification_probe as notification_sample
import build_cosmic_time_applet_v2 as driver
import cosmic_workspace_applets_v1 as workspace
import cosmic_applet_object_profile_v1 as objects
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, parent, require = workspace.base, workspace.parent, workspace.require
KIND = objects.NOTIFICATIONS_FEATURE
PORT = base.ROOT / 'ports/cosmic/native-notifications-applet-v1'
PROGRAM = 'cosmic-applet-notifications'
PROGRAMS = (PROGRAM,)
DESKTOP = 'com.system76.CosmicAppletNotifications'
ASSETS = {
    'LICENSE': f'usr/share/doc/{PROGRAM}/LICENSE',
    f'{PROGRAM}/data/{DESKTOP}.desktop': f'usr/share/applications/{DESKTOP}.desktop',
    f'{PROGRAM}/data/icons/scalable/apps/{DESKTOP}-symbolic.svg':
        f'usr/share/icons/hicolor/scalable/apps/{DESKTOP}-symbolic.svg',
}
for suffix in ('', '-disabled', '-new'):
    icon_path = f'scalable/status/cosmic-applet-notification{suffix}-symbolic.svg'
    ASSETS[f'{PROGRAM}/data/icons/{icon_path}'] = f'usr/share/icons/hicolor/{icon_path}'
CLOSE_ICON_ASSETS = {
    'cosmic-icons/freedesktop/scalable/actions/window-close-symbolic.svg':
        'usr/share/icons/hicolor/scalable/actions/window-close-symbolic.svg',
    'cosmic-icons/COPYING': 'usr/share/doc/cosmic-icons/COPYING',
    'cosmic-icons/LICENSE': 'usr/share/doc/cosmic-icons/LICENSE',
}

additional_link_inputs = workspace.additional_link_inputs


def contract():
    policy = base.load_json(PORT / 'source-policy.json')
    workspace_policy, workspace_recipe, component, profile, parent_policy = workspace.contract()
    require(policy['kind'] == KIND and policy['commit'] == parent.COMMIT
            and policy['parent_policy_sha256'] == base.digest(workspace.PORT / 'source-policy.json')
            and policy['patch_sha256'] == base.digest(PORT / 'native.patch')
            and set(policy['before']) == set(policy['after']) == {'Cargo.lock', f'{PROGRAM}/Cargo.toml'}
            and policy['before']['Cargo.lock'] == workspace_policy['after']['Cargo.lock'],
            'Notification applet source contract changed')
    features = [PROGRAM + '/cyxia-native']
    recipe = dict(workspace_recipe, package=PROGRAM, binary=PROGRAM, binaries=list(PROGRAMS),
                  features=features, metadata_features=[*parent.FEATURES, *features],
                  source_lock_sha256=policy['before']['Cargo.lock'],
                  effective_lock_sha256=policy['after']['Cargo.lock'],
                  patches=[{'path': 'native.patch', 'sha256': policy['patch_sha256']}])
    profile = dict(profile, purpose='Genuine Epoch notification center on the one-GiB workspace applet profile.')
    return policy, recipe, component, profile, parent_policy


def original_inputs(source_cache, native_cache, cargo_cache):
    inputs = workspace.original_inputs(source_cache, native_cache, cargo_cache)
    inputs['notifications_applet_patch'] = {
        str(PORT / name): base.digest(PORT / name) for name in ('source-policy.json', 'native.patch')
    }
    return inputs


def verify_export(stage, inputs):
    policy = contract()[0]
    return workspace.verify_export(stage, inputs, overlay=policy['after'])


def export(source_cache, native_cache, cargo_cache, stage):
    original, tree = workspace.export(source_cache, native_cache, cargo_cache, stage)
    policy = contract()[0]
    require(all(tree['files'][name]['sha256'] == digest for name, digest in policy['before'].items()),
            'Notification applet patch preimage changed')
    subprocess.run(['/usr/bin/git', 'apply', str(PORT / 'native.patch')], cwd=stage,
                   check=True, capture_output=True, env=base.clean_environment('/usr/bin:/bin'))
    inputs = original_inputs(source_cache, native_cache, cargo_cache)
    require(all(inputs[name] == value for name, value in original.items()), 'Workspace applet inputs changed')
    return inputs, verify_export(stage, inputs)


def metadata_identity(metadata, stage, cache, recipe, policy):
    return workspace.metadata_identity(metadata, stage, cache, recipe, policy, programs=PROGRAMS)


def commands(cargo, stage, recipe, jobs, programs=None):
    return workspace.commands(cargo, stage, recipe, jobs, programs, names=PROGRAMS)


def assemble(build, base_build, output, probe_build=None):
    build, base_build, output = map(base.no_symlink_path, (build, base_build, output))
    report = workspace_catalog.validate(build, contract_module=sys.modules[__name__])
    manifest = base.load_json(base_build / 'build-manifest.json')
    prefix = base.no_symlink_path(manifest['sysroot'])
    original = os_x86.catalog_inputs(prefix)
    require(manifest['status'] == 'BUILT_NOT_RUN' and manifest['ram_mib'] == 1024
            and manifest['cpus'] == 4 and 'cosmic-workspace-applets-v1' in manifest['features']
            and manifest['external_inputs'] == original, 'Expected a bound one-GiB workspace applet catalog')
    object_contract = objects.validate(prefix, original)
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
            for p in (build, base_build, prefix)), 'Preserving existing catalog inputs and outputs')
    files = {PROGRAM + '.elf': build / (PROGRAM + '.elf'),
             **{'rootfs/' + target: build / 'source' / src for src, target in ASSETS.items()}}
    libcosmic = next(row for row in report['cargo_dependencies']['dependencies']['packages']
                     if row['name'] == 'libcosmic')['git_checkout']
    for relative, target in CLOSE_ICON_ASSETS.items():
        source = base.no_symlink_path(Path(libcosmic['path']) / relative)
        require(base.digest(source) == libcosmic['files'][relative]['sha256'], 'COSMIC close icon input changed')
        files['rootfs/' + target] = source
    if probe_build is not None:
        probe_build = base.no_symlink_path(probe_build)
        sample = base.load_json(probe_build / notification_sample.RECEIPT)
        probe = base.no_symlink_path(probe_build / notification_sample.EXECUTABLE)
        require(sample['status'] == 'BUILT_NOT_RUN' and sample['architecture'] == 'x86_64'
                and sample['panel_clear'] is True and sample['capture_window_ms'] == 0
                and sample['producer_inputs'] == notification_sample.producer_identity()
                and sample['probe']['sha256'] == base.digest(probe),
                'Expected the real D-Bus probe built in panel clear mode')
        files[notification_sample.EXECUTABLE] = probe
    require(not original.keys() & files.keys(), 'Notification applet files already installed')
    icon_index = 'rootfs/usr/share/icons/hicolor/index.theme'
    theme = (prefix / icon_index).read_text()
    require(theme == (workspace.PORT / 'hicolor-index.theme').read_text(), 'Unexpected icon theme index')
    extended_theme = theme.replace('Directories=scalable/apps\n',
                                   'Directories=scalable/apps,scalable/actions,scalable/status\n')
    extended_theme += '\n[scalable/actions]\nSize=48\nMinSize=8\nMaxSize=512\nType=Scalable\nContext=Actions\n'
    extended_theme += '\n[scalable/status]\nSize=48\nMinSize=8\nMaxSize=512\nType=Scalable\nContext=Status\n'
    with tempfile.TemporaryDirectory(prefix='.cosmic-notifications-applet-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'catalog'
        subprocess.run(['/bin/cp', '-cRp', str(prefix), str(stage)], check=True)
        for relative, source in files.items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755 if relative.endswith('.elf') else 0o644)
        (stage / icon_index).write_text(extended_theme)
        object_contract.update(objects.NOTIFICATIONS_FIELDS)
        (stage / objects.CONTRACT).write_text(json.dumps(object_contract, sort_keys=True, indent=2) + '\n')
        added = {name: base.digest(path) for name, path in files.items()}
        replacements = {name: base.digest(stage / name) for name in (icon_index, objects.CONTRACT)}
        current = os_x86.catalog_inputs(stage)
        require(current == {**original, **added, **replacements}
                and os_x86.catalog_inputs(prefix) == original, 'Unrelated catalog input changed')
        require(len(current) <= workspace_catalog.MAX_ENTRIES, 'Notification applet catalog entry budget')
        objects.validate(stage, current, notifications=True)
        receipt = dict(kind=KIND, status='NOTIFICATIONS_APPLET_INSTALLED_NOT_RUN',
                       upstream_commit=report['component']['commit'],
                       build_report_sha256=base.digest(build / 'build-report.json'),
                       base_manifest_sha256=base.digest(base_build / 'build-manifest.json'),
                       producers=os_x86.producer_sources(__file__), files=current, added=added,
                       replaced={name: dict(before=original[name], after=digest)
                                 for name, digest in replacements.items()})
        (stage / 'cosmic-notifications-applet-origin.json').write_text(json.dumps(receipt, indent=2) + '\n')
        stage.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest='command', required=True)
    build = subcommands.add_parser('build')
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--sysroot', type=Path, required=True)
    build.add_argument('--cache-from', type=Path)
    build.add_argument('--rust-root', type=Path,
                       default=Path.home() / '.rustup/toolchains/stable-aarch64-apple-darwin')
    install = subcommands.add_parser('assemble')
    for name in ('--build', '--base-build', '--output'):
        install.add_argument(name, type=Path, required=True)
    install.add_argument('--probe-build', type=Path)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        if args.command == 'build':
            artifacts = base.ROOT / 'artifacts'
            report = driver.build(args.output, args.sysroot, artifacts / 'cosmic-sources',
                artifacts / 'cosmic-native-sources', artifacts / 'cosmic-comp-cache',
                args.rust_root, Path('/usr/bin/clang'), args.cache_from,
                contract_module=sys.modules[__name__], programs=PROGRAMS, producer_entry=__file__)
        else:
            report = assemble(args.build, args.base_build, args.output, args.probe_build)
    print(json.dumps({'status': report['status'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
