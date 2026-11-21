#!/usr/bin/env python3
"""Build the pinned COSMIC application library for the native Wayland session."""
import argparse
import fcntl
import json
from pathlib import Path
import shutil

import build_cosmic as base
from build_cosmic_bg_v1 import prepare_wayland
from build_cosmic_comp_linux import metadata_identity
import cosmic_applet_hosts_v1 as applet_hosts
from cosmic_notifications_elf import inspect_full_os_elf
import cosmic_notifications_static_v1 as static_source
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

APP = 'cosmic-app-library'
APP_ID = 'com.system76.CosmicAppLibrary'
PORT = base.ROOT / 'ports/cosmic/native-app-library-v1'
RECIPE = PORT / 'native-recipe.json'
XKB_PORT = PORT.parent / 'native-time-applet-v2'
GENERATED = (APP_ID + '.desktop', APP_ID + '.metainfo.xml')


def prepare_native(stage, cache):
    wayland = prepare_wayland(stage, cache)
    xkb_policy = base.load_json(XKB_PORT / 'source-policy.json')['xkb_registry_input']
    xkb_path = XKB_PORT / 'xkbcommon-dl'
    xkb = static_source.read_tree(xkb_path)
    if xkb['sha256'] != xkb_policy['after_tree_sha256']:
        raise base.CosmicBuildError('Static XKB binding differs from the reviewed source')
    shutil.copytree(xkb_path, stage / xkb_policy['destination'])

    # Use the session adapter with the desktop profile's 128-FD limit.
    support = stage.parent / 'session-support'
    _, tree = applet_hosts.export('session', support)
    launch = Path('native-deps/launch-pad')
    (support / launch).rename(stage / launch)
    return dict(wayland=wayland, xkb_sha256=xkb['sha256'], session_support_sha256=tree['sha256'])


def verify_launch_adapter(report):
    reviewed, _ = applet_hosts.contract('session')
    if report['native_source']['session_support_sha256'] != reviewed['after_tree_sha256']:
        raise base.CosmicBuildError('Expected the desktop profile\'s 128-FD native launch adapter')


def verify_resolution(metadata):
    packages = {row['id']: row for row in metadata['packages']}
    nodes = {packages[row['id']]['name']: row for row in metadata['resolve']['nodes']}
    for name, required in (
        (APP, 'cyxia-native'), ('wayland-sys', 'cyxia-static-client'),
        ('xkbcommon-dl', 'static-wayland'), ('launch-pad', 'cyxia-native'),
    ):
        node = nodes.get(name)
        if node is None or packages[node['id']]['source'] is not None or required not in node['features']:
            raise base.CosmicBuildError('Missing native application library dependency ' + name)
    if 'wgpu' in nodes[APP]['features'] or 'wgpu' in nodes['libcosmic']['features']:
        raise base.CosmicBuildError('Expected the Wayland software renderer')


def resource_profile(recipe):
    return base.select_profile(base.load_json(PORT / 'resource-profile.json'),
                               recipe['resource_profile'], 2, base.ports.user_target(recipe['target']))


def publish_desktop_assets(output, target):
    release = output / 'target' / target / 'release'
    artifacts = list((release / 'build').glob(APP + '-*/out/' + GENERATED[0]))
    if len(artifacts) != 1:
        raise base.CosmicBuildError('Expected one package of localized desktop data')
    bindings = {}
    for name in GENERATED:
        published = output / name
        shutil.copyfile(artifacts[0].with_name(name), published)
        bindings[name] = base.digest(published)
    return bindings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, default=base.ROOT / 'artifacts/v017-cosmic-input-sdk-v3')
    parser.add_argument('--cargo-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-comp-cache')
    args = parser.parse_args()
    source, record, recipe = base.source_and_recipe(APP, RECIPE, base.ports.load_manifest(), base.ports.CACHE)
    profile = resource_profile(recipe)
    output = base.no_symlink_path(args.output)
    sdk = base.no_symlink_path(args.sysroot)
    cache = base.validate_cache(args.cargo_cache)
    with native_lease(DEFAULT_NATIVE_LOCK), (cache / '.cyxia-build.lock').open('a') as lock:
        idle_native_host()
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = base.perform_build(source, record, recipe, RECIPE, output, sdk, cache, profile, 2,
                                    prepare_source=prepare_native, inspect_dependencies=metadata_identity,
                                    bundle_static_archives=True,
                                    inspect_image=lambda path: inspect_full_os_elf(path, profile)['executable'])
        verify_launch_adapter(report)
        verify_resolution(base.load_json(output / 'metadata.json'))
        report['desktop_assets'] = publish_desktop_assets(output, recipe['target'])
        (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'output': str(output)}))


if __name__ == '__main__':
    main()
