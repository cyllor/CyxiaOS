#!/usr/bin/env python3
"""Build the pinned background program with CyxiaOS's static Wayland binding."""
import argparse
import fcntl
import json
from pathlib import Path

import build_cosmic as base
import build_cosmic_bg_sdk_v1 as decoder
import cosmic_notifications_static_v1 as static_wayland
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

PORT = decoder.PORT
WAYLAND_PORT = PORT.parent / 'native-notifications-static-v2'
RECIPE = PORT / 'native-recipe.json'
PATCH = 'wayland-sys-0.31.11-static-client.patch'


def prepare_wayland(stage, cache):
    policy = base.load_json(WAYLAND_PORT / 'source-policy.json')
    entry = next(row for row in policy['registry_inputs'] if row['name'] == 'wayland-sys')
    original, modes, receipt = static_wayland.registry_snapshot(cache, entry)
    directory = stage / entry['destination']
    for relative, data in original.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(modes[relative])
    patch = next(row for row in policy['patches'] if row['path'] == PATCH)
    patches = base.apply_patches({'patches': [patch]}, stage, WAYLAND_PORT)
    binding = static_wayland.read_tree(directory)
    if binding['sha256'] != entry['after_tree_sha256']:
        raise base.CosmicBuildError('Static Wayland binding differs from the reviewed source')
    return dict(registry=receipt, patches=patches, tree_sha256=binding['sha256'])


def verify_resolution(metadata):
    packages = {row['id']: row for row in metadata['packages']}
    for package, required in (
        ('cosmic-bg', {'default', 'avif', 'cyxia-native'}),
        ('wayland-sys', {'cyxia-static-client'}),
    ):
        matches = [row for row in metadata['resolve']['nodes'] if packages[row['id']]['name'] == package]
        if len(matches) != 1 or not required <= set(matches[0]['features']):
            raise base.CosmicBuildError('Missing reviewed background build features for ' + package)
        if packages[matches[0]['id']]['source'] is not None:
            raise base.CosmicBuildError('Expected the local effective source of ' + package)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--cargo-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-comp-cache')
    args = parser.parse_args()
    source, record, recipe = base.source_and_recipe(
        'cosmic-bg', RECIPE, base.ports.load_manifest(), base.ports.CACHE)
    profile = base.select_profile(base.load_json(PORT / 'resource-profile.json'),
                                  recipe['resource_profile'], 2, base.ports.user_target(recipe['target']))
    sdk = base.no_symlink_path(args.sysroot)
    cache = base.validate_cache(args.cargo_cache)
    output = base.no_symlink_path(args.output)
    with native_lease(DEFAULT_NATIVE_LOCK), (cache / '.cyxia-build.lock').open('a') as lock:
        idle_native_host()
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = base.perform_build(source, record, recipe, RECIPE, output, sdk, cache, profile, 2,
                                    prepare_source=prepare_wayland)
        verify_resolution(base.load_json(output / 'metadata.json'))
    print(json.dumps({'status': report['status'], 'output': str(output)}))


if __name__ == '__main__':
    main()
