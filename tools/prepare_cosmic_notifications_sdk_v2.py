#!/usr/bin/env python3
"""Bind the unchanged static notification port to independently built SDK inputs.

Run core and X.Org build_sysroot plus build_xkbcommon_x11_target first. This
assembler adds real retained Wayland/FFI and verified XKB outputs to that fresh
SDK, then writes a separate recipe. It never modifies the parent SDK or v1 port.
"""
import argparse
import json
from pathlib import Path
import shutil

import build_cosmic as base
import cosmic_notifications_static_v1 as static
import build_xkbcommon_x11_target as xkb
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from target_profile import profile_for

ROOT = base.ROOT


def assemble(parent, sdk, xkb_output, port):
    parent, sdk, xkb_output, port = map(base.no_symlink_path, (parent, sdk, xkb_output, port))
    base.no_symlink_path(sdk / 'runtime-sdk-origin.json')
    static.require(not port.exists() and not (sdk / 'runtime-sdk-origin.json').exists(),
                   'Preserving existing notification SDK origin/recipe')
    for other in (sdk, xkb_output, port):
        static.require(not other.is_relative_to(parent) and not parent.is_relative_to(other),
                       'New notification inputs overlap the preserved parent SDK')
    static.require(not port.is_relative_to(sdk) and not sdk.is_relative_to(port),
                   'Recipe overlaps its SDK')
    core = base.load_json(sdk / 'build-report.json')
    xorg = base.load_json(sdk / 'xorg-bootstrap-report.json')
    target = profile_for('x86_64')
    target.require_report(core)
    target.require_report(xorg)
    static.require(core['status'] == 'cross-built', 'Core SDK was not built')
    xkb_report = xkb.validate_build(xkb_output)
    static.require(xkb_report['inputs']['path'] == str(sdk)
                   and xkb.sdk_identity(sdk, target) == xkb_report['inputs'],
                   'XKB build no longer binds this unmodified SDK')
    parent_inputs = os_x86.catalog_inputs(parent)
    parent_tree = base.tree_identity(parent / 'sysroot')
    old_origin = base.load_json(parent / 'runtime-sdk-origin.json')
    old_recipe = base.load_json(ROOT / 'ports/cosmic/native-settings-linux-v4/native-recipe.json')
    static.require(base.digest(parent / 'runtime-sdk-origin.json')
                   == old_recipe['native_sdk_origin']['sha256'], 'Parent SDK origin changed')
    old_files = old_origin['new_inputs']['trees']['sysroot']['files']
    copied = {}

    def copy(source, destination):
        source, destination = map(base.no_symlink_path, (source, destination))
        data = static.read_regular(source)
        if destination.exists():
            static.require(static.read_regular(destination) == data,
                           'Refusing to replace a different SDK input: ' + str(destination))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as stream:
                stream.write(data)
            destination.chmod(source.stat().st_mode & 0o777)
        copied[str(destination.relative_to(sdk))] = {
            'source': str(source), 'bytes': len(data), 'sha256': static.sha(data)}

    # Real libraries and their headers/metadata; all are bound by the original
    # runtime SDK receipt. No compiler wrappers are copied across prefixes.
    relatives = ['usr/lib/libwayland-client.a', 'usr/lib/libffi.a',
                 'usr/lib/pkgconfig/wayland-client.pc', 'usr/lib/pkgconfig/libffi.pc']
    for path in (parent / 'sysroot/usr/include').iterdir():
        if path.is_file() and (path.name.startswith('wayland-') or path.name in ('ffi.h', 'ffitarget.h')):
            relatives.append(str(path.relative_to(parent / 'sysroot')))
    for relative in relatives:
        source = parent / 'sysroot' / relative
        static.require(base.digest(source) == old_files[relative]['sha256'],
                       'Retained Wayland/FFI input differs from its SDK origin')
        copy(source, sdk / 'sysroot' / relative)
    for path in sorted((xkb_output / 'sdk').rglob('*')):
        if path.is_file():
            copy(path, sdk / 'sysroot' / path.relative_to(xkb_output / 'sdk'))
    for path in sorted((parent / 'licenses').rglob('*')):
        if path.is_file():
            copy(path, sdk / 'licenses/parent' / path.relative_to(parent / 'licenses'))
    for path in sorted((xkb_output / 'licenses').rglob('*')):
        if path.is_file():
            copy(path, sdk / 'licenses/xkb-x11' / path.relative_to(xkb_output / 'licenses'))

    recipe = base.load_json(static.PORT / 'native-recipe.json')
    for row in recipe['native_inputs']:
        path = sdk / row['path']
        if path.suffix == '.a':
            target.inspect_archive(path)
        row['sha256'] = base.digest(path)
    static.require(os_x86.catalog_inputs(parent) == parent_inputs
                   and base.tree_identity(parent / 'sysroot') == parent_tree,
                   'Parent SDK/catalog changed during assembly')
    origin = dict(schema_version=1, status='NOTIFICATION_SDK_ASSEMBLED_NOT_RUN',
                  architecture='x86_64', guest_execution=False, parent_preserved=True,
                  parent_sdk=str(parent), parent_origin_sha256=base.digest(parent / 'runtime-sdk-origin.json'),
                  reports={str(path): base.digest(path) for path in (
                      sdk / 'build-report.json', sdk / 'xorg-bootstrap-report.json',
                      xkb_output / 'build-report.json')}, copied_inputs=copied,
                  native_inputs=recipe['native_inputs'], sysroot_tree=base.tree_identity(sdk / 'sysroot'),
                  producer_sources=os_x86.producer_sources(__file__))
    origin_path = sdk / 'runtime-sdk-origin.json'
    origin_path.write_text(json.dumps(origin, indent=2) + '\n')
    recipe['native_sdk_origin']['sha256'] = base.digest(origin_path)
    policy = static.load_policy()
    source = next(row for row in base.ports.load_manifest()['components']
                  if row['name'] == 'cosmic-notifications')
    static.validate_recipe(recipe, source, policy)
    port.mkdir(parents=True)
    for path in static.support_sources(static.PORT / 'source-policy.json', policy):
        shutil.copyfile(path, port / Path(path).name)
    shutil.copyfile(static.PORT / 'resource-profile.json', port / 'resource-profile.json')
    (port / 'native-recipe.json').write_text(json.dumps(recipe, indent=2) + '\n')
    return {'status': origin['status'], 'recipe': str(port / 'native-recipe.json'),
            'native_sdk_origin_sha256': recipe['native_sdk_origin']['sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--xkb-output', type=Path, required=True)
    parser.add_argument('--port', type=Path, default=ROOT / 'ports/cosmic/native-notifications-static-v2')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = assemble(args.parent, args.sdk, args.xkb_output, args.port)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
