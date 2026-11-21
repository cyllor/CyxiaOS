#!/usr/bin/env python3
"""Stage the native COSMIC application library on the wallpaper catalog."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import build_cosmic as base
import build_cosmic_app_library_v1 as application
import build_workspace_state_probe as workspace_probe
import cosmic_applet_object_profile_v1 as objects
from cosmic_notifications_elf import inspect_full_os_elf
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

APP = application.APP
APP_ID = application.APP_ID
FIXTURE = base.ROOT / 'user/ported/app_library_fixture.c'


def strip_catalog_image(image, destination, inspection, profile, toolchain):
    rust_root = Path(toolchain['tools']['rustc']['path']).parent.parent
    tools = list(rust_root.glob('lib/rustlib/*/bin/llvm-strip'))
    require = os_x86.pc.require
    require(len(tools) == 1, 'Install the pinned Rust toolchain llvm-tools component')
    strip = base.no_symlink_path(tools[0])
    digest = base.digest(strip)
    subprocess.run([str(strip), '--strip-all', '-o', str(destination), str(image)],
                   check=True, timeout=30)
    packed = inspect_full_os_elf(destination, profile)['executable']
    headers = inspection['program_headers']
    require(base.digest(strip) == digest and packed['program_headers'] == headers
            and packed['entry'] == inspection['entry'] and packed['bytes'] < inspection['bytes'],
            'Symbol stripping changed the program headers or entry point')

    def loaded_bytes(path):
        raw = bytearray(path.read_bytes())
        # Strip is allowed to update section-table metadata in the ELF header.
        raw[40:48] = bytes(8)
        raw[58:64] = bytes(6)
        return tuple(raw[p['offset']:p['offset'] + p['filesz']] for p in headers if p['type'] == 1)

    require(loaded_bytes(destination) == loaded_bytes(image), 'Symbol stripping changed the loaded program')
    return dict(tool=str(strip), tool_sha256=digest, original=inspection, packed=packed)


def assemble(build, base_build, output, *, with_test_fixtures=False):
    require = os_x86.pc.require
    build, base_build, output = map(base.no_symlink_path, (build, base_build, output))
    source, origin, recipe = base.source_and_recipe(
        APP, application.RECIPE, base.ports.load_manifest(), base.ports.CACHE)
    target = base.ports.user_target(recipe['target'])
    profile = application.resource_profile(recipe)
    report_path = build / 'build-report.json'
    report = base.load_json(report_path)
    image = build / (APP + '.elf')
    inspection = inspect_full_os_elf(image, profile)['executable']
    require(report['status'] == 'cross-built' and report['target_linked'] and report['source_preserved']
            and report['component'] == source and report['recipe'] == recipe
            and report['recipe_sha256'] == base.digest(application.RECIPE)
            and report['linked_binary']['sha256'] == base.digest(image)
            and report['executable'] == inspection,
            'Expected the pinned native application library')
    application.verify_launch_adapter(report)
    application.verify_resolution(base.load_json(build / 'metadata.json'))
    require(report['desktop_assets'] == {name: base.digest(build / name) for name in application.GENERATED},
            'Generated COSMIC desktop data changed')

    base_manifest = base_build / 'build-manifest.json'
    previous = base.load_json(base_manifest)
    prefix = base.no_symlink_path(previous['sysroot'])
    original = os_x86.catalog_inputs(prefix)
    require(previous['status'] == 'BUILT_NOT_RUN' and previous['ram_mib'] == 1024
            and previous['cpus'] == 4 and 'cosmic-bg-v1' in previous['features']
            and previous['external_inputs'] == original and 'cosmic-bg.elf' in original,
            'Expected the bound one-GiB wallpaper catalog')
    objects.validate(prefix, original, notifications=True)
    require(not output.exists() and all(not output.is_relative_to(path) and not path.is_relative_to(output)
            for path in (build, base_build, prefix)), 'Use a fresh catalog outside the source inputs')

    upstream = Path(origin['path'])
    inputs = {
        f'rootfs/usr/share/applications/{APP_ID}.desktop': build / (APP_ID + '.desktop'),
        f'rootfs/usr/share/metainfo/{APP_ID}.metainfo.xml': build / (APP_ID + '.metainfo.xml'),
        f'rootfs/usr/share/icons/hicolor/scalable/apps/{APP_ID}.svg': upstream / f'data/icons/{APP_ID}.svg',
        f'rootfs/usr/share/doc/{APP}/LICENSE.md': upstream / 'LICENSE.md',
    }
    fixture_name = 'app-library-fixture.elf'
    added_files = {*inputs, image.name}
    if with_test_fixtures:
        added_files.add(fixture_name)
        require({'workspace-window-probe.elf', 'env-probe.elf'} <= original.keys(),
                'Missing the installed Wayland window and environment fixtures')
    require(not original.keys() & added_files, 'Application library files already present')
    with tempfile.TemporaryDirectory(prefix='.cosmic-app-library-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'catalog'
        subprocess.run(['/bin/cp', '-cRp', str(prefix), str(stage)], check=True)
        for relative, path in inputs.items():
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            destination.chmod(0o644)
        packing = strip_catalog_image(image, stage / image.name, inspection, profile, report['toolchain'])
        (stage / image.name).chmod(0o755)
        fixture = None
        updated_test_images = {}
        if with_test_fixtures:
            compiler = report['toolchain']['tools']['target_cc']
            require(base.digest(Path(compiler['path'])) == compiler['sha256'], 'Target compiler changed')
            command = [compiler['path'], '-O2', '-Wall', '-Wextra', '-Werror',
                       str(FIXTURE), '-o', str(stage / fixture_name)]
            checksum = base.digest(FIXTURE)
            subprocess.run(command, env=base.clean_environment('/usr/bin:/bin:/opt/homebrew/bin'),
                           check=True, timeout=60)
            require(base.digest(FIXTURE) == checksum, 'Fixture source changed during the link')
            fixture = dict(source_sha256=checksum, image=base.inspect_elf(stage / fixture_name, target))
            window_build = Path(temporary) / 'workspace-probe'
            window = workspace_probe.build(window_build, Path(compiler['path']).parent.parent)
            window_name = 'workspace-window-probe.elf'
            shutil.copy2(window_build / window_name, stage / window_name)
            updated_test_images[window_name] = window['evidence'][window_name]
            fixture['window'] = dict(image=window['window_image_admission'], inputs=window['inputs'])
        added = {name: base.digest(stage / name) for name in sorted(added_files)}
        complete = os_x86.catalog_inputs(stage)
        require(complete == {**original, **added, **updated_test_images}
                and os_x86.catalog_inputs(prefix) == original,
                'Unrelated catalog input changed')
        receipt = dict(status='COSMIC_APP_LIBRARY_INSTALLED_NOT_RUN', upstream=source,
                       base_manifest_sha256=base.digest(base_manifest), build_report_sha256=base.digest(report_path),
                       files=complete, added=added, updated_test_images=updated_test_images,
                       packing=packing, fixture=fixture)
        (stage / 'cosmic-app-library-origin.json').write_text(json.dumps(receipt, indent=2) + '\n')
        stage.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'base-build', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--with-test-fixtures', action='store_true')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        receipt = assemble(args.build, args.base_build, args.output, with_test_fixtures=args.with_test_fixtures)
    print(receipt['status'])


if __name__ == '__main__':
    main()
