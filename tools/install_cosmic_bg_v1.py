#!/usr/bin/env python3
"""Install the genuine COSMIC wallpaper program in an existing 1 GiB catalog."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import build_cosmic as base
import build_cosmic_bg_v1 as background
import build_cosmic_bg_sdk_v1 as decoder
import cosmic_applet_object_profile_v1 as objects
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

PORT = decoder.PORT
APP = 'cosmic-bg'
CONFIG = 'rootfs/usr/share/cosmic/com.system76.CosmicBackground/v1/all'


def require(condition, message):
    if not condition:
        raise base.CosmicBuildError(message)


def assemble(build, base_build, artwork, output):
    build, base_build, artwork, output = map(base.no_symlink_path, (build, base_build, artwork, output))
    recipe_path = PORT / 'native-recipe.json'
    source, origin, recipe = base.source_and_recipe(
        APP, recipe_path, base.ports.load_manifest(), base.ports.CACHE)
    report_path = build / 'build-report.json'
    report = base.load_json(report_path)
    image = build / (APP + '.elf')
    target = base.ports.user_target(recipe['target'])
    require(report['status'] == 'cross-built' and report['target_linked'] and report['source_preserved']
            and report['component'] == source and report['recipe'] == recipe
            and report['recipe_sha256'] == base.digest(recipe_path)
            and report['executable'] == base.inspect_elf(image, target)
            and report['linked_binary']['sha256'] == base.digest(image)
            and '--no-default-features' not in report['command'],
            'Expected the complete pinned COSMIC background binary')
    background.verify_resolution(base.load_json(build / 'metadata.json'))
    wayland_policy = base.load_json(background.WAYLAND_PORT / 'source-policy.json')
    wayland = next(row for row in wayland_policy['registry_inputs'] if row['name'] == 'wayland-sys')
    wayland_license = Path(report['native_source']['registry']['source']) / 'LICENSE.txt'
    require(report['native_source']['tree_sha256'] == wayland['after_tree_sha256']
            and base.digest(wayland_license) == wayland['files']['LICENSE.txt']['sha256'],
            'Static Wayland source or license differs from the reviewed policy')
    sdk = Path(report['toolchain']['tools']['target_cc']['path']).parents[1]
    native = base.load_json(sdk / decoder.RECEIPT)
    require(native['status'] == 'DAV1D_SDK_BUILT'
            and native['source']['commit'] == base.load_json(decoder.DECODER)['commit']
            and all(base.digest(sdk / name) == native['files'][name]
                    for name in (decoder.ARCHIVE, decoder.PKG_CONFIG, decoder.LICENSE)),
            'AVIF decoder inputs differ from the native SDK receipt')

    manifest_path = base_build / 'build-manifest.json'
    manifest = base.load_json(manifest_path)
    prefix = base.no_symlink_path(manifest['sysroot'])
    original = os_x86.catalog_inputs(prefix)
    require(manifest['status'] == 'BUILT_NOT_RUN' and manifest['ram_mib'] == 1024
            and manifest['cpus'] == 4 and objects.NOTIFICATIONS_FEATURE in manifest['features']
            and manifest['external_inputs'] == original, 'Expected the bound notifications catalog')
    objects.validate(prefix, original, notifications=True)
    require(not output.exists() and all(not output.is_relative_to(path) and not path.is_relative_to(output)
            for path in (build, base_build, prefix, artwork, sdk)),
            'Preserving existing inputs and outputs')

    pin = base.load_json(PORT / 'wallpaper.json')
    photo, notes = artwork / pin['file'], artwork / 'README.md'
    require(base.digest(photo) == pin['sha256'] and base.digest(notes) == pin['source_notes_sha256'],
            'The upstream wallpaper bytes or source notes changed')
    source_path = Path(origin['path'])
    inputs = {
        image.name: image,
        CONFIG: source_path / 'data/v1/all',
        'rootfs/usr/share/doc/cosmic-bg/LICENSE.md': source_path / 'LICENSE.md',
        'rootfs/usr/share/doc/cosmic-bg/wayland-sys-LICENSE.txt': wayland_license,
        'rootfs/usr/share/doc/dav1d/COPYING': sdk / decoder.LICENSE,
        'rootfs/usr/share/doc/cosmic-wallpapers/README.md': notes,
        'rootfs/usr/share/doc/cosmic-wallpapers/orion.json': PORT / 'wallpaper.json',
    }
    photo_relative = 'rootfs/usr/share/backgrounds/cosmic/' + pin['file']
    require(not original.keys() & {*inputs, photo_relative}, 'Wallpaper files already present')
    with tempfile.TemporaryDirectory(prefix='.cosmic-bg-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'catalog'
        subprocess.run(['/bin/cp', '-cRp', str(prefix), str(stage)], check=True)
        for relative, path in inputs.items():
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            destination.chmod(0o755 if relative.endswith('.elf') else 0o644)

        wallpaper = stage / photo_relative
        wallpaper.parent.mkdir(parents=True, exist_ok=True)
        width, height = pin['packed_pixels']
        ffmpeg = os_x86.pc.executable('ffmpeg')
        resize = [ffmpeg, '-nostdin', '-v', 'error', '-n', '-i', str(photo), '-vf',
                  f'scale={width}:{height}:flags=lanczos', '-frames:v', '1', '-q:v', '3', str(wallpaper)]
        subprocess.run(resize, check=True, timeout=30)
        added = {name: base.digest(stage / name) for name in (*inputs, photo_relative)}
        result = os_x86.catalog_inputs(stage)
        require(result == {**original, **added} and os_x86.catalog_inputs(prefix) == original,
                'Unrelated catalog input changed')
        receipt = dict(status='COSMIC_BG_INSTALLED_NOT_RUN', upstream=source,
                       build_report_sha256=base.digest(report_path),
                       base_manifest_sha256=base.digest(manifest_path), wallpaper=pin,
                       transcoder=dict(path=ffmpeg, sha256=base.digest(ffmpeg), command=resize),
                       producers=os_x86.producer_sources(__file__), added=added, files=result)
        (stage / 'cosmic-bg-origin.json').write_text(json.dumps(receipt, indent=2) + '\n')
        stage.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('--build', '--base-build', '--output'):
        parser.add_argument(flag, type=Path, required=True)
    parser.add_argument('--artwork', type=Path,
                        default=base.ROOT / 'artifacts/cosmic-native-sources/cosmic-orion-wallpaper')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        receipt = assemble(args.build, args.base_build, args.artwork, args.output)
    print(json.dumps({'status': receipt['status'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
