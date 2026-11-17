"""Exact nine-image fresh service catalog, including actual read-only embedding.

Uses the preserved notification v2 catalog primitives without modifying globals.
New session/settings/probe bytes must each be in PORTED, ROOT_FILES, generated
copies, curated inputs and exactly one read-only kernel LOAD. No runtime claim.
"""
from pathlib import Path
import re

if __package__:
    from . import os_cosmic_notifications_runtime_v2 as base
else:
    import os_cosmic_notifications_runtime_v2 as base

require = base.require
plain_directory = base.plain_directory
read_regular = base.read_regular
identity = base.identity
generated_catalog_path = base.generated_catalog_path
os_smoke = base.os_smoke
IMAGE_NAMES = ('probe.elf', 'dbus-daemon.elf', 'dbus-send.elf', 'cosmic-comp.elf',
               'cosmic-notifications.elf', 'notification-probe.elf', 'cosmic-session.elf',
               'cosmic-settings-daemon.elf', 'settings-probe.elf')


def catalog_identity(build, manifest, programs):
    require(type(programs) is dict and set(programs) == set(IMAGE_NAMES),
            'Service catalog requires exactly the nine declared real executable inputs')
    prefix = plain_directory(manifest['sysroot'])
    catalog = generated_catalog_path(manifest)
    raw = read_regular(catalog, 1024 * 1024)
    entries = re.findall(rb'^\("([^"\n]+)", "([^"\n]+)", include_bytes!\(concat!\(env!\("OUT_DIR"\), "/([^"\n]+)"\)\)\),$', raw, re.MULTILINE)
    require(len(entries) == len(IMAGE_NAMES)
            and {row[0] for row in entries} == {name.removesuffix('.elf').encode() for name in IMAGE_NAMES},
            'Generated service executable set is missing, duplicated or undeclared')
    bound = os_smoke.embedded_images(build, manifest, IMAGE_NAMES)
    for name, image in programs.items():
        matches = [(i, row) for i, row in enumerate(entries) if row[0] == name.removesuffix('.elf').encode()]
        expected = (name.removesuffix('.elf').encode(), ('/bin/' + name.removesuffix('.elf')).encode(), name.encode())
        require(len(matches) == 1 and matches[0][1] == expected, 'Guest catalog image/path mismatch: ' + name)
        root = f'("/bin/{name.removesuffix(".elf")}", PORTED[{matches[0][0]}].2),'.encode()
        require(raw.splitlines().count(root) == 1, 'Guest ROOT_FILES mapping mismatch: ' + name)
        require(identity(catalog.parent / name) == identity(prefix / name) == identity(image),
                'Generated/installed/original executable bytes differ: ' + name)
        require(bound[name] == identity(image)['sha256'] == manifest['external_inputs'].get(name), 'Kernel embeds a different executable: ' + name)
    assets = re.findall(rb'^\("([^"\n]+)", include_bytes!\(concat!\(env!\("OUT_DIR"\), "/(asset-\d+)"\)\)\),$',
                        raw, re.MULTILINE)
    require(len(entries) + len(assets) <= 256 and len({row[0] for row in assets}) == len(assets),
            'Generated root catalog count/uniqueness exceeds the production contract')
    copied_assets = {}
    total = sum((catalog.parent / row[2].decode()).stat().st_size for row in entries)
    for guest, filename in assets:
        name = guest.decode()
        require(name.startswith('/') and '..' not in Path(name).parts and len(guest) < 96,
                'Invalid generated root asset path')
        generated = catalog.parent / filename.decode()
        require(identity(generated) == identity(prefix / 'rootfs' / name.lstrip('/')),
                'Actual generated root asset differs from curated input: ' + name)
        copied_assets[name] = identity(generated)
        total += copied_assets[name]['bytes']
    require(total <= 96 * 1024**2, 'Generated full-OS catalog exceeds its existing byte budget')
    expected_assets = {('/' + name.removeprefix('rootfs/')) for name in manifest['external_inputs']
                       if name.startswith('rootfs/')}
    require(set(copied_assets) == expected_assets, 'Generated root asset closure differs from the actual OS inputs')
    require(len({row[1] for row in assets}) == len(assets)
            and not ({row[0].decode() for row in assets} & {'/bin/' + name.removesuffix('.elf') for name in IMAGE_NAMES}),
            'Generated root asset filenames or executable paths collide')
    require(set(manifest['external_inputs']) == set(IMAGE_NAMES) | {'rootfs' + name for name in copied_assets},
            'Service catalog external input set contains undeclared files')
    for name, entry in copied_assets.items():
        require(manifest['external_inputs']['rootfs' + name] == entry['sha256'],
                'Generated root asset differs from manifest bytes: ' + name)
    return {'path': str(catalog), 'identity': identity(catalog), 'embedded': bound,
            'generated_assets': copied_assets, 'catalog_bytes': total}

