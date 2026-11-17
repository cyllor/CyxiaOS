"""Pure capacity preflight for adding an admitted, original-byte panel.

Callers supply identities from independently revalidated component inputs. This
module does not authenticate files, load executables, authorize AI grants, or
publish a catalog. It keeps the current raw catalog contract: every logical
guest entry contributes its full length, including byte-identical licenses at
different paths. Potential content interning is reported but never credited.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re

MAX_CATALOG_BYTES = 96 * 1024**2
MAX_CATALOG_ENTRIES = 256
MAX_GUEST_PATH_BYTES = 96
MAX_FILE_BYTES = 64 * 1024**2
STACK_PAGES = 512
PRIVATE_EXEC_POOL_PAGES = 16384
IMAGE_NAMES = frozenset((
    'probe.elf', 'dbus-daemon.elf', 'dbus-send.elf', 'cosmic-comp.elf',
    'cosmic-notifications.elf', 'notification-probe.elf', 'cosmic-session.elf',
    'cosmic-settings-daemon.elf', 'settings-probe.elf', 'cosmic-panel.elf',
))
PANEL_FILES = frozenset((
    'cosmic-panel.elf',
    'rootfs/usr/share/doc/cosmic-panel/LICENSE.md',
    'rootfs/usr/share/doc/cosmic-panel/launch-pad-LICENSE.md',
    'rootfs/usr/share/doc/cosmic-panel/smithay-LICENSE.txt',
    'rootfs/usr/share/doc/cosmic-panel/smithay-drm-extras-LICENSE',
    'rootfs/usr/share/doc/cosmic-panel/wayland-sys-LICENSE',
))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def guest_path(name):
    require(type(name) is str and name and '\\' not in name and '\0' not in name,
            'Invalid catalog input name')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'Catalog input must have a canonical relative path')
    if name in IMAGE_NAMES:
        result = '/bin/' + name.removesuffix('.elf')
    else:
        require(name.startswith('rootfs/') and len(path.parts) > 1,
                'Undeclared executable or non-rootfs input')
        result = '/' + name.removeprefix('rootfs/')
    require(len(result.encode('utf-8')) < MAX_GUEST_PATH_BYTES,
            'Guest path exceeds the existing byte bound')
    return result


def file_identity(name, row):
    require(type(row) is dict and {'bytes', 'sha256'} <= set(row),
            'Missing independently verified file identity')
    require(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE_BYTES,
            'File length exceeds the original individual input bound')
    require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
            'Invalid file digest')
    if 'mode' in row:
        require(type(row['mode']) is int and row['mode'] == (0o755 if name in IMAGE_NAMES else 0o644),
                'Unexpected installed guest file mode')
    return {'bytes': row['bytes'], 'sha256': row['sha256']}


def preflight(base_files, panel_installation):
    """Return an explicit blocked/fit plan; never relax limits on overflow."""
    require(type(base_files) is dict and type(panel_installation) is dict,
            'Expected independently revalidated base and panel identities')
    require({name for name in base_files if name.endswith('.elf')} == IMAGE_NAMES - {'cosmic-panel.elf'},
            'The preserved base must contain exactly the nine original images')
    require(panel_installation.get('kind') == 'cosmic-panel-linux-v1-installation'
            and panel_installation.get('status') == 'PANEL_INSTALLATION_REVALIDATED_NOT_RUN'
            and panel_installation.get('guest_execution') == 'not performed'
            and all(panel_installation.get(key) is False for key in (
                'panel_verified', 'panel_applet_lifecycle_verified', 'cosmic_session_ready',
                'cosmic_session_verified', 'full_cosmic_complete')),
            'Panel installation is not the independently revalidated original-byte installation')
    added = panel_installation.get('files')
    require(type(added) is dict and set(added) == PANEL_FILES,
            'Panel must retain its real ELF and all five full upstream licenses')
    load_pages = panel_installation.get('image_load_pages')
    required_pages = panel_installation.get('required_pages')
    require(type(load_pages) is int and type(required_pages) is int
            and load_pages > 0 and required_pages == load_pages + STACK_PAGES
            and required_pages <= PRIVATE_EXEC_POOL_PAGES,
            'Panel per-process image/stack accounting changed')

    combined = {name: file_identity(name, row) for name, row in base_files.items()}
    require(not (set(combined) & set(added)), 'Panel installation collides with a preserved guest input')
    combined.update({name: file_identity(name, row) for name, row in added.items()})
    guest_names = [guest_path(name) for name in combined]
    require(len(set(guest_names)) == len(guest_names), 'Two input files alias the same guest path')
    total = sum(row['bytes'] for row in combined.values())
    count = len(combined)
    violations = []
    if count > MAX_CATALOG_ENTRIES:
        violations.append('entry_count')
    if total > MAX_CATALOG_BYTES:
        violations.append('raw_catalog_bytes')

    by_content = {}
    for name, row in combined.items():
        key = (row['sha256'], row['bytes'])
        by_content.setdefault(key, []).append(name)
    duplicates = [
        {'sha256': sha, 'bytes': size, 'paths': sorted(names),
         'potential_stored_saving': size * (len(names) - 1)}
        for (sha, size), names in sorted(by_content.items()) if len(names) > 1
    ]
    return {
        'schema_version': 1,
        'kind': 'cosmic-panel-original-byte-catalog-capacity-v1',
        'status': 'BLOCKED_EXISTING_CATALOG_LIMIT' if violations else 'FITS_EXISTING_CATALOG_LIMIT_NOT_ASSEMBLED',
        'violations': violations,
        'catalog_count': count,
        'catalog_bytes': total,
        'catalog_limits': {'max_entries': MAX_CATALOG_ENTRIES, 'max_bytes': MAX_CATALOG_BYTES,
                           'max_guest_path_bytes_exclusive': MAX_GUEST_PATH_BYTES},
        'excess_bytes': max(total - MAX_CATALOG_BYTES, 0),
        'preserved_entry_count': len(base_files),
        'panel_entry_count': len(added),
        'panel_load_pages': load_pages,
        'panel_required_pages': required_pages,
        'exec_pool_scope': 'per-process private slot; no sum with compositor or other services',
        'guest_ai_admission': 'unchanged and still required; this host plan grants no pages',
        'content_duplicates': duplicates,
        'duplicate_savings_credited_to_existing_limit': 0,
        'catalog': dict(sorted(combined.items())),
        'catalog_assembled': False,
        'guest_execution': False,
        'full_cosmic_complete': False,
    }


def require_fit(base_files, panel_installation):
    """Recompute before copying inputs; never trust a serialized fit claim."""
    plan = preflight(base_files, panel_installation)
    require(plan['status'] == 'FITS_EXISTING_CATALOG_LIMIT_NOT_ASSEMBLED',
            'Panel does not fit the unchanged raw catalog; no assembly or limit override is authorized')
    return plan
