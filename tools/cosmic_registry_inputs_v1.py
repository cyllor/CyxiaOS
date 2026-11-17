"""Read-only Cargo.lock -> .crate -> complete extracted-source verification.

This versioned helper does not acquire or extract packages. It validates the
existing private cache, including every source file, without trusting a Cargo
checksum sidecar as a substitute for the pinned archive itself.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tomllib

try:
    from . import build_cosmic as base
    from . import cosmic_notifications_elf as bounded
except ImportError:
    import build_cosmic as base
    import cosmic_notifications_elf as bounded

MAX_ARCHIVE = 32 * 1024**2
MAX_FILE = 16 * 1024**2
MAX_TREE = 64 * 1024**2
MAX_MEMBERS = 100000
BuildError = base.CosmicBuildError


def require(value, message):
    if not value:
        raise BuildError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def registry_identity(manifest, cache, locked):
    """Return one archive/source identity from one exact registry lock entry."""
    try:
        manifest, cache = Path(manifest), Path(cache)
        require(manifest.is_absolute() and cache.is_absolute()
                and '..' not in manifest.parts and '..' not in cache.parts, 'Noncanonical registry input path')
        manifest, cache = base.no_symlink_path(manifest), base.no_symlink_path(cache)
        package_name, version, checksum = locked['name'], locked['version'], locked['checksum']
        require(isinstance(package_name, str) and re.fullmatch(r'[A-Za-z0-9_-]+', package_name)
                and isinstance(version, str) and re.fullmatch(r'[0-9][A-Za-z0-9.+_-]*', version)
                and isinstance(locked.get('source'), str) and locked['source'].startswith('registry+')
                and isinstance(checksum, str) and re.fullmatch('[0-9a-f]{64}', checksum),
                'Incomplete pinned registry package identity')
        relative = manifest.relative_to(cache / 'registry/src')
        stem = package_name + '-' + version
        require(len(relative.parts) == 3 and relative.parts[1:] == (stem, 'Cargo.toml'),
                'Registry manifest is not the exact locked package root')
        source = manifest.parent
        archive = base.no_symlink_path(cache / 'registry/cache' / relative.parts[0] / (stem + '.crate'))
        packed = bounded._read_regular(archive, MAX_ARCHIVE)
        require(sha(packed) == checksum, 'Registry archive differs from Cargo.lock checksum: ' + stem)
        files, seen, allowed_directories, expanded = {}, set(), set(), 0
        with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as stream:
            for member in stream:
                require(len(seen) < MAX_MEMBERS and (member.isfile() or member.isdir()),
                        'Unsupported or excessive registry archive members')
                if member.isdir() and member.name.rstrip('/') == stem:
                    require('' not in seen, 'Duplicate registry root directory')
                    seen.add('')
                    continue
                require(member.name.startswith(stem + '/'), 'Registry archive member escapes package root')
                relative_name = member.name[len(stem)+1:].rstrip('/') if member.isdir() \
                    else member.name[len(stem)+1:]
                if not relative_name and member.isdir():
                    continue
                selected = base.dependencies.relative_path(relative_name)
                require(relative_name not in seen, 'Duplicate registry archive member')
                seen.add(relative_name)
                allowed_directories.update(str(parent) for parent in selected.parents if str(parent) != '.')
                if member.isdir():
                    allowed_directories.add(relative_name)
                    require((source / selected).is_dir(), 'Missing registry archive directory')
                    base.no_symlink_path(source / selected)
                    continue
                require(relative_name not in ('.cargo-ok', '.cargo-checksum.json'),
                        'Archive supplies Cargo-owned extraction metadata')
                expanded += member.size
                require(0 <= member.size <= MAX_FILE and expanded <= MAX_TREE,
                        'Registry archive exceeds expanded byte budget')
                data = stream.extractfile(member).read(member.size + 1)
                require(len(data) == member.size and bounded._read_regular(source / selected, MAX_FILE) == data,
                        'Registry extracted source differs from pinned archive: ' + relative_name)
                require(bool((source / selected).stat().st_mode & 0o111) == bool(member.mode & 0o111),
                        'Registry extracted executable mode differs: ' + relative_name)
                files[relative_name] = {'bytes': len(data), 'sha256': sha(data),
                                        'executable': bool(member.mode & 0o111)}
        observed, observed_directories, sidecars = set(), set(), {}
        for parent, directories, names in os.walk(source, followlinks=False):
            for name in directories:
                selected = Path(parent) / name
                require(not selected.is_symlink() and stat.S_ISDIR(selected.lstat().st_mode),
                        'Linked or non-directory registry source directory')
                observed_directories.add(str(selected.relative_to(source)))
            for name in names:
                selected = Path(parent) / name
                relative_name = str(selected.relative_to(source))
                if relative_name in ('.cargo-ok', '.cargo-checksum.json'):
                    raw = bounded._read_regular(selected, MAX_FILE)
                    sidecars[relative_name] = sha(raw)
                    if relative_name == '.cargo-checksum.json':
                        value = json.loads(raw, object_pairs_hook=base.ports.unique_object)
                        require(value == {'package': checksum,
                                'files': {name: item['sha256'] for name, item in files.items()}},
                                'Registry checksum sidecar differs from pinned archive')
                    continue
                require(stat.S_ISREG(selected.lstat().st_mode) and not selected.is_symlink(),
                        'Non-regular registry source entry')
                observed.add(relative_name)
        require(files and 'Cargo.toml' in files and observed == set(files)
                and observed_directories == allowed_directories,
                'Registry extraction has missing or unbound files/directories')
        require(sha(bounded._read_regular(archive, MAX_ARCHIVE)) == checksum,
                'Registry archive changed during inspection')
        return {'name': package_name, 'version': version, 'source': str(source), 'archive': str(archive),
                'archive_sha256': checksum, 'archive_bytes': len(packed), 'source_bytes': expanded,
                'directories': sorted(allowed_directories),
                'file_count': len(files), 'files_sha256': sha(json.dumps(files, sort_keys=True,
                    separators=(',', ':')).encode()), 'cargo_metadata_sha256': sidecars}
    except BuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        raise BuildError('Invalid pinned registry input: ' + str(error)) from error


def registry_identities(metadata, source, cache):
    """Map metadata package IDs to canonical registry identities, using lock bytes."""
    try:
        raw = bounded._read_regular(Path(source) / 'Cargo.lock', 4 * 1024**2)
        locked = {}
        for item in tomllib.loads(raw.decode())['package']:
            if item.get('source', '').startswith('registry+'):
                key = (item['name'], item['version'], item['source'])
                require(key not in locked, 'Duplicate registry entry in Cargo.lock')
                locked[key] = item
        result = {}
        for package in metadata['packages']:
            if (package.get('source') or '').startswith('registry+'):
                key = (package['name'], package['version'], package['source'])
                require(key in locked and package['id'] not in result, 'Metadata registry package is not uniquely locked')
                result[package['id']] = registry_identity(package['manifest_path'], cache, locked[key])
        return result
    except BuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise BuildError('Invalid registry resolution: ' + str(error)) from error
