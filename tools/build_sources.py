"""Architecture-neutral source identities and isolated Cargo cache selection."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CODE_ROOTS = {'kernel', 'crates', 'user', 'ports', '.cargo'}
ROOT_BUILD_FILES = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'rust-toolchain'}
EXCLUDED_COMPONENTS = {'tests', 'docs', 'target', '__pycache__', '.git'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def working_tree_names(source_root):
    """Retain strict missing-source checks while accepting declared renames.

    Git's cached list still contains old names until a rename is staged. Only
    explicit kernel migrations with a present, unique replacement are omitted;
    arbitrary missing tracked sources remain errors in the caller.
    """
    source_root = Path(source_root).resolve(strict=True)
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                            cwd=source_root, capture_output=True, check=True, timeout=10)
    names = set(result.stdout.decode('utf-8').split('\0')) - {''}
    manifest = source_root / 'kernel/layout-migration.json'
    if not manifest.exists():
        return sorted(names)
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 131072,
            'invalid kernel migration manifest')
    migration = json.loads(manifest.read_text())
    require(migration.get('version') == 1 and isinstance(migration.get('moves'), dict),
            'unsupported kernel migration manifest')
    moves = migration['moves']
    require(all(isinstance(old, str) and isinstance(new, str) for old, new in moves.items()),
            'invalid kernel migration path')
    require(len(set(moves.values())) == len(moves), 'ambiguous kernel migration destination')
    for old, new in moves.items():
        require(old != new and all(not Path(p).is_absolute() and '..' not in Path(p).parts
                and p.startswith(('kernel/src/', 'kernel/linker')) for p in (old, new)),
                'escaping kernel migration path')
        if old not in names:
            continue
        previous, replacement = source_root / old, source_root / new
        if previous.exists() or previous.is_symlink():
            require(new not in names, 'both kernel migration paths exist')
            continue
        require(new in names and replacement.is_file() and not replacement.is_symlink()
                and replacement.resolve().is_relative_to(source_root),
                'missing kernel migration replacement')
        names.remove(old)
    return sorted(names)


def code_source_map(source_root=None, *, required_sources=('Cargo.lock',)):
    # Bind every potentially compiled source/asset, including extensionless and
    # vendor files, while excluding mutable evidence and test-only fixtures.
    source_root = Path(source_root or ROOT).resolve(strict=True)
    names = sorted(set(name for name in working_tree_names(source_root) if name
                       and (name in ROOT_BUILD_FILES or Path(name).parts[0] in CODE_ROOTS)
                       and not any(part in EXCLUDED_COMPONENTS for part in Path(name).parts)))
    require(set(required_sources) <= set(names), 'incomplete native source checkout')
    files = [source_root / name for name in names]
    require(all(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(source_root) for p in files),
            'missing, linked, or external native build source')
    return {name: sha(path) for name, path in zip(names, files)}


def build_cache_context(cache_base, source_root, sources):
    """Keep backdated source and other checkouts out of Cargo's mtime cache."""
    base = Path(cache_base).expanduser().resolve()
    root = Path(source_root).resolve(strict=True)
    source_sha = hashlib.sha256(json.dumps(sources, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    identity = dict(version=1, source_root=str(root), compiled_source_sha256=source_sha)
    key = hashlib.sha256(json.dumps(identity, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    target = base / ('source-' + key)
    require(not target.is_symlink() and target.resolve().parent == base,
            'linked or escaping build cache namespace')
    return dict(base=str(base), effective=str(target), namespace_key=key,
                source_root=str(root), compiled_source_sha256=source_sha,
                strategy='source-and-checkout-v1')


def cache_artifact(path, target_dir):
    actual = Path(path).resolve(strict=True)
    require(actual.is_relative_to(Path(target_dir).resolve(strict=True)),
            'Cargo artifact outside selected build cache namespace')
    return actual
