"""Verified immutable build-artifact sharing. Never use for mutable disk images."""
from __future__ import annotations
import errno
import os
from pathlib import Path
import re
import shutil
import tempfile
from verify_smp import require, sha


def _regular(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _copy(source: Path, target: Path, expected: str):
    with source.open('rb') as original, target.open('xb') as copy:
        shutil.copyfileobj(original, copy, 1024 * 1024)
    target.chmod(0o600)
    require(sha(target) == expected and sha(source) == expected, 'immutable artifact changed during copy')


def materialize(source: Path, destination: Path, expected: str, cache: Path | None = None):
    """Materialize exact bytes, optionally linking a private verified CAS copy.

    The original build file is never hard-linked. A later edit of the build
    therefore cannot mutate existing evidence. Every reuse checks the bytes;
    a digest-shaped filename alone is not an integrity assertion.
    """
    source, destination = Path(source), Path(destination)
    require(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected)
            and _regular(source) and sha(source) == expected, 'wrong immutable artifact source/hash')
    require(not destination.exists() and not destination.is_symlink(), 'refuse to replace evidence artifact')
    if cache is None:
        _copy(source, destination, expected)
        return
    cache = Path(cache)
    if not cache.exists(): cache.mkdir(parents=True, mode=0o700)
    require(cache.is_dir() and not cache.is_symlink() and cache.stat().st_mode & 0o077 == 0,
            'artifact cache must be a private real directory')
    blob = cache / expected
    if not blob.exists() and not blob.is_symlink():
        fd, name = tempfile.mkstemp(prefix='.incoming-', dir=cache)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'wb') as copy, source.open('rb') as original:
                shutil.copyfileobj(original, copy, 1024 * 1024)
            require(sha(temporary) == expected and sha(source) == expected, 'immutable artifact changed during caching')
            temporary.chmod(0o400)
            try: os.link(temporary, blob)
            except FileExistsError: pass  # A competing writer must pass the same byte check below.
        finally:
            temporary.unlink(missing_ok=True)
    require(_regular(blob) and sha(blob) == expected and blob.stat().st_mode & 0o222 == 0,
            'corrupt, linked, or writable immutable cache entry')
    try: os.link(blob, destination)
    except OSError as error:
        if error.errno != errno.EXDEV: raise
        _copy(blob, destination, expected)
        destination.chmod(0o400)
    require(sha(destination) == expected and sha(source) == expected, 'immutable artifact changed during materialization')
