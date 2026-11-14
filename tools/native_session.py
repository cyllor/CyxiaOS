"""Architecture-neutral host exclusion shared by native capture producers."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NATIVE_LOCK = ROOT / 'artifacts/v016-focus-a03-a10-20261109-r9/native-session.lock'
BUSY_EXECUTABLES = frozenset(('qemu-system-aarch64', 'qemu-system-x86_64', 'cargo', 'rustc', 'clang'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


@contextmanager
def native_lease(path):
    path = Path(path)
    require(path.parent.is_dir() and not path.is_symlink(), 'native lock parent/target')
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags, 0o600), 'a') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def idle_native_host():
    rows = subprocess.run(['ps', '-axo', 'pid=,comm='], capture_output=True,
                          text=True, check=True, timeout=10).stdout
    busy = [row.strip() for row in rows.splitlines() if row.split()
            and Path(row.strip().split(None, 1)[-1]).name in BUSY_EXECUTABLES]
    require(not busy, 'native/build exclusion: ' + repr(busy))
