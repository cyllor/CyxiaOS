"""Hash-pinned, bounded HTTPS range downloads for desktop build inputs.

Sequential requests avoid the old four-worker request burst. Retrying a 429
never weakens byte counts, Content-Range or the final release SHA256. No target
code is executed, and no unverified archive is published at the output path.
"""
from __future__ import annotations

from contextlib import contextmanager
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request


class DownloadError(ValueError):
    """An input, transport budget, or content integrity check failed."""


def _require(value: bool, message: str) -> None:
    if not value:
        raise DownloadError(message)


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _regular(path: Path) -> bool:
    _require(not path.is_symlink(), "Refusing a symlink in download outputs")
    _require(not path.exists() or path.is_file(), "Download output is not a regular file")
    return path.is_file()


def retry_delay(header: str | None, attempt: int, wall_time: float) -> float:
    """Honor Retry-After, including HTTP dates. Never retry earlier than asked."""
    delay = min(2 ** attempt, 16)
    if header is None:
        return float(delay)
    value = header.strip()
    if re.fullmatch(r"[0-9]{1,12}", value):
        return max(float(delay), float(value))
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is not None:
            return max(float(delay), parsed.timestamp() - wall_time)
    except (ValueError, TypeError, OverflowError):
        pass
    return float(delay)


@contextmanager
def _work_lock(path: Path):
    _regular(path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DownloadError("Another download owns this output") from error
        yield
    finally:
        os.close(fd)


def _atomic_part(path: Path, content: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=".range-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _regular(path)
        # No replacement of someone else's already-published part.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def download_ranges(url: str, destination: Path, *, size: int, sha256: str,
                    max_bytes: int, opener, chunk_size: int = 2 * 1024 * 1024,
                    attempts: int = 4, budget_seconds: float = 300,
                    socket_timeout: float = 30, clock=time.monotonic,
                    wall_clock=time.time, sleep=time.sleep) -> Path:
    """Acquire exact ranges, then verify the complete archive before publication.

    The opener must enforce HTTPS-only redirects (the Mesa caller supplies its
    existing HTTPSRedirects handler). A final URL check is defense in depth.
    The elapsed budget is checked around each blocking operation. An in-flight
    socket call may finish after that deadline; it is bounded by socket_timeout.
    The build runner remains responsible for its outer hard process deadline.
    Test hooks are explicit; production callers do not supply clock or sleep.
    """
    parsed = urlsplit(url)
    _require(parsed.scheme == "https" and bool(parsed.hostname)
             and parsed.username is None and parsed.password is None and not parsed.fragment,
             "Expected an HTTPS source without embedded credentials")
    _require(type(size) is int and type(max_bytes) is int and 0 < size <= max_bytes,
             "Invalid pinned source size")
    _require(isinstance(sha256, str) and re.fullmatch(r"[0-9a-f]{64}", sha256) is not None,
             "Invalid SHA256 pin")
    _require(type(chunk_size) is int and 0 < chunk_size <= 8 * 1024 * 1024,
             "Invalid chunk size")
    _require(type(attempts) is int and 1 <= attempts <= 8, "Invalid attempt budget")
    _require(0 < budget_seconds <= 3600 and 0 < socket_timeout <= 60,
             "Invalid time budget")
    destination = Path(destination)
    _require(destination.parent.is_dir() and not destination.parent.is_symlink(),
             "Output parent must be an existing non-symlink directory")
    deadline = clock() + budget_seconds

    def remaining() -> float:
        value = deadline - clock()
        _require(value > 0, "Download elapsed budget exhausted")
        return value

    with _work_lock(destination.with_suffix(destination.suffix + ".lock")):
        if _regular(destination):
            _require(destination.stat().st_size == size and _digest(destination) == sha256,
                     "Existing archive is invalid; preserve it and select a fresh output")
            return destination
        # Cache identity includes the full hash, size and range layout. A part
        # with the right length is only a candidate, never a trusted release.
        parts = destination.parent / f".ranges-{sha256}-{size}-{chunk_size}"
        _require(not parts.is_symlink(), "Refusing linked range cache")
        parts.mkdir(exist_ok=True)
        _require(parts.is_dir(), "Range cache is not a directory")
        ordered = []
        for start in range(0, size, chunk_size):
            remaining()
            end = min(start + chunk_size, size) - 1
            expected = end - start + 1
            path = parts / f"{start}-{end}.part"
            if _regular(path):
                _require(path.stat().st_size == expected, "Invalid cached range length")
                ordered.append((path, expected))
                continue
            for attempt in range(attempts):
                retry_after = None
                try:
                    request = Request(url, headers={"Range": f"bytes={start}-{end}",
                        "Accept-Encoding": "identity", "User-Agent": "CyxiaOS-mesa-port/2"})
                    with opener.open(request, timeout=min(socket_timeout, remaining())) as response:
                        _require(urlsplit(response.geturl()).scheme == "https", "HTTPS redirect required")
                        _require(response.status == 206
                                 and response.headers.get("Content-Range") == f"bytes {start}-{end}/{size}",
                                 "Server did not honor the exact byte range")
                        _require(response.headers.get("Content-Encoding", "identity").lower() == "identity",
                                 "Encoded range responses are not accepted")
                        length = response.headers.get("Content-Length")
                        _require(length is None or length == str(expected), "Incorrect range Content-Length")
                        content = response.read(expected + 1)
                    remaining()
                    _require(len(content) == expected, "Truncated or oversized range")
                except HTTPError as error:
                    status = error.code
                    retry_after = error.headers.get("Retry-After") if error.headers else None
                    error.close()
                    if status not in (408, 429, 500, 502, 503, 504):
                        raise DownloadError(f"Source returned non-retryable HTTP {status}") from error
                    reason = f"HTTP {status}"
                except (URLError, TimeoutError, ConnectionError) as error:
                    reason = type(error).__name__
                else:
                    _atomic_part(path, content)
                    ordered.append((path, expected))
                    break
                if attempt + 1 == attempts:
                    raise DownloadError(f"Source retry budget exhausted ({reason})")
                delay = retry_delay(retry_after, attempt, wall_clock())
                _require(delay < remaining(), "Retry-After exceeds remaining download budget")
                sleep(delay)
        remaining()
        fd, name = tempfile.mkstemp(prefix=".unverified-", dir=destination.parent)
        temporary = Path(name)
        try:
            digest = hashlib.sha256()
            written = 0
            with os.fdopen(fd, "wb") as stream:
                for part, expected in ordered:
                    remaining()
                    _regular(part)
                    with part.open("rb") as source:
                        content = source.read(expected + 1)
                    _require(len(content) == expected, "Range cache changed after acquisition")
                    written += len(content)
                    _require(written <= size, "Range cache grew beyond the pinned size")
                    digest.update(content)
                    stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            _require(written == size and digest.hexdigest() == sha256,
                     "Assembled archive differs from the release SHA256")
            remaining()
            _regular(destination)
            os.link(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination
