"""Prepare pinned desktop sources; never extract archives or run package scripts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "ports/desktop/manifest.json"
DEFAULT_CACHE = ROOT / "artifacts/desktop-sources"
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
RESERVE_BYTES = 64 * 1024 * 1024
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class PortError(ValueError):
    """An actionable validation or preparation failure."""


def unique_object(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise PortError(f"duplicate JSON key: {key}")
        value[key] = entry
    return value


def https_url(value: object, *, redirects: bool = False) -> str:
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise PortError("source URL must be an HTTPS string without control characters")
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise PortError("malformed source URL") from error
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or (parsed.query and not redirects)):
        raise PortError("source URL must use HTTPS without credentials or a fragment")
    return value


def component(value: object, label: str) -> str:
    if not isinstance(value, str) or not SAFE_COMPONENT.fullmatch(value) or ".." in value:
        raise PortError(f"invalid {label}: expected a plain package/version name")
    return value


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict:
    try:
        manifest = json.loads(path.read_text(), object_pairs_hook=unique_object)
    except (OSError, ValueError) as error:
        raise PortError(f"cannot read manifest: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise PortError("unsupported desktop manifest schema")
    packages = manifest.get("packages")
    unresolved = manifest.get("unresolved_dependencies")
    if not isinstance(packages, list) or not isinstance(unresolved, list):
        raise PortError("packages and unresolved_dependencies must be lists")
    identities = set()
    for package in packages + unresolved:
        if not isinstance(package, dict):
            raise PortError("package entries must be objects")
        name = component(package.get("name"), "package name")
        if name in identities:
            raise PortError(f"duplicate package identity: {name}")
        identities.add(name)
    for package in packages:
        component(package.get("version"), "version")
        https_url(package.get("source_url"))
        for field, pattern in (("expected_sha256", SHA256), ("source_commit", COMMIT)):
            value = package.get(field)
            if value is not None and (not isinstance(value, str) or not pattern.fullmatch(value)):
                raise PortError(f"{package['name']}: malformed {field}")
        if package.get("source_git_url") is not None:
            https_url(package["source_git_url"])
        dependencies = package.get("depends_on")
        if not isinstance(dependencies, list) or not all(isinstance(d, str) for d in dependencies):
            raise PortError(f"{package['name']}: depends_on must list package identities")
        if len(dependencies) != len(set(dependencies)) or not set(dependencies) <= identities:
            raise PortError(f"{package['name']}: duplicate or unknown dependency")
    return manifest


def package_named(manifest: dict, name: str) -> dict:
    for package in manifest["packages"]:
        if package["name"] == name:
            return package
    raise PortError(f"package is absent or unresolved: {name}")


def identity(package: dict) -> dict:
    component(package.get("name"), "package name")
    component(package.get("version"), "version")
    if package.get("expected_sha256"):
        kind, pin, url = "sha256-archive", package["expected_sha256"], package["source_url"]
        if not isinstance(pin, str) or not SHA256.fullmatch(pin):
            raise PortError("malformed expected_sha256")
    elif package.get("source_commit") and package.get("source_git_url"):
        kind, pin, url = "git-commit", package["source_commit"], package["source_git_url"]
        if not isinstance(pin, str) or not COMMIT.fullmatch(pin):
            raise PortError("malformed source_commit")
    else:
        raise PortError(f"{package['name']}: no fixed SHA-256 or exact Git commit plus repository URL")
    https_url(url)
    return {"name": package["name"], "version": package["version"],
            "kind": kind, "pin": pin, "source_url": url}


def destination(cache: Path, package: dict) -> Path:
    selected = identity(package)
    return cache / f"{selected['name']}-{selected['version']}-{selected['pin']}"


def inspect_manifest(manifest: dict, selected: str | None = None) -> dict:
    packages = {p["name"]: p for p in manifest["packages"]}
    unresolved = {p["name"]: p for p in manifest["unresolved_dependencies"]}
    wanted = [selected] if selected else list(packages)
    if selected:
        package_named(manifest, selected)
    seen, pending, blockers = set(), list(wanted), []
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        if name in unresolved:
            blockers.append({"name": name, "reason": "unresolved version/source"})
            continue
        package = packages[name]
        try:
            identity(package)
        except PortError as error:
            blockers.append({"name": name, "reason": str(error)})
        pending.extend(package["depends_on"])
    if not selected:
        for name in sorted(set(unresolved) - seen):
            blockers.append({"name": name, "reason": "unresolved desktop asset/dependency"})
    rows = []
    for name in wanted:
        try:
            rows.append({**identity(packages[name]), "source_pinned": True})
        except PortError as error:
            rows.append({"name": name, "source_pinned": False, "reason": str(error)})
    return {"scope": selected or "desktop", "packages": rows,
            "source_closure_ready": not blockers,
            "manifest_closure_complete": manifest.get("closure_complete") is True,
            "desktop_build_ready": False,
            "blockers": sorted(blockers, key=lambda row: row["name"]),
            "host_tools": {name: shutil.which(name) for name in
                           ("git", "clang", "pkg-config", "meson", "ninja", "valac", "intltoolize")}}


def require_space(directory: Path, bytes_needed: int) -> None:
    free = shutil.disk_usage(directory).free
    if free < bytes_needed + RESERVE_BYTES:
        raise PortError(f"insufficient disk space: {free} bytes free; need {bytes_needed} "
                        f"plus {RESERVE_BYTES} bytes reserve")


def regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise PortError(f"source file unavailable: {path}") from error
    if not stat.S_ISREG(mode):
        raise PortError(f"expected a regular file, not a symlink/device: {path}")


def hash_file(path: Path, max_bytes: int) -> tuple[str, int]:
    regular_file(path)
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            count += len(block)
            if count > max_bytes:
                raise PortError("source exceeds --max-bytes")
            digest.update(block)
    return digest.hexdigest(), count


def copy_verified(source, target: Path, expected: str, max_bytes: int) -> tuple[str, int]:
    digest, count, started = hashlib.sha256(), 0, time.monotonic()
    with target.open("xb") as output:
        for block in iter(lambda: source.read(65536), b""):
            count += len(block)
            if count > max_bytes:
                raise PortError("source exceeds --max-bytes")
            if time.monotonic() - started > 120:
                raise PortError("source download timed out")
            require_space(target.parent, len(block))
            output.write(block)
            digest.update(block)
        output.flush()
        os.fsync(output.fileno())
    if digest.hexdigest() != expected:
        raise PortError("SHA-256 mismatch; source was not published")
    return digest.hexdigest(), count


class HTTPSRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        https_url(new_url, redirects=True)
        return super().redirect_request(request, response, code, message, headers, new_url)


def git_env() -> dict:
    # Ignore caller Git overrides, credential prompts and user/global hooks/config.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_ATTR_NOSYSTEM="1")
    return env


def git_run(arguments: list[str], directory: Path, max_bytes: int,
            output: Path | None = None, local_bundle: bool = False,
            online: bool = False) -> str:
    git = shutil.which("git")
    if not git:
        raise PortError("Git is required to verify an exact commit")
    command = [git, "-c", f"core.hooksPath={os.devnull}", "-c", "protocol.allow=never",
               "-c", f"core.attributesFile={os.devnull}", "-c", "tar.umask=0002",
               "-c", "protocol.https.allow=" + ("always" if online else "never"),
               "-c", "credential.helper=",
               "-c", "transfer.fsckObjects=true"]
    if local_bundle:
        command += ["-c", "protocol.file.allow=always"]
    command += arguments
    # Monitor both package size and free disk while Git receives/writes objects.
    # This is a bounded preparation operation, not a package build sandbox.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        sink = output.open("xb") if output else stdout
        try:
            process = subprocess.Popen(command, cwd=directory, env=git_env(),
                                       stdin=subprocess.DEVNULL, stdout=sink, stderr=stderr,
                                       start_new_session=True)
            started = time.monotonic()
            try:
                while process.poll() is None:
                    if time.monotonic() - started > 120:
                        raise PortError("Git source operation timed out")
                    require_space(directory, 0)
                    size = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())
                    if size > max_bytes * 2:
                        raise PortError("Git source/object data exceeds --max-bytes budget")
                    time.sleep(0.05)
            except BaseException:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
                raise
            if process.returncode:
                stderr.seek(0)
                detail = stderr.read(2000).decode("utf-8", errors="replace").strip()
                raise PortError(f"Git operation failed: {detail}")
            require_space(directory, 0)
            if sum(p.stat().st_size for p in directory.rglob("*") if p.is_file()) > max_bytes * 2:
                raise PortError("Git source/object data exceeds --max-bytes budget")
            stdout.seek(0)
            return stdout.read(4096).decode("utf-8", errors="strict").strip()
        finally:
            if output:
                sink.close()


def git_identity(directory: Path, expected: str, max_bytes: int) -> None:
    repository = directory / "repository.git"
    if repository.is_symlink() or not repository.is_dir():
        raise PortError("cached Git repository is absent or a symlink")
    if (repository / "info/attributes").exists() or (repository / "info/attributes").is_symlink():
        raise PortError("cached Git repository contains local archive attribute overrides")
    actual = git_run(["--git-dir=repository.git", "rev-parse", "--verify", expected + "^{commit}"],
                     directory, max_bytes)
    if actual != expected:
        raise PortError("Git commit identity mismatch")
    git_run(["--git-dir=repository.git", "fsck", "--full", "--strict", "--no-reflogs",
             "--no-dangling", expected], directory, max_bytes)


def verify(package: dict, cache: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    wanted = identity(package)
    directory = destination(cache, package)
    if directory.is_symlink() or not directory.is_dir():
        raise PortError("verified source cache entry is absent or a symlink")
    record_path = directory / "provenance.json"
    regular_file(record_path)
    try:
        record = json.loads(record_path.read_text(), object_pairs_hook=unique_object)
    except (OSError, ValueError) as error:
        raise PortError("invalid source provenance record") from error
    if not isinstance(record, dict) or record.get("identity") != wanted:
        raise PortError("cached source identity does not match the manifest")
    payload = directory / ("source.tar" if wanted["kind"] == "git-commit" else "source.archive")
    digest, count = hash_file(payload, max_bytes)
    if record.get("sha256") != digest or record.get("bytes") != count:
        raise PortError("cached source content/size does not match its provenance")
    if wanted["kind"] == "sha256-archive":
        if digest != wanted["pin"]:
            raise PortError("cached source does not match the manifest SHA-256")
    else:
        git_identity(directory, wanted["pin"], max_bytes)
        # Re-export from verified objects, so editing both tar and provenance
        # cannot turn an arbitrary archive into the claimed commit.
        require_space(directory, max_bytes)
        with tempfile.TemporaryDirectory(prefix=".verify-", dir=cache) as temporary:
            generated = Path(temporary) / "source.tar"
            git_run([f"--git-dir={directory / 'repository.git'}", "archive", "--format=tar",
                     wanted["pin"]], Path(temporary), max_bytes, output=generated)
            if hash_file(generated, max_bytes)[0] != digest:
                raise PortError("cached archive differs from the exact Git commit")
    return {"status": "verified", "directory": str(directory), **record}


def fetch(package: dict, cache: Path, *, online: bool = False,
          offline_file: Path | None = None, max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    if online == (offline_file is not None):
        raise PortError("choose exactly one of --online or --offline-file")
    if max_bytes < 1:
        raise PortError("--max-bytes must be positive")
    wanted = identity(package)  # Refuse unpinned input before any filesystem mutation.
    if offline_file is not None:
        regular_file(offline_file)
        offline_file = offline_file.resolve()
        if offline_file.stat().st_size > max_bytes:
            raise PortError("offline source exceeds --max-bytes")
    cache.mkdir(parents=True, exist_ok=True)
    cache = cache.resolve()
    final = destination(cache, package)
    if final.exists() or final.is_symlink():
        return verify(package, cache, max_bytes)
    require_space(cache, max_bytes * (3 if wanted["kind"] == "git-commit" else 1))
    lock = cache / (".lock-" + final.name)
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise PortError(f"source is locked by another preparation; inspect {lock}") from error
    try:
        with os.fdopen(lock_fd, "w") as handle:
            handle.write(f"pid={os.getpid()}\n")
        if final.exists() or final.is_symlink():
            return verify(package, cache, max_bytes)
        with tempfile.TemporaryDirectory(prefix=".prepare-", dir=cache) as temporary:
            stage = Path(temporary)
            if wanted["kind"] == "sha256-archive":
                payload = stage / "source.archive"
                if offline_file:
                    with offline_file.open("rb") as source:
                        digest, size = copy_verified(source, payload, wanted["pin"], max_bytes)
                    origin = str(offline_file)
                else:
                    request = Request(wanted["source_url"], headers={"User-Agent": "CyxiaOS-desktop-ports/1"})
                    with build_opener(HTTPSRedirects()).open(request, timeout=15) as source:
                        https_url(source.geturl(), redirects=True)
                        length = source.headers.get("Content-Length")
                        if length is not None and (not length.isdigit() or int(length) > max_bytes):
                            raise PortError("invalid or excessive source Content-Length")
                        digest, size = copy_verified(source, payload, wanted["pin"], max_bytes)
                        origin = source.geturl()
            else:
                git_run(["init", "--bare", "repository.git"], stage, max_bytes)
                if offline_file:
                    git_run(["--git-dir=repository.git", "bundle", "verify", str(offline_file)],
                            stage, max_bytes)
                remote = str(offline_file) if offline_file else wanted["source_url"]
                args = ["--git-dir=repository.git", "fetch", "--no-tags", "--no-recurse-submodules"]
                if not offline_file:
                    args += ["--depth=1"]
                git_run(args + [remote, wanted["pin"]], stage, max_bytes,
                        local_bundle=offline_file is not None, online=offline_file is None)
                fetched = git_run(["--git-dir=repository.git", "rev-parse", "FETCH_HEAD"], stage, max_bytes)
                if fetched != wanted["pin"]:
                    raise PortError("fetched Git commit differs from the manifest")
                git_identity(stage, wanted["pin"], max_bytes)
                payload = stage / "source.tar"
                git_run(["--git-dir=repository.git", "archive", "--format=tar", wanted["pin"]],
                        stage, max_bytes, output=payload)
                digest, size = hash_file(payload, max_bytes)
                origin = remote
            record = {"identity": wanted, "sha256": digest, "bytes": size,
                      "retrieved_from": origin, "mode": "offline" if offline_file else "online",
                      "checked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "extracted": False, "built": False, "signature_verified": False}
            with (stage / "provenance.json").open("x") as handle:
                json.dump(record, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(stage, final)
        return {"status": "verified", "directory": str(final), **record}
    finally:
        lock.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("inventory", help="read the manifest and local tool paths; never download")
    check = commands.add_parser("check", help="fail on missing pins/dependency closure; never download")
    check.add_argument("--package")
    acquire = commands.add_parser("fetch", help="prepare exactly one pinned source")
    acquire.add_argument("--package", required=True)
    source = acquire.add_mutually_exclusive_group(required=True)
    source.add_argument("--online", action="store_true")
    source.add_argument("--offline-file", type=Path, help="matching source archive or self-contained Git bundle")
    validate = commands.add_parser("verify", help="verify cached source without network")
    validate.add_argument("--package", required=True)
    args = parser.parse_args(argv)
    try:
        if args.max_bytes < 1:
            raise PortError("--max-bytes must be positive")
        manifest = load_manifest(args.manifest)
        command = args.command or "inventory"
        if command in ("inventory", "check"):
            result = inspect_manifest(manifest, getattr(args, "package", None))
            status = 0 if command == "inventory" or result["source_closure_ready"] else 1
            if command == "check" and not args.package and not result["manifest_closure_complete"]:
                status = 1
        else:
            package = package_named(manifest, args.package)
            if command == "verify":
                result = verify(package, args.cache.resolve(), args.max_bytes)
            else:
                result = fetch(package, args.cache, online=args.online,
                               offline_file=args.offline_file, max_bytes=args.max_bytes)
            status = 0
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return status
    except (PortError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "error", "reason": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
