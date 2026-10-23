#!/usr/bin/env python3
"""Offline COSMIC source/backend inventory; explicit fetch never builds or runs it.

Pins and AArch64 library files are prerequisites, not proof of ABI compatibility.
This tool cannot certify a compositor build or guest runtime. It deliberately
keeps those gates closed until an implementation and dedicated guest gates exist.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'ports/cosmic/manifest.json'
CACHE = ROOT / 'artifacts/cosmic-sources'
SYSROOT = ROOT / 'artifacts/sysroot/aarch64-musl/sysroot'
COMMIT = re.compile(r'[0-9a-f]{40}')
SAFE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*')


class PortError(ValueError):
    """Source identity, architecture, or preparation failure."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PortError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def plain_name(value):
    if not isinstance(value, str) or not SAFE_NAME.fullmatch(value) or '..' in value:
        raise PortError('expected a plain component/directory name')
    return value


def repository_url(value):
    if not isinstance(value, str) or any(ord(c) <= 32 for c in value):
        raise PortError('repository must be an HTTPS URL')
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise PortError('malformed repository URL') from error
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise PortError('repository must be HTTPS without credentials/query/fragment')
    return value.rstrip('/').removesuffix('.git')


def validate_source(source):
    if not isinstance(source, dict):
        raise PortError('source must be an object')
    plain_name(source.get('name'))
    plain_name(source.get('directory'))
    repository_url(source.get('repository'))
    if not isinstance(source.get('commit'), str) or not COMMIT.fullmatch(source['commit']):
        raise PortError('source needs a full immutable commit')


def load_manifest(path=MANIFEST):
    manifest = json.loads(Path(path).read_text(), object_pairs_hook=unique_object)
    if manifest.get('schema_version') != 1 or manifest.get('target') != 'aarch64-unknown-linux-musl':
        raise PortError('unsupported manifest schema or target')
    sources = [manifest['epoch'], *manifest['components']]
    names, directories = set(), set()
    for source in sources:
        validate_source(source)
        if source['name'] in names or source['directory'] in directories:
            raise PortError('duplicate source identity or directory')
        names.add(source['name'])
        directories.add(source['directory'])
    comp = manifest['compositor']
    if comp['component'] not in {p['name'] for p in manifest['components']}:
        raise PortError('compositor absent from epoch component lock')
    if not re.fullmatch(r'[0-9a-f]{64}', comp['cargo_lock_sha256']):
        raise PortError('invalid Cargo.lock SHA256')
    if not re.fullmatch(r'\d+\.\d+(\.\d+)?', comp['rust_version']):
        raise PortError('invalid Rust minimum version')
    git_sources = comp['cargo_git_sources']
    if len(git_sources) != len(set(git_sources)):
        raise PortError('duplicate Cargo git pin')
    for source in git_sources:
        if not re.fullmatch(r'git\+https://[^\s#]+#[0-9a-f]{40}', source):
            raise PortError('Cargo git dependency lacks a full commit')
    if manifest['backend']['candidate'] != 'winit-software-egl':
        raise PortError('unsupported backend candidate')
    if manifest['backend']['implemented'] is not False:
        raise PortError('this inventory does not certify a backend implementation')
    library_names = set()
    for library in manifest['target_libraries']:
        plain_name(library['name'])
        if library['name'] in library_names:
            raise PortError('duplicate target library')
        library_names.add(library['name'])
        for pattern in library['filenames']:
            if not re.fullmatch(r'lib[A-Za-z0-9_.-]+(?:\.\*)?', pattern):
                raise PortError('invalid target library filename pattern')
    return manifest


def run(args, *, timeout=30):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=env)
    if result.returncode:
        raise PortError(f'{args[0]} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def git(path, *args):
    return run(['git', '-C', str(path), *args])


def source_path(cache, source):
    validate_source(source)
    path = Path(cache) / source['directory']
    if path.is_symlink():
        raise PortError(f'source directory is a symlink: {path}')
    return path


def inspect_source(cache, source):
    record = {**source, 'verified': False, 'status': 'not-fetched'}
    try:
        path = source_path(cache, source)
        record['path'] = str(path)
        if not path.exists():
            return record
        # Prevent an uninitialized subdirectory from accidentally using the
        # enclosing CyxiaOS repository. Worktrees with a .git file are valid.
        if Path(git(path, 'rev-parse', '--show-toplevel')).resolve() != path.resolve():
            raise PortError('source directory is not its own Git worktree')
        record['actual_commit'] = git(path, 'rev-parse', 'HEAD')
        record['actual_repository'] = git(path, 'remote', 'get-url', 'origin')
        if record['actual_commit'] != source['commit']:
            raise PortError('source commit differs from epoch pin')
        if repository_url(record['actual_repository']) != repository_url(source['repository']):
            raise PortError('source origin differs from pinned repository')
        if git(path, 'status', '--porcelain', '--untracked-files=all'):
            raise PortError('source worktree is modified or has untracked files')
        record.update(verified=True, status='verified', commit_time=git(path, 'show', '-s', '--format=%cI'))
    except (PortError, OSError, subprocess.SubprocessError) as error:
        record.update(status='invalid', error=str(error))
    return record


def epoch_pins(path):
    """Read all gitlinks and URLs from the same pinned Git tree, no submodule init."""
    urls = {}
    for section in re.split(r'\[submodule [^\]]+\]', git(path, 'show', 'HEAD:.gitmodules'))[1:]:
        fields = dict(re.findall(r'^\s*(path|url)\s*=\s*(\S+)\s*$', section, re.M))
        if set(fields) != {'path', 'url'} or fields['path'] in urls:
            raise PortError('invalid or duplicate epoch submodule mapping')
        urls[fields['path']] = fields['url']
    pins = {}
    for line in git(path, 'ls-tree', 'HEAD').splitlines():
        metadata, name = line.split('\t', 1)
        mode, kind, commit = metadata.split()
        if mode == '160000':
            if kind != 'commit' or name not in urls:
                raise PortError('gitlink lacks its submodule URL')
            pins[name] = (commit, repository_url(urls[name]))
    # Upstream can retain a stale .gitmodules entry (currently simple-wrapper).
    # Record it explicitly; never invent a commit or silently fetch its branch.
    unlinked = {name: repository_url(urls[name]) for name in set(urls) - set(pins)}
    return pins, unlinked


def inspect_locks(manifest, cache, sources):
    checks = {'epoch_components': False, 'compositor_cargo_lock': False, 'errors': []}
    by_name = {s['name']: s for s in sources}
    epoch = by_name[manifest['epoch']['name']]
    comp = by_name[manifest['compositor']['component']]
    try:
        if not epoch['verified']:
            raise PortError('epoch checkout is not verified')
        expected = {p['name']: (p['commit'], repository_url(p['repository'])) for p in manifest['components']}
        actual, unlinked = epoch_pins(Path(epoch['path']))
        expected_unlinked = {p['name']: repository_url(p['repository'])
                             for p in manifest.get('epoch_unlinked_submodules', [])}
        if actual != expected or unlinked != expected_unlinked:
            raise PortError('manifest does not match the complete epoch gitlink/URL set')
        checks['epoch_components'] = True
    except (PortError, OSError, subprocess.SubprocessError) as error:
        checks['errors'].append(str(error))
    try:
        if not comp['verified']:
            raise PortError('compositor checkout is not verified')
        data = (Path(comp['path']) / 'Cargo.lock').read_bytes()
        lock = tomllib.loads(data.decode())
        expected = manifest['compositor']
        actual_sources = sorted({p['source'] for p in lock['package'] if p.get('source', '').startswith('git+')})
        if (hashlib.sha256(data).hexdigest() != expected['cargo_lock_sha256']
                or len(lock['package']) != expected['cargo_lock_package_count']
                or actual_sources != expected['cargo_git_sources']):
            raise PortError('compositor Cargo.lock hash/count/git pins differ')
        checks['compositor_cargo_lock'] = True
    except (PortError, OSError, ValueError, KeyError) as error:
        checks['errors'].append(str(error))
    return checks


def elf_header(data, allowed_types):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise PortError('not ELF64 little-endian')
    kind, machine = struct.unpack_from('<HH', data, 16)
    if machine != 183 or kind not in allowed_types:
        raise PortError('not an AArch64 ELF object of the expected kind')


def architecture(path, *, rust_archive=False):
    """Reject host objects, empty/thin/truncated archives and external symlinks."""
    path = Path(path)
    data = path.read_bytes()
    count = 0
    if data.startswith(b'!<arch>\n'):
        offset = 8
        while offset < len(data):
            header = data[offset:offset + 60]
            if len(header) != 60 or header[58:] != b'`\n':
                raise PortError('invalid archive header')
            try:
                size = int(header[48:58])
            except ValueError as error:
                raise PortError('invalid archive size') from error
            end = offset + 60 + size
            if size < 0 or end > len(data):
                raise PortError('truncated archive member')
            body, name = data[offset + 60:end], header[:16].strip()
            if name not in (b'/', b'//', b'/SYM64/'):
                # rustc's .rlib includes a non-ELF metadata member. Regular C
                # libraries do not get this exception, nor do arbitrary bytes.
                metadata = rust_archive and name in (b'lib.rmeta/', b'lib.rmeta')
                if not metadata:
                    elf_header(body, (1,))
                    count += 1
            offset = end + size % 2
        if offset != len(data) or count == 0:
            raise PortError('empty or truncated archive')
        kind = 'static-archive'
    else:
        elf_header(data, (3,))
        count, kind = 1, 'shared-object'
    return {'kind': kind, 'aarch64_objects': count, 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def inspect_libraries(manifest, sysroot):
    root = Path(sysroot).resolve()
    results = []
    # Never invoke host pkg-config or search /usr/lib on the build machine.
    for library in manifest['target_libraries']:
        files, candidates = [], set()
        for relative in ('usr/lib', 'lib', 'usr/lib/aarch64-linux-musl'):
            for pattern in library['filenames']:
                candidates.update((root / relative).glob(pattern))
        for path in sorted(candidates):
            item = {'file': str(path), 'architecture_verified': False}
            try:
                if not path.resolve().is_relative_to(root):
                    raise PortError('library symlink escapes the target sysroot')
                item.update(architecture(path), architecture_verified=True)
            except (PortError, OSError, ValueError) as error:
                item['error'] = str(error)
            files.append(item)
        results.append({**library, 'files': files,
                        'target_library_present': any(f['architecture_verified'] for f in files),
                        'linked': False, 'guest_tested': False})
    return results


def inspect_rust(target, minimum, rustc=None):
    compiler = rustc or shutil.which('rustc', path=str(Path.home() / '.cargo/bin') + os.pathsep + os.environ.get('PATH', ''))
    result = {'compiler': compiler, 'target': target, 'minimum_version': minimum,
              'minimum_version_met': False, 'std_target_present': False, 'guest_tested': False}
    try:
        if not compiler:
            raise PortError('rustc not found')
        result['version'] = run([compiler, '--version'])
        match = re.search(r'rustc (\d+)\.(\d+)\.(\d+)', result['version'])
        if not match:
            raise PortError('unrecognized rustc version')
        result['minimum_version_met'] = tuple(map(int, match.groups())) >= tuple(map(int, (minimum + '.0').split('.')[:3]))
        directory = Path(run([compiler, '--print', 'target-libdir', '--target', target]))
        result['target_libdir'] = str(directory)
        archives = sorted(directory.glob('libstd-*.rlib'))
        if not archives:
            raise PortError('target libstd rlib is not installed')
        result['std_archives'] = [{'file': str(p), **architecture(p, rust_archive=True)} for p in archives]
        result['std_target_present'] = True
    except (PortError, OSError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    return result


def inventory(manifest, cache=CACHE, sysroot=SYSROOT, rustc=None):
    sources = [inspect_source(cache, p) for p in [manifest['epoch'], *manifest['components']]]
    checks = inspect_locks(manifest, cache, sources)
    libraries = inspect_libraries(manifest, sysroot)
    rust = inspect_rust(manifest['target'], manifest['compositor']['rust_version'], rustc)
    blockers = [{'id': p['id'], 'scope': p['scope'], 'status': 'requires-implementation-or-guest-evidence',
                 'detail': p['detail']} for p in manifest['required_work']]
    if not checks['epoch_components'] or not checks['compositor_cargo_lock']:
        blockers.append({'id': 'source-lock-validation', 'scope': 'source', 'detail': checks['errors']})
    if not rust['std_target_present'] or not rust['minimum_version_met']:
        blockers.append({'id': 'rust-target', 'scope': 'build', 'detail': rust.get('error', 'rustc is below minimum version')})
    for library in libraries:
        if not library['target_library_present'] and library['scope'] == 'winit-software-candidate':
            blockers.append({'id': 'target-library-' + library['name'], 'scope': 'build',
                             'detail': 'No verified AArch64 candidate library in the selected target sysroot.'})
    return {'target': manifest['target'], 'backend': manifest['backend'], 'sources': sources,
            'component_count': len(manifest['components']), 'lock_checks': checks,
            'compositor_lock': manifest['compositor'], 'initial_comp_audit': manifest['initial_comp_audit'],
            'epoch_unlinked_submodules': manifest.get('epoch_unlinked_submodules', []),
            'rust': rust, 'target_libraries': libraries, 'blockers': blockers,
            'source_pins_verified': checks['epoch_components'] and checks['compositor_cargo_lock'],
            'source_verification_scope': [manifest['epoch']['name'], manifest['compositor']['component']],
            'source_closure_vendored': False, 'compositor_build_ready': False,
            'compositor_built': False, 'guest_runtime_ready': False, 'full_cosmic_session_ready': False,
            'network_used': False, 'guest_execution': 'not performed',
            'scope_note': 'Offline prerequisite inventory; presence and architecture do not establish link or runtime compatibility.'}


def fetch_source(source, cache=CACHE):
    """Fetch one exact source, never reset an existing tree or initialize submodules."""
    path = source_path(cache, source)
    if path.exists():
        record = inspect_source(cache, source)
        if not record['verified']:
            raise PortError('existing source preserved: ' + record.get('error', record['status']))
        return {**record, 'network_used': False}
    Path(cache).mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(cache).free < 512 * 1024 * 1024:
        raise PortError('less than 512 MiB free; refusing source fetch')
    lock = Path(cache) / ('.' + source['directory'] + '.fetch.lock')
    try:
        lock.mkdir()
    except FileExistsError as error:
        raise PortError('another fetch holds ' + str(lock)) from error
    try:
        with tempfile.TemporaryDirectory(prefix='.' + source['directory'] + '-', dir=cache) as temporary:
            staging = Path(temporary) / 'checkout'
            run(['git', 'init', '--quiet', str(staging)])
            git(staging, 'remote', 'add', 'origin', source['repository'])
            run(['git', '-C', str(staging), '-c', 'protocol.file.allow=never',
                 '-c', 'submodule.recurse=false', 'fetch', '--no-recurse-submodules',
                 '--depth=1', 'origin', source['commit']], timeout=180)
            git(staging, '-c', 'submodule.recurse=false', 'checkout', '--detach', source['commit'])
            if git(staging, 'rev-parse', 'HEAD') != source['commit']:
                raise PortError('fetch returned a different commit')
            if path.exists():
                raise PortError('destination appeared while fetching; preserving it')
            staging.rename(path)
        record = inspect_source(cache, source)
        if not record['verified']:
            raise PortError('fetched checkout failed verification: ' + record.get('error', record['status']))
        return {**record, 'network_used': True,
                'recursive_submodule_fetch': False, 'built': False, 'guest_execution': 'not performed'}
    finally:
        lock.rmdir()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('inventory', 'check', 'fetch'), default='inventory')
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    parser.add_argument('--cache', type=Path, default=CACHE)
    parser.add_argument('--sysroot', type=Path, default=SYSROOT)
    parser.add_argument('--rustc')
    parser.add_argument('--component', help='fetch exactly cosmic-epoch or one locked component')
    parser.add_argument('--output', type=Path, help='write the JSON report to this file as well')
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        if args.action == 'fetch':
            if not args.component:
                raise PortError('fetch requires --component; no recursive or implicit bulk download')
            sources = {p['name']: p for p in [manifest['epoch'], *manifest['components']]}
            if args.component not in sources:
                raise PortError('component is not in the locked epoch')
            report = fetch_source(sources[args.component], args.cache)
        else:
            if args.component:
                raise PortError('--component is only valid for fetch')
            report = inventory(manifest, args.cache, args.sysroot, args.rustc)
        report['manifest_sha256'] = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
        encoded = json.dumps(report, indent=2) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded)
        print(encoded, end='')
        return 1 if args.action == 'check' and not report['compositor_build_ready'] else 0
    except (PortError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f'COSMIC preflight: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
