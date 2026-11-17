#!/usr/bin/env python3
"""Copy nine fixed genuine COSMIC font/license assets; never generate or run them.

Cargo's normal file:// cache origin is accepted. The upstream association comes
from the complete pinned notification Cargo.lock and its full libcosmic source
pin. Canonical Git commit/tree/blob identities, modes and file bytes are checked
again before atomic publication. This tool performs no acquisition or native run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'ports/cosmic/fonts-v1/source-policy.json'
POLICY_SHA256 = '22f83868cc3867448f070178738d12ba35c1556bb8f80246b5af8da6a4ebbfa8'
CHECKOUT = ROOT / 'artifacts/cosmic-runtime-cargo-cache/git/checkouts/libcosmic-41009aea1d72760b/5a8bd94'
NOTIFICATION_LOCK = ROOT / 'artifacts/cosmic-sources/cosmic-notifications/Cargo.lock'
REPOSITORY = 'https://github.com/pop-os/libcosmic'
COMMIT = '5a8bd9482a35ae94c1e54edf77b331c6b970f170'
GIT_TREE = 'd58817590f7e9e27540b0d42fc84652a10d7084f'
RECEIPT = 'cosmic-font-assets.json'
MAX_FILE_BYTES = 2 * 1024**2
MAX_TOTAL_BYTES = 4 * 1024**2
SOURCES = ('res/open-sans/OpenSans-Regular.ttf', 'res/open-sans/OpenSans-Light.ttf',
           'res/open-sans/OpenSans-Semibold.ttf', 'res/open-sans/OpenSans-Bold.ttf',
           'res/open-sans/OpenSans-ExtraBold.ttf', 'res/open-sans/LICENSE',
           'res/noto/NotoSansMono-Regular.ttf', 'res/noto/NotoSansMono-Bold.ttf', 'res/noto/LICENSE')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def plain_path(path):
    require(isinstance(path, (str, Path)), 'Invalid font input path')
    path = Path(path).absolute()
    require('..' not in path.parts, 'Font path traversal is not allowed')
    for parent in (*reversed(path.parents), path):
        require(not parent.is_symlink(), 'Font input/output aliases are not allowed: ' + str(parent))
    return path


def read_regular(path, limit=MAX_FILE_BYTES):
    path = plain_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
                'Font input is not a bounded regular file')
        data = stream.read(limit + 1)
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns)
        require(len(data) == before.st_size and len(data) <= limit
                and key(before) == key(os.fstat(stream.fileno())) == key(path.stat(follow_symlinks=False)),
                'Font input changed during read')
        return data


def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate font evidence JSON key')
        result[key] = value
    return result


def json_file(path):
    value = json.loads(read_regular(path), object_pairs_hook=no_duplicates)
    require(type(value) is dict, 'Font evidence must be a JSON object')
    return value


def destination(relative):
    if relative.endswith('.ttf'):
        return '/usr/share/fonts/cosmic/' + Path(relative).name
    family = 'OpenSans' if relative.startswith('res/open-sans/') else 'NotoSansMono'
    return '/usr/share/licenses/cosmic-fonts/' + family + '-LICENSE'


def load_policy(path=POLICY):
    raw = read_regular(path)
    require(identity(raw)['sha256'] == POLICY_SHA256, 'Unreviewed COSMIC font policy')
    policy = json.loads(raw, object_pairs_hook=no_duplicates)
    require(type(policy) is dict and set(policy) == {'schema_version', 'kind', 'source', 'notification_lock', 'files'}
            and type(policy['schema_version']) is int and policy['schema_version'] == 1
            and policy['kind'] == 'cosmic-font-assets-v1', 'Invalid COSMIC font policy schema')
    require(policy['source'] == {'repository': REPOSITORY, 'commit': COMMIT, 'git_tree': GIT_TREE},
            'Font source selection changed')
    lock = policy['notification_lock']
    require(type(lock) is dict and set(lock) == {'sha256', 'package'}
            and isinstance(lock['sha256'], str) and re.fullmatch('[0-9a-f]{64}', lock['sha256'])
            and lock['package'] == {'name': 'libcosmic', 'version': '1.0.0',
                                    'source': 'git+' + REPOSITORY + '#' + COMMIT},
            'Font source lacks its complete notification lock pin')
    files = policy['files']
    require(type(files) is dict and set(files) == {destination(name) for name in SOURCES},
            'Font policy must select exactly seven fonts and two licenses')
    for relative in SOURCES:
        row = files[destination(relative)]
        require(type(row) is dict and set(row) == {'source_relative', 'bytes', 'sha256', 'git_blob', 'mode'}
                and row['source_relative'] == relative and row['mode'] == '100644'
                and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE_BYTES
                and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256'])
                and isinstance(row['git_blob'], str) and re.fullmatch('[0-9a-f]{40}', row['git_blob']),
                'Invalid font path, mode or content identity')
    require(sum(row['bytes'] for row in files.values()) <= MAX_TOTAL_BYTES, 'Font closure exceeds byte budget')
    return policy


def git_bytes(checkout, *arguments):
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_OPTIONAL_LOCKS': '0'}
    result = subprocess.run(['/usr/bin/git', '-C', str(checkout), '--no-replace-objects', *arguments],
                            env=env, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    require(result.returncode == 0 and len(result.stdout) <= MAX_FILE_BYTES,
            'Cannot read canonical font Git identity')
    return result.stdout


def verify_sources(checkout, notification_lock, policy):
    checkout, notification_lock = plain_path(checkout), plain_path(notification_lock)
    require(checkout.is_dir() and plain_path(checkout / '.git').is_dir(), 'Missing font Git checkout')
    def checkout_identity():
        require(git_bytes(checkout, 'rev-parse', '--show-toplevel').decode().strip() == str(checkout)
                and git_bytes(checkout, 'rev-parse', 'HEAD').decode().strip() == COMMIT
                and git_bytes(checkout, 'rev-parse', 'HEAD^{tree}').decode().strip() == GIT_TREE,
                'Font checkout HEAD or canonical tree changed')
    checkout_identity()
    locked = read_regular(notification_lock)
    require(identity(locked)['sha256'] == policy['notification_lock']['sha256'],
            'Original notification Cargo.lock changed')
    selected = [p for p in tomllib.loads(locked.decode())['package'] if p['name'] == 'libcosmic']
    require(len(selected) == 1 and {key: selected[0].get(key) for key in ('name', 'version', 'source')}
            == policy['notification_lock']['package'], 'Notification lock selects a different libcosmic source')
    observed = {}
    for record in git_bytes(checkout, 'ls-tree', '-rz', 'HEAD', '--', *SOURCES).decode().split('\0'):
        if not record:
            continue
        head, relative = record.split('\t', 1)
        require(relative not in observed and relative in SOURCES, 'Unexpected font Git tree entry')
        observed[relative] = head
    require(set(observed) == set(SOURCES), 'Incomplete pinned font Git tree')
    files = {}
    for guest, expected in policy['files'].items():
        relative = expected['source_relative']
        path = plain_path(checkout / relative)
        raw = read_regular(path)
        require(path.stat().st_mode & 0o777 == 0o644, 'Font source file mode changed')
        require(identity(raw) == {key: expected[key] for key in ('bytes', 'sha256')},
                'Font/license content differs from reviewed bytes')
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(blob == expected['git_blob'] and observed[relative] == '100644 blob ' + blob
                and git_bytes(checkout, 'cat-file', 'blob', blob) == raw,
                'Font/license differs from its canonical Git blob')
        files[guest] = {**expected, 'source': str(path)}
    checkout_identity()
    return {'source': {**policy['source'], 'checkout': str(checkout)}, 'files': files,
            'notification_lock': {'path': str(notification_lock), **identity(locked),
                                  'package': policy['notification_lock']['package']}}


def producers():
    path = plain_path(__file__)
    return {str(path.relative_to(ROOT)): identity(read_regular(path))}


def validate_inputs(prefix):
    """Recheck a standalone or curated prefix without executing any font loader."""
    prefix = plain_path(prefix)
    report = json_file(prefix / RECEIPT)
    require(set(report) == {'schema_version', 'status', 'source', 'files', 'policy', 'notification_lock',
                            'producers', 'guest_font_loading_observed'}
            and type(report['schema_version']) is int and report['schema_version'] == 1
            and report['status'] == 'ASSETS_INSTALLED_NOT_RUN' and report['guest_font_loading_observed'] is False,
            'Invalid font installation receipt')
    try:
        policy_path = plain_path(report['policy']['path'])
        policy = load_policy(policy_path)
        require(report['policy'] == {'path': str(policy_path), **identity(read_regular(policy_path))}
                and report['producers'] == producers(), 'Font policy or installer identity changed')
        proof = verify_sources(report['source']['checkout'], report['notification_lock']['path'], policy)
        require(all(report[key] == value for key, value in proof.items()), 'Font source or lock receipt changed')
        for guest, row in proof['files'].items():
            installed = plain_path(prefix / 'rootfs' / guest.lstrip('/'))
            require(identity(read_regular(installed)) == {key: row[key] for key in ('bytes', 'sha256')}
                    and installed.stat().st_mode & 0o777 == 0o644, 'Installed font/license bytes or mode changed')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed font installation evidence') from error
    return report


def install(output, *, checkout=CHECKOUT, notification_lock=NOTIFICATION_LOCK, policy_path=POLICY):
    output, checkout, notification_lock, policy_path = map(plain_path,
        (output, checkout, notification_lock, policy_path))
    require(not output.exists(), 'Preserving existing font installation')
    for path in (checkout, notification_lock, policy_path):
        require(not output.is_relative_to(path) and not path.is_relative_to(output),
                'Font output overlaps a source input')
    policy = load_policy(policy_path)
    proof = verify_sources(checkout, notification_lock, policy)
    report = {'schema_version': 1, 'status': 'ASSETS_INSTALLED_NOT_RUN', **proof,
              'policy': {'path': str(policy_path), **identity(read_regular(policy_path))},
              'producers': producers(), 'guest_font_loading_observed': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary)
        for guest, row in proof['files'].items():
            raw = read_regular(row['source'])
            require(identity(raw) == {key: row[key] for key in ('bytes', 'sha256')},
                    'Font source changed while copying')
            target = pending / 'rootfs' / guest.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            target.chmod(0o644)
        with (pending / RECEIPT).open('x') as stream:
            json.dump(report, stream, indent=2); stream.write('\n')
            stream.flush(); os.fsync(stream.fileno())
        validate_inputs(pending)
        require(not output.exists() and not output.is_symlink(), 'Preserving concurrently created font installation')
        pending.rename(output)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--checkout', type=Path, default=CHECKOUT)
    parser.add_argument('--notification-lock', type=Path, default=NOTIFICATION_LOCK)
    parser.add_argument('--policy', type=Path, default=POLICY)
    args = parser.parse_args(argv)
    try:
        report = install(args.output, checkout=args.checkout,
                         notification_lock=args.notification_lock, policy_path=args.policy)
        print(json.dumps({'status': report['status'], 'files': len(report['files']),
                          'asset_bytes': sum(row['bytes'] for row in report['files'].values()),
                          'guest_font_loading_observed': False}, indent=2))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('COSMIC font installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
