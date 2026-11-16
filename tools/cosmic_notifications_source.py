"""Exact review of notification Cargo configuration; no implicit Cargo settings.

Only the pinned root .cargo/config.toml is removed. Its two reviewed cfg flags
are supplied explicitly by the notification acquisition/build entry points.
The original checkout and frozen generic producers remain unchanged.
"""
import copy
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile

try:
    from . import build_cosmic as build
except ImportError:
    import build_cosmic as build

CONFIG = b'[build]\nrustflags = ["--cfg", "tokio_unstable"]\nrustdocflags = ["--cfg", "tokio_unstable"]\n'
CONFIG_SHA256 = hashlib.sha256(CONFIG).hexdigest()
FLAGS = ['--cfg', 'tokio_unstable']
POLICY_KEYS = {'schema_version', 'component', 'repository', 'commit', 'source_lock_sha256',
               'before', 'after', 'rust_flags', 'rustdoc_flags'}


def require(value, message):
    if not value:
        raise build.CosmicBuildError(message)


def validate_policy(policy, source, recipe):
    """Public pure-data validator; no arbitrary path/flag/config exemptions."""
    require(isinstance(policy, dict) and set(policy) == POLICY_KEYS
            and type(policy['schema_version']) is int and policy['schema_version'] == 1,
            'Unsupported notification source policy')
    require(source['name'] == policy['component'] == recipe['component'] == 'cosmic-notifications'
            and policy['commit'] == source['commit'] == recipe['commit']
            and build.ports.repository_url(policy['repository'])
                == build.ports.repository_url(source['repository'])
            and policy['source_lock_sha256'] == recipe['source_lock_sha256'],
            'Notification source policy differs from pinned recipe/source')
    require(policy['before'] == {'.cargo/config.toml': CONFIG_SHA256}
            and policy['after'] == {'.cargo/config.toml': None},
            'Only the exact reviewed notification configuration may be removed')
    require(policy['rust_flags'] == policy['rustdoc_flags'] == FLAGS
            and recipe.get('reviewed_rust_flags') == recipe.get('reviewed_rustdoc_flags') == FLAGS,
            'Unknown or inconsistent reviewed notification flags')
    require('source_series' not in recipe, 'Notification source series are unsupported')
    return policy


def load_policy(recipe, recipe_path, source):
    binding = recipe.get('source_export_policy')
    require(isinstance(binding, dict) and set(binding) == {'path', 'sha256'},
            'Notification recipe must bind its source export policy')
    relative = build.dependencies.relative_path(binding['path'])
    root = build.no_symlink_path(Path(recipe_path).parent)
    selected = build.no_symlink_path(root / relative)
    require(selected.is_relative_to(root) and selected.is_file()
            and build.digest(selected) == binding['sha256'], 'Notification source policy identity changed')
    return validate_policy(build.load_json(selected), source, recipe)


def archive_members(archive, max_bytes=64 * 1024**2):
    """Validate a complete export before extraction, including all Cargo configs."""
    members = archive.getmembers()
    require(sum(item.size for item in members) <= max_bytes, 'Notification export exceeds byte bound')
    seen, configs = set(), set()
    for item in members:
        relative = str(build.dependencies.relative_path(item.name.rstrip('/')))
        require(relative not in seen, 'Duplicate notification export path')
        seen.add(relative)
        require(item.isfile() or item.isdir(), 'Notification export contains non-regular entry')
        if '.cargo' in Path(relative).parts and Path(relative).name in ('config', 'config.toml'):
            require(item.isfile() and relative == '.cargo/config.toml',
                    'Unreviewed source Cargo configuration')
            data = archive.extractfile(item).read(len(CONFIG) + 1)
            require(item.size == len(CONFIG) and data == CONFIG,
                    'Reviewed notification Cargo configuration changed')
            configs.add(relative)
    require(configs == {'.cargo/config.toml'}, 'Reviewed notification configuration is absent')
    return members


def export_source(source, output, policy):
    """Root-lease operation: preserve HEAD, export, and apply one exact removal."""
    source = build.no_symlink_path(source)
    output = build.no_symlink_path(output)
    require(not output.is_relative_to(source) and not source.is_relative_to(output),
            'Notification export overlaps original source')
    require(not output.exists(), 'Preserving existing notification export')
    pin = dict(name=policy['component'], repository=policy['repository'],
               commit=policy['commit'], directory=source.name)
    build.inspect_source(source.parent, pin)
    require(build.digest(source / 'Cargo.lock') == policy['source_lock_sha256'],
            'Notification source lock changed')
    producer = build.digest(__file__)
    output.mkdir(parents=True)
    with tempfile.TemporaryFile() as stream:
        subprocess.run(['/usr/bin/git', '-C', str(source), 'archive', '--format=tar', 'HEAD'],
                       env=build.clean_environment('/usr/bin:/bin'), stdout=stream, check=True)
        stream.seek(0)
        with tarfile.open(fileobj=stream) as archive:
            members = archive_members(archive)
            archive.extractall(output, members=members, filter='data')
    before = build.tree_identity(output)
    require((output / '.cargo/config.default').read_bytes() == CONFIG,
            'Notification packaging configuration changed')
    (output / '.cargo/config.toml').unlink()
    after = build.tree_identity(output)
    expected = copy.deepcopy(before['files'])
    removed = expected.pop('.cargo/config.toml')
    require(removed['sha256'] == CONFIG_SHA256 and after['files'] == expected,
            'Notification export contains undeclared changes')
    require(build.digest(__file__) == producer, 'Notification source exporter changed')
    build.inspect_source(source.parent, pin)
    return {'policy': policy, 'exporter_sha256': producer, 'original_tree': before,
            'source_tree': after, 'removed': {'.cargo/config.toml': removed},
            'source_preserved': True}


def cargo_environment(environment, policy):
    """Add the reviewed cfg without losing the caller's bounded static flags."""
    require(policy.get('rust_flags') == policy.get('rustdoc_flags') == FLAGS,
            'Unknown reviewed notification flags')
    result = dict(environment)
    require(not any(key in result for key in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS')),
            'Unreviewed notification flag environment')
    existing = result.get('CARGO_ENCODED_RUSTFLAGS', '')
    result['CARGO_ENCODED_RUSTFLAGS'] = (existing + '\x1f' if existing else '') + '\x1f'.join(FLAGS)
    result['CARGO_ENCODED_RUSTDOCFLAGS'] = '\x1f'.join(FLAGS)
    return result
