"""One explicit peer-lifecycle delta on the frozen, genuine static-v2 port."""
import json
from pathlib import Path
import subprocess

import cosmic_notifications_static_v1 as static
import install_cosmic_notifications_static_v1 as parent_consumer

ROOT = static.ROOT
PORT = ROOT / 'ports/cosmic/native-notifications-peer-v2'
POLICY_SHA256 = '674e3d9ddd6484378c89b7cc6af4673fe45cbd9dab0c7a9f231fdcf19f90aef1'
KIND = 'cosmic-notifications-peer-v2'
require = static.require


def load_policy():
    raw = static.read_regular(PORT / 'source-policy.json')
    require(static.sha(raw) == POLICY_SHA256, 'Peer source policy changed')
    policy = json.loads(raw, object_pairs_hook=static.no_duplicates)
    parent_port = ROOT / static.build.dependencies.relative_path(policy['parent_port'])
    require(policy['kind'] == KIND and policy['active_handshake_seconds'] == policy['client_handshake_seconds'] == 5
            and policy['full_os_verified'] is False and policy['cosmic_session_verified'] is False
            and static.sha(static.read_regular(parent_port / 'native-recipe.json'))
                == policy['parent_recipe_sha256']
            and static.sha(static.read_regular(parent_port / 'source-policy.json'))
                == policy['parent_policy_sha256'] == static.POLICY_SHA256,
            'Peer port changed its frozen parent or runtime verdict')
    patch = PORT / static.build.dependencies.relative_path(policy['patch']['path'])
    require(static.sha(static.read_regular(patch)) == policy['patch']['sha256'], 'Peer patch changed')
    return policy, parent_port


def validate_parent(output):
    policy, port = load_policy()
    output = static.build.no_symlink_path(output)
    validated = parent_consumer.validate_build_directory(output)
    report = static.build.load_json(output / 'build-report.json')
    require(Path(report['recipe_path']) == port / 'native-recipe.json'
            and report['recipe_sha256'] == policy['parent_recipe_sha256'],
            'Peer build requires the admitted static-v2 recipe')
    return report, validated


def expected_tree(parent_tree):
    policy, _ = load_policy()
    files = dict(parent_tree['files'])
    require(set(policy['changed_files']) == {
        'src/subscriptions/applet.rs', 'src/subscriptions/notifications.rs'},
        'Peer patch must only change the two actual subscriptions')
    for name, change in policy['changed_files'].items():
        require(files[name] == change['before'], 'Peer patch input changed: ' + name)
        files[name] = change['after']
    tree = {'files': files, 'sha256': static.canonical_hash(files)}
    require(tree['sha256'] == policy['source_tree_sha256'], 'Peer expected export changed')
    return tree


def validate_source(source, parent_tree):
    actual = static.read_tree(source)
    require(actual == expected_tree(parent_tree), 'Peer export differs outside its reviewed patch')
    return actual


def export_source(parent, destination):
    policy, port = load_policy()
    old_policy = static.load_policy(port / 'source-policy.json')
    original = Path(parent['source_cache']) / parent['component']['directory']
    record = static.export_source(original, Path(parent['cache']), destination, port / 'source-policy.json')
    require(record == parent['static_source'], 'Peer parent export differs from its admitted build')
    patch = PORT / policy['patch']['path']
    for check in (['--check'], []):
        subprocess.run(['/usr/bin/git', 'apply', *check, str(patch)], cwd=destination,
                       env=static.build.clean_environment('/usr/bin:/bin'), check=True, capture_output=True)
    return validate_source(destination, record['source_tree']), old_policy
