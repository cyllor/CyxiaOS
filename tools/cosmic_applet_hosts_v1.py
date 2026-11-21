"""Exact-source 128-FD native launch adapters for genuine session and panel."""
import hashlib
import json
from pathlib import Path
import stat
import subprocess

import cosmic_panel_allocation_v2 as panel
import cosmic_session_linux_v2 as session

base, require = panel.base, panel.require
PORT = base.ROOT / 'ports/cosmic/native-applet-hosts-v1'
CACHE = base.ROOT / 'artifacts/cosmic-comp-cache'
SOURCES = base.ROOT / 'artifacts/cosmic-sources'
NATIVE = base.ROOT / 'artifacts/cosmic-native-sources'
NAMES = {'panel': 'cosmic-panel', 'session': 'cosmic-session'}


def parent_contract(kind):
    require(kind in NAMES, 'Unknown applet host')
    if kind == 'panel':
        policy, recipe, component, profile, _ = panel.contract()
    else:
        directory = base.ROOT / session.PORT
        policy, recipe, component, profile = session.contract(
            directory / 'native-recipe.json', directory / 'resource-profile.json', 1)
    return policy, recipe, component, profile


def original_export(kind, destination):
    policy, recipe, _, _ = parent_contract(kind)
    if kind == 'panel':
        inputs, _ = panel.export(SOURCES, NATIVE, CACHE, destination)
    else:
        inputs, _, _ = session.export_source(SOURCES,
            base.ROOT / session.PORT / 'native-recipe.json', recipe, policy, destination)
    return inputs


def canonical_inputs(kind):
    if kind == 'panel': return panel.original_inputs(SOURCES, NATIVE, CACHE)
    return session.verify_sources(SOURCES, base.ROOT / session.PORT / 'native-recipe.json', parent_contract(kind)[0])


def modes(root):
    return {name: stat.S_IMODE((root / name).stat().st_mode) for name in base.tree_identity(root)['files']}


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def contract(kind):
    policy = base.load_json(PORT / 'source-policy.json')
    record = policy['components'][kind]
    original = parent_contract(kind)
    require(policy['kind'] == 'cosmic-applet-hosts-v1' and policy['fd_limit'] == 128
            and set(policy['components']) == set(NAMES)
            and record['commit'] == original[2]['commit']
            and record['recipe_sha256'] == canonical(original[1])
            and record['patch_sha256'] == base.digest(PORT / (kind + '.patch'))
            and record['source_path'] == 'native-deps/launch-pad/src/native_child.rs',
            'Applet host source/feature/ABI contract changed')
    return record, original


def verify_export(kind, stage):
    record, _ = contract(kind)
    tree = base.tree_identity(stage)
    require(tree['sha256'] == record['after_tree_sha256']
            and canonical(modes(stage)) == record['mode_sha256']
            and base.digest(stage / record['source_path']) == record['after'],
            'Complete retained applet host source changed')
    return tree


def export(kind, destination):
    record, _ = contract(kind)
    inputs = original_export(kind, destination)
    require(base.tree_identity(destination)['sha256'] == record['before_tree_sha256']
            and base.digest(destination / record['source_path']) == record['before'],
            'Applet host patch preimage differs from genuine complete source')
    for flags in (['--check'], []):
        subprocess.run(['/usr/bin/git', 'apply', *flags, str(PORT / (kind + '.patch'))],
            cwd=destination, env=base.clean_environment('/usr/bin:/bin'), capture_output=True, check=True)
    return inputs, verify_export(kind, destination)


def metadata_identity(kind, metadata, stage, recipe, policy):
    if kind == 'panel':
        identity = panel.parent.metadata_identity(metadata, stage, CACHE, recipe, policy)
        return identity, identity['resolution']['package_id']
    return session.metadata_identity(metadata, stage, CACHE, recipe, policy), session.resolution(metadata, stage, recipe, policy)


def commands(kind, cargo, stage, recipe, package_id=None):
    if kind == 'panel': return panel.parent.commands(cargo, stage, recipe, 2, package_id)
    return session.commands(cargo, stage, recipe, 1, package_id)
