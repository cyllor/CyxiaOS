"""Independent exact-source export for panel allocation/error propagation.

The historical Linux-v2 source/Mesa summary receipts are unavailable locally.
This version does not recreate them: it revalidates every canonical Git tree,
registry archive, support file and the unchanged SDK/archive pins directly.
"""
from pathlib import Path
import stat
import subprocess

import cosmic_panel_linux_v3 as parent

base, require = parent.base, parent.require
PORT = base.ROOT / 'ports/cosmic/native-panel-allocation-v1'
PARENT = base.ROOT / parent.PORT


def contract():
    policy, recipe, component, profile = parent.contract(
        PARENT / 'native-recipe.json', PARENT / 'resource-profile.json', 2)
    fix = base.load_json(PORT / 'source-policy.json')
    require(fix['kind'] == 'cosmic-panel-allocation-v1'
            and fix['parent_policy_sha256'] == parent.POLICY_SHA256
            and fix['upstream_commit'] == component['commit']
            and fix['patch_sha256'] == base.digest(PORT / 'panel-allocation.patch'),
            'Panel allocation source contract changed')
    require(set(fix['before']) == set(fix['after']) == {
        'cosmic-panel-bin/src/xdg_shell_wrapper/util.rs',
        'cosmic-panel-bin/src/space/panel_space.rs',
        'cosmic-panel-bin/src/space/wrapper_space.rs'}, 'Unexpected panel allocation scope')
    return policy, recipe, component, profile, fix


def original_inputs(source_cache, native_cache, cargo_cache):
    policy, recipe, _, _, fix = contract()
    originals = {}
    for name, expected in policy['git_sources'].items():
        root = source_cache if expected['cache'] == 'original' else native_cache
        path = root / expected['directory']
        identity = parent.common.git_identity(path, expected['commit'])
        require(identity['commit'] == expected['commit']
                and identity['git_tree'] == expected['git_tree']
                and identity['sha256'] == expected['tree_sha256']
                and identity['total_bytes'] == expected['source_bytes']
                and len(identity['files']) == expected['file_count']
                and identity['submodules'] == {}, 'Panel canonical source changed: ' + name)
        require(base.ports.repository_url(parent.common.objects.pinned_git(
            path, 'remote', 'get-url', 'origin')) == parent.REPOSITORIES[name],
            'Panel source repository changed: ' + name)
        originals[name] = dict(path=str(path), **identity)
    registry = [parent.files.registry_snapshot(cargo_cache, spec)[2]
                for spec in policy['registry_inputs']]
    paths = {PARENT / 'source-policy.json': parent.POLICY_SHA256,
             PARENT / 'native-recipe.json': parent.RECIPE_SHA256,
             PARENT / 'resource-profile.json': parent.RESOURCE_SHA256,
             PARENT / policy['patch']['path']: policy['patch']['sha256'],
             PORT / 'panel-allocation.patch': fix['patch_sha256']}
    paths.update({base.ROOT / name: digest for name, digest in policy['support_inputs'].items()})
    require(all(base.digest(path) == digest for path, digest in paths.items()),
            'Frozen native panel support changed')
    paths[PORT / 'source-policy.json'] = base.digest(PORT / 'source-policy.json')
    require(base.digest(Path(originals['panel']['path']) / 'Cargo.lock') == recipe['source_lock_sha256'],
            'Panel original Cargo.lock changed')
    return dict(originals=originals, registry_inputs=registry,
                bindings={str(path): digest for path, digest in paths.items()},
                original_panel_configuration=policy['original_panel_configuration'])


def verify_export(stage, inputs):
    policy, recipe, _, _, fix = contract()
    expected, modes = parent.expected_export(policy, inputs)
    require(all(expected.get(name) == digest for name, digest in fix['before'].items()),
            'Panel allocation patch preimage changed')
    expected.update(fix['after'])
    actual = parent.files.read_tree(stage)
    require(set(actual['files']) == set(expected), 'Panel export inventory changed')
    for name, digest in expected.items():
        path = stage / name
        require(actual['files'][name]['sha256'] == digest
                and stat.S_IMODE(path.stat().st_mode) == modes[name],
                'Panel export differs from exact patch result: ' + name)
    require(base.digest(stage / 'Cargo.lock') == recipe['effective_lock_sha256'],
            'Panel allocation fix changed the complete lock')
    return actual


def export(source_cache, native_cache, cargo_cache, stage):
    policy, recipe, _, _, _ = contract()
    inputs = original_inputs(source_cache, native_cache, cargo_cache)
    for name in ('panel', 'launch_pad', 'smithay'):
        original = inputs['originals'][name]
        prefix = policy['git_sources'][name]['prefix']
        parent.common.export_canonical(Path(original['path']), stage / prefix, original['commit'])
    for spec in policy['registry_inputs']:
        content, modes, _ = parent.files.registry_snapshot(cargo_cache, spec)
        for name, data in content.items():
            path = stage / spec['prefix'] / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(modes[name])
    for patch in (PARENT / recipe['patches'][0]['path'], PORT / 'panel-allocation.patch'):
        for check in (['--check'], []):
            subprocess.run(['/usr/bin/git', 'apply', *check, str(patch)], cwd=stage,
                           check=True, capture_output=True, env=base.clean_environment('/usr/bin:/bin'))
    return inputs, verify_export(stage, inputs)
