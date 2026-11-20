"""Exact complete Epoch 1.10.0 applets workspace with real static Wayland.

Only three manifests/lock files select the already verified native bindings.
The upstream clock, translations, GUI features and other workspace members are
retained. Validation reads canonical Git objects and pinned registry archives.
"""
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tomllib

import cosmic_panel_linux_v3 as parent
import cosmic_registry_inputs_v1 as registry

base, require, common, files = parent.base, parent.require, parent.common, parent.files
PORT = base.ROOT / 'ports/cosmic/native-time-applet-v2'
TARGET = parent.TARGET
FEATURES = ['cosmic-applet-time/cyxia-native']
COMMIT = '406d1b7d627138fdf4078f654268d3d8774e50f1'


def contract():
    policy = base.load_json(PORT / 'source-policy.json')
    recipe = base.load_json(PORT / 'native-recipe.json')
    profile = base.load_json(PORT / 'resource-profile.json')
    require(policy['kind'] == 'cosmic-time-applet-v2' and policy['commit'] == COMMIT
            and policy['original']['commit'] == COMMIT
            and policy['original']['git_tree'] == 'c89eb775d158710941fa6084d21682b68d168f41'
            and set(policy['before']) == set(policy['after']) == {
                'Cargo.toml', 'Cargo.lock', 'cosmic-applet-time/Cargo.toml'}
            and base.digest(PORT / 'native.patch') == policy['patch_sha256'],
            'Clock complete source/patch contract changed')
    previous = base.load_json(Path(policy['parent_build']) / 'build-report.json')
    require(base.digest(Path(policy['parent_build']) / 'build-report.json') == policy['parent_report_sha256']
            and previous['status'] == 'cross-built'
            and recipe['native_inputs'] == previous['recipe']['native_inputs']
            and recipe['static_link_inputs'] == previous['recipe']['static_link_inputs']
            and recipe['native_sdk_origin'] == previous['recipe']['native_sdk_origin'],
            'Clock must use the actual previously verified Wayland/Mesa SDK')
    require(recipe['component'] == recipe['package'] == recipe['binary'] == 'cosmic-applet-time'
            and recipe['commit'] == COMMIT and recipe['target'] == TARGET
            and recipe['features'] == FEATURES and recipe['default_features'] is True
            and recipe['source_lock_sha256'] == policy['before']['Cargo.lock']
            and recipe['effective_lock_sha256'] == policy['after']['Cargo.lock']
            and recipe['patches'] == [{'path': 'native.patch', 'sha256': policy['patch_sha256']}],
            'Clock recipe changed the locked source, binary or GUI features')
    require({k: v for k, v in profile.items() if k != 'purpose'}
            == {k: v for k, v in previous['resource_profile'].items() if k != 'purpose'},
            'Clock must preserve the existing FullOs process/build bounds')
    component = dict(name=recipe['component'], commit=COMMIT, repository=policy['repository'])
    return policy, recipe, component, profile, policy


def original_inputs(source_cache, native_cache, cargo_cache):
    policy, _, _, _, _ = contract()
    path = base.no_symlink_path(source_cache / 'cosmic-applets-406d1b7')
    identity = common.git_identity(path, COMMIT)
    require(identity == policy['original'] and identity['submodules'] == {}
            and base.ports.repository_url(common.objects.pinned_git(path, 'remote', 'get-url', 'origin'))
                == policy['repository'], 'Original full applets Git tree changed')
    content, _, _ = files.registry_snapshot(cargo_cache, policy['xkb_registry_input'])
    require({n: files.sha(b) for n, b in content.items()} == policy['xkb_before']
            and set(policy['xkb_before']) == set(policy['xkb_after'])
            and base.digest(PORT / 'xkbcommon-static.patch') == policy['xkb_patch_sha256'],
            'Clock XKB original complete registry input changed')
    native = {}
    for name, record in policy['native_bindings'].items():
        selected = base.no_symlink_path(record['path'])
        tree = files.read_tree(selected)
        require(tree == {k: v for k, v in record.items() if k != 'path'},
                'Real native binding source changed: ' + name)
        if name == 'xkbcommon-dl':
            require({n: row['sha256'] for n, row in tree['files'].items()} == policy['xkb_after'],
                    'Clock actual XKB binding differs from reviewed full patch result')
        native[name] = dict(path=str(selected), **tree)
    return dict(originals={'applets': dict(path=str(path), **identity)}, native_bindings=native,
        bindings={str(PORT / name): base.digest(PORT / name) for name in (
            'source-policy.json', 'native-recipe.json', 'resource-profile.json', 'native.patch', 'xkbcommon-static.patch')})


def verify_export(stage, inputs):
    policy, recipe, _, _, _ = contract()
    expected = {name: row['sha256'] for name, row in inputs['originals']['applets']['files'].items()}
    modes = {name: 0o755 if row['mode'] == '100755' else 0o644
             for name, row in inputs['originals']['applets']['files'].items()}
    require(all(expected.get(n) == digest for n, digest in policy['before'].items()),
            'Clock native patch preimage changed')
    for name, binding in inputs['native_bindings'].items():
        for relative, row in binding['files'].items():
            key = 'native-deps/' + name + '/' + relative
            expected[key] = row['sha256']
            modes[key] = stat.S_IMODE((Path(binding['path']) / relative).stat().st_mode)
    expected.update(policy['after'])
    actual = files.read_tree(stage)
    require(set(actual['files']) == set(expected), 'Complete applets export inventory changed')
    for name, checksum in expected.items():
        require(actual['files'][name]['sha256'] == checksum
                and stat.S_IMODE((stage / name).stat().st_mode) == modes[name],
                'Complete applets export changed: ' + name)
    manifest = tomllib.loads((stage / 'Cargo.toml').read_text())
    require(manifest['workspace']['members'] == policy['workspace']['members']
            and manifest['workspace']['default-members'] == policy['workspace']['default-members']
            and manifest['workspace']['dependencies'] == policy['workspace']['dependencies']
            and base.digest(stage / 'Cargo.lock') == recipe['effective_lock_sha256'],
            'Clock workspace, complete GUI features or dependency versions changed')
    return actual


def export(source_cache, native_cache, cargo_cache, stage):
    inputs = original_inputs(source_cache, native_cache, cargo_cache)
    common.export_canonical(Path(inputs['originals']['applets']['path']), stage, COMMIT)
    for name, record in inputs['native_bindings'].items():
        shutil.copytree(record['path'], stage / 'native-deps' / name)
    for options in (['--check'], []):
        subprocess.run(['/usr/bin/git', 'apply', *options, str(PORT / 'native.patch')],
                       cwd=stage, check=True, capture_output=True, env=base.clean_environment('/usr/bin:/bin'))
    return inputs, verify_export(stage, inputs)


def resolution(metadata, stage, recipe, policy):
    graph = files.normalized_resolution(metadata)
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    members = {}
    for directory in policy['workspace']['members']:
        selected = [p for p in packages.values() if p.get('source') is None
                    and Path(p['manifest_path']) == stage / directory / 'Cargo.toml']
        require(len(selected) == 1, 'Missing original applets workspace member: ' + directory)
        members[directory] = selected[0]['id']
    require(metadata['workspace_root'] == str(stage) and metadata['resolve'].get('root') is None
            and set(metadata['workspace_members']) == set(members.values())
            and len(metadata['workspace_members']) == len(members)
            and set(metadata['workspace_default_members']) == {
                members[n] for n in policy['workspace']['default-members']},
            'Applets workspace members/default members changed')
    identifier = members['cosmic-applet-time']
    clock = packages[identifier]
    require(clock['version'] == '1.10.0' and nodes[identifier]['features'] == ['cyxia-native']
            and any(t['name'] == recipe['binary'] and 'bin' in t['kind']
                    and Path(t['src_path']) == stage / 'cosmic-applet-time/src/main.rs'
                    for t in clock['targets']), 'Clock binary/default features changed')
    native = {}
    for name, version, flags in (
            ('wayland-sys', '0.31.11', {'cyxia-static-client', 'cyxia-static-egl'}),
            ('wayland-backend', '0.3.17', {'client_system'}),
            ('xkbcommon-dl', '0.4.2', {'static-wayland'})):
        selected = [p for p in packages.values() if p['name'] == name]
        require(len(selected) == 1 and selected[0].get('source') is None
                and selected[0]['version'] == version
                and Path(selected[0]['manifest_path']) == stage / 'native-deps' / name / 'Cargo.toml'
                and flags <= set(nodes[selected[0]['id']]['features']),
                'Unadapted or incomplete genuine native binding: ' + name)
        native[name] = selected[0]['id']
    return dict(package_id=identifier, workspace_members=members, native_packages=native,
        features=FEATURES, default_features_preserved=True, package_count=len(graph),
        graph_sha256=files.canonical_hash(graph))


def metadata_identity(metadata, stage, cache, recipe, policy):
    """Validate all packages against unchanged lock bytes, Git trees and .crates."""
    selected = resolution(metadata, stage, recipe, policy)
    locked = {(p['name'], p['version'], common.source_key(p.get('source')))
              for p in tomllib.loads((stage / 'Cargo.lock').read_text())['package']}
    roots, records = {}, []
    archives = registry.registry_identities(metadata, stage, cache)
    for p in metadata['packages']:
        manifest = base.no_symlink_path(p['manifest_path'])
        spec = p.get('source')
        require((p['name'], p['version'], common.source_key(spec)) in locked,
                'Applet dependency differs from exact effective lock: ' + p['name'])
        record = dict(name=p['name'], version=p['version'], source=spec, manifest=str(manifest))
        if spec is None:
            require(manifest.is_relative_to(stage), 'Local applet dependency escapes retained source')
            record['source_tree_sha256'] = base.tree_identity(manifest.parent)['sha256']
        elif spec.startswith('registry+'):
            record['registry_archive'] = archives[p['id']]
            record['source_tree_sha256'] = base.tree_identity(manifest.parent)['sha256']
        else:
            match = re.fullmatch(r'git\+https://[^\s#]+#([0-9a-f]{40})', spec)
            require(match and manifest.is_relative_to(cache / 'git/checkouts'), 'Unpinned applet Git source')
            relative = manifest.relative_to(cache / 'git/checkouts')
            require(len(relative.parts) >= 3, 'Missing applet Git package root')
            checkout = cache / 'git/checkouts' / relative.parts[0] / relative.parts[1]
            key = str(checkout)
            if key not in roots:
                roots[key] = common.git_identity(checkout, match.group(1))
            require(roots[key]['commit'] == match.group(1)
                    and str(manifest.relative_to(checkout)) in roots[key]['files'], 'Untracked applet Git manifest')
            record['git_checkout'] = dict(path=key, **roots[key])
            record['source_tree_sha256'] = roots[key]['sha256']
        records.append(record)
    return dict(resolution=selected, packages=records)


def commands(cargo, stage, recipe, jobs, package_id=None):
    require(recipe['features'] == FEATURES and recipe['default_features'] is True,
            'Clock must preserve original GUI/default features')
    options = ['--manifest-path', str(stage / 'Cargo.toml'), '--locked', '--offline',
               '--features', ','.join(FEATURES)]
    metadata = [str(cargo), 'metadata', '--format-version', '1', '--filter-platform', TARGET, *options]
    command = None if package_id is None else [str(cargo), 'build', '--release', '--target', TARGET,
        '--jobs', str(jobs), '--package', package_id, '--bin', recipe['binary'], *options]
    return metadata, command
