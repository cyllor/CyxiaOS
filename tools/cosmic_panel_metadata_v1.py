"""Exact virtual-workspace selection for the genuine panel Linux build.

This keeps the existing canonical Git and strict registry verifiers. Unlike the
single-package settings/compositor profiles, the executable manifest is nested
inside a three-member virtual workspace. No Cargo/global helper is monkeypatched.
"""
from pathlib import Path
import re
import tomllib

if __package__:
    from . import build_cosmic_comp_linux as common
    from . import cosmic_notifications_static_v1 as files
    from . import cosmic_registry_inputs_v1 as registry
else:
    import build_cosmic_comp_linux as common
    import cosmic_notifications_static_v1 as files
    import cosmic_registry_inputs_v1 as registry

base, require = common.base, common.require
MEMBERS = ('cosmic-panel-bin', 'cosmic-panel-config', 'xdg-shell-wrapper-config')
FEATURES = ['cosmic-panel-bin/cyxia-native']
NATIVE_FEATURES = {
    'launch-pad': {'cyxia-native'},
    'smithay': {'use_system_lib', 'desktop', 'backend_egl', 'backend_drm', 'renderer_gl', 'backend_egl_static'},
    'wayland-sys': {'client', 'server', 'egl', 'dlopen', 'cyxia-static-client', 'cyxia-static-server', 'cyxia-static-egl'},
}


def resolution(metadata, stage, recipe):
    """Require the original three members and the actual nested binary."""
    stage = base.no_symlink_path(stage)
    graph = files.normalized_resolution(metadata)
    packages = {row['id']: row for row in metadata['packages']}
    nodes = {row['id']: row for row in metadata['resolve']['nodes']}
    require(metadata.get('workspace_root') == str(stage) and metadata['resolve'].get('root') is None,
            'Panel metadata is not the selected virtual workspace')
    selected_members = {}
    for name in MEMBERS:
        selected = [row for row in packages.values() if row['name'] == name and row.get('source') is None
                    and Path(row['manifest_path']) == stage / name / 'Cargo.toml']
        require(len(selected) == 1 and selected[0]['version'] == '1.10.0',
                'Missing exact original panel workspace member: ' + name)
        selected_members[name] = selected[0]['id']
    expected_members = set(selected_members.values())
    require(len(metadata['workspace_members']) == len(MEMBERS)
            and set(metadata['workspace_members']) == expected_members
            and len(metadata.get('workspace_default_members', [])) == len(MEMBERS)
            and set(metadata['workspace_default_members']) == expected_members,
            'Panel workspace members/default members were removed or substituted')
    identifier = selected_members['cosmic-panel-bin']
    root = packages[identifier]
    require(recipe['package'] == root['name'] and recipe['binary'] == 'cosmic-panel'
            and recipe['default_features'] is True and recipe['features'] == FEATURES
            and nodes[identifier]['features'] == ['cyxia-native'],
            'Panel root/default/native feature selection changed')
    bins = [row for row in root['targets'] if 'bin' in row['kind']]
    require(len(bins) == 1 and bins[0]['name'] == 'cosmic-panel'
            and Path(bins[0]['src_path']) == stage / 'cosmic-panel-bin/src/main.rs',
            'Panel metadata selects another executable source')
    require(selected_members['cosmic-panel-config'] in nodes[identifier]['dependencies']
            and selected_members['xdg-shell-wrapper-config'] in nodes[identifier]['dependencies'],
            'Original panel configuration members are no longer direct dependencies')
    native = {}
    for name, version in [('launch-pad', '1.0.1'), ('smithay', '0.7.0'), ('wayland-sys', '0.31.11')]:
        selected = [row for row in packages.values() if row['name'] == name and row.get('source') is None
                    and Path(row['manifest_path']) == stage / 'native-deps' / name / 'Cargo.toml']
        require(len(selected) == 1 and selected[0]['version'] == version
                and selected[0]['id'] in nodes[identifier]['dependencies']
                and NATIVE_FEATURES[name] <= set(nodes[selected[0]['id']]['features']),
                'Panel did not select the exact real native dependency: ' + name)
        native[name] = selected[0]['id']
        require(all(row.get('source') is None and row['id'] == native[name]
                    for row in packages.values() if row['name'] == name),
                'A second unadapted native dependency would bypass the selected binding: ' + name)
    return {'package_id': identifier, 'workspace_members': selected_members,
            'native_packages': native, 'features': FEATURES, 'default_features_preserved': True,
            'package_count': len(graph), 'graph_sha256': files.canonical_hash(graph)}


def metadata_identity(metadata, stage, cache, recipe):
    """Validate every locked package, complete Git source and registry archive."""
    stage, cache = map(base.no_symlink_path, (stage, cache))
    selected = resolution(metadata, stage, recipe)
    locked = {(row['name'], row['version'], common.source_key(row.get('source')))
              for row in tomllib.loads((stage / 'Cargo.lock').read_text())['package']}
    roots, records = {}, []
    for package in metadata['packages']:
        manifest = base.no_symlink_path(package['manifest_path'])
        spec = package.get('source')
        require(manifest.is_file() and (package['name'], package['version'], common.source_key(spec)) in locked,
                'Panel dependency differs from the exact effective lock: ' + package['name'])
        record = {'name': package['name'], 'version': package['version'], 'source': spec,
                  'manifest': str(manifest)}
        if spec is None:
            require(manifest.is_relative_to(stage), 'Local panel dependency escapes the complete retained source')
            record['source_tree_sha256'] = base.tree_identity(manifest.parent)['sha256']
        elif spec.startswith('registry+'):
            require(manifest.is_relative_to(cache / 'registry/src'), 'Panel registry input escapes the selected cache')
            record['source_tree_sha256'] = base.tree_identity(manifest.parent)['sha256']
        else:
            match = re.fullmatch(r'git\+https://[^\s#]+#([0-9a-f]{40})', spec)
            require(match is not None and manifest.is_relative_to(cache / 'git/checkouts'),
                    'Panel Git dependency is not a pinned selected cache input')
            relative = manifest.relative_to(cache / 'git/checkouts')
            require(len(relative.parts) >= 3, 'Missing independent panel Git checkout path')
            checkout = cache / 'git/checkouts' / relative.parts[0] / relative.parts[1]
            key = str(checkout)
            if key not in roots:
                roots[key] = common.git_identity(checkout, match.group(1))
            require(roots[key]['commit'] == match.group(1)
                    and str(manifest.relative_to(checkout)) in roots[key]['files'],
                    'Panel Git metadata uses an untracked manifest or another commit')
            record['git_checkout'] = {'path': key, **roots[key]}
            record['source_tree_sha256'] = roots[key]['sha256']
        records.append(record)
    archives = registry.registry_identities(metadata, stage, cache)
    for record, package in zip(records, metadata['packages']):
        if package['id'] in archives:
            record['registry_archive'] = archives[package['id']]
    return {'resolution': selected, 'packages': records}


def commands(cargo, stage, recipe, jobs, package_id=None):
    """Root manifest preserves all members; only build selects the actual bin."""
    require(recipe['default_features'] is True and recipe['features'] == FEATURES,
            'Panel command may not disable upstream default features')
    options = ['--manifest-path', str(Path(stage) / 'Cargo.toml'), '--locked', '--offline',
               '--features', ','.join(FEATURES)]
    metadata = [str(cargo), 'metadata', '--format-version', '1', '--filter-platform', recipe['target'], *options]
    compile_command = None if package_id is None else [str(cargo), 'build', '--release', '--target', recipe['target'],
        '--jobs', str(jobs), '--package', package_id, '--bin', recipe['binary'], *options]
    return metadata, compile_command
