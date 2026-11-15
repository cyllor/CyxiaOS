#!/usr/bin/env python3
"""Bounded COSMIC component build with exact local Cargo package selection.

The earlier builder remains unchanged for existing source-bound receipts. This
entry point shares its input, environment and resource validators, selects the
actual metadata package ID (names alone can be ambiguous), and preserves the
source export. Legacy ELF admission and explicit profile bounds both apply.
The caller must hold the native lease, as for build_cosmic.py.
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

try:
    from . import build_cosmic as base
except ImportError:
    import build_cosmic as base


def local_package(metadata, source, recipe):
    matches = [p for p in metadata['packages']
               if p['name'] == recipe['package'] and p.get('source') is None
               and Path(p['manifest_path']).resolve() == source / 'Cargo.toml']
    if len(matches) != 1 or not any(t['name'] == recipe['binary'] and 'bin' in t['kind']
                                  for t in matches[0]['targets']):
        raise base.CosmicBuildError('recipe does not select one root package binary')
    package_id = matches[0].get('id')
    if not isinstance(package_id, str) or not package_id.startswith('path+file://'):
        raise base.CosmicBuildError('root package lacks a local Cargo package ID')
    return package_id


def perform_build(source, record, recipe, recipe_path, output, sysroot, cache, profile, jobs):
    target = base.ports.user_target(recipe['target'])
    with (sysroot / '.build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tools, identities = base.tools_and_sysroot(sysroot, recipe)
        output = base.new_output(output)
        report = dict(status='building', component=source, recipe=recipe,
                      recipe_sha256=base.digest(recipe_path), resource_profile=profile,
                      profile_sha256=hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest(),
                      target=target.rust_target, architecture=target.architecture,
                      builder_sha256=base.digest(__file__), common_builder_sha256=base.digest(base.__file__),
                      toolchain=identities, operation='build', cargo_offline=True,
                      build_script_network_sandbox=False, guest_execution='not performed',
                      cosmic_session_ready=False, link_completed=False, target_linked=False)
        try:
            with tempfile.TemporaryDirectory(prefix='cyxia-component-') as temporary:
                control = Path(temporary).resolve()
                for parent in (control, *control.parents):
                    if (parent / 'Cargo.toml').exists() or any(
                            (parent / '.cargo' / name).exists() for name in ('config', 'config.toml')):
                        raise base.CosmicBuildError('inherited Cargo workspace/configuration')
                stage = control / 'source'
                base.export_source(Path(record['path']), stage)
                if 'source_series' in recipe:
                    raise base.CosmicBuildError('use ordinary component patches')
                report['patches'] = base.apply_patches(recipe, stage, recipe_path.parent)
                if base.digest(stage / 'Cargo.lock') != recipe['effective_lock_sha256']:
                    raise base.CosmicBuildError('effective Cargo.lock mismatch')
                report['source_tree'] = base.tree_identity(stage)
                shutil.copytree(stage, output / 'source', symlinks=True)
                env = base.cargo_environment(tools, identities, sysroot, output, cache, control)
                env['SOURCE_DATE_EPOCH'] = base.git(Path(record['path']), 'show', '-s', '--format=%ct')
                env['CYXIA_COSMIC_UPSTREAM_COMMIT'] = source['commit']
                common = ['--manifest-path', str(stage / 'Cargo.toml'), '--locked', '--offline']
                features = [] if recipe['default_features'] else ['--no-default-features']
                if recipe['features']:
                    features += ['--features', ','.join(recipe['features'])]
                cargo = str(tools['cargo'])
                metadata_command = [cargo, 'metadata', '--format-version', '1', '--filter-platform',
                                    target.rust_target, *common, *features]
                report['metadata_command'] = metadata_command
                bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
                budget = dict(budget_root=output, scratch_roots=(control,),
                              growth_roots=((cache, base.directory_bytes(cache)),))
                base.run_bounded(metadata_command, control, env, output / 'metadata.json', *bounds,
                                 stderr_log=output / 'metadata.stderr.log', **budget)
                metadata = base.load_json(output / 'metadata.json')
                report['cargo_dependencies'] = base.verify_metadata(metadata, stage, cache, recipe)
                report['package_id'] = local_package(metadata, stage, recipe)
                report['sysroot_before'] = base.tree_identity(sysroot / 'sysroot')
                command = [cargo, 'build', '--release', '--target', target.rust_target,
                           '--jobs', str(jobs), '--package', report['package_id'],
                           '--bin', recipe['binary'], *common, *features]
                report['command'] = command
                base.run_bounded(command, control, env, output / 'cargo.log', *bounds, **budget)
                checks = [base.tree_identity(stage) == report['source_tree'],
                          base.tree_identity(output / 'source') == report['source_tree'],
                          base.tree_identity(sysroot / 'sysroot') == report['sysroot_before'],
                          base.digest(__file__) == report['builder_sha256'],
                          base.digest(base.__file__) == report['common_builder_sha256'],
                          base.verify_metadata(metadata, stage, cache, recipe) == report['cargo_dependencies']]
                if not all(checks):
                    raise base.CosmicBuildError('build source, dependency, SDK or producer changed')
                for item in recipe['native_inputs']:
                    if base.digest(sysroot / item['path']) != item['sha256']:
                        raise base.CosmicBuildError('native input changed')
                report['source_preserved'] = base.inspect_source(Path(record['path']).parent, source)['verified']
                if not report['source_preserved']:
                    raise base.CosmicBuildError('original source changed')
                linked = output / 'target' / target.rust_target / 'release' / recipe['binary']
                if not linked.is_file() or not linked.resolve().is_relative_to(output):
                    raise base.CosmicBuildError('missing/escaped link output')
                report.update(link_completed=True, linked_binary=dict(
                    path=str(linked), bytes=linked.stat().st_size, sha256=base.digest(linked)))
                executable = base.inspect_elf(linked, target)
                pages = sum((p['vaddr'] + p['memsz'] + 4095) // 4096 - p['vaddr'] // 4096
                            for p in executable['program_headers'] if p['type'] == 1)
                if (executable['bytes'] > profile['max_elf_bytes']
                        or pages * 4096 + profile['stack_bytes'] > profile['image_bytes']):
                    raise base.CosmicBuildError('linked ELF exceeds admitted image profile')
                final = output / (recipe['binary'] + '.elf')
                shutil.copyfile(linked, final)
                report.update(status='cross-built', target_linked=True, image_load_pages=pages,
                              executable=base.inspect_elf(final, target))
        except Exception as error:
            report.update(status='failed', error=str(error))
            raise
        finally:
            (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', required=True)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--resource-profile', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=1)
    args = parser.parse_args()
    source, record, recipe = base.source_and_recipe(
        args.component, args.recipe, base.ports.load_manifest(), base.ports.CACHE)
    target = base.ports.user_target(recipe['target'])
    profile = base.select_profile(base.load_json(args.resource_profile), recipe['resource_profile'],
                                  args.jobs, target)
    sysroot = base.no_symlink_path(args.sysroot)
    cache = base.validate_cache(base.CARGO_CACHE)
    base.resource_check(sysroot, profile['min_free_bytes'] + profile['max_build_bytes'], 2**63)
    report = perform_build(source, record, recipe, args.recipe.resolve(), args.output, sysroot,
                           cache, profile, args.jobs)
    print(json.dumps({'status': report['status'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
