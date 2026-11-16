#!/usr/bin/env python3
"""Bounded notifications build with exact reviewed Cargo-config removal.

Frozen generic source/build producers are imported unchanged. This dedicated
orchestration records the export policy and restores its explicit cfg flags.
The caller must hold the root native lease; this is not guest validation.
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import os_x86

try:
    from . import build_cosmic as base
    from . import build_cosmic_component as component_builder
    from . import cosmic_notifications_source as reviewed
    from . import cosmic_notifications_dependencies as dependency_inputs
except ImportError:
    import build_cosmic as base
    import build_cosmic_component as component_builder
    import cosmic_notifications_source as reviewed
    import cosmic_notifications_dependencies as dependency_inputs


def perform_build(source, record, recipe, recipe_path, output, sysroot, cache, profile, jobs):
    producers = os_x86.producer_sources(__file__)
    policy = reviewed.load_policy(recipe, recipe_path, source)
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
                      source_exporter_sha256=base.digest(reviewed.__file__),
                      package_selector_sha256=base.digest(component_builder.__file__),
                      dependency_validator_sha256=base.digest(dependency_inputs.__file__),
                      producer_sources=producers,
                      source_export_policy=policy,
                      reviewed_rust_flags=policy['rust_flags'], reviewed_rustdoc_flags=policy['rustdoc_flags'],
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
                report['source_normalization'] = reviewed.export_source(Path(record['path']), stage, policy)
                if 'source_series' in recipe:
                    raise base.CosmicBuildError('use ordinary component patches')
                report['patches'] = base.apply_patches(recipe, stage, recipe_path.parent)
                if base.digest(stage / 'Cargo.lock') != recipe['effective_lock_sha256']:
                    raise base.CosmicBuildError('effective Cargo.lock mismatch')
                report['source_tree'] = base.tree_identity(stage)
                shutil.copytree(stage, output / 'source', symlinks=True)
                env = reviewed.cargo_environment(
                    base.cargo_environment(tools, identities, sysroot, output, cache, control), policy)
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
                report['cargo_dependencies'] = dependency_inputs.verify_metadata(metadata, stage, cache, recipe)
                report['package_id'] = component_builder.local_package(metadata, stage, recipe)
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
                          base.digest(reviewed.__file__) == report['source_exporter_sha256'],
                          base.digest(component_builder.__file__) == report['package_selector_sha256'],
                          base.digest(dependency_inputs.__file__) == report['dependency_validator_sha256'],
                          os_x86.producer_sources(__file__) == producers,
                          reviewed.load_policy(recipe, recipe_path, source) == policy,
                          dependency_inputs.verify_metadata(metadata, stage, cache, recipe) == report['cargo_dependencies']]
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
            try:
                report['producer_sources_after'] = os_x86.producer_sources(__file__)
                report['producer_sources_preserved'] = report['producer_sources_after'] == producers
            except Exception as error:
                report['producer_sources_preserved'] = False
                report['producer_check_error'] = str(error)
            if not report['producer_sources_preserved']:
                report.update(status='failed', error='Transitive notification build producers changed')
            (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
            if not report['producer_sources_preserved']:
                raise base.CosmicBuildError(report['error'])
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--resource-profile', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=1)
    args = parser.parse_args()
    source, record, recipe = base.source_and_recipe(
        'cosmic-notifications', args.recipe, base.ports.load_manifest(), base.ports.CACHE)
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
