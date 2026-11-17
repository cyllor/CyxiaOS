#!/usr/bin/env python3
"""Acquire the genuine notification closure through reviewed source export.

The root native lease owns this explicit network/Cargo operation. Original
checkout, source lock, and frozen generic producers remain unchanged. Source
availability is not a target build or guest result.
"""
import argparse
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import os_x86

try:
    from . import build_cosmic as build
    from . import cosmic_dependencies as dependencies
    from . import cosmic_ports as ports
    from . import cosmic_notifications_source as reviewed
    from . import cosmic_port_source as acquisition
    from . import cosmic_notifications_toolchain as toolchain_selection
except ImportError:
    import build_cosmic as build
    import cosmic_dependencies as dependencies
    import cosmic_ports as ports
    import cosmic_notifications_source as reviewed
    import cosmic_port_source as acquisition
    import cosmic_notifications_toolchain as toolchain_selection


def prepare(recipe_path, output, *, source_cache=ports.CACHE, cache=build.CARGO_CACHE,
            timeout=900, min_free=1024**3, max_bytes=2 * 1024**3, offline=False, rust_root=None):
    producers = os_x86.producer_sources(__file__)
    if any(type(value) is not int or value <= 0 for value in (timeout, min_free, max_bytes)):
        raise build.CosmicBuildError('resource bounds must be positive integers')
    source, record, recipe = build.source_and_recipe(
        'cosmic-notifications', recipe_path, ports.load_manifest(), source_cache)
    policy = reviewed.load_policy(recipe, recipe_path, source)
    target = ports.user_target(recipe['target']).rust_target
    default_features, features = recipe['default_features'], recipe['features']
    if type(offline) is not bool:
        raise build.CosmicBuildError('offline selection must be boolean')
    cache = build.no_symlink_path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    build.validate_cache(cache)
    output = build.new_output(output)
    report = {'schema_version': 1, 'status': 'INCOMPLETE', 'source': source,
              'recipe': recipe, 'recipe_sha256': build.digest(recipe_path),
              'builder_sha256': build.digest(__file__), 'common_builder_sha256': build.digest(build.__file__),
              'source_exporter_sha256': build.digest(reviewed.__file__),
              'acquisition_helper_sha256': build.digest(acquisition.__file__),
              'producer_sources': producers,
              'source_export_policy': policy, 'reviewed_rust_flags': policy['rust_flags'],
              'reviewed_rustdoc_flags': policy['rustdoc_flags'],
              'target': target, 'cache': str(cache), 'built': False,
              'default_features': default_features, 'features': list(features),
              'network_acquisition': not offline,
              'guest_tested': False, 'native_dependency_closure_verified': False,
              'vendored': False, 'bounds': {'timeout_seconds': timeout,
              'min_free_bytes': min_free, 'max_growth_bytes': max_bytes},
              'scope': 'Cargo source availability; not target link or runtime readiness.'}
    started = time.monotonic()
    try:
        # Serialize preparation runs. Cargo additionally takes its own cache lock.
        with (cache / '.cyxia-build.lock').open('a') as lock, \
                tempfile.TemporaryDirectory(prefix='cyxia-cargo-source-') as temporary:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            control = Path(temporary).resolve()
            for ancestor in (control, *control.parents):
                if ((ancestor / 'Cargo.toml').exists() or
                        any((ancestor / '.cargo' / name).exists() for name in ('config', 'config.toml'))):
                    raise build.CosmicBuildError('acquisition directory inherits Cargo workspace/configuration')
            stage = control / 'source'
            baseline = build.directory_bytes(cache)
            build.resource_check(output, min_free + max_bytes, max_bytes)
            report['source_normalization'] = reviewed.export_source(Path(record['path']), stage, policy)
            report['patches'] = build.apply_patches(recipe, stage, Path(recipe_path).parent)
            if build.digest(stage / 'Cargo.lock') != recipe['effective_lock_sha256']:
                raise build.CosmicBuildError('effective notification lock mismatch')
            before = build.tree_identity(stage)
            report['source_tree_sha256'] = before['sha256']
            report['metadata_source_directory'] = str(stage)
            report['metadata_source_directory_temporary'] = True
            report['preserved_source_directory'] = str(output / 'source')
            report['lock'] = dependencies.lock_summary((stage / 'Cargo.lock').read_bytes())
            if report['lock']['unfixed_sources']:
                raise build.CosmicBuildError('Cargo.lock contains unfixed dependency sources')
            if rust_root is None:
                cargo, env = acquisition.acquisition_environment(cache)
            else:
                cargo, env, report['toolchain_selection'] = toolchain_selection.acquisition_environment(
                    cache, rust_root)
            env = reviewed.cargo_environment(env, policy)
            env['CARGO_NET_OFFLINE'] = 'true' if offline else 'false'
            env['CARGO_TARGET_DIR'] = str(output / 'target')
            report['cargo'] = {'path': str(cargo), 'sha256': build.digest(cargo)}
            # Cargo metadata resolves manifests for every lockfile platform even
            # with --filter-platform; a target-only fetch leaves those absent.
            commands = [([str(cargo), 'fetch', '--locked'] + (['--offline'] if offline else []), 'fetch.log'),
                        ([str(cargo), 'metadata', '--locked', '--offline', '--format-version', '1',
                          '--filter-platform', target]
                         + ([] if default_features else ['--no-default-features'])
                         + (['--features', ','.join(features)] if features else []), 'metadata.json')]
            report['commands'] = [command for command, _ in commands]
            for command, name in commands:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise build.CosmicBuildError('preparation deadline exceeded')
                build.run_bounded(command, stage, env, output / name,
                    remaining, min_free, max_bytes, budget_root=output,
                    growth_roots=((cache, baseline),), scratch_roots=(control,),
                    stderr_log=output / 'metadata.stderr' if name == 'metadata.json' else None)
            if build.tree_identity(stage) != before:
                raise build.CosmicBuildError('Cargo changed the immutable source export')
            report['resolved'] = acquisition.summarize_metadata(output / 'metadata.json', stage)
            # Preserve the exact input without rewriting raw Cargo metadata paths.
            shutil.copytree(stage, output / 'source', symlinks=True)
            report['cache_growth_bytes'] = max(0, build.directory_bytes(cache) - baseline)
            checks = [build.digest(__file__) == report['builder_sha256'],
                      build.digest(build.__file__) == report['common_builder_sha256'],
                      build.digest(reviewed.__file__) == report['source_exporter_sha256'],
                      build.digest(acquisition.__file__) == report['acquisition_helper_sha256'],
                      build.digest(recipe_path) == report['recipe_sha256'],
                      reviewed.load_policy(recipe, recipe_path, source) == policy]
            if not all(checks):
                raise build.CosmicBuildError('notification acquisition producer/policy changed')
            report['source_preserved'] = build.inspect_source(source_cache, source)['verified']
            report['status'] = 'CARGO_SOURCES_AVAILABLE'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report['status'] = 'FAILED'
        report['error'] = str(error)
        raise
    finally:
        try:
            report['producer_sources_after'] = os_x86.producer_sources(__file__)
            report['producer_sources_preserved'] = report['producer_sources_after'] == producers
        except Exception as error:
            report['producer_sources_preserved'] = False
            report['producer_check_error'] = str(error)
        if not report['producer_sources_preserved']:
            report.update(status='FAILED', error='Transitive notification acquisition producers changed')
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'preparation.json').write_text(json.dumps(report, indent=2) + '\n')
        if not report['producer_sources_preserved']:
            raise build.CosmicBuildError(report['error'])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source-cache', type=Path, default=ports.CACHE)
    parser.add_argument('--cache', type=Path, default=build.CARGO_CACHE)
    parser.add_argument('--offline', action='store_true', help='only use already acquired source inputs')
    parser.add_argument('--rust-root', type=Path, help='explicit installed Rust toolchain root')
    args = parser.parse_args(argv)
    try:
        result = prepare(args.recipe.resolve(), args.output, source_cache=args.source_cache,
                         cache=args.cache, offline=args.offline, rust_root=args.rust_root)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('prepare_cosmic_notifications: ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
