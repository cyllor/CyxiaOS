#!/usr/bin/env python3
"""Materialize a pinned COSMIC Cargo closure without compiling build scripts.

Explicit network acquisition uses a private Cargo home and an immutable Git
export. A successful offline metadata pass establishes source availability for
the selected target, not a native-library closure, port, or runnable desktop.
"""
import argparse
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

try:
    from . import build_cosmic as build
    from . import cosmic_dependencies as dependencies
    from . import cosmic_ports as ports
except ImportError:
    import build_cosmic as build
    import cosmic_dependencies as dependencies
    import cosmic_ports as ports


def acquisition_environment(cache):
    env = build.clean_environment('/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin')
    rust_root = Path(subprocess.check_output(
        [str(Path.home() / '.cargo/bin/rustc'), '--print', 'sysroot'],
        env=env, text=True, timeout=30).strip())
    cargo = rust_root / 'bin/cargo'
    env.update(CARGO_HOME=str(cache), CARGO_NET_OFFLINE='false',
               CARGO_NET_RETRY='2', RUSTC=str(rust_root / 'bin/rustc'))
    return cargo, env


def summarize_metadata(path, source):
    data = build.load_json(path)
    if data.get('version') != 1 or not data.get('resolve', {}).get('nodes'):
        raise build.CosmicBuildError('Cargo did not return a resolved dependency graph')
    packages = data.get('packages', [])
    ids = {p['id'] for p in packages}
    if len(ids) != len(packages):
        raise build.CosmicBuildError('duplicate package identity in Cargo metadata')
    for node in data['resolve']['nodes']:
        if node['id'] not in ids or any(p not in ids for p in node['dependencies']):
            raise build.CosmicBuildError('incomplete Cargo dependency graph')
    source = Path(source).resolve()
    roots = [p for p in packages if p.get('source') is None]
    if not roots or any(not Path(p['manifest_path']).resolve().is_relative_to(source) for p in roots):
        raise build.CosmicBuildError('path dependency escapes the immutable source export')
    for package in packages:
        if not Path(package['manifest_path']).is_file():
            raise build.CosmicBuildError('resolved package source is absent')
    return {'package_count': len(packages),
            'registry_packages': sum((p.get('source') or '').startswith('registry+') for p in packages),
            'git_sources': sorted({p['source'] for p in packages if (p.get('source') or '').startswith('git+')}),
            'metadata_sha256': build.digest(path),
            'root_packages': sorted(p['name'] for p in roots)}


def prepare(component, output, *, source_cache=ports.CACHE, cache=build.CARGO_CACHE,
            timeout=900, min_free=1024**3, max_bytes=2 * 1024**3):
    if any(type(value) is not int or value <= 0 for value in (timeout, min_free, max_bytes)):
        raise build.CosmicBuildError('resource bounds must be positive integers')
    manifest = ports.load_manifest()
    source = next((p for p in manifest['components'] if p['name'] == component), None)
    if source is None:
        raise build.CosmicBuildError('unknown pinned component')
    record = build.inspect_source(source_cache, source)
    cache = build.no_symlink_path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    build.validate_cache(cache)
    output = build.new_output(output)
    report = {'schema_version': 1, 'status': 'INCOMPLETE', 'source': source,
              'target': build.TARGET, 'cache': str(cache), 'built': False,
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
            build.export_source(record['path'], stage)
            before = build.tree_identity(stage)
            report['source_tree_sha256'] = before['sha256']
            report['metadata_source_directory'] = str(stage)
            report['metadata_source_directory_temporary'] = True
            report['preserved_source_directory'] = str(output / 'source')
            report['lock'] = dependencies.lock_summary((stage / 'Cargo.lock').read_bytes())
            if report['lock']['unfixed_sources']:
                raise build.CosmicBuildError('Cargo.lock contains unfixed dependency sources')
            cargo, env = acquisition_environment(cache)
            env['CARGO_TARGET_DIR'] = str(output / 'target')
            report['cargo'] = {'path': str(cargo), 'sha256': build.digest(cargo)}
            # Cargo metadata resolves manifests for every lockfile platform even
            # with --filter-platform; a target-only fetch leaves those absent.
            commands = [([str(cargo), 'fetch', '--locked'], 'fetch.log'),
                        ([str(cargo), 'metadata', '--locked', '--offline', '--format-version', '1',
                          '--filter-platform', build.TARGET], 'metadata.json')]
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
            report['resolved'] = summarize_metadata(output / 'metadata.json', stage)
            # Preserve the exact input without rewriting raw Cargo metadata paths.
            shutil.copytree(stage, output / 'source', symlinks=True)
            report['cache_growth_bytes'] = max(0, build.directory_bytes(cache) - baseline)
            report['status'] = 'CARGO_SOURCES_AVAILABLE'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report['status'] = 'FAILED'
        report['error'] = str(error)
        raise
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'preparation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source-cache', type=Path, default=ports.CACHE)
    parser.add_argument('--cache', type=Path, default=build.CARGO_CACHE)
    args = parser.parse_args(argv)
    try:
        result = prepare(args.component, args.output, source_cache=args.source_cache, cache=args.cache)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('cosmic_port_source: ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
