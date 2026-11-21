#!/usr/bin/env python3
"""Build the complete genuine Epoch 1.10.0 clock applet, offline."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import cosmic_time_applet_v2 as fix
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, parent, require = fix.base, fix.parent, fix.require


@contextmanager
def workspace(cached):
    if cached is None:
        with tempfile.TemporaryDirectory(prefix='cyxia-panel-allocation-', dir='/private/tmp') as temporary:
            yield Path(temporary)
        return
    control = Path(cached['original_export_root']).parent
    require(control.parent == Path('/private/tmp') and control.name.startswith('cyxia-panel-allocation-')
            and not control.exists() and not control.is_symlink(), 'Preserving prior temporary path')
    control.mkdir()
    try:
        yield control
    finally:
        shutil.rmtree(control)


def build(output, sysroot, source_cache, native_cache, cargo_cache, rust_root, host_cc, cache_from=None,
          *, contract_module=fix, programs=('cosmic-applet-time',), producer_entry=None):
    fix = contract_module
    output, sysroot, source_cache, native_cache, cargo_cache, rust_root, host_cc = map(
        base.no_symlink_path, (output, sysroot, source_cache, native_cache, cargo_cache, rust_root, host_cc))
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
                for p in (sysroot, source_cache, native_cache, cargo_cache, rust_root, fix.PORT)),
            'Preserving existing/overlapping clock inputs')
    policy, recipe, component, profile, _ = fix.contract()
    output.mkdir(parents=True)
    producers = os_x86.producer_sources(producer_entry or __file__)
    for name, digest in producers.items():
        snapshot = output / 'producer-sources' / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base.ROOT / name, snapshot)
        require(base.digest(snapshot) == digest, 'Clock producer snapshot changed')
    started = time.monotonic()
    deadline = started + profile['timeout_seconds']
    bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
    report = dict(kind=getattr(fix, 'KIND', 'cosmic-time-applet-v2'), status='building', component=component,
        recipe=recipe, resource_profile=profile, producers=producers, sysroot=str(sysroot),
        source_policy_sha256=base.digest(fix.PORT / 'source-policy.json'),
        historical_summary_receipts_reused=False, cargo_offline=True,
        full_os_verified=False, cosmic_session_verified=False, applet_verified=False)
    cached = None
    reuse_target = False
    if cache_from is not None:
        cache_from = base.no_symlink_path(cache_from)
        cached = base.load_json(cache_from / 'build-report.json')
        require(all(cached['recipe'][k] == recipe[k] for k in
                ('native_inputs', 'static_link_inputs', 'native_sdk_origin', 'target'))
                and all(cached['resource_profile'][k] == profile[k]
                        for k in profile if k != 'purpose')
                and cached['sysroot'] == str(sysroot) and cached['status'] in ('cross-built', 'failed')
                and 'cargo_dependencies' in cached, 'Cache is not a complete matching clock graph')
        require(not output.is_relative_to(cache_from) and not cache_from.is_relative_to(output),
                'Preserving cache input')
        native_base = Path(cached.get('cache_native_directory', str(cache_from)))
        reuse_target = (native_base / 'native').is_dir() and (native_base / 'bin').is_dir()
        if not reuse_target:
            report['cache_reuse'] = dict(parent=str(cache_from), target_reused=False,
                reason='historical native linker/search path unavailable; rebuild from verified source')
    try:
        with (cargo_cache / '.cyxia-build.lock').open('a') as cache_lock, \
             (sysroot / '.build.lock').open('a') as sdk_lock, \
             workspace(cached if reuse_target else None) as temporary:
            fcntl.flock(cache_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(sdk_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            control = Path(temporary).resolve()
            for ancestor in (control, *control.parents):
                require(not (ancestor / 'Cargo.toml').exists()
                    and not any((ancestor / '.cargo' / name).exists() for name in ('config', 'config.toml')),
                    'Inherited clock Cargo configuration')
            stage = control / 'source'
            inputs, tree = fix.export(source_cache, native_cache, cargo_cache, stage)
            if reuse_target:
                for name, identity in cached['source_tree']['files'].items():
                    selected = stage / name
                    if selected.is_file() and base.digest(selected) == identity['sha256']:
                        info = (cache_from / 'source' / name).stat()
                        os.utime(selected, ns=(info.st_atime_ns, info.st_mtime_ns))
                cache_tree = base.tree_identity(cache_from / 'target')
                require(not any('symlink' in row for row in cache_tree['files'].values()),
                        'Cache contains external links')
                subprocess.run(['/bin/cp', '-cRp', str(cache_from / 'target'), str(output / 'target')], check=True)
                require(base.tree_identity(output / 'target') == cache_tree, 'Cache clone changed bytes')
                report['cache_reuse'] = dict(parent=str(cache_from), input_tree_sha256=cache_tree['sha256'])
            report.update(source_inputs=inputs, source_tree=tree, original_export_root=str(stage))
            shutil.copytree(stage, output / 'source')
            tools, toolchain = parent.common.selection.tools_and_sysroot(
                sysroot, recipe, rust_root=rust_root, host_cc=host_cc)
            parent.check_toolchain(toolchain)
            require(base.digest(sysroot / recipe['native_sdk_origin']['path'])
                    == recipe['native_sdk_origin']['sha256'], 'Pinned clock SDK origin changed')
            report.update(toolchain=toolchain, sdk_tree=base.tree_identity(sysroot / 'sysroot'))
            if cached is not None:
                require(toolchain == cached['toolchain'] and report['sdk_tree'] == cached['sdk_tree'],
                        'Cache compiler or SDK changed')
            environment = base.cargo_environment(tools, toolchain, sysroot, output, cargo_cache, control)
            environment.update(CARGO_NET_OFFLINE='true',
                SOURCE_DATE_EPOCH=parent.common.objects.pinned_git(
                    Path(inputs['originals']['applets']['path']), 'show', '-s', '--format=%ct'),
                CYXIA_COSMIC_UPSTREAM_COMMIT=component['commit'])
            report['native_archive_search'] = parent.stage_native_archives(
                output, sysroot, recipe, toolchain, environment)
            if reuse_target:
                native_base = Path(cached.get('cache_native_directory', str(cache_from)))
                require(parent.native_search(cache_from, sysroot, recipe, toolchain)
                        == cached['native_archive_search'], 'Cache native archives changed')
                require(parent.native_search(native_base, sysroot, recipe, toolchain)['files']
                        == cached['native_archive_search']['files'], 'Original native cache changed')
                environment['CARGO_ENCODED_RUSTFLAGS'] = environment['CARGO_ENCODED_RUSTFLAGS'].replace(
                    'native=' + str(output / 'native'), 'native=' + str(native_base / 'native'))
                for name, value in list(environment.items()):
                    if str(output / 'bin') in value:
                        environment[name] = value.replace(str(output / 'bin'), str(native_base / 'bin'))
                report['cache_native_directory'] = str(native_base)
            if hasattr(fix, 'additional_link_inputs'):
                extra = fix.additional_link_inputs(sysroot, recipe)
                flags = ['-L', 'native=' + str(sysroot / 'sysroot/usr/lib'),
                         '-C', 'link-arg=-Wl,--start-group']
                for relative in extra['libraries']:
                    flags += ['-C', 'link-arg=' + str(sysroot / relative)]
                flags += ['-C', 'link-arg=-Wl,--end-group']
                environment['CARGO_ENCODED_RUSTFLAGS'] += '\x1f' + '\x1f'.join(flags)
                report['additional_native_inputs'] = extra
            if hasattr(fix, 'configure_native_environment'):
                report['native_environment'] = fix.configure_native_environment(
                    environment, tools, sysroot, output)
            baseline = base.directory_bytes(cargo_cache)
            budget = dict(budget_root=output, scratch_roots=(control,), growth_roots=((cargo_cache, baseline),))
            metadata_command, _ = fix.commands(tools['cargo'], stage, recipe, 2)
            report['metadata_command'] = metadata_command
            base.run_bounded(metadata_command, control, environment, output / 'metadata.json',
                *parent.common.remaining_bounds(deadline, bounds),
                stderr_log=output / 'metadata.stderr.log', **budget)
            metadata = base.load_json(output / 'metadata.json')
            dependencies = fix.metadata_identity(metadata, stage, cargo_cache, recipe, policy)
            report['cargo_dependencies'] = dependencies
            selection = dependencies['programs'] if 'programs' in dependencies else dependencies['resolution']['package_id']
            _, command = fix.commands(tools['cargo'], stage, recipe, 2, selection)
            report['command'] = command
            base.run_bounded(command, control, environment, output / 'cargo.log',
                             *parent.common.remaining_bounds(deadline, bounds), **budget)
            log = (output / 'cargo.log').read_text()
            require(all('Compiling ' + name + ' v' in log for name in programs),
                    'Every selected genuine applet root must be compiled')
            require(fix.verify_export(stage, inputs) == tree
                    and fix.verify_export(output / 'source', inputs) == tree
                    and fix.original_inputs(source_cache, native_cache, cargo_cache) == inputs,
                    'Clock sources changed during build')
            require(fix.metadata_identity(metadata, stage, cargo_cache, recipe, policy) == dependencies,
                    'Clock locked dependency sources changed during build')
            require(parent.common.selection.tools_and_sysroot(sysroot, recipe,
                    rust_root=rust_root, host_cc=host_cc)[1] == toolchain
                    and base.tree_identity(sysroot / 'sysroot') == report['sdk_tree'],
                    'Clock compiler or SDK changed during build')
            parent.native_search(output, sysroot, recipe, toolchain)
            if hasattr(fix, 'additional_link_inputs'):
                require(fix.additional_link_inputs(sysroot, recipe) == report['additional_native_inputs'],
                        'Additional applet native inputs changed during build')
            if hasattr(fix, 'verify_native_environment'):
                report['native_build_probes'] = fix.verify_native_environment(output, toolchain, sysroot,
                    report['native_environment'])
            if reuse_target:
                require(base.tree_identity(cache_from / 'target') == cache_tree,
                        'Original cache changed during rebuild')
                report['cache_reuse']['parent_preserved'] = True
            published = {}
            for name in programs:
                linked = output / 'target' / parent.TARGET / 'release' / name
                inspection = parent.elf.inspect_full_os_elf(linked, profile)
                final = output / (name + '.elf')
                shutil.copyfile(linked, final)
                final.chmod(0o755)
                require(base.digest(final) == inspection['executable']['sha256'], 'Applet publication differs')
                published[name] = dict(image_admission=inspection,
                    linked_binary=dict(path=str(linked), bytes=linked.stat().st_size, sha256=base.digest(linked)))
            require(os_x86.producer_sources(producer_entry or __file__) == producers, 'Applet producer changed during build')
            if programs == ('cosmic-applet-time',):
                report.update(published['cosmic-applet-time'])
            else:
                report['binaries'] = published
            report.update(status='cross-built',
                input_sources_preserved=True, sdk_preserved=True,
                evidence_files={name: base.digest(output / name) for name in
                                ('metadata.json', 'metadata.stderr.log', 'cargo.log')})
    except BaseException as error:
        report.update(status='failed', error=str(error))
        for name in programs:
            (output / (name + '.elf')).unlink(missing_ok=True)
        raise
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, default=base.ROOT / 'artifacts/sysroot/x86_64-musl')
    parser.add_argument('--source-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-sources')
    parser.add_argument('--native-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-native-sources')
    parser.add_argument('--cargo-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-comp-cache')
    parser.add_argument('--rust-root', type=Path, default=Path('/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin'))
    parser.add_argument('--host-cc', type=Path, default=Path('/usr/bin/clang'))
    parser.add_argument('--cache-from', type=Path)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        report = build(args.output, args.sysroot, args.source_cache, args.native_cache,
                       args.cargo_cache, args.rust_root, args.host_cc, args.cache_from)
    print(json.dumps({name: report[name] for name in ('status', 'elapsed_seconds', 'linked_binary')}, indent=2))


if __name__ == '__main__':
    main()
