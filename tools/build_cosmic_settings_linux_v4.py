#!/usr/bin/env python3
"""Build the pinned genuine settings daemon with explicit Linux Rust/Clang.

The caller must hold the shared root native lease. Both operations are locked
and offline. Metadata is never installable, and no target process runs here.
The original settings patch, SDK and source stay unchanged. A separate fixed
v2 patch keeps theme jobs off the current-thread executor; the appended v3
guard patch releases the interface read guard before the event loop awaits.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

if __package__:
    from . import cosmic_settings_linux_v4 as contract
else:
    import cosmic_settings_linux_v4 as contract

base, common, require = contract.base, contract.common, contract.require
BUILDER = Path(__file__).resolve()
PROGRAM = contract.COMPONENT + '.elf'


def producer_sources():
    return contract.files.producer_sources(BUILDER)


def input_paths(output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc):
    selected = [base.no_symlink_path(path) for path in
                (output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc)]
    output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc = selected
    protected_paths = [recipe_path.parent, profile_path.parent, sysroot, source_cache, cache,
                       rust_root, host_cc, host_cc.parent, base.ROOT / 'tools', base.ROOT / 'ports']
    # Match the unchanged tool selector without executing it. Legitimate
    # pkg-config symlinks protect both the declared and resolved directories.
    pkg_config = shutil.which('pkg-config', path=common.selection.HOST_PATH)
    if pkg_config is not None:
        tool = Path(pkg_config)
        protected_paths += [base.no_symlink_path(tool.parent),
                            base.no_symlink_path(tool.resolve(strict=True).parent)]
    for protected in protected_paths:
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                'Settings output overlaps a read-only input: ' + str(protected))
    for directory in (sysroot, source_cache, cache, rust_root):
        require(directory.is_dir(), 'Missing existing settings input directory: ' + str(directory))
    require(host_cc.is_file(), 'Missing explicit settings host compiler')
    base.validate_cache(cache)
    return selected


def revoke(output, report):
    report['target_linked'] = False
    for name in (PROGRAM, '.' + PROGRAM + '.pending'):
        (output / name).unlink(missing_ok=True)


def write_report(output, report):
    pending = output / '.build-report.json.pending'
    pending.unlink(missing_ok=True)
    data = (json.dumps(report, indent=2, allow_nan=False) + '\n').encode()
    with pending.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    pending.replace(output / 'build-report.json')


def publish(linked, output, inspection, profile):
    candidate, final = output / ('.' + PROGRAM + '.pending'), output / PROGRAM
    require(not final.exists() and not final.is_symlink(), 'Unexpected settings publication')
    with linked.open('rb') as source, candidate.open('xb') as destination:
        shutil.copyfileobj(source, destination)
        destination.flush(); os.fsync(destination.fileno())
    actual = contract.elf.inspect_full_os_elf(candidate, profile)
    expected = {**inspection, 'executable': {**inspection['executable'], 'file': candidate.name}}
    require(actual == expected, 'Settings candidate differs from verified link output')
    candidate.replace(final)
    published = contract.elf.inspect_full_os_elf(final, profile)
    require(published == {**actual, 'executable': {**actual['executable'], 'file': final.name}},
            'Settings ELF changed during atomic publication')
    return published


def _perform(action, recipe_path, profile_path, output, sysroot, source_cache, cache,
             rust_root, host_cc, jobs, owned):
    require(action in ('metadata', 'build'), 'Unsupported settings operation')
    output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc = input_paths(
        output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc)
    policy, recipe, source, profile = contract.contract(recipe_path, profile_path, jobs)
    output = base.new_output(output)
    producers = producer_sources()
    report = dict(schema_version=1, kind=contract.KIND, status='FAILED', operation=action,
        component=source, output=str(output), recipe_path=str(recipe_path), recipe=recipe,
        recipe_sha256=base.digest(recipe_path), profile_path=str(profile_path),
        profile_sha256=base.digest(profile_path), policy_sha256=contract.POLICY_SHA256,
        source_cache=str(source_cache), cargo_cache=str(cache), sysroot=str(sysroot),
        resource_profile=profile, target=contract.TARGET, architecture='x86_64', jobs=jobs,
        producer_sources=producers, builder_sha256=base.digest(BUILDER),
        link_completed=False, target_linked=False, cargo_resolution_verified=False,
        source_preserved=False, inputs_preserved=False, producer_sources_preserved=False,
        cargo_offline=True, build_script_network_sandbox=False, guest_execution='not performed',
        settings_verified=False, cosmic_session_ready=False, cosmic_session_verified=False,
        boundary=policy['boundary'], operation_timeout_seconds=profile['timeout_seconds'],
        timeout_scope=contract.TIMEOUT_SCOPE, retained_logs={})
    owned.append((output, report))
    started = time.monotonic()
    deadline = started + profile['timeout_seconds']
    bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
    failure = None
    with ExitStack() as stack:
        try:
            for path, mode in ((cache / '.cyxia-build.lock', fcntl.LOCK_EX),
                               (sysroot / '.build.lock', fcntl.LOCK_SH)):
                handle = stack.enter_context(base.no_symlink_path(path).open('a'))
                fcntl.flock(handle, mode | fcntl.LOCK_NB)
            temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix='cyxia-settings-linux-v3-'))
            control = Path(temporary).resolve()
            common.check_control(control)
            stage = control / 'source'
            report['original_export_root'] = str(stage)
            inputs, patches, tree = contract.export_source(source_cache, cache, recipe_path, recipe, policy, stage)
            report.update(source_inputs=inputs, patches=patches, source_tree=tree)
            shutil.copytree(stage, output / 'source')
            tools, identities = common.selection.tools_and_sysroot(
                sysroot, recipe, rust_root=rust_root, host_cc=host_cc)
            contract.check_toolchain(identities)
            report.update(toolchain=identities, sysroot_before=base.tree_identity(sysroot / 'sysroot'),
                native_sdk_origin=contract.files.sdk_origin(sysroot, recipe),
                rust_libraries_before=contract.rust_libraries(identities))
            env = base.cargo_environment(tools, identities, sysroot, output, cache, control)
            env['CARGO_NET_OFFLINE'] = 'true'
            report['native_archive_search'] = contract.stage_native_archives(output, sysroot, recipe, identities, env)
            report['generated_build_inputs'] = contract.generated_inputs(output, sysroot, recipe, identities)
            original = Path(inputs['originals']['settings']['path'])
            env.update(SOURCE_DATE_EPOCH=common.objects.pinned_git(original, 'show', '-s', '--format=%ct'),
                       CYXIA_COSMIC_UPSTREAM_COMMIT=policy['commit'])
            baseline = base.directory_bytes(cache)
            budget = dict(budget_root=output, scratch_roots=(control,), growth_roots=((cache, baseline),))
            metadata_command, _ = contract.commands(tools['cargo'], stage, recipe, jobs)
            report['metadata_command'] = metadata_command
            base.run_bounded(metadata_command, control, env, output / 'metadata.json',
                *common.remaining_bounds(deadline, bounds), stderr_log=output / 'metadata.stderr.log', **budget)
            metadata = contract.read_json(output / 'metadata.json')
            require(metadata.get('target_directory') == str(output / 'target'), 'Settings Cargo target directory changed')
            report['metadata_sha256'] = base.digest(output / 'metadata.json')
            report['cargo_dependencies'] = contract.metadata_identity(metadata, stage, cache, recipe, policy)
            report['package_id'] = report['cargo_dependencies']['resolution']['package_id']
            report['cargo_resolution_verified'] = True
            if action == 'build':
                _, command = contract.commands(tools['cargo'], stage, recipe, jobs, report['package_id'])
                report['command'] = command
                base.run_bounded(command, control, env, output / 'cargo.log',
                                 *common.remaining_bounds(deadline, bounds), **budget)
                linked = base.no_symlink_path(output / 'target' / contract.TARGET / 'release' / recipe['binary'])
                require(linked.is_file(), 'Missing raw linked settings binary')
                report.update(link_completed=True, linked_binary={
                    'path': str(linked), 'bytes': linked.stat().st_size, 'sha256': base.digest(linked)})
                inspection = contract.elf.inspect_full_os_elf(linked, profile)
                require(inspection['executable']['sha256'] == report['linked_binary']['sha256']
                        and inspection['executable']['bytes'] == report['linked_binary']['bytes'],
                        'Raw settings ELF changed during admission')
                report['full_os_inspection'] = inspection
            report['cache_growth_bytes'] = max(0, base.directory_bytes(cache) - baseline)
        except BaseException as error:
            failure = error
            report['error'] = str(error)
        finally:
            try:
                errors = []
                checks = [('contract', lambda: contract.contract(recipe_path, profile_path, jobs)
                           == (policy, recipe, source, profile)),
                          ('producer', lambda: producer_sources() == producers)]
                if 'source_inputs' in report:
                    checks += [('sources', lambda: contract.verify_export(source_cache, cache, recipe_path, policy,
                        stage, report['source_inputs']) == report['source_tree']),
                        ('retained source', lambda: contract.verify_export(source_cache, cache, recipe_path, policy,
                        output / 'source', report['source_inputs']) == report['source_tree'])]
                if 'toolchain' in report:
                    checks += [('toolchain', lambda: common.selection.tools_and_sysroot(sysroot, recipe,
                        rust_root=rust_root, host_cc=host_cc)[1] == report['toolchain']),
                        ('SDK', lambda: base.tree_identity(sysroot / 'sysroot') == report['sysroot_before']
                         and contract.files.sdk_origin(sysroot, recipe) == report['native_sdk_origin']),
                        ('Rust archives', lambda: contract.rust_libraries(report['toolchain'])
                         == report['rust_libraries_before'])]
                if 'generated_build_inputs' in report:
                    checks.append(('generated inputs', lambda: contract.generated_inputs(output, sysroot, recipe,
                        report['toolchain']) == report['generated_build_inputs']))
                if 'cargo_dependencies' in report:
                    checks.append(('dependency sources', lambda:
                        base.digest(output / 'metadata.json') == report['metadata_sha256']
                        and contract.metadata_identity(contract.read_json(output / 'metadata.json'), stage, cache,
                            recipe, policy) == report['cargo_dependencies']))
                for name, check in checks:
                    try:
                        require(check(), name + ' changed')
                    except Exception as error:
                        errors.append(name + ': ' + str(error))
                report['postcheck_errors'] = errors
                report['inputs_preserved'] = not errors and 'generated_build_inputs' in report
                report['source_preserved'] = 'source_inputs' in report and not any(
                    item.startswith(('sources:', 'retained source:')) for item in errors)
                report['producer_sources_after'] = producer_sources()
                report['producer_sources_preserved'] = report['producer_sources_after'] == producers
                if 'generated_build_inputs' in report and not errors:
                    report['generated_build_inputs_after'] = contract.generated_inputs(output, sysroot, recipe,
                                                                                      report['toolchain'])
                    report['rust_libraries_after'] = contract.rust_libraries(report['toolchain'])
                if errors or not report['producer_sources_preserved']:
                    if failure is None:
                        failure = BuildFailure('Settings postchecks failed: ' + '; '.join(errors))
                        report['error'] = str(failure)
                for name in contract.LOGS:
                    path = output / name
                    if path.exists() or path.is_symlink():
                        raw = contract.read_regular(path, 64 * 1024**2)
                        report['retained_logs'][name] = {'bytes': len(raw), 'sha256': contract.files.sha(raw)}
                if failure is None:
                    require(set(report['retained_logs']) == set(contract.LOGS if action == 'build' else contract.LOGS[:2]),
                            'Incomplete successful settings build evidence inventory')
                    common.remaining_bounds(deadline, bounds)
                    base.resource_check(output, bounds[1], bounds[2])
                    require(base.directory_bytes(output) + base.directory_bytes(control)
                            + max(0, base.directory_bytes(cache) - baseline) <= bounds[2],
                            'Settings operation exceeded its aggregate byte budget')
                    if action == 'build':
                        admitted = publish(linked, output, inspection, profile)
                        for name, check in checks:
                            require(check(), 'Settings input changed during publication: ' + name)
                        for name, expected in report['retained_logs'].items():
                            raw = contract.read_regular(output / name, 64 * 1024**2)
                            require(expected == {'bytes': len(raw), 'sha256': contract.files.sha(raw)},
                                    'Settings build evidence changed during publication')
                        common.remaining_bounds(deadline, bounds)
                        base.resource_check(output, bounds[1], bounds[2])
                        require(base.directory_bytes(output) + base.directory_bytes(control)
                                + max(0, base.directory_bytes(cache) - baseline) <= bounds[2],
                                'Settings publication exceeded its aggregate byte budget')
                        report.update(status='cross-built', target_linked=True,
                            executable=admitted['executable'], image_admission=admitted,
                            image_load_pages=admitted['image_load_pages'], required_pages=admitted['required_pages'])
                    else:
                        report['status'] = 'SETTINGS_METADATA_VERIFIED_NOT_BUILT'
                if report['status'] != 'cross-built':
                    revoke(output, report)
                report['elapsed_seconds'] = round(time.monotonic() - started, 3)
                write_report(output, report)
            except BaseException as error:
                report.update(status='FAILED', target_linked=False, inputs_preserved=False, source_preserved=False)
                report.setdefault('error', str(error))
                revoke(output, report)
                report['elapsed_seconds'] = round(time.monotonic() - started, 3)
                try:
                    write_report(output, report)
                except OSError:
                    pass
                raise
        if failure is not None:
            raise failure
    return report


BuildFailure = contract.BuildError


def perform(action, recipe_path, profile_path, output, sysroot, source_cache, cache,
            rust_root, host_cc, jobs=1):
    # Cover failures in ExitStack cleanup as well as compilation/finalization.
    # Only a fresh output actually created by this call may be revoked.
    owned = []
    try:
        return _perform(action, recipe_path, profile_path, output, sysroot, source_cache, cache,
                        rust_root, host_cc, jobs, owned)
    except BaseException as error:
        for directory, report in owned:
            if report.get('status') == 'cross-built':
                report.update(inputs_preserved=False, source_preserved=False)
            report.update(status='FAILED', target_linked=False)
            report.setdefault('error', str(error))
            revoke(directory, report)
            try:
                write_report(directory, report)
            except OSError:
                pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('metadata', 'build'))
    parser.add_argument('--recipe', type=Path, default=contract.ROOT / contract.PORT / 'native-recipe.json')
    parser.add_argument('--resource-profile', type=Path, default=contract.ROOT / contract.PORT / 'resource-profile.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--source-cache', type=Path, default=base.ports.CACHE)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--host-cc', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=1)
    args = parser.parse_args(argv)
    try:
        result = perform(args.action, args.recipe, args.resource_profile, args.output, args.sysroot,
                         args.source_cache, args.cache, args.rust_root, args.host_cc, args.jobs)
        print(json.dumps({key: result[key] for key in
            ('status', 'cargo_resolution_verified', 'link_completed', 'target_linked', 'settings_verified')}, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print('Settings build failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
