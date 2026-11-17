#!/usr/bin/env python3
"""Build the pinned genuine native cosmic-session with explicit Linux tools.

Both operations are locked and offline. Metadata alone is never installable.
The historical session producer/patch remain unchanged; no operation here
executes a target binary or asserts that a COSMIC session is ready.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time

try:
    from . import cosmic_session_linux_v1 as contract
except ImportError:
    import cosmic_session_linux_v1 as contract

base, common = contract.base, contract.common
ROOT = contract.ROOT
BUILDER = Path(__file__).resolve()
DEFAULT_NATIVE_LOCK = ROOT / 'artifacts/v017-cosmic-completion-20261116/native-session.lock'
require = contract.require


def producer_sources():
    return common.os_x86.producer_sources(BUILDER)


def input_paths(output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc):
    selected = [base.no_symlink_path(item) for item in
                (output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc)]
    output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc = selected
    for protected in (recipe_path.parent, profile_path.parent, sysroot, source_cache, cache,
                      rust_root, host_cc, ROOT / 'tools', ROOT / 'ports'):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                'Session output overlaps a read-only input: ' + str(protected))
    for directory in (sysroot, source_cache, cache, rust_root):
        require(directory.is_dir(), 'Missing existing session input directory: ' + str(directory))
    require(host_cc.is_file(), 'Missing explicit session host compiler')
    base.validate_cache(cache)
    return selected


def _perform(action, recipe_path, profile_path, output, sysroot, source_cache, cache,
             rust_root, host_cc, jobs, owned):
    require(action in ('metadata', 'build'), 'Unsupported session operation')
    output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc = input_paths(
        output, recipe_path, profile_path, sysroot, source_cache, cache, rust_root, host_cc)
    policy, recipe, source, profile = contract.contract(recipe_path, profile_path, jobs)
    output = base.new_output(output)
    owned['output'] = output
    producers = producer_sources()
    report = dict(schema_version=1, kind=contract.KIND, status='FAILED', operation=action,
                  component=source, output=str(output), recipe_path=str(recipe_path), recipe=recipe,
                  recipe_sha256=base.digest(recipe_path), source_cache=str(source_cache), cargo_cache=str(cache),
                  profile_file=str(profile_path), profile_file_sha256=base.digest(profile_path),
                  resource_profile=profile, target=contract.TARGET, architecture='x86_64', jobs=jobs,
                  producer_sources=producers, builder_sha256=base.digest(BUILDER),
                  link_completed=False, target_linked=False, source_preserved=False,
                  inputs_preserved=False, producer_sources_preserved=False, cargo_offline=True,
                  build_script_network_sandbox=False, guest_execution='not performed', cosmic_session_ready=False,
                  operation_timeout_seconds=profile['timeout_seconds'], timeout_scope=contract.TIMEOUT_SCOPE,
                  sysroot=str(sysroot), retained_logs={})
    owned['report'] = report
    started = time.monotonic()
    deadline = started + profile['timeout_seconds']
    bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
    failure = None
    with ExitStack() as stack:
        try:
            for path, mode in ((cache / '.cyxia-build.lock', fcntl.LOCK_EX),
                               (sysroot / '.build.lock', fcntl.LOCK_SH)):
                lock = stack.enter_context(path.open('a'))
                fcntl.flock(lock, mode | fcntl.LOCK_NB)
            temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix='cyxia-native-session-v1-'))
            control = Path(temporary).resolve()
            common.check_control(control)
            stage = control / 'source'
            report['original_export_root'] = str(stage)
            inputs, patches, tree = contract.export_source(source_cache, recipe_path, recipe, policy, stage)
            report.update(source_inputs=inputs, patches=patches, source_tree=tree)
            shutil.copytree(stage, output / 'source')
            tools, identities = common.selection.tools_and_sysroot(
                sysroot, recipe, rust_root=rust_root, host_cc=host_cc)
            contract.check_toolchain(identities)
            report.update(toolchain=identities, sysroot_before=base.tree_identity(sysroot / 'sysroot'),
                          rust_libraries_before=contract.rust_libraries(identities))
            env = base.cargo_environment(tools, identities, sysroot, output, cache, control)
            report['generated_build_inputs'] = contract.generated_inputs(output, identities)
            original = Path(inputs['originals']['session']['path'])
            env.update(SOURCE_DATE_EPOCH=common.objects.pinned_git(original, 'show', '-s', '--format=%ct'),
                       CYXIA_COSMIC_UPSTREAM_COMMIT=policy['commit'])
            baseline = base.directory_bytes(cache)
            budget = dict(budget_root=output, scratch_roots=(control,), growth_roots=((cache, baseline),))
            metadata_command, _ = contract.commands(tools['cargo'], stage, recipe, jobs)
            report['metadata_command'] = metadata_command
            base.run_bounded(metadata_command, control, env, output / 'metadata.json',
                             *common.remaining_bounds(deadline, bounds),
                             stderr_log=output / 'metadata.stderr.log', **budget)
            metadata = base.load_json(output / 'metadata.json')
            report['metadata_sha256'] = base.digest(output / 'metadata.json')
            require(metadata.get('workspace_root') == str(stage)
                    and metadata.get('target_directory') == str(output / 'target'),
                    'Unexpected session Cargo workspace or target directory')
            report['package_id'] = contract.resolution(metadata, stage, recipe, policy)
            report['cargo_dependencies'] = contract.metadata_identity(metadata, stage, cache, recipe, policy)
            if action == 'build':
                _, command = contract.commands(tools['cargo'], stage, recipe, jobs, report['package_id'])
                report['command'] = command
                base.run_bounded(command, control, env, output / 'cargo.log',
                                 *common.remaining_bounds(deadline, bounds), **budget)
                linked = base.no_symlink_path(output / 'target' / recipe['target'] / 'release/cosmic-session')
                # Admission reads the exact linked bytes and all loader guards.
                # A successful link followed by admission failure remains failed.
                require(linked.is_file(), 'Missing raw linked session binary')
                report.update(link_completed=True, linked_binary={
                    'path': str(linked), 'bytes': linked.stat().st_size, 'sha256': base.digest(linked)})
                inspection = contract.elf.inspect_full_os_elf(linked, profile)
                report['full_os_inspection'] = inspection
            report['cache_growth_bytes'] = max(0, base.directory_bytes(cache) - baseline)
        except BaseException as error:
            failure = error
            report['error'] = str(error)
        finally:
            # Reinspect preserved inputs on both success and failure. The locks
            # and original export remain live until this receipt is finalized.
            errors = []
            checks = [
                ('contract', lambda: contract.contract(recipe_path, profile_path, jobs)
                 == (policy, recipe, source, profile)),
                ('producer', lambda: producer_sources() == producers),
            ]
            if 'source_inputs' in report:
                checks += [('sources', lambda: contract.verify_export(source_cache, recipe_path, policy,
                               stage, report['source_inputs']) == report['source_tree']),
                           ('retained source', lambda: contract.verify_export(source_cache, recipe_path, policy,
                               output / 'source', report['source_inputs']) == report['source_tree'])]
            if 'toolchain' in report:
                checks += [('toolchain', lambda: common.selection.tools_and_sysroot(sysroot, recipe,
                               rust_root=rust_root, host_cc=host_cc)[1] == report['toolchain']),
                           ('SDK', lambda: base.tree_identity(sysroot / 'sysroot') == report['sysroot_before']),
                           ('Rust archives', lambda: contract.rust_libraries(report['toolchain'])
                               == report['rust_libraries_before'])]
            if 'generated_build_inputs' in report:
                checks.append(('generated inputs', lambda: contract.generated_inputs(output, report['toolchain'])
                               == report['generated_build_inputs']))
            if 'cargo_dependencies' in report:
                checks.append(('Cargo metadata', lambda: base.digest(output / 'metadata.json')
                               == report['metadata_sha256']))
                checks.append(('dependency sources', lambda: contract.metadata_identity(
                    base.load_json(output / 'metadata.json'), stage, cache, recipe, policy)
                    == report['cargo_dependencies']))
            for name, check in checks:
                try:
                    require(check(), name + ' changed')
                except BaseException as error:
                    errors.append(name + ': ' + str(error))
                    if not isinstance(error, Exception):
                        failure = error
            report['postcheck_errors'] = errors
            report['inputs_preserved'] = not errors and 'generated_build_inputs' in report
            report['source_preserved'] = 'source_inputs' in report and not any(
                item.startswith(('sources:', 'retained source:')) for item in errors)
            try:
                report['producer_sources_after'] = producer_sources()
                report['producer_sources_preserved'] = report['producer_sources_after'] == producers
            except Exception as error:
                report['producer_sources_preserved'] = False
                errors.append('producer: ' + str(error))
            if errors and failure is None:
                failure = base.CosmicBuildError('Session inputs changed: ' + '; '.join(errors))
                report['error'] = str(failure)
            if failure is None:
                try:
                    mandatory_logs = ('metadata.json', 'metadata.stderr.log', 'cargo.log') if action == 'build' \
                        else ('metadata.json', 'metadata.stderr.log')
                    for name in mandatory_logs:
                        raw = contract.elf._read_regular(output / name, 64 * 1024**2)
                        report['retained_logs'][name] = hashlib.sha256(raw).hexdigest()
                    common.remaining_bounds(deadline, bounds)
                    base.resource_check(output, bounds[1], bounds[2])
                    # run_bounded covers output + live export + cache growth;
                    # retain this same aggregate check through publication.
                    require(base.directory_bytes(output) + base.directory_bytes(control)
                            + max(0, base.directory_bytes(cache)-baseline) <= bounds[2],
                            'Session operation exceeded its aggregate byte budget')
                    if action == 'build':
                        final = output / 'cosmic-session.elf'
                        with tempfile.TemporaryDirectory(prefix='.publication-', dir=output) as publishing:
                            candidate = Path(publishing) / final.name
                            shutil.copyfile(linked, candidate)
                            admitted = contract.elf.inspect_full_os_elf(candidate, profile)
                            comparable = dict(admitted)
                            comparable['executable'] = {**admitted['executable'], 'file': linked.name}
                            require(comparable == inspection
                                    and base.digest(linked) == report['linked_binary']['sha256'],
                                    'Session linked bytes changed before publication')
                            common.remaining_bounds(deadline, bounds)
                            require(base.directory_bytes(output) + base.directory_bytes(control)
                                    + max(0, base.directory_bytes(cache)-baseline) <= bounds[2],
                                    'Session publication exceeded its aggregate byte budget')
                            base.resource_check(output, bounds[1], bounds[2])
                            candidate.replace(final)
                        report.update(status='cross-built', target_linked=True,
                                      executable={**admitted['executable'], 'path': str(final)},
                                      image_load_pages=admitted['image_load_pages'],
                                      required_pages=admitted['required_pages'])
                    else:
                        report['status'] = 'SESSION_METADATA_VERIFIED_NOT_BUILT'
                except BaseException as error:
                    failure = error
                    report['error'] = str(error)
            if failure is not None:
                # Failure evidence may be incomplete. Do not turn unreadable
                # logs into an apparent successful receipt or hide the cause.
                for name in ('metadata.json', 'metadata.stderr.log', 'cargo.log'):
                    try:
                        if (output / name).is_file():
                            raw = contract.elf._read_regular(output / name, 64 * 1024**2)
                            report['retained_logs'][name] = hashlib.sha256(raw).hexdigest()
                    except (OSError, ValueError) as error:
                        report.setdefault('evidence_errors', []).append(name + ': ' + str(error))
            report['elapsed_seconds'] = time.monotonic() - started
            if failure is not None or not report['producer_sources_preserved']:
                report.update(status='FAILED', target_linked=False)
                (output / 'cosmic-session.elf').unlink(missing_ok=True)
            destination = output / 'build-report.json'
            temporary_report = output / '.build-report.json.tmp'
            temporary_report.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
            temporary_report.replace(destination)
    if failure is not None:
        if not isinstance(failure, Exception):
            raise failure
        raise base.CosmicBuildError(str(failure)) from failure
    require(report['status'] != 'FAILED', 'Session producer identities changed')
    return report


def perform(action, recipe_path, profile_path, output, sysroot, source_cache, cache,
            rust_root, host_cc, jobs=1):
    # This outer guard includes temporary cleanup and receipt/log finalization,
    # including KeyboardInterrupt. It only touches a fresh output we created.
    owned = {}
    try:
        return _perform(action, recipe_path, profile_path, output, sysroot, source_cache, cache,
                        rust_root, host_cc, jobs, owned)
    except BaseException as error:
        if 'output' in owned:
            destination = owned['output']
            (destination / 'cosmic-session.elf').unlink(missing_ok=True)
            report = owned.get('report', {'schema_version': 1, 'kind': contract.KIND,
                     'operation': action, 'output': str(destination), 'guest_execution': 'not performed',
                     'cosmic_session_ready': False})
            report.update(status='FAILED', target_linked=False)
            report.setdefault('error', str(error) or type(error).__name__)
            for key in ('executable', 'image_load_pages', 'required_pages'):
                report.pop(key, None)
            # If the normal atomic write failed, a best-effort diagnostic must
            # never leave a cross-built report behind. Missing evidence fails
            # closed in the consumer; the original exception is propagated.
            receipt = destination / 'build-report.json'
            try:
                temporary = destination / '.failed-build-report.json.tmp'
                temporary.write_bytes((json.dumps(report, indent=2, allow_nan=False) + '\n').encode())
                temporary.replace(receipt)
            except (OSError, ValueError):
                receipt.unlink(missing_ok=True)
            raise
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('metadata', 'build'))
    parser.add_argument('--recipe', type=Path, default=ROOT / contract.PORT / 'native-recipe.json')
    parser.add_argument('--resource-profile', type=Path, default=ROOT / contract.PORT / 'resource-profile.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--source-cache', type=Path, default=base.ports.CACHE)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--host-cc', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    args = parser.parse_args(argv)
    with common.native_lease(args.native_lock):
        common.idle_native_host()
        result = perform(args.action, args.recipe, args.resource_profile, args.output, args.sysroot,
                         args.source_cache, args.cache, args.rust_root, args.host_cc, args.jobs)
    print(json.dumps({'status': result['status'], 'output': result['output'],
                      'guest_execution': False, 'cosmic_session_ready': False}))


if __name__ == '__main__':
    main()
