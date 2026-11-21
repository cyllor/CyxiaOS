#!/usr/bin/env python3
"""Build genuine COSMIC hosts against the explicit 128-FD object profile."""
import argparse
import fcntl
import json
from pathlib import Path
import shutil
import tempfile
import time

import cosmic_applet_hosts_v1 as hosts
import build_mesa_wayland_oom_v1 as mesa
import relink_cosmic_mesa_wayland_v1 as relink
import os_x86
import cosmic_popup_input_v1 as popup
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, require = hosts.base, hosts.require


def validate(output):
    output = base.no_symlink_path(output)
    report = base.load_json(output / 'build-report.json'); kind = report['host']
    _, (policy, recipe, component, profile) = hosts.contract(kind)
    require(report['status'] == 'cross-built' and report['kind'] == 'cosmic-applet-hosts-v1'
            and report['recipe'] == recipe and report['component'] == component
            and report['resource_profile'] == profile and report['fd_limit'] == 128
            and report['source_policy_sha256'] == base.digest(hosts.PORT / 'source-policy.json'),
            'Incomplete applet host build')
    extension = report.get('popup_input')
    if extension:
        require(kind == 'panel' and extension == dict(kind='cosmic-panel-popup-input-v1',
            source_policy_sha256=base.digest(popup.PORT / 'source-policy.json')), 'Popup source extension changed')
    verify_source = popup.verify_export if extension else lambda source: hosts.verify_export(kind, source)
    require(verify_source(output / 'source') == report['source_tree']
            and hosts.canonical_inputs(kind) == report['source_inputs'], 'Host source inputs changed')
    for name, digest in report['producers'].items():
        require(base.digest(output / 'producer-sources' / name) == digest, 'Host producer snapshot changed')
    for name, digest in report['evidence'].items():
        require(base.digest(output / name) == digest, 'Host build evidence changed')
    rebound = lambda data: json.loads(json.dumps(data).replace(report['original_export_root'], str(output / 'source')))
    metadata = rebound(base.load_json(output / 'metadata.json'))
    dependencies, package = hosts.metadata_identity(kind, metadata, output / 'source', recipe, policy)
    require(dependencies == rebound(report['cargo_dependencies']) and package == rebound(report['package_id']),
            'Complete locked host graph changed')
    sdk = Path(report['sysroot']); selected = report['toolchain']['selection']
    _, toolchain = hosts.session.common.selection.tools_and_sysroot(sdk, recipe,
        rust_root=selected['rust_root'], host_cc=selected['host_cc'])
    require(toolchain == report['toolchain'] and base.tree_identity(sdk / 'sysroot') == report['sdk_tree'],
            'Host compiler or SDK changed')
    if kind == 'panel':
        repair = Path(report['mesa_repair']); mesa.verify(repair)
        require(base.digest(repair / mesa.MEMBER) == report['mesa_object_sha256'], 'Host Mesa object changed')
    final = output / (hosts.NAMES[kind] + '.elf')
    linked = output / 'target' / recipe['target'] / 'release' / recipe['binary']
    require(base.digest(final) == base.digest(linked) == report['binary_sha256'], 'Published host differs from raw link')
    actual = hosts.session.elf.inspect_full_os_elf(final, profile)
    require(actual == report['image_admission'], 'Host ELF admission changed')
    return report


def build(kind, output, sdk, repair=None, popup_input=False):
    output, sdk = map(base.no_symlink_path, (output, sdk))
    record, (policy, recipe, component, profile) = hosts.contract(kind)
    require(not output.exists() and not output.is_relative_to(sdk) and not sdk.is_relative_to(output),
            'Preserving host inputs and output')
    require(kind != 'panel' or repair is not None, 'Panel must retain the genuine Mesa OOM repair')
    require(not popup_input or kind == 'panel', 'Popup input extension applies only to panel')
    if popup_input: popup.contract()
    if repair is not None: repair = base.no_symlink_path(repair); mesa.verify(repair)
    output.mkdir(parents=True)
    producers = os_x86.producer_sources(__file__)
    for name in producers:
        target = output / 'producer-sources' / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base.ROOT / name, target)
    report = dict(kind='cosmic-applet-hosts-v1', host=kind, status='building', fd_limit=128,
        recipe=recipe, component=component, resource_profile=profile, producers=producers,
        source_policy_sha256=base.digest(hosts.PORT / 'source-policy.json'), sysroot=str(sdk),
        cargo_offline=True, full_os_verified=False, cosmic_session_verified=False)
    started = time.monotonic(); deadline = started + profile['timeout_seconds']
    bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
    try:
        with (hosts.CACHE / '.cyxia-build.lock').open('a') as lock, (sdk / '.build.lock').open('a') as sdk_lock, \
                tempfile.TemporaryDirectory(prefix='cyxia-applet-host-', dir='/private/tmp') as temporary:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); fcntl.flock(sdk_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            control = Path(temporary); stage = control / 'source'
            hosts.session.common.check_control(control)
            inputs, tree = hosts.export(kind, stage)
            if popup_input:
                tree = popup.apply(stage)
                report['popup_input'] = dict(kind='cosmic-panel-popup-input-v1',
                    source_policy_sha256=base.digest(popup.PORT / 'source-policy.json'))
            verify_source = popup.verify_export if popup_input else lambda source: hosts.verify_export(kind, source)
            shutil.copytree(stage, output / 'source')
            report.update(source_inputs=inputs, source_tree=tree, original_export_root=str(stage))
            tools, toolchain = hosts.session.common.selection.tools_and_sysroot(sdk, recipe,
                rust_root=Path('/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin'), host_cc=Path('/usr/bin/clang'))
            (hosts.panel.parent if kind == 'panel' else hosts.session).check_toolchain(toolchain)
            report.update(toolchain=toolchain, sdk_tree=base.tree_identity(sdk / 'sysroot'))
            environment = base.cargo_environment(tools, toolchain, sdk, output, hosts.CACHE, control)
            environment['CARGO_NET_OFFLINE'] = 'true'
            if kind == 'panel': hosts.panel.parent.stage_native_archives(output, sdk, recipe, toolchain, environment)
            metadata_command, _ = hosts.commands(kind, tools['cargo'], stage, recipe)
            budget = dict(budget_root=output, scratch_roots=(control,), growth_roots=((hosts.CACHE, base.directory_bytes(hosts.CACHE)),))
            base.run_bounded(metadata_command, control, environment, output / 'metadata.json',
                *hosts.session.common.remaining_bounds(deadline, bounds), stderr_log=output / 'metadata.stderr.log', **budget)
            metadata = base.load_json(output / 'metadata.json')
            dependencies, package = hosts.metadata_identity(kind, metadata, stage, recipe, policy)
            _, command = hosts.commands(kind, tools['cargo'], stage, recipe, package)
            if kind == 'panel':
                wrapper = output / 'link-repaired-mesa'
                wrapper.write_text(relink.linker_script(tools['target_cc'], repair / mesa.MEMBER, output)); wrapper.chmod(0o755)
                command[1] = 'rustc'; command += ['--', '-C', 'linker=' + str(wrapper)]
                report.update(mesa_repair=str(repair), mesa_object_sha256=base.digest(repair / mesa.MEMBER))
            report.update(metadata_command=metadata_command, command=command, cargo_dependencies=dependencies, package_id=package)
            base.run_bounded(command, control, environment, output / 'cargo.log',
                *hosts.session.common.remaining_bounds(deadline, bounds), **budget)
            require('Compiling ' + recipe['package'] + ' v' in (output / 'cargo.log').read_text(), 'Genuine host root was not compiled')
            require(verify_source(stage) == tree and verify_source(output / 'source') == tree
                    and hosts.canonical_inputs(kind) == inputs and os_x86.producer_sources(__file__) == producers
                    and base.tree_identity(sdk / 'sysroot') == report['sdk_tree'], 'Host inputs changed during build')
            if kind == 'panel':
                mapping = (output / 'native-link.map').read_text()
                require(str(repair / mesa.MEMBER) in mapping and not any(mesa.MEMBER in line
                    and ('.rlib(' in line or 'libEGL.a(' in line) for line in mapping.splitlines()), 'Old Mesa Wayland object selected')
                mesa.verify(repair)
            linked = output / 'target' / recipe['target'] / 'release' / recipe['binary']
            final = output / (hosts.NAMES[kind] + '.elf'); shutil.copyfile(linked, final); final.chmod(0o755)
            inspection = hosts.session.elf.inspect_full_os_elf(final, profile)
            names = ['metadata.json', 'metadata.stderr.log', 'cargo.log']
            if kind == 'panel': names += ['native-link.map', 'link-invocation.json', 'link-repaired-mesa']
            report.update(status='cross-built', binary_sha256=base.digest(final), image_admission=inspection,
                          evidence={name: base.digest(output / name) for name in names})
    except BaseException as error:
        report.update(status='failed', error=repr(error)); (output / (hosts.NAMES[kind] + '.elf')).unlink(missing_ok=True)
        raise
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return validate(output)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--component', choices=hosts.NAMES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, default=base.ROOT / 'artifacts/sysroot/x86_64-musl')
    parser.add_argument('--mesa-repair', type=Path)
    parser.add_argument('--popup-input', action='store_true')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host(); result = build(args.component, args.output, args.sysroot, args.mesa_repair, args.popup_input)
    print(json.dumps({key: result[key] for key in ('host', 'status', 'elapsed_seconds', 'binary_sha256')}))


if __name__ == '__main__': main()
