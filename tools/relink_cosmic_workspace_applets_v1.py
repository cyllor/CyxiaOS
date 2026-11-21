#!/usr/bin/env python3
"""Recompile both genuine applet roots with the verified Mesa repair object."""
import argparse
import fcntl
import json
from pathlib import Path
import shutil
import time

import cosmic_workspace_applets_v1 as applets
import build_cosmic_time_applet_v2 as driver
import build_mesa_wayland_oom_v1 as mesa
import relink_cosmic_mesa_wayland_v1 as relink
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, require = applets.base, applets.require
backend = applets.parent.parent


def validate(output):
    # The parent consumer validates genuine complete source, every locked
    # dependency and real target SDK; no historical success summary is invented.
    from assemble_cosmic_workspace_applets_v1 import validate as validate_parent
    output = base.no_symlink_path(output)
    report = base.load_json(output / 'relink-report.json')
    parent = Path(report['parent']); original = validate_parent(parent)
    require(report['status'] == 'cross-built' and report['kind'] == 'cosmic-workspace-mesa-relink-v1'
            and report['parent_sha256'] == base.digest(parent / 'build-report.json')
            and set(report['binaries']) == set(applets.PROGRAMS), 'Incomplete genuine applet relink')
    repair = Path(report['repair']); mesa.verify(repair)
    require(base.digest(repair / mesa.MEMBER) == report['object_sha256'], 'Applet Mesa object changed')
    for name, digest in report['producers'].items():
        require(base.digest(output / 'producer-sources' / name) == digest, 'Applet relink producer changed')
    for name, digest in report['evidence'].items():
        require(base.digest(output / name) == digest, 'Applet relink evidence changed')
    require(applets.verify_export(output / 'source', original['source_inputs']) == original['source_tree'],
            'Complete retained applet source changed')
    for name, row in report['binaries'].items():
        path = output / (name + '.elf')
        linked = output / 'target' / applets.parent.TARGET / 'release' / name
        require(base.digest(path) == base.digest(linked) == row['sha256'], 'Repaired applet publication changed')
        require(backend.elf.inspect_full_os_elf(path, original['resource_profile']) == row['image_admission'],
                'Repaired applet ELF admission changed')
        mapping = (output / name / 'native-link.map').read_text()
        require(not any(mesa.MEMBER in line and ('.rlib(' in line or 'libEGL.a(' in line)
                        for line in mapping.splitlines()), 'Old applet Mesa Wayland object selected')
        require(row['mesa_wayland_object_selected'] == (str(repair / mesa.MEMBER) in mapping),
                'Applet selected-object classification changed')
    return report


def build(parent, repair, output):
    from assemble_cosmic_workspace_applets_v1 import validate as validate_parent
    parent, repair, output = map(base.no_symlink_path, (parent, repair, output))
    cached = validate_parent(parent); mesa.verify(repair)
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
            for p in (parent, repair, Path(cached['sysroot']))), 'Preserving applet relink inputs')
    output.mkdir(parents=True); producers = os_x86.producer_sources(__file__)
    for name in producers:
        target = output / 'producer-sources' / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base.ROOT / name, target)
    report = dict(status='building', kind='cosmic-workspace-mesa-relink-v1', parent=str(parent),
        parent_sha256=base.digest(parent / 'build-report.json'), repair=str(repair),
        object_sha256=base.digest(repair / mesa.MEMBER), producers=producers,
        full_os_verified=False, cosmic_session_verified=False)
    started = time.monotonic(); recipe = cached['recipe']; profile = cached['resource_profile']
    deadline = started + profile['timeout_seconds']
    bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
    cache = base.ROOT / 'artifacts/cosmic-comp-cache'; sdk = Path(cached['sysroot'])
    try:
        with (cache / '.cyxia-build.lock').open('a') as lock, (sdk / '.build.lock').open('a') as sdk_lock, driver.workspace(cached) as control:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); fcntl.flock(sdk_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            control = Path(control); stage = control / 'source'
            inputs, tree = applets.export(base.ROOT / 'artifacts/cosmic-sources', base.ROOT / 'artifacts/cosmic-native-sources', cache, stage)
            require(tree == cached['source_tree'] and inputs == cached['source_inputs'], 'Applet source selection changed')
            for name in tree['files']:
                info = (parent / 'source' / name).stat()
                import os
                os.utime(stage / name, ns=(info.st_atime_ns, info.st_mtime_ns))
            shutil.copytree(stage, output / 'source')
            cache_before = base.tree_identity(parent / 'target')
            import subprocess
            subprocess.run(['/bin/cp', '-cRp', str(parent / 'target'), str(output / 'target')], check=True)
            require(base.tree_identity(output / 'target') == cache_before, 'Applet compiler cache clone changed bytes')
            selected = cached['toolchain']['selection']
            tools, toolchain = backend.common.selection.tools_and_sysroot(sdk, recipe,
                rust_root=selected['rust_root'], host_cc=selected['host_cc'])
            require(toolchain == cached['toolchain'], 'Applet compiler selection changed')
            environment = base.cargo_environment(tools, toolchain, sdk, output, cache, control)
            environment['CARGO_NET_OFFLINE'] = 'true'
            backend.stage_native_archives(output, sdk, recipe, toolchain, environment)
            native = Path(cached.get('cache_native_directory', str(parent)))
            require(backend.native_search(native, sdk, recipe, toolchain)['files'] == cached['native_archive_search']['files'],
                    'Applet cached native archives changed')
            environment['CARGO_ENCODED_RUSTFLAGS'] = environment['CARGO_ENCODED_RUSTFLAGS'].replace('native=' + str(output / 'native'), 'native=' + str(native / 'native'))
            for key, value in list(environment.items()):
                environment[key] = value.replace(str(output / 'bin'), str(native / 'bin'))
            extra = applets.additional_link_inputs(sdk, recipe)
            flags = ['-L', 'native=' + str(sdk / 'sysroot/usr/lib'), '-C', 'link-arg=-Wl,--start-group']
            for relative in extra['libraries']: flags += ['-C', 'link-arg=' + str(sdk / relative)]
            flags += ['-C', 'link-arg=-Wl,--end-group']
            environment['CARGO_ENCODED_RUSTFLAGS'] += '\x1f' + '\x1f'.join(flags)
            applets.configure_native_environment(environment, tools, sdk, output)
            budget = dict(budget_root=output, scratch_roots=(control,), growth_roots=((cache, base.directory_bytes(cache)),))
            metadata_command, _ = applets.commands(tools['cargo'], stage, recipe, 2)
            base.run_bounded(metadata_command, control, environment, output / 'metadata.json',
                *backend.common.remaining_bounds(deadline, bounds), stderr_log=output / 'metadata.stderr.log', **budget)
            metadata = base.load_json(output / 'metadata.json')
            identity = applets.metadata_identity(metadata, stage, cache, recipe, applets.contract()[0])
            require(identity == cached['cargo_dependencies'], 'Full locked applet graph changed during relink')
            binaries = {}; commands = []
            for name in applets.PROGRAMS:
                directory = output / name; directory.mkdir()
                wrapper = directory / 'link-repaired-mesa'
                wrapper.write_text(relink.linker_script(tools['target_cc'], repair / mesa.MEMBER, directory)); wrapper.chmod(0o755)
                command = [str(tools['cargo']), 'rustc', '--release', '--target', applets.parent.TARGET, '--jobs', '2',
                    '--package', identity['programs'][name], '--bin', name, '--manifest-path', str(stage / 'Cargo.toml'),
                    '--locked', '--offline', '--features', name + '/cyxia-native', '--', '-C', 'linker=' + str(wrapper)]
                commands.append(command)
                base.run_bounded(command, control, environment, directory / 'cargo.log',
                    *backend.common.remaining_bounds(deadline, bounds), **budget)
                mapping = (directory / 'native-link.map').read_text()
                require(not any(mesa.MEMBER in line
                    and ('.rlib(' in line or 'libEGL.a(' in line) for line in mapping.splitlines()), 'Old applet Mesa object selected')
                linked = output / 'target' / applets.parent.TARGET / 'release' / name
                final = output / (name + '.elf'); shutil.copyfile(linked, final); final.chmod(0o755)
                binaries[name] = dict(sha256=base.digest(final), image_admission=backend.elf.inspect_full_os_elf(final, profile),
                    mesa_wayland_object_selected=str(repair / mesa.MEMBER) in mapping)
            require(applets.verify_export(stage, inputs) == tree and base.tree_identity(parent / 'target') == cache_before
                    and base.tree_identity(sdk / 'sysroot') == cached['sdk_tree']
                    and os_x86.producer_sources(__file__) == producers, 'Applet relink inputs changed')
            mesa.verify(repair)
            names = ['metadata.json', 'metadata.stderr.log']
            for name in applets.PROGRAMS:
                names += [name + '/' + file for file in ('cargo.log', 'native-link.map', 'link-invocation.json', 'link-repaired-mesa')]
            report.update(status='cross-built', binaries=binaries, commands=commands,
                parent_cache_preserved=True, source_preserved=True,
                evidence={name: base.digest(output / name) for name in names})
    except BaseException as error:
        report.update(status='failed', error=repr(error))
        for name in applets.PROGRAMS: (output / (name + '.elf')).unlink(missing_ok=True)
        raise
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'relink-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return validate(output)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--build', type=Path, required=True); parser.add_argument('--repair', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host(); report = build(args.build, args.repair, args.output)
    print(json.dumps({key: report[key] for key in ('status', 'elapsed_seconds')}))


if __name__ == '__main__': main()
