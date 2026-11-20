#!/usr/bin/env python3
"""Recompile the genuine GUI root, linking the repaired Mesa object first.

Rust sources, lock resolution, features and every dependency archive remain
unchanged. The link map must prove the old bundled Wayland object was not used.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import sys
import time

import build_cosmic_time_applet_v2 as clock_builder
import build_mesa_wayland_oom_v1 as mesa
import cosmic_panel_allocation_v2 as panel
import cosmic_time_applet_v2 as clock
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base = panel.base
require = panel.require


def linker_script(compiler, obj, output):
    # JSON literals are Python values here, never interpolated shell code.
    return '#!' + sys.executable + '\n' + '''import hashlib,json,subprocess,sys
from pathlib import Path
''' + 'compiler=' + repr(str(compiler)) + '\nobject_path=' + repr(str(obj)) + '\noutput=' + repr(str(output)) + '\n' + '''
before = sys.argv[1:]
after = [object_path, '-Wl,-Map,' + str(Path(output)/'native-link.map'), *before]
record = dict(original_arguments=before, actual_arguments=after, native_object_sha256=hashlib.sha256(Path(object_path).read_bytes()).hexdigest())
Path(output,'link-invocation.json').write_text(json.dumps(record,indent=2)+'\\n')
sys.exit(subprocess.run([compiler,*after]).returncode)
'''


def build(parent_build, repair, output, sdk, rust_root, host_cc, cache):
    cached = base.load_json(parent_build / 'build-report.json')
    require(cached['status'] == 'cross-built', 'Parent is not a complete genuine GUI build')
    kind = cached['component']['name']
    fix = panel if kind == 'cosmic-panel' else clock
    require(kind in ('cosmic-panel', 'cosmic-applet-time'), 'Unsupported native GUI root')
    policy, recipe, component, profile, _ = fix.contract()
    require(cached['recipe'] == recipe and cached['component'] == component,
            'Parent recipe/source selection differs')
    mesa_report = mesa.verify(repair)
    obj = repair / mesa.MEMBER
    require(not output.exists(), 'Preserving existing relink output')
    require(all(not output.is_relative_to(p) and not p.is_relative_to(output)
        for p in (parent_build, repair, sdk, cache)), 'Relink output overlaps an input')
    output.mkdir(parents=True)
    producers = os_x86.producer_sources(__file__)
    for module in (mesa, fix, clock_builder):
        path = Path(module.__file__).resolve()
        producers[str(path.relative_to(base.ROOT))] = base.digest(path)
    for name, digest in producers.items():
        target = output / 'producer-sources' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base.ROOT / name, target)
        require(base.digest(target) == digest, 'Relink producer snapshot changed')
    started = time.monotonic()
    deadline = started + profile['timeout_seconds']
    bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
    report = dict(kind='cosmic-mesa-wayland-relink-v1', status='building', component=component,
        recipe=recipe, resource_profile=profile, producers=producers,
        parent_build=str(parent_build), parent_report_sha256=base.digest(parent_build / 'build-report.json'),
        repair=str(repair), repair_report_sha256=base.digest(repair / 'repair-origin.json'),
        full_os_verified=False, cosmic_session_verified=False, applet_verified=False, cargo_offline=True)
    try:
        with (cache / '.cyxia-build.lock').open('a') as cache_lock, \
             (sdk / '.build.lock').open('a') as sdk_lock, clock_builder.workspace(cached) as temporary:
            fcntl.flock(cache_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(sdk_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            control = Path(temporary).resolve()
            stage = control / 'source'
            source_cache = base.ROOT / 'artifacts/cosmic-sources'
            native_cache = base.ROOT / 'artifacts/cosmic-native-sources'
            inputs, tree = fix.export(source_cache, native_cache, cache, stage)
            require(tree == cached['source_tree'], 'Relink changed genuine Rust source bytes')
            for name in tree['files']:
                info = (parent_build / 'source' / name).stat()
                os.utime(stage / name, ns=(info.st_atime_ns, info.st_mtime_ns))
            shutil.copytree(stage, output / 'source')
            original_cache = base.tree_identity(parent_build / 'target')
            require(not any('symlink' in row for row in original_cache['files'].values()), 'External cache links')
            import subprocess
            subprocess.run(['/bin/cp', '-cRp', str(parent_build / 'target'), str(output / 'target')], check=True)
            require(base.tree_identity(output / 'target') == original_cache, 'Cache clone changed bytes')
            parent = fix.parent
            tools, toolchain = parent.common.selection.tools_and_sysroot(
                sdk, recipe, rust_root=rust_root, host_cc=host_cc)
            parent.check_toolchain(toolchain)
            require(toolchain == cached['toolchain'], 'Relink compiler/SDK changed')
            sdk_tree = base.tree_identity(sdk / 'sysroot')
            require(sdk_tree == cached['sdk_tree'], 'Relink SDK headers changed')
            environment = base.cargo_environment(tools, toolchain, sdk, output, cache, control)
            parent.stage_native_archives(output, sdk, recipe, toolchain, environment)
            native_base = Path(cached.get('cache_native_directory', str(parent_build)))
            require(parent.native_search(native_base, sdk, recipe, toolchain)['files']
                    == cached['native_archive_search']['files'], 'Original native archives changed')
            environment['CARGO_ENCODED_RUSTFLAGS'] = environment['CARGO_ENCODED_RUSTFLAGS'].replace(
                'native=' + str(output / 'native'), 'native=' + str(native_base / 'native'))
            for name, value in list(environment.items()):
                if str(output / 'bin') in value:
                    environment[name] = value.replace(str(output / 'bin'), str(native_base / 'bin'))
            wrapper = output / 'link-repaired-mesa'
            wrapper.write_text(linker_script(tools['target_cc'], obj, output))
            wrapper.chmod(0o755)
            metadata_command = cached['metadata_command']
            budget = dict(budget_root=output, scratch_roots=(control,),
                          growth_roots=((cache, base.directory_bytes(cache)),))
            base.run_bounded(metadata_command, control, environment, output / 'metadata.json',
                *parent.common.remaining_bounds(deadline, bounds),
                stderr_log=output / 'metadata.stderr.log', **budget)
            metadata = base.load_json(output / 'metadata.json')
            dependencies = (parent.metadata_identity if kind == 'cosmic-panel' else fix.metadata_identity)(
                metadata, stage, cache, recipe, policy)
            require(dependencies == cached['cargo_dependencies'], 'Relink changed full locked Rust graph')
            command = list(cached['command'])
            require(command[1] == 'build', 'Unexpected parent Cargo invocation')
            command[1] = 'rustc'
            command += ['--', '-C', 'linker=' + str(wrapper)]
            report.update(command=command, metadata_command=metadata_command, cargo_dependencies=dependencies,
                source_inputs=inputs, source_tree=tree, toolchain=toolchain, sdk_tree=sdk_tree,
                original_export_root=str(stage), cache_native_directory=str(native_base))
            base.run_bounded(command, control, environment, output / 'cargo.log',
                *parent.common.remaining_bounds(deadline, bounds), **budget)
            require((output / 'link-invocation.json').is_file(), 'Repaired native linker was not used')
            link = base.load_json(output / 'link-invocation.json')
            require(link['native_object_sha256'] == mesa_report['outputs'][mesa.MEMBER], 'Wrong native object linked')
            mapping = (output / 'native-link.map').read_text()
            require(str(obj) in mapping and not any(mesa.MEMBER in line
                and ('.rlib(' in line or 'libEGL.a(' in line) for line in mapping.splitlines()),
                'Old bundled Mesa Wayland object was selected')
            linked = output / 'target' / recipe['target'] / 'release' / recipe['binary']
            inspection = parent.elf.inspect_full_os_elf(linked, profile)
            final = output / (recipe['binary'] + '.elf')
            shutil.copyfile(linked, final)
            require(b'missing software back buffer' in final.read_bytes(), 'Repaired callback not retained in ELF')
            require(fix.verify_export(stage, inputs) == tree
                and fix.verify_export(output / 'source', inputs) == tree
                and base.tree_identity(parent_build / 'target') == original_cache
                and base.tree_identity(sdk / 'sysroot') == sdk_tree, 'Original source/cache/SDK changed')
            mesa.verify(repair)
            report.update(status='cross-built', image_admission=inspection,
                linked_binary=dict(path=str(linked), bytes=linked.stat().st_size, sha256=base.digest(linked)),
                parent_cache_preserved=True, old_native_object_unselected=True,
                evidence_files={name: base.digest(output / name) for name in
                    ('metadata.json', 'cargo.log', 'link-invocation.json', 'native-link.map')})
    except BaseException as error:
        report.update(status='failed', error=str(error))
        (output / (recipe['binary'] + '.elf')).unlink(missing_ok=True)
        raise
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-build', type=Path, required=True)
    parser.add_argument('--repair', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, default=base.ROOT / 'artifacts/sysroot/x86_64-musl')
    parser.add_argument('--cargo-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-comp-cache')
    parser.add_argument('--rust-root', type=Path, default=Path('/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin'))
    parser.add_argument('--host-cc', type=Path, default=Path('/usr/bin/clang'))
    args = parser.parse_args()
    paths = [base.no_symlink_path(p) for p in (args.parent_build, args.repair, args.output,
                                              args.sysroot, args.rust_root, args.host_cc, args.cargo_cache)]
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = build(*paths)
    print(json.dumps({k: result[k] for k in ('status', 'elapsed_seconds', 'linked_binary')}, indent=2))


if __name__ == '__main__':
    main()
