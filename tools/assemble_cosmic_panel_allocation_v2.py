#!/usr/bin/env python3
"""Revalidate the full panel build, link its actual helper probe, preserve the catalog."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import cosmic_panel_allocation_v2 as fix
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, parent, require = fix.base, fix.parent, fix.require
LICENSES = {
    'LICENSE.md': 'LICENSE.md',
    'native-deps/launch-pad/LICENSE.md': 'launch-pad-LICENSE.md',
    'native-deps/smithay/LICENSE.txt': 'smithay-LICENSE.txt',
    'native-deps/smithay/smithay-drm-extras/LICENSE': 'smithay-drm-extras-LICENSE',
    'native-deps/wayland-sys/LICENSE.txt': 'wayland-sys-LICENSE.txt',
    'native-deps/wayland-backend/LICENSE.txt': 'wayland-backend-LICENSE.txt',
}


def function(source, signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def validate(build):
    report = base.load_json(build / 'build-report.json')
    policy, recipe, _, profile, _ = fix.contract()
    require(report['status'] == 'cross-built' and report['recipe'] == recipe
            and report['resource_profile'] == profile
            and report['source_policy_sha256'] == base.digest(fix.PORT / 'source-policy.json'),
            'Panel is not an admitted complete allocation build')
    for name, digest in report['producers'].items():
        require(base.digest(base.ROOT / name) == digest, 'Panel producer changed: ' + name)
    for name, digest in report['evidence_files'].items():
        require(base.digest(build / name) == digest, 'Panel build evidence changed')
    source = build / 'source'
    require(fix.verify_export(source, report['source_inputs']) == report['source_tree'],
            'Retained complete panel source changed')
    inputs = report['source_inputs']
    original_cache = Path(inputs['originals']['panel']['path']).parent
    native_cache = Path(inputs['originals']['smithay']['path']).parent
    metadata = base.load_json(build / 'metadata.json')
    cargo_cache = next(Path(p['manifest_path']).parents[3] for p in metadata['packages']
                       if (p.get('source') or '').startswith('registry+'))
    # registry/src/<index>/<crate>/Cargo.toml -> CARGO_HOME is four parents up.
    cargo_cache = cargo_cache.parent
    require(fix.original_inputs(original_cache, native_cache, cargo_cache) == inputs,
            'Panel original closure changed')
    old_stage = report['original_export_root']
    rebound = json.loads(json.dumps(metadata).replace(old_stage, str(source)))
    expected = json.loads(json.dumps(report['cargo_dependencies']).replace(old_stage, str(source)))
    require(parent.metadata_identity(rebound, source, cargo_cache, recipe, policy) == expected,
            'Panel complete Cargo graph changed')
    sysroot = Path(report['sysroot'])
    selected = report['toolchain']['selection']
    tools, identity = parent.common.selection.tools_and_sysroot(sysroot, recipe,
                        rust_root=selected['rust_root'], host_cc=selected['host_cc'])
    require(identity == report['toolchain']
            and base.tree_identity(sysroot / 'sysroot') == report['sdk_tree'],
            'Panel SDK or compiler changed')
    require(parent.native_search(build, sysroot, recipe, identity) == report['native_archive_search'],
            'Panel static native archives changed')
    require(base.digest(build / 'cosmic-panel.elf') == report['linked_binary']['sha256'],
            'Published panel differs from raw link')
    actual = parent.elf.inspect_full_os_elf(build / 'cosmic-panel.elf', profile)
    original = report['image_admission']
    require(actual == {**original, 'executable': {**original['executable'], 'file': 'cosmic-panel.elf'}},
            'Panel FullOs admission changed')
    return report, tools


def assemble(build, base_build, output, probe_output):
    build, base_build, output, probe_output = map(base.no_symlink_path, (build, base_build, output, probe_output))
    report, tools = validate(build)
    manifest_path = base_build / 'build-manifest.json'
    manifest = base.load_json(manifest_path)
    original = Path(manifest['sysroot'])
    require(manifest['status'] == 'BUILT_NOT_RUN'
            and os_x86.catalog_inputs(original) == manifest['external_inputs'], 'Parent OS inputs changed')
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
            for p in (build, base_build, original, Path(report['sysroot']), fix.PORT)),
            'Panel catalog overlaps an input')
    subprocess.run(['/bin/cp', '-cRp', str(original), str(output)], check=True)
    pending = output / '.cosmic-panel.pending'
    shutil.copyfile(build / 'cosmic-panel.elf', pending)
    pending.chmod(0o755)
    pending.replace(output / 'cosmic-panel.elf')
    added = {}
    for name, target in LICENSES.items():
        relative = 'rootfs/usr/share/doc/cosmic-panel/' + target
        require(relative not in manifest['external_inputs'], 'Panel license would replace an input')
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(build / 'source' / name, destination)
        destination.chmod(0o644)
        added[relative] = base.digest(destination)

    updated = {**manifest['external_inputs'], **added,
               'cosmic-panel.elf': report['linked_binary']['sha256']}
    require(os_x86.catalog_inputs(output) == updated, 'Normal panel catalog changed other inputs')
    total = sum((output / name).stat().st_size for name in updated)
    require(total <= 128 * 1024**2, 'Normal panel catalog exceeds the unchanged 128 MiB bound')
    require(not probe_output.exists() and all(not probe_output.is_relative_to(p)
            and not p.is_relative_to(probe_output) for p in
            (build, base_build, original, output, Path(report['sysroot']), fix.PORT)),
            'Probe catalog overlaps an input')
    subprocess.run(['/bin/cp', '-cRp', str(output), str(probe_output)], check=True)
    # The full normal catalog retains every diagnostic. The isolated mechanism
    # image replaces only an unused diagnostic, preserving all five core ELFs.
    excluded = 'notifications-peer-probe.elf'
    require(excluded in updated, 'Expected isolated-probe replacement is absent')
    (probe_output / excluded).unlink()

    source = build / 'source'
    helper = function((source / 'cosmic-panel-bin/src/xdg_shell_wrapper/util.rs').read_text(),
                      'pub fn get_client_sock(')
    client = (source / 'cosmic-panel-bin/src/xdg_shell_wrapper/client/state.rs').read_text()
    context = '#[derive(Debug, Default)]\n' + function(client, 'pub struct WrapperClientCompositorState {')
    context += '\n' + function(client, 'impl ClientData for WrapperClientCompositorState {')
    generated = probe_output / 'panel-allocation-helper.rs'
    generated.write_text(context + '\n' + helper + '\n')
    probe = base.ROOT / 'user/ported/panel_allocation_probe.rs'
    dependencies = build / 'target' / parent.TARGET / 'release/deps'
    # A cloned Cargo cache retains old dependency cohorts. Select the cohort
    # recorded by the actual raw linked panel, never by file order or mtime.
    roots = [p for p in dependencies.glob('cosmic_panel-*') if not p.suffix
             and p.is_file() and base.digest(p) == report['linked_binary']['sha256']]
    require(len(roots) == 1, 'Ambiguous linked panel Cargo unit')
    fingerprints = dependencies.parent / '.fingerprint'
    root_tag = roots[0].name.removeprefix('cosmic_panel-')
    root_record = fingerprints / ('cosmic-panel-bin-' + root_tag) / 'bin-cosmic-panel.json'
    root_dependencies = base.load_json(root_record)['deps']
    selected = [d[3] for d in root_dependencies if d[1] == 'smithay']
    require(len(selected) == 1, 'Missing actual panel Smithay fingerprint')
    candidates = [p.parent.name.removeprefix('smithay-')
        for p in fingerprints.glob('smithay-*/lib-smithay')
        if int.from_bytes(bytes.fromhex(p.read_text().strip()), 'little') == selected[0]]
    require(len(candidates) == 1, 'Ambiguous real panel Smithay dependency')
    smithay = [dependencies / ('libsmithay-' + candidates[0] + '.rlib')]
    require(smithay[0].is_file(), 'Missing actual panel Smithay rlib')
    environment = base.clean_environment('/usr/bin:/bin')
    environment['CYXIA_PANEL_ALLOCATION_HELPER'] = str(generated)
    command = [str(tools['rustc']), '--edition=2024', '--target', parent.TARGET, '-C', 'panic=abort',
               '-C', 'opt-level=2', '-C', 'link-self-contained=no', '-C', 'relocation-model=static',
               '-C', 'target-feature=+crt-static', '-C', 'linker=' + str(tools['target_cc']),
               '-L', 'dependency=' + str(dependencies),
               '-L', 'dependency=' + str(build / 'target/release/deps'),
               '-L', 'native=' + str(build / 'native'),
               '--extern', 'smithay=' + str(smithay[0]), '-C', 'link-arg=-Wl,--start-group']
    command += [value for name in report['recipe']['static_link_inputs']
                for value in ('-C', 'link-arg=' + str(Path(report['sysroot']) / name))]
    command += ['-C', 'link-arg=-Wl,--end-group', str(probe), '-o', str(probe_output / 'panel-allocation-probe.elf')]
    (probe_output / 'panel-allocation-probe-command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (probe_output / 'panel-allocation-probe-link.log').open('w') as log:
        subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT,
                       timeout=120, check=True)
    probe_inputs = {name: digest for name, digest in updated.items() if name != excluded}
    probe_inputs['panel-allocation-probe.elf'] = base.digest(probe_output / 'panel-allocation-probe.elf')
    require(os_x86.catalog_inputs(output) == updated and os_x86.catalog_inputs(original)
            == manifest['external_inputs'], 'Catalog changed outside the exact panel/probe addition')
    probe_total = sum((probe_output / name).stat().st_size for name in probe_inputs)
    require(os_x86.catalog_inputs(probe_output) == probe_inputs
            and probe_total <= 128 * 1024**2, 'Isolated probe catalog exceeds the unchanged bound')
    require(validate(build)[0] == report, 'Panel changed during probe linking')
    record = dict(status='PANEL_ALLOCATION_CATALOG_ASSEMBLED_NOT_RUN',
        build=str(build), build_report_sha256=base.digest(build / 'build-report.json'),
        base_build=str(base_build), base_manifest_sha256=base.digest(manifest_path),
        original_inputs=manifest['external_inputs'], inputs=updated, raw_bytes=total,
        probe_catalog=str(probe_output), probe_inputs=probe_inputs, probe_raw_bytes=probe_total,
        isolated_diagnostic_replaced={excluded: updated[excluded]},
        probe_source_sha256=base.digest(probe), helper_sha256=base.digest(generated),
        probe_smithay_rlib=dict(path=str(smithay[0]), sha256=base.digest(smithay[0]),
                               cargo_unit_sha256=base.digest(root_record)),
        probe_command=command, producers=os_x86.producer_sources(__file__),
        full_os_verified=False, cosmic_session_verified=False)
    (output / 'cosmic-panel-allocation-origin.json').write_text(json.dumps(record, indent=2) + '\n')
    (probe_output / 'cosmic-panel-allocation-origin.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], raw_bytes=total, probe_raw_bytes=probe_total,
                         panel_sha256=updated['cosmic-panel.elf']), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--probe-output', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        assemble(args.build, args.base_build, args.output, args.probe_output)


if __name__ == '__main__':
    main()
