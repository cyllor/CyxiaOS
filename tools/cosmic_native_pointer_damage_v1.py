#!/usr/bin/env python3
"""Build genuine COSMIC before/after damage-bounded native presentation.

Both builds use the pinned full dependency graph, existing SDK and tile-capacity
patch. The only difference is the native damage selection and cursor region.
Historical builders, source policies and retained artifacts remain immutable.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import build_cosmic_comp_linux_v5 as parent
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, require = parent.base, parent.require
PORT = base.ROOT / 'ports/cosmic/native-pointer-damage-v1'
TILE_PORT = base.ROOT / 'ports/cosmic/native-presentation-v1'
RELATIVES = ('src/backend/cyxia/mod.rs', 'src/backend/cyxia/native/presentation.rs')
RECIPE = base.ROOT / 'ports/cosmic/native-comp-phase-v4/native-linux-recipe.json'
PROFILE = base.ROOT / 'ports/cosmic/native-comp/native-linux-resource-v1.json'
KIND = 'cosmic-native-pointer-damage-v1'


def inputs():
    policy = base.load_json(PORT / 'source-policy.json')
    require(policy['kind'] == KIND, 'Unsupported pointer damage policy')
    for name, digest in policy['base_sources'].items():
        require(base.digest(PORT / 'base' / Path(name).name) == digest, 'Damage base changed')
    require(base.digest(PORT / 'damage.patch') == policy['patch_sha256'], 'Damage patch changed')
    tile = base.load_json(TILE_PORT / 'source-policy.json')
    require(base.digest(TILE_PORT / 'base/presentation.rs') == tile['base_phase_source_sha256']
            and base.digest(TILE_PORT / 'tile-capacity.patch') == tile['patch_sha256']
            and tile['patched_source_sha256'] == policy['base_sources']['native/presentation.rs'],
            'Existing tile-capacity preimage changed')
    paths = [PORT / n for n in ('source-policy.json', 'base/mod.rs', 'base/presentation.rs', 'damage.patch', 'LICENSE')]
    paths += [TILE_PORT / n for n in ('source-policy.json', 'base/presentation.rs', 'tile-capacity.patch', 'LICENSE')]
    paths += [RECIPE, PROFILE]
    return policy, {str(p.relative_to(base.ROOT)): base.digest(p) for p in paths}


def apply_patch(stage, patch):
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=stage, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    subprocess.run(['git', 'apply', str(patch)], cwd=stage, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)


def prepare_baseline(stage, policy):
    tile = base.load_json(TILE_PORT / 'source-policy.json')
    relative = 'src/backend/cyxia/native/presentation.rs'
    require(base.digest(stage / relative) == tile['base_phase_source_sha256'], 'Wrong phase preimage')
    apply_patch(stage, TILE_PORT / 'tile-capacity.patch')
    for name, digest in policy['base_sources'].items():
        require(base.digest(stage / 'src/backend/cyxia' / name) == digest, 'Wrong damage preimage')


def apply(stage, policy):
    for name, digest in policy['base_sources'].items():
        require(base.digest(stage / 'src/backend/cyxia' / name) == digest, 'Wrong damage preimage')
    apply_patch(stage, PORT / 'damage.patch')
    for name, digest in policy['patched_sources'].items():
        require(base.digest(stage / 'src/backend/cyxia' / name) == digest, 'Wrong damage postimage')


def only_cursor_changed(before, after):
    a, b = before['files'], after['files']
    require(a.keys() == b.keys() and sorted(p for p in a if a[p] != b[p]) == sorted(RELATIVES),
            'Compositor source changed beyond native damage presentation')


def build_pair(args):
    policy, selected = inputs()
    producers = os_x86.producer_sources(__file__)
    original_compile = parent.compile_selected

    def compile_pair(report, cargo, env, control, stage, output, common, features,
                     bounds, budget, recipe, cache, profile, sysroot, deadline):
        started = time.monotonic()
        prepare_baseline(stage, policy)
        # The parent exported the phase baseline. Replace only this new build's
        # retained source with the identical tile-capacity baseline being built.
        require(base.tree_identity(output / 'source') == report['source_tree'], 'Initial source changed')
        (output / 'source').rename(output / 'phase-source')
        report['source_tree'] = base.tree_identity(stage)
        shutil.copytree(stage, output / 'source', symlinks=True)
        report['baseline_tile_policy_sha256'] = base.digest(TILE_PORT / 'source-policy.json')
        original_compile(report, cargo, env, control, stage, output, common, features,
                         bounds, budget, recipe, cache, profile, sysroot, deadline)
        raw = output / 'cosmic-comp-baseline.elf'
        shutil.copyfile(Path(report['linked_binary']['path']), raw)
        baseline = dict(elapsed_seconds=time.monotonic() - started,
            source_tree=report['source_tree'], cargo_dependencies=report['cargo_dependencies'],
            preserved_resolution=report['preserved_resolution'], command=report['command'],
            executable=dict(path=str(raw), bytes=raw.stat().st_size, sha256=base.digest(raw)),
            inspection=parent.inspect_full_os_elf(raw, profile))
        for name in ('metadata.json', 'metadata.stderr.log', 'cargo.log'):
            shutil.copyfile(output / name, output / ('baseline-' + name))
        (output / 'source').rename(output / 'baseline-source')
        apply(stage, policy)
        fixed_tree = base.tree_identity(stage)
        only_cursor_changed(baseline['source_tree'], fixed_tree)
        report['source_tree'] = fixed_tree
        shutil.copytree(stage, output / 'source', symlinks=True)
        report['baseline'] = baseline
        report['patches'].append(dict(policy=str(PORT / 'source-policy.json'),
                                      patch_sha256=policy['patch_sha256'],
                                      before=policy['base_sources'],
                                      after=policy['patched_sources']))
        print(json.dumps(dict(stage='baseline_complete', seconds=round(baseline['elapsed_seconds'], 3),
                              bytes=raw.stat().st_size, sha256=base.digest(raw))), flush=True)
        fixed_started = time.monotonic()
        original_compile(report, cargo, env, control, stage, output, common, features,
                         bounds, budget, recipe, cache, profile, sysroot, deadline)
        report['fixed_compile_seconds'] = time.monotonic() - fixed_started

    output = Path(args.output).resolve()
    try:
        parent.compile_selected = compile_pair
        report = parent.perform('build', RECIPE, PROFILE, output, args.sysroot,
            args.source_cache, args.cache, args.rust_root, args.host_cc, 2, False)
    finally:
        parent.compile_selected = original_compile
        path = output / 'build-report.json'
        if path.exists():
            report = base.load_json(path)
            report['base_kind'] = report['kind']
            report['kind'] = KIND
            report['pointer_damage_extension'] = dict(inputs=selected, producers=producers)
            if inputs()[1] != selected or os_x86.producer_sources(__file__) != producers:
                report.update(status='FAILED', error='Pointer-damage input/producer changed')
            archive = output / 'producer-inputs'
            for name in {**producers, **selected}:
                destination = archive / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(base.ROOT / name, destination)
            path.write_text(json.dumps(report, indent=2) + '\n')
    require(report['status'] == 'cross-built', 'Complete compositor pair did not build')
    return report


def validate(directory):
    directory = base.no_symlink_path(directory)
    report = base.load_json(directory / 'build-report.json')
    policy, selected = inputs()
    extension = report['pointer_damage_extension']
    require(report['kind'] == KIND and report['status'] == 'cross-built'
            and extension['inputs'] == selected, 'Unadmitted pointer damage build')
    parent.contract(report['recipe'])
    parent.full_os_profile(base.load_json(PROFILE), report['recipe'], 2)
    for name, digest in {**report['producer_sources'], **extension['producers'], **selected}.items():
        require(base.digest(base.ROOT / name) == digest
                and base.digest(directory / 'producer-inputs' / name) == digest,
                'Compositor producer changed: ' + name)
    baseline = report['baseline']
    require(base.tree_identity(directory / 'baseline-source') == baseline['source_tree']
            and base.tree_identity(directory / 'source') == report['source_tree'], 'Retained compositor source changed')
    only_cursor_changed(baseline['source_tree'], report['source_tree'])
    original = Path(report['source_cache']) / report['component']['directory']
    require(parent.git_identity(original, parent.COMMIT) == report['canonical_source'], 'Original compositor changed')
    with tempfile.TemporaryDirectory(prefix='cyx-tiles-verify-') as tmp:
        stage = Path(tmp) / 'source'
        parent.export(original, stage)
        require(base.tree_identity(stage) == base.tree_identity(directory / 'phase-source'), 'Phase export changed')
        prepare_baseline(stage, policy)
        require(base.tree_identity(stage) == baseline['source_tree'], 'Baseline differs from canonical port export')
        apply(stage, policy)
        require(base.tree_identity(stage) == report['source_tree'], 'Fixed source differs from exact patch export')
    cache = Path(report['cargo_cache'])
    old = report['original_export_root']
    for prefix, source, expected in [('', directory / 'source', report['cargo_dependencies']),
                                     ('baseline-', directory / 'baseline-source', baseline['cargo_dependencies'])]:
        metadata = json.loads((directory / (prefix + 'metadata.json')).read_text().replace(old, str(source)))
        expected = json.loads(json.dumps(expected).replace(old, str(source)))
        require(parent.metadata_identity(metadata, source, cache, report['recipe']) == expected,
                'Complete compositor dependency closure changed')
    sysroot = Path(report['sysroot'])
    choice = report['toolchain']['selection']
    _, identities = parent.selection.tools_and_sysroot(sysroot, report['recipe'],
        rust_root=choice['rust_root'], host_cc=choice['host_cc'])
    require(identities == report['toolchain']
            and base.tree_identity(sysroot / 'sysroot') == report['sysroot_before'], 'Compositor SDK/toolchain changed')
    require({n: base.tree_identity(directory / n) for n in ('bin', 'native')} == report['generated_build_inputs'],
            'Native linker wrappers changed')
    for name, digest in report['retained_logs'].items():
        require(base.digest(directory / name) == digest, 'Compositor retained evidence changed')
    for name, entry in [('cosmic-comp-baseline.elf', baseline['executable']),
                         ('cosmic-comp.elf', report['linked_binary'])]:
        require(base.digest(directory / name) == entry['sha256'], 'Raw compositor ELF changed')
        parent.inspect_full_os_elf(directory / name, report['resource_profile'])
    return report


def assemble(args):
    build, base_build, output = map(base.no_symlink_path, (args.build, args.base_build, args.output))
    report = validate(build)
    manifest = base.load_json(base_build / 'build-manifest.json')
    original = Path(manifest['sysroot'])
    require(manifest['status'] == 'BUILT_NOT_RUN'
            and os_x86.catalog_inputs(original) == manifest['external_inputs'], 'Normal catalog changed')
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
            for p in (build, base_build, original, Path(report['sysroot']), PORT)), 'Unsafe compositor catalog output')
    variant = 'cosmic-comp-baseline.elf' if args.baseline else 'cosmic-comp.elf'
    raw = build / variant
    subprocess.run(['/bin/cp', '-cRp', str(original), str(output)], check=True)
    pending = output / '.cosmic-comp.pending'
    shutil.copyfile(raw, pending)
    pending.chmod(0o755)
    pending.replace(output / 'cosmic-comp.elf')
    expected = {**manifest['external_inputs'], 'cosmic-comp.elf': base.digest(raw)}
    require(os_x86.catalog_inputs(output) == expected, 'Compositor catalog changed other inputs')
    total = sum((output / name).stat().st_size for name in expected)
    require(total <= 192 * 1024**2, 'Clock-enabled normal catalog exceeds its existing profile')
    receipt = dict(status='COMPLETE_COMPOSITOR_CATALOG_NOT_RUN', baseline=args.baseline,
        build=str(build), report_sha256=base.digest(build / 'build-report.json'),
        base_build=str(base_build), base_manifest_sha256=base.digest(base_build / 'build-manifest.json'),
        input_count=len(expected), inputs=expected, raw_bytes=total,
        producers=os_x86.producer_sources(__file__), full_os_verified=False, cosmic_session_verified=False)
    (output / 'cosmic-native-pointer-damage-origin.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    b = sub.add_parser('build')
    b.add_argument('--output', type=Path, required=True)
    b.add_argument('--sysroot', type=Path, required=True)
    b.add_argument('--source-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-sources')
    b.add_argument('--cache', type=Path, default=base.ROOT / 'artifacts/cosmic-comp-cache')
    b.add_argument('--rust-root', type=Path, required=True)
    b.add_argument('--host-cc', type=Path, default=Path('/usr/bin/clang'))
    a = sub.add_parser('assemble')
    a.add_argument('--build', type=Path, required=True)
    a.add_argument('--base-build', type=Path, required=True)
    a.add_argument('--output', type=Path, required=True)
    a.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = build_pair(args) if args.action == 'build' else assemble(args)
    print(json.dumps(dict(status=result['status'], output=str(args.output)), indent=2))


if __name__ == '__main__':
    main()
