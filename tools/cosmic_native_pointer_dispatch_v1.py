#!/usr/bin/env python3
"""Build and install the pinned native compositor with pointer latency fixes."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import build_cosmic_comp_linux_v5 as parent
import cosmic_native_pointer_motion_v1 as motion
import os_x86
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

base, require = parent.base, parent.require
KIND = 'cosmic-native-pointer-dispatch-v1'
PORT = base.ROOT / 'ports/cosmic/native-pointer-dispatch-v1'
PATCH = PORT / 'dispatch.patch'
SOURCES = {'src/backend/cyxia/mod.rs', 'src/input/mod.rs',
           'src/backend/cyxia/native/presentation.rs'}


def inputs():
    policy_file = PORT / 'source-policy.json'
    policy = base.load_json(policy_file)
    require(policy['kind'] == KIND and policy['commit'] == parent.COMMIT
            and set(policy['base_sources']) == set(policy['patched_sources']) == SOURCES
            and base.digest(PATCH) == policy['patch_sha256'], 'Invalid motion dispatch policy')
    motion_policy, files = motion.inputs()
    files.update({str(p.relative_to(base.ROOT)): base.digest(p)
                  for p in (policy_file, PATCH, PORT / 'LICENSE')})
    return policy, motion_policy, files


def patch_source(stage, policy, motion_policy):
    motion.prepare_baseline(stage, motion_policy)
    motion.apply(stage, motion_policy)
    before = base.tree_identity(stage)['files']
    for relative, digest in policy['base_sources'].items():
        require(base.digest(stage / relative) == digest, 'Wrong motion dispatch preimage')
    motion.apply_patch(stage, PATCH)
    tree = base.tree_identity(stage)
    after = tree['files']
    require(before.keys() == after.keys()
            and {name for name in before if before[name] != after[name]} == SOURCES,
            'Unexpected motion dispatch source changes')
    for relative, digest in policy['patched_sources'].items():
        require(base.digest(stage / relative) == digest, 'Wrong motion dispatch postimage')
    return tree


def build(args):
    policy, motion_policy, files = inputs()
    producers = os_x86.producer_sources(__file__)
    original_compile = parent.compile_selected

    def compile_dispatch(report, cargo, env, control, stage, output, *options):
        if args.reuse_build:
            origin = base.no_symlink_path(args.reuse_build)
            receipt = origin / 'build-report.json'
            prior = base.load_json(receipt)
            validate_reuse(prior)
            native = reused_native(prior['reused_target']) if 'reused_target' in prior else origin / 'native'
            native_tree = base.tree_identity(native)
            binary = origin / 'target' / report['target'] / 'release/cosmic-comp'
            require(prior['status'] == 'cross-built' and prior['target_linked']
                    and prior['pointer_dispatch']['kind'] == KIND
                    and prior['recipe'] == report['recipe'] and prior['toolchain'] == report['toolchain']
                    and native_tree == prior['generated_build_inputs']['native']
                    == report['generated_build_inputs']['native']
                    and base.digest(binary) == base.digest(origin / 'cosmic-comp.elf')
                    == prior['executable']['sha256'], 'Incompatible compositor Cargo cache')
            subprocess.run(['/bin/cp', '-cRp', str(origin / 'target'), str(output / 'target')], check=True)
            flags = env['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')
            new_native = 'native=' + str(output / 'native')
            require(flags.count(new_native) == 1, 'Missing native linker search path')
            flags[flags.index(new_native)] = 'native=' + str(native)
            env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
            report['reused_target'] = dict(build=str(origin), report_sha256=base.digest(receipt),
                                          native=native_tree, native_path=str(native))
        report['source_tree'] = patch_source(stage, policy, motion_policy)
        shutil.copytree(stage, output / 'source', symlinks=True, dirs_exist_ok=True)
        for name, applied in [('native-pointer-motion-v1', motion_policy),
                              (PORT.name, policy)]:
            report['patches'].append(dict(policy=str(base.ROOT / 'ports/cosmic' / name / 'source-policy.json'),
                                          patch_sha256=applied['patch_sha256'],
                                          before=applied['base_sources'], after=applied['patched_sources']))
        report['pointer_dispatch'] = dict(kind=KIND, inputs=files, producers=producers)
        original_compile(report, cargo, env, control, stage, output, *options)
        validate_reuse(report)
        require(inputs()[2] == files and os_x86.producer_sources(__file__) == producers,
                'Motion dispatch producer or source changed')
        for relative in files.keys() | producers.keys():
            destination = output / 'producer-inputs' / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(base.ROOT / relative, destination)

    try:
        parent.compile_selected = compile_dispatch
        return parent.perform('build', motion.RECIPE, motion.PROFILE, args.output, args.sysroot,
                              args.source_cache, args.cache, args.rust_root, args.host_cc, 2, False)
    finally:
        parent.compile_selected = original_compile


def reused_native(reuse):
    return base.no_symlink_path(reuse.get('native_path', Path(reuse['build']) / 'native'))


def validate_reuse(report):
    if 'reused_target' in report:
        reuse = report['reused_target']
        origin = Path(reuse['build'])
        require(base.digest(origin / 'build-report.json') == reuse['report_sha256']
                and base.tree_identity(reused_native(reuse)) == reuse['native'],
                'Reused native link inputs changed')


def validate(build):
    report = base.load_json(build / 'build-report.json')
    policy, motion_policy, files = inputs()
    producers = os_x86.producer_sources(__file__)
    require(report['status'] == 'cross-built' and report['target_linked']
            and report['pointer_dispatch'] == dict(kind=KIND, inputs=files, producers=producers),
            'Unadmitted motion dispatch build')
    validate_reuse(report)
    for relative, digest in {**files, **producers}.items():
        require(base.digest(build / 'producer-inputs' / relative) == digest,
                'Archived motion dispatch inputs changed')
    parent.contract(report['recipe'])
    original = Path(report['source_cache']) / report['component']['directory']
    require(parent.git_identity(original, parent.COMMIT) == report['canonical_source'],
            'Canonical compositor source changed')
    with tempfile.TemporaryDirectory(prefix='cyx-dispatch-verify-') as tmp:
        stage = Path(tmp).resolve() / 'source'
        parent.export(original, stage)
        require(patch_source(stage, policy, motion_policy) == report['source_tree']
                == base.tree_identity(build / 'source'), 'Motion dispatch source tree changed')
    for relative, digest in report['retained_logs'].items():
        require(base.digest(build / relative) == digest, 'Motion dispatch build log changed')
    executable = build / 'cosmic-comp.elf'
    profile = parent.full_os_profile(base.load_json(motion.PROFILE), report['recipe'], 2)
    inspection = parent.inspect_full_os_elf(executable, profile)
    require(inspection['executable']['sha256'] == report['executable']['sha256'],
            'Motion dispatch executable changed')
    return executable


def assemble(args):
    build, base_build, output = map(base.no_symlink_path, (args.build, args.base_build, args.output))
    raw = validate(build)
    manifest = base.load_json(base_build / 'build-manifest.json')
    original = Path(manifest['sysroot'])
    require(manifest['status'] == 'BUILT_NOT_RUN' and 'cosmic-comp.elf' in manifest['external_inputs']
            and os_x86.catalog_inputs(original) == manifest['external_inputs'], 'Normal catalog changed')
    require(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
            for p in (build, base_build, original, PORT)), 'Unsafe compositor catalog output')
    subprocess.run(['/bin/cp', '-cRp', str(original), str(output)], check=True)
    pending = output / '.cosmic-comp.pending'
    shutil.copyfile(raw, pending)
    pending.chmod(0o755)
    pending.replace(output / 'cosmic-comp.elf')
    expected = {**manifest['external_inputs'], 'cosmic-comp.elf': base.digest(raw)}
    require(os_x86.catalog_inputs(output) == expected, 'Compositor catalog changed other inputs')
    receipt = dict(status='COMPLETE_COMPOSITOR_CATALOG_NOT_RUN', build=str(build),
                   report_sha256=base.digest(build / 'build-report.json'), base_build=str(base_build),
                   base_manifest_sha256=base.digest(base_build / 'build-manifest.json'), inputs=expected,
                   full_os_verified=False, cosmic_session_verified=False)
    (output / 'cosmic-native-pointer-dispatch-origin.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    builder = commands.add_parser('build')
    builder.add_argument('--output', type=Path, required=True)
    builder.add_argument('--sysroot', type=Path, required=True)
    builder.add_argument('--rust-root', type=Path, required=True)
    builder.add_argument('--reuse-build', type=Path)
    builder.add_argument('--host-cc', type=Path, default=Path('/usr/bin/clang'))
    builder.add_argument('--source-cache', type=Path, default=base.ROOT / 'artifacts/cosmic-sources')
    builder.add_argument('--cache', type=Path, default=base.ROOT / 'artifacts/cosmic-comp-cache')
    catalog = commands.add_parser('assemble')
    catalog.add_argument('--build', type=Path, required=True)
    catalog.add_argument('--base-build', type=Path, required=True)
    catalog.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = build(args) if args.action == 'build' else assemble(args)
    print(json.dumps(dict(status=result['status'], output=str(args.output))))


if __name__ == '__main__':
    main()
