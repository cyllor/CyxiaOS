"""Two genuine Epoch workspace controls on the preserved complete applets tree."""
from pathlib import Path
import json
import stat
import subprocess
import sys

import cosmic_time_applet_v2 as parent
import cosmic_ports

base, require = parent.base, parent.require
PORT = base.ROOT / 'ports/cosmic/native-workspace-applets-v1'
PROGRAMS = ('cosmic-applet-workspaces', 'cosmic-applet-tiling')
FEATURES = [name + '/cyxia-native' for name in PROGRAMS]
METADATA_FEATURES = [*parent.FEATURES, *FEATURES]
KIND = 'cosmic-workspace-applets-v1'
INPUT_LIBRARIES = tuple('sysroot/usr/lib/lib' + name + '.a' for name in ('input', 'udev', 'evdev', 'mtdev'))


def cross_probe_wrapper(rustc, sysroot, output):
    """libudev-sys 0.1.4 invokes bare rustc without TARGET/RUSTC/linker flags.

    Cargo still uses the selected absolute RUSTC for every package. This narrow
    adapter accepts only the pinned upstream symbol probe and performs a real
    target link. It never runs the resulting Linux executable on the host.
    """
    config = dict(rustc=str(rustc), sdk=str(sysroot), output=str(output), target=parent.TARGET)
    return '#!' + sys.executable + '\n' + 'config = ' + repr(config) + '\n' + '''import hashlib, json, os
from pathlib import Path
import subprocess, sys
args = sys.argv[1:]
if len(args) != 5 or args[1] != '--out-dir' or args[3:] != ['-l', 'udev']:
    sys.exit('Only the pinned libudev-sys symbol probe may use the target rustc adapter')
source, directory = Path(args[0]).resolve(), Path(args[2]).resolve()
root = Path(config['output']) / 'target' / config['target'] / 'release/build'
expected = ('extern "C" {\\n    fn udev_hwdb_new();\\n}\\n\\nfn main() {\\n'
            '    unsafe {\\n        udev_hwdb_new();\\n    }\\n}\\n').encode()
if (source.parent != directory or source.name != 'check_udev_hwdb_new.rs'
        or not directory.is_relative_to(root) or source.read_bytes() != expected):
    sys.exit('Unexpected libudev-sys symbol probe source or path')
sdk = Path(config['sdk'])
command = [config['rustc'], *args, '--target', config['target'], '-L', 'native=' + str(sdk / 'sysroot/usr/lib'),
           '-L', 'native=' + str(Path(config['output']) / 'native'),
           '-C', 'linker=' + str(sdk / 'bin/x86_64-linux-musl-cc'), '-C', 'link-self-contained=no',
           '-C', 'target-feature=+crt-static', '-C', 'relocation-model=static']
result = subprocess.run(command, capture_output=True, timeout=30)
evidence = Path(config['output']) / 'libudev-target-probe'
evidence.mkdir(exist_ok=True)
(evidence / 'stdout.log').write_bytes(result.stdout)
(evidence / 'stderr.log').write_bytes(result.stderr)
data = dict(command=command, returncode=result.returncode, source=str(source),
            source_sha256=hashlib.sha256(expected).hexdigest(),
            executable=str(directory / 'check_udev_hwdb_new'), executed=False)
(evidence / 'result.json').write_text(json.dumps(data, indent=2) + '\\n')
sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
sys.exit(result.returncode)
'''


def configure_native_environment(environment, tools, sysroot, output):
    directory = output / 'cross-probe-bin'; directory.mkdir()
    wrapper = directory / 'rustc'
    wrapper.write_text(cross_probe_wrapper(tools['rustc'], sysroot, output)); wrapper.chmod(0o755)
    environment['PATH'] = str(directory) + ':' + environment['PATH']
    return dict(wrapper=str(wrapper), sha256=base.digest(wrapper), scope='libudev-sys-0.1.4-target-symbol-link')


def verify_native_environment(output, toolchain, sysroot, expected):
    wrapper = output / 'cross-probe-bin/rustc'
    rustc = toolchain['tools']['rustc']['path']
    require(wrapper.read_text() == cross_probe_wrapper(rustc, sysroot, output)
            and base.digest(wrapper) == expected['sha256'] and stat.S_IMODE(wrapper.stat().st_mode) == 0o755,
            'Target symbol probe adapter changed')
    evidence = output / 'libudev-target-probe'
    result = base.load_json(evidence / 'result.json')
    executable = base.no_symlink_path(Path(result['executable']))
    source = base.no_symlink_path(Path(result['source']))
    require(result['returncode'] == 0 and result['executed'] is False
            and executable.parent == source.parent
            and executable.is_relative_to(output / 'target' / parent.TARGET / 'release/build')
            and base.digest(source) == result['source_sha256'], 'Genuine target libudev hwdb link did not pass')
    cosmic_ports.elf_header(executable.read_bytes(), (2,), target='x86_64')
    return dict(result=result, executable_sha256=base.digest(executable),
                evidence={p.name: base.digest(p) for p in evidence.iterdir() if p.is_file()})


def contract():
    policy = base.load_json(PORT / 'source-policy.json')
    recipe = base.load_json(PORT / 'native-recipe.json')
    profile = base.load_json(PORT / 'resource-profile.json')
    original_policy, original_recipe, component, original_profile, _ = parent.contract()
    require(policy['kind'] == KIND and policy['commit'] == parent.COMMIT
            and policy['parent_policy_sha256'] == base.digest(parent.PORT / 'source-policy.json')
            and policy['patch_sha256'] == base.digest(PORT / 'native.patch')
            and set(policy['before']) == set(policy['after']) == {
                'Cargo.lock', *(name + '/Cargo.toml' for name in PROGRAMS)},
            'Workspace applet source contract changed')
    require(recipe['component'] == 'cosmic-applets'
            and recipe['package'] == recipe['binary'] == PROGRAMS[0]
            and recipe['binaries'] == list(PROGRAMS) and recipe['features'] == FEATURES
            and recipe['metadata_features'] == METADATA_FEATURES
            and recipe['default_features'] is True and recipe['target'] == parent.TARGET
            and recipe['commit'] == parent.COMMIT
            and recipe['source_lock_sha256'] == policy['before']['Cargo.lock']
            and recipe['effective_lock_sha256'] == policy['after']['Cargo.lock']
            and recipe['patches'] == [{'path': 'native.patch', 'sha256': policy['patch_sha256']}],
            'Workspace applet binary, lock or GUI feature changed')
    for key in ('native_inputs', 'static_link_inputs', 'native_sdk_origin'):
        require(recipe[key] == original_recipe[key], 'Workspace applet SDK contract changed: ' + key)
    require(recipe['native_sdk_extension'] == policy['native_sdk_extension']
            and recipe['native_sdk_extension']['path'] == 'native-input-sdk-origin.json'
            and [row['path'] for row in recipe['additional_native_inputs']] == list(INPUT_LIBRARIES)
            and all(set(row) == {'path', 'sha256', 'bytes'} and row['bytes'] > 0
                    for row in recipe['additional_native_inputs']),
            'Workspace applet native input extension changed')
    require(recipe['additional_native_licenses'] == policy['additional_native_licenses']
            and [row['destination'] for row in recipe['additional_native_licenses']] ==
                ['usr/share/doc/' + name + '/COPYING' for name in ('libinput', 'libudev', 'libevdev', 'libmtdev')],
            'Input SDK license inventory changed')
    require({k: v for k, v in profile.items() if k != 'purpose'} ==
            {k: v for k, v in original_profile.items() if k != 'purpose'},
            'Workspace applets must retain original process and build bounds')
    return policy, recipe, component, profile, original_policy


def additional_link_inputs(sysroot, recipe):
    """Admit only the pinned real SDK libraries, never host libraries or stubs."""
    sysroot = base.no_symlink_path(sysroot)
    origin = recipe['native_sdk_extension']
    require(base.digest(sysroot / origin['path']) == origin['sha256'], 'Input SDK receipt changed')
    receipt = base.load_json(sysroot / origin['path'])
    libraries = {row['path']: {k: row[k] for k in ('sha256', 'bytes')}
                 for row in recipe['additional_native_inputs']}
    require(receipt['status'] == 'NATIVE_INPUT_SDK_BUILT_NOT_RUN'
            and receipt['target'] == parent.TARGET and receipt['libraries'] == libraries
            and receipt['sources'] == base.load_json(base.ROOT / 'ports/cosmic/native-input-sdk-v1/sources.json')
            and receipt['original_native_inputs'] == {row['path']: row['sha256'] for row in recipe['native_inputs']}
            and receipt['compiler_sha256'] == base.digest(sysroot / 'bin/x86_64-linux-musl-cc')
            and receipt['original_inputs_preserved'] is True
            and receipt['device_runtime_verified'] is False and receipt['guest_execution'] is False,
            'Not a genuine complete input SDK build')
    for relative, digest in receipt['producers'].items():
        require(base.digest(sysroot / 'producer-sources' / relative) == digest,
                'Archived SDK producer changed: ' + relative)
    require(receipt['producers']['tools/build_cosmic_input_sdk_v1.py'] == receipt['producer_sha256']
            and receipt['producers']['ports/cosmic/native-input-sdk-v1/sources.json'] ==
                receipt['source_manifest_sha256'], 'Input SDK producer identity mismatch')
    for relative, row in libraries.items():
        path = base.no_symlink_path(sysroot / relative)
        require(base.digest(path) == row['sha256'] and path.stat().st_size == row['bytes'],
                'Input SDK static archive changed: ' + relative)
        cosmic_ports.architecture(path, target='x86_64')
    smoke = sysroot / 'native-input-port/static-link.elf'
    require(base.digest(smoke) == receipt['static_link_probe']['sha256']
            and smoke.stat().st_size == receipt['static_link_probe']['bytes']
            and receipt['static_link_probe']['executed'] is False, 'Input SDK real static link changed')
    cosmic_ports.elf_header(smoke.read_bytes(), (2,), target='x86_64')
    for row in recipe['additional_native_licenses']:
        require(base.digest(base.no_symlink_path(sysroot / row['path'])) == row['sha256'],
                'Input SDK license changed: ' + row['path'])
    return dict(origin=origin, libraries=libraries, producers=receipt['producers'],
                static_link_probe=receipt['static_link_probe'], licenses=recipe['additional_native_licenses'])


def verify_export(stage, inputs, *, overlay=None):
    policy, _, _, _, _ = contract()
    original_policy = parent.contract()[0]
    after = {**policy['after'], **(overlay or {})}
    expected = {name: {'sha256': row['sha256'], 'mode': 0o755 if row['mode'] == '100755' else 0o644}
                for name, row in inputs['originals']['applets']['files'].items()}
    for name, binding in inputs['native_bindings'].items():
        for relative, row in binding['files'].items():
            expected['native-deps/' + name + '/' + relative] = {
                **row, 'mode': stat.S_IMODE((Path(binding['path']) / relative).stat().st_mode)}
    for name, digest in original_policy['after'].items():
        expected[name] = {**expected[name], 'sha256': digest}
    actual = parent.files.read_tree(stage)
    require(set(actual['files']) == set(expected), 'Complete workspace applet inventory changed')
    for name, record in expected.items():
        digest = after.get(name, record['sha256'])
        require(actual['files'][name]['sha256'] == digest
                and stat.S_IMODE((stage / name).stat().st_mode) == record['mode'],
                'Workspace applet source changed: ' + name)
    return actual


def original_inputs(source_cache, native_cache, cargo_cache):
    policy, _, _, _, _ = contract()
    inputs = parent.original_inputs(source_cache, native_cache, cargo_cache)
    inputs['workspace_patch'] = {str(PORT / name): base.digest(PORT / name)
        for name in ('source-policy.json', 'native-recipe.json', 'resource-profile.json', 'native.patch')}
    return inputs


def export(source_cache, native_cache, cargo_cache, stage):
    policy, _, _, _, _ = contract()
    original, _ = parent.export(source_cache, native_cache, cargo_cache, stage)
    require(all(base.digest(stage / name) == digest for name, digest in policy['before'].items()),
            'Workspace applet patch preimage changed')
    for options in (['--check'], []):
        subprocess.run(['/usr/bin/git', 'apply', *options, str(PORT / 'native.patch')], cwd=stage,
            check=True, capture_output=True, env=base.clean_environment('/usr/bin:/bin'))
    inputs = original_inputs(source_cache, native_cache, cargo_cache)
    require(all(inputs[key] == value for key, value in original.items()), 'Parent applet source changed')
    return inputs, verify_export(stage, inputs)


def metadata_identity(metadata, stage, cache, recipe, policy, *, programs=PROGRAMS):
    original_policy, original_recipe, _, _, _ = parent.contract()
    # This checks every registry archive and pinned Git tree, all 19 original
    # members and native bindings. The child patch adds no package/version.
    identity = parent.metadata_identity(metadata, stage, cache, original_recipe, original_policy)
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    selected = {}
    for name in programs:
        identifier = identity['resolution']['workspace_members'][name]
        package = packages[identifier]
        require(package['source'] is None and package['version'] == '1.10.0'
                and nodes[identifier]['features'] == ['cyxia-native']
                and any(t['name'] == name and 'bin' in t['kind']
                    and Path(t['src_path']) == stage / name / 'src/main.rs' for t in package['targets']),
                'Missing genuine workspace applet binary or complete native features: ' + name)
        selected[name] = identifier
    return dict(dependencies=identity, programs=selected, features=recipe['features'],
                metadata_features=recipe['metadata_features'], default_features_preserved=True)


def commands(cargo, stage, recipe, jobs, programs=None, *, names=PROGRAMS):
    features = [name + '/cyxia-native' for name in names]
    require(recipe['features'] == features and recipe['default_features'] is True,
            'Incomplete workspace applet feature selection')
    options = ['--manifest-path', str(stage / 'Cargo.toml'), '--locked', '--offline',
               '--features', ','.join(features)]
    metadata_options = [*options[:-1], ','.join(recipe['metadata_features'])]
    metadata = [str(cargo), 'metadata', '--format-version', '1', '--filter-platform', parent.TARGET, *metadata_options]
    if programs is None:
        return metadata, None
    require(set(programs) == set(names), 'Incomplete workspace applet package selection')
    command = [str(cargo), 'build', '--release', '--target', parent.TARGET, '--jobs', str(jobs)]
    for name in names:
        command += ['--package', programs[name]]
    return metadata, command + ['--bins', *options]
