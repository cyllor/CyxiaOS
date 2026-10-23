#!/usr/bin/env python3
"""Controlled single-binary COSMIC Cargo experiments; offline, never a guest gate.

`check --component NAME` is read-only. `build` requires an explicit reviewed
recipe, an existing clean pinned checkout, and a separately prepared private
Cargo cache. No fetch, recursive checkout, shell command, or full-workspace build
is performed. Cargo offline mode is not an OS sandbox for trusted build scripts.
"""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

if __package__:
    from . import cosmic_ports as ports
    from . import cosmic_dependencies as dependencies
    from .build_sysroot import inspect_elf
else:
    import cosmic_ports as ports
    import cosmic_dependencies as dependencies
    from build_sysroot import inspect_elf

ROOT = ports.ROOT
TARGET = 'aarch64-unknown-linux-musl'
DEFAULT_SYSROOT = ROOT / 'artifacts/sysroot/aarch64-musl'
PROFILE = ROOT / 'ports/cosmic/resource-profile.json'
DEPENDENCIES = ROOT / 'ports/cosmic/dependencies.json'
CARGO_CACHE = ROOT / 'artifacts/cosmic-cargo-cache'


class CosmicBuildError(ValueError):
    """A reproducibility, configuration, resource or target validation failure."""


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=ports.unique_object)


def no_symlink_path(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            # macOS /var is a system alias; canonicalize parents before passing
            # paths to this API. User-selected paths themselves cannot redirect.
            raise CosmicBuildError('symlink in selected path: ' + str(part))
    return path


def new_output(path):
    path = no_symlink_path(path)
    if path.exists():
        raise CosmicBuildError('output already exists; preserving it: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()
    return path


def clean_environment(path):
    # An allowlist avoids new Cargo/cc/pkg-config injection variables silently
    # escaping a finite blacklist. HOME retains its actual identity.
    env = {key: os.environ[key] for key in ('HOME', 'USER', 'LOGNAME', 'SYSTEMROOT') if key in os.environ}
    env.update(PATH=str(path), LC_ALL='C', LANG='C', GIT_TERMINAL_PROMPT='0',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never')
    return env


def tree_identity(root):
    result = {}
    root = Path(root).resolve()
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            if not path.resolve().is_relative_to(root):
                raise CosmicBuildError('source/library symlink escapes its root: ' + str(path))
            result[str(path.relative_to(root))] = {'symlink': os.readlink(path)}
        elif path.is_file():
            result[str(path.relative_to(root))] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    return {'sha256': hashlib.sha256(encoded).hexdigest(), 'files': result}


def git(source, *arguments):
    env = clean_environment('/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin')
    result = subprocess.run(['/usr/bin/git', '-c', 'core.fsmonitor=false', '-C', str(source), *arguments],
                            env=env, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise CosmicBuildError('Git identity check failed: ' + result.stderr.strip())
    return result.stdout.strip()


def inspect_source(cache, source):
    path = no_symlink_path(Path(cache) / source['directory'])
    if not path.is_dir() or Path(git(path, 'rev-parse', '--show-toplevel')).resolve() != path:
        raise CosmicBuildError('source is not its own existing Git worktree')
    if git(path, 'rev-parse', 'HEAD') != source['commit']:
        raise CosmicBuildError('source commit differs from epoch pin')
    if ports.repository_url(git(path, 'remote', 'get-url', 'origin')) != ports.repository_url(source['repository']):
        raise CosmicBuildError('source origin differs from pinned repository')
    if git(path, 'status', '--porcelain', '--untracked-files=all', '--ignored'):
        raise CosmicBuildError('source is modified or contains untracked/ignored inputs; preserving it')
    return {**source, 'path': str(path), 'verified': True}


def directory_bytes(root):
    return sum(p.stat().st_size for p in Path(root).rglob('*') if p.is_file() and not p.is_symlink())


def resource_check(root, min_free, max_bytes):
    if shutil.disk_usage(root).free < min_free:
        raise CosmicBuildError('insufficient free space; reserve must remain available')
    if directory_bytes(root) > max_bytes:
        raise CosmicBuildError('build directory exceeded its byte budget')


def run_bounded(command, cwd, env, log, timeout, min_free, max_bytes, *, budget_root=None,
                stderr_log=None, scratch_roots=(), growth_roots=()):
    """Run a real subprocess; terminate the entire process group on limit breach."""
    budget_root = Path(budget_root or cwd)
    resource_check(budget_root, min_free, max_bytes)
    def check_resources():
        resource_check(budget_root, min_free, max_bytes)
        total = directory_bytes(budget_root)
        for root in scratch_roots:
            resource_check(root, min_free, max_bytes)
            total += directory_bytes(root)
        for root, baseline in growth_roots:
            resource_check(root, min_free, 2**63)
            total += max(0, directory_bytes(root) - baseline)
        if total > max_bytes:
            raise CosmicBuildError('combined build/scratch directories exceeded byte budget')

    check_resources()
    deadline = time.monotonic() + timeout
    with ExitStack() as stack:
        stream = stack.enter_context(Path(log).open('w'))
        error_stream = stack.enter_context(Path(stderr_log).open('w')) if stderr_log else subprocess.STDOUT
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                 stderr=error_stream, start_new_session=True)
        try:
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    raise CosmicBuildError('build deadline exceeded')
                check_resources()
                time.sleep(min(.2, max(0, deadline - time.monotonic())))
            check_resources()
            if child.returncode:
                raise CosmicBuildError(f'command exit {child.returncode}; see {log}')
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            raise


def select_profile(document, name, jobs):
    if document.get('schema_version') != 1 or document.get('target') != TARGET:
        raise CosmicBuildError('unsupported resource profile')
    try:
        profile = document['build_profiles'][name]
    except KeyError as error:
        raise CosmicBuildError('unknown resource profile') from error
    for key in ('jobs_max', 'min_free_bytes', 'max_build_bytes', 'timeout_seconds',
                'max_elf_bytes', 'image_bytes', 'stack_bytes'):
        if type(profile.get(key)) is not int or profile[key] <= 0:
            raise CosmicBuildError('missing or invalid bound: ' + key)
    if type(jobs) is not int or jobs < 1 or jobs > profile['jobs_max']:
        raise CosmicBuildError('jobs exceed selected resource profile')
    if profile['stack_bytes'] >= profile['image_bytes']:
        raise CosmicBuildError('profile leaves no executable image capacity')
    return profile


def export_source(source, output, max_bytes=64 * 1024 * 1024):
    if any(line.startswith('160000 ') for line in git(source, 'ls-tree', '-r', 'HEAD').splitlines()):
        raise CosmicBuildError('source has gitlinks; explicit pinned submodule materialization is not implemented')
    output = Path(output)
    output.mkdir(parents=True)
    with tempfile.TemporaryFile() as stream:
        subprocess.run(['/usr/bin/git', '-C', str(source), 'archive', '--format=tar', 'HEAD'],
                       env=clean_environment('/usr/bin:/bin'), stdout=stream, check=True)
        stream.seek(0)
        with tarfile.open(fileobj=stream) as archive:
            members = archive.getmembers()
            if sum(m.size for m in members) > max_bytes:
                raise CosmicBuildError('expanded source exceeds configured budget')
            for member in members:
                relative = dependencies.relative_path(member.name.rstrip('/'))
                destination = output / relative
                if not (member.isfile() or member.isdir() or member.issym()):
                    raise CosmicBuildError('unsupported source archive member')
                if member.issym():
                    target = Path(member.linkname)
                    if target.is_absolute() or not (destination.parent / target).resolve().is_relative_to(output.resolve()):
                        raise CosmicBuildError('source symlink escapes export')
                if '.cargo' in relative.parts and relative.name in ('config', 'config.toml'):
                    raise CosmicBuildError('source Cargo config needs explicit review/port; refusing inherited settings')
            archive.extractall(output, members=members, filter='data')


def checked_name(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', name):
        raise CosmicBuildError('invalid package/binary/feature name')
    return name


def validate_recipe(recipe, source):
    if (recipe.get('schema_version') != 1 or recipe.get('component') != source['name']
            or recipe.get('commit') != source['commit'] or recipe.get('target') != TARGET):
        raise CosmicBuildError('recipe does not identify the selected pinned component/target')
    if recipe.get('purpose') != 'bounded-build-experiment':
        raise CosmicBuildError('recipe must explicitly describe a bounded build experiment')
    for key in ('package', 'binary', 'resource_profile'):
        checked_name(recipe.get(key))
    if type(recipe.get('default_features')) is not bool or not isinstance(recipe.get('features'), list):
        raise CosmicBuildError('explicit default/features selection required')
    for feature in recipe['features']:
        if not isinstance(feature, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_/-]*', feature):
            raise CosmicBuildError('invalid Cargo feature')
    if len(set(recipe['features'])) != len(recipe['features']):
        raise CosmicBuildError('duplicate Cargo features')
    for key in ('source_lock_sha256', 'effective_lock_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', recipe.get(key, '')):
            raise CosmicBuildError('recipe needs pinned source/effective Cargo.lock identities')
    if not isinstance(recipe.get('native_inputs'), list) or not isinstance(recipe.get('patches'), list):
        raise CosmicBuildError('explicit native input and patch lists required')
    return recipe


def apply_patches(recipe, source, recipe_directory):
    records = []
    for patch in recipe['patches']:
        dependencies.relative_path(patch['path'])
        path = recipe_directory / patch['path']
        if path.is_symlink() or not path.resolve().is_relative_to(recipe_directory.resolve()):
            raise CosmicBuildError('patch path escapes recipe directory')
        if digest(path) != patch['sha256']:
            raise CosmicBuildError('patch identity mismatch')
        subprocess.run(['git', 'apply', '--check', str(path.resolve())], cwd=source, check=True)
        subprocess.run(['git', 'apply', str(path.resolve())], cwd=source, check=True)
        records.append({'path': str(path), 'sha256': digest(path)})
    for config in source.rglob('*'):
        if '.cargo' in config.parts and config.name in ('config', 'config.toml'):
            raise CosmicBuildError('patch introduced unreviewed Cargo configuration')
    return records


def source_and_recipe(component, recipe_path, manifest, cache):
    source = next((s for s in manifest['components'] if s['name'] == component), None)
    if source is None:
        raise CosmicBuildError('unknown component; choose exactly one pinned component')
    record = inspect_source(cache, source)
    if recipe_path is None:
        raise CosmicBuildError('no reviewed component recipe; source identity alone is not a build contract')
    recipe = validate_recipe(load_json(recipe_path), source)
    if digest(Path(record['path']) / 'Cargo.lock') != recipe['source_lock_sha256']:
        raise CosmicBuildError('source Cargo.lock does not match recipe')
    return source, record, recipe


def validate_cache(path):
    cache = no_symlink_path(path)
    if cache == (Path.home() / '.cargo').resolve():
        raise CosmicBuildError('global user Cargo home is not an isolated dependency cache')
    if not cache.is_dir() or any((cache / name).exists() for name in ('config', 'config.toml')):
        raise CosmicBuildError('private Cargo cache absent or contains unreviewed config; prepare it separately')
    for child in ('registry', 'git'):
        if (cache / child).is_symlink():
            raise CosmicBuildError('private Cargo cache aliases external inputs')
    return cache


def tools_and_sysroot(sysroot, recipe):
    env = clean_environment('/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin')
    proxy = Path.home() / '.cargo/bin/rustc'
    rust_root = Path(subprocess.check_output([str(proxy), '--print', 'sysroot'], env=env, text=True).strip())
    rustc, cargo = rust_root / 'bin/rustc', rust_root / 'bin/cargo'
    version = subprocess.check_output([str(rustc), '-vV'], env=env, text=True)
    host = next(line.split(': ', 1)[1] for line in version.splitlines() if line.startswith('host: '))
    llvm = rust_root / 'lib/rustlib' / host / 'bin'
    libdir = rust_root / 'lib/rustlib' / TARGET / 'lib'
    std = list(libdir.glob('libstd-*.rlib'))
    if len(std) != 1:
        raise CosmicBuildError('exactly one official target libstd archive is required')
    ports.architecture(std[0], rust_archive=True)
    cc = sysroot / 'bin/aarch64-linux-musl-cc'
    tools = {'rustc': rustc, 'cargo': cargo, 'target_cc': cc,
             'target_cxx': sysroot / 'bin/aarch64-linux-musl-cxx',
             'target_ar': sysroot / 'bin/aarch64-linux-musl-ar',
             'target_ranlib': sysroot / 'bin/aarch64-linux-musl-ranlib',
             'host_cc': Path('/usr/bin/clang'), 'strip': llvm / 'llvm-strip',
             'pkg_config': Path(shutil.which('pkg-config', path=env['PATH']) or '/missing/pkg-config')}
    for name, path in tools.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise CosmicBuildError('required tool missing: ' + name)
    native = []
    required = {'sysroot/usr/lib/' + name for name in
                ('libc.a', 'libclang_rt.builtins-aarch64.a', 'crt1.o', 'crti.o', 'crtn.o')}
    declared = set()
    for item in recipe['native_inputs']:
        relative = str(dependencies.relative_path(item['path']))
        if relative in declared:
            raise CosmicBuildError('duplicate native input')
        declared.add(relative)
        path = sysroot / relative
        if not path.resolve().is_relative_to(sysroot.resolve()) or digest(path) != item['sha256']:
            raise CosmicBuildError('native input identity mismatch: ' + relative)
        if path.suffix == '.a':
            ports.architecture(path)
        elif path.suffix == '.o':
            ports.elf_header(path.read_bytes(), (1,))
        native.append({'path': relative, 'sha256': item['sha256']})
    if not required.issubset(declared):
        raise CosmicBuildError('recipe lacks pinned target musl/CRT/compiler runtime inputs')
    unwind = libdir / 'self-contained/libunwind.a'
    ports.architecture(unwind)
    return tools, {'rustc_version': version, 'host': host, 'std': {'path': str(std[0]), 'sha256': digest(std[0])},
                   'unwind': {'path': str(unwind), 'sha256': digest(unwind)}, 'native_inputs': native,
                   'tools': {name: {'path': str(path), 'sha256': digest(path)} for name, path in tools.items()}}


def wrapper(path, command, environment):
    path.write_text('#!' + sys.executable + '\nimport os,subprocess,sys\n'
                    'env=dict(os.environ)\nenv.update(' + repr(environment) + ')\n'
                    'sys.exit(subprocess.call(' + repr(list(map(str, command))) + '+sys.argv[1:],env=env))\n')
    path.chmod(0o755)
    return path


def pkg_flags(text, target_root):
    """Reject absolute host include/library paths emitted by target .pc files."""
    arguments = shlex.split(text)
    paths = []
    following_path = False
    for argument in arguments:
        if following_path:
            paths.append(argument)
            following_path = False
        elif argument in ('-I', '-L', '-isystem'):
            following_path = True
        elif argument.startswith(('-I', '-L')):
            paths.append(argument[2:])
        elif argument.startswith('/'):
            paths.append(argument)
        elif argument.startswith(('-F', '-Wl,')) or argument == '-framework':
            raise CosmicBuildError('unsupported target pkg-config linker flag')
    if following_path:
        raise CosmicBuildError('incomplete pkg-config path flag')
    for path in paths:
        if not Path(path).is_absolute() or not Path(path).resolve().is_relative_to(Path(target_root).resolve()):
            raise CosmicBuildError('target pkg-config emits a host/relative path: ' + path)
    return text


def target_pkg_wrapper(path, executable, environment, target_root):
    path.write_text('#!' + sys.executable + '\nimport os,subprocess,sys\n'
                    'sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ')\n'
                    'from build_cosmic import pkg_flags,CosmicBuildError\n'
                    'env=dict(os.environ)\nenv.update(' + repr(environment) + ')\n'
                    'result=subprocess.run(' + repr([str(executable), '--static']) +
                    '+sys.argv[1:],env=env,text=True,capture_output=True)\n'
                    'sys.stderr.write(result.stderr)\n'
                    'if result.returncode: sys.exit(result.returncode)\n'
                    'try:\n    text=pkg_flags(result.stdout,' + repr(str(target_root)) + ')\n'
                    'except CosmicBuildError as error:\n    sys.exit(str(error))\n'
                    'sys.stdout.write(text)\n')
    path.chmod(0o755)
    return path


def cargo_environment(tools, identities, sysroot, output, cargo_cache, control):
    env = clean_environment('/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin')
    native = output / 'native'
    native.mkdir()
    shutil.copyfile(identities['unwind']['path'], native / 'libunwind.a')
    binary = output / 'bin'
    binary.mkdir()
    target_root = sysroot / 'sysroot'
    pcdirs = os.pathsep.join(str(target_root / p) for p in ('usr/lib/pkgconfig', 'usr/share/pkgconfig'))
    target_pc = target_pkg_wrapper(binary / 'target-pkg-config', tools['pkg_config'],
                        {'PKG_CONFIG_PATH': '', 'PKG_CONFIG_LIBDIR': pcdirs,
                         'PKG_CONFIG_SYSROOT_DIR': str(target_root)}, target_root)
    host_pc = wrapper(binary / 'host-pkg-config', [tools['pkg_config']],
                      {'PKG_CONFIG_PATH': '', 'PKG_CONFIG_LIBDIR': str(control / 'empty-pkg-config'),
                       'PKG_CONFIG_SYSROOT_DIR': ''})
    env.update(CARGO_HOME=str(cargo_cache), CARGO_TARGET_DIR=str(output / 'target'),
               CARGO_INCREMENTAL='0', RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustc'].with_name('rustdoc')),
               CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_LTO='false',
               CARGO_PROFILE_RELEASE_PANIC='abort', CARGO_PROFILE_RELEASE_OPT_LEVEL='2',
               CC=str(tools['host_cc']), CXX=str(tools['host_cc'].with_name('clang++')),
               HOST_CC=str(tools['host_cc']), PKG_CONFIG=str(host_pc),
               PKG_CONFIG_PATH='', PKG_CONFIG_LIBDIR=str(control / 'empty-pkg-config'),
               PKG_CONFIG_SYSROOT_DIR='', TMPDIR=str(control),
               CARGO_ENCODED_RUSTFLAGS='\x1f'.join(['-C', 'link-self-contained=no', '-C', 'relocation-model=static',
                   '-C', 'target-feature=+crt-static', '-L', 'native=' + str(native)]))
    env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER'] = str(tools['target_cc'])
    for target in (TARGET, TARGET.replace('-', '_')):
        env['CC_' + target] = str(tools['target_cc'])
        env['CXX_' + target] = str(tools['target_cxx'])
        env['AR_' + target] = str(tools['target_ar'])
        env['RANLIB_' + target] = str(tools['target_ranlib'])
        env['PKG_CONFIG_' + target] = str(target_pc)
        env['PKG_CONFIG_LIBDIR_' + target] = pcdirs
        env['PKG_CONFIG_SYSROOT_DIR_' + target] = str(target_root)
        env['PKG_CONFIG_ALLOW_CROSS_' + target] = '1'
    return env


def verify_metadata(metadata, source, cache, recipe):
    selected = [p for p in metadata['packages'] if p['name'] == recipe['package']
                and Path(p['manifest_path']).resolve().is_relative_to(source.resolve())]
    if len(selected) != 1 or not any(t['name'] == recipe['binary'] and 'bin' in t['kind'] for t in selected[0]['targets']):
        raise CosmicBuildError('recipe does not select exactly one local package binary')
    records = []
    for package in metadata['packages']:
        path = Path(package['manifest_path']).resolve()
        if not (path.is_relative_to(source.resolve()) or path.is_relative_to(cache.resolve())):
            raise CosmicBuildError('Cargo dependency escapes pinned source/private cache: ' + str(path))
        spec = package.get('source')
        if spec and not (spec.startswith('registry+') or re.fullmatch(r'git\+https://[^\s#]+#[0-9a-f]{40}', spec)):
            raise CosmicBuildError('Cargo resolved an unpinned source')
        identity = tree_identity(path.parent)
        records.append({'name': package['name'], 'version': package['version'], 'source': spec,
                        'manifest': str(path), 'source_tree_sha256': identity['sha256']})
    return records


def perform_build(source, record, recipe, recipe_path, output, sysroot, cargo_cache, profile, jobs):
    # Shared target library mutation and another COSMIC build cannot overlap.
    with (sysroot / '.build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tools, identities = tools_and_sysroot(sysroot, recipe)
        report = {'status': 'building', 'component': source, 'recipe_sha256': digest(recipe_path),
                  'recipe': recipe, 'resource_profile': profile, 'target': TARGET,
                  'builder_sha256': digest(Path(__file__)),
                  'profile_sha256': hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest(),
                  'guest_execution': 'not performed', 'cosmic_session_ready': False,
                  'cargo_offline': True, 'build_script_network_sandbox': False, 'toolchain': identities}
        output = new_output(output)
        report_path = output / 'build-report.json'
        try:
            # Invoking Cargo outside the repository prevents ancestor .cargo
            # config lookup. The private cache must contain no Cargo config.
            with tempfile.TemporaryDirectory(prefix='cyxia-cargo-') as temporary:
                control = Path(temporary).resolve()
                for ancestor in (control, *control.parents):
                    if any((ancestor / '.cargo' / name).exists() for name in ('config', 'config.toml')):
                        raise CosmicBuildError('Cargo control directory has inherited configuration')
                stage = control / 'source'
                export_source(Path(record['path']), stage)
                report['patches'] = apply_patches(recipe, stage, recipe_path.parent)
                if digest(stage / 'Cargo.lock') != recipe['effective_lock_sha256']:
                    raise CosmicBuildError('effective Cargo.lock mismatch after patches')
                before = tree_identity(stage)
                report['source_tree'] = before
                env = cargo_environment(tools, identities, sysroot, output, cargo_cache, control)
                epoch = git(Path(record['path']), 'show', '-s', '--format=%ct')
                env['SOURCE_DATE_EPOCH'] = epoch
                common = ['--manifest-path', str(stage / 'Cargo.toml'), '--locked', '--offline']
                features = ([] if recipe['default_features'] else ['--no-default-features'])
                if recipe['features']:
                    features += ['--features', ','.join(recipe['features'])]
                metadata_command = [str(tools['cargo']), 'metadata', '--format-version', '1',
                                    '--filter-platform', TARGET, *common, *features]
                bounds = (profile['timeout_seconds'], profile['min_free_bytes'], profile['max_build_bytes'])
                report['metadata_command'] = metadata_command
                cache_baseline = directory_bytes(cargo_cache)
                run_bounded(metadata_command, control, env, output / 'metadata.json', *bounds, budget_root=output,
                            stderr_log=output / 'metadata.stderr.log', scratch_roots=(control,),
                            growth_roots=((cargo_cache, cache_baseline),))
                try:
                    metadata = json.loads((output / 'metadata.json').read_text())
                except json.JSONDecodeError as error:
                    raise CosmicBuildError('Cargo metadata did not produce one complete JSON document') from error
                report['cargo_dependencies'] = verify_metadata(metadata, stage, cargo_cache, recipe)
                report['sysroot_before'] = tree_identity(sysroot / 'sysroot')
                command = [str(tools['cargo']), 'build', '--release', '--target', TARGET, '--jobs', str(jobs),
                           '--package', recipe['package'], '--bin', recipe['binary'], *common, *features]
                report['command'] = command
                run_bounded(command, control, env, output / 'cargo.log', *bounds, budget_root=output,
                            scratch_roots=(control,), growth_roots=((cargo_cache, cache_baseline),))
                if tree_identity(stage)['sha256'] != before['sha256']:
                    raise CosmicBuildError('build modified pinned source inputs')
                if tree_identity(sysroot / 'sysroot')['sha256'] != report['sysroot_before']['sha256']:
                    raise CosmicBuildError('build modified target sysroot')
                if digest(Path(__file__)) != report['builder_sha256']:
                    raise CosmicBuildError('builder changed during execution')
                if verify_metadata(metadata, stage, cargo_cache, recipe) != report['cargo_dependencies']:
                    raise CosmicBuildError('build modified dependency source inputs')
                result = output / 'target' / TARGET / 'release' / recipe['binary']
                if not result.is_file() or not result.resolve().is_relative_to(output.resolve()):
                    raise CosmicBuildError('expected binary missing or escaped output')
                executable = inspect_elf(result)
                pages = sum(((p['vaddr'] + p['memsz'] + 4095) // 4096 - p['vaddr'] // 4096)
                            for p in executable['program_headers'] if p['type'] == 1)
                if executable['bytes'] > profile['max_elf_bytes'] or pages * 4096 + profile['stack_bytes'] > profile['image_bytes']:
                    raise CosmicBuildError('linked ELF exceeds admitted image profile')
                final = output / (recipe['binary'] + '.elf')
                shutil.copyfile(result, final)
                report.update(status='cross-built', executable=inspect_elf(final), image_load_pages=pages,
                              source_preserved=inspect_source(Path(record['path']).parent, source)['verified'])
                if not report['source_preserved']:
                    raise CosmicBuildError('original source changed during build')
        except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
            report.update(status='failed', error=str(error))
            raise
        finally:
            report_path.write_text(json.dumps(report, indent=2) + '\n')
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'build'), nargs='?', default='check')
    parser.add_argument('--component', required=True)
    parser.add_argument('--recipe', type=Path)
    parser.add_argument('--cache', type=Path, default=ports.CACHE)
    parser.add_argument('--sysroot', type=Path, default=DEFAULT_SYSROOT)
    parser.add_argument('--cargo-cache', type=Path, default=CARGO_CACHE)
    parser.add_argument('--resource-profile', type=Path, default=PROFILE)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--jobs', type=int, default=1)
    args = parser.parse_args(argv)
    try:
        manifest = ports.load_manifest()
        source, record, recipe = source_and_recipe(args.component, args.recipe, manifest, args.cache)
        profile = select_profile(load_json(args.resource_profile), recipe['resource_profile'], args.jobs)
        sysroot = no_symlink_path(args.sysroot)
        cache = validate_cache(args.cargo_cache)
        tools_and_sysroot(sysroot, recipe)
        resource_check(sysroot, profile['min_free_bytes'] + profile['max_build_bytes'], 2**63)
        if args.action == 'check':
            print(json.dumps({'status': 'preflight-passed', 'component': source['name'],
                              'cargo_resolved': False, 'target_built': False, 'guest_tested': False}, indent=2))
            return 0
        if args.output is None:
            raise CosmicBuildError('build requires a new explicit --output directory')
        report = perform_build(source, record, recipe, args.recipe.resolve(), args.output,
                               sysroot, cache, profile, args.jobs)
        print(json.dumps({'status': report['status'], 'report': str(args.output / 'build-report.json')}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('build_cosmic: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
