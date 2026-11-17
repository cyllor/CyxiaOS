"""Explicit host tools for notifications, preserving the frozen generic builder.

An explicit Rust installation avoids a machine-specific rustup proxy. The target
libraries still come exclusively from the hash-bound CyxiaOS SDK and official
Rust target; selecting a host compiler never selects host target libraries.
"""
import os
from pathlib import Path
import shutil
import subprocess

try:
    from . import build_cosmic as base
except ImportError:
    import build_cosmic as base


HOST_PATH = '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin'
DEFAULT_HOST_CC = Path('/usr/bin/clang')


def rust_toolchain(root=None):
    env = base.clean_environment(HOST_PATH)
    if root is None:
        root = subprocess.check_output(
            [str(Path.home() / '.cargo/bin/rustc'), '--print', 'sysroot'],
            env=env, text=True, timeout=30).strip()
    root = base.no_symlink_path(root)
    for name in ('rustc', 'cargo', 'rustdoc'):
        path = root / 'bin' / name
        if not path.is_file() or not os.access(path, os.X_OK):
            raise base.CosmicBuildError('required Rust tool missing: ' + name)
    rustc = root / 'bin/rustc'
    actual = subprocess.check_output([str(rustc), '--print', 'sysroot'],
                                     env=env, text=True, timeout=30).strip()
    if Path(actual).resolve() != root:
        raise base.CosmicBuildError('selected Rust compiler belongs to a different sysroot')
    version = subprocess.check_output([str(rustc), '-vV'], env=env, text=True, timeout=30)
    return root, version


def acquisition_environment(cache, rust_root):
    root, version = rust_toolchain(rust_root)
    env = base.clean_environment(HOST_PATH)
    env.update(CARGO_HOME=str(cache), CARGO_NET_OFFLINE='false', CARGO_NET_RETRY='2',
               CARGO_NET_GIT_FETCH_WITH_CLI='true', RUSTC=str(root / 'bin/rustc'))
    # Source acquisition is explicitly online. Preserve only conventional proxy
    # transport settings; the offline build environment remains unchanged. Do
    # not copy proxy values into the public receipt (they can contain credentials).
    proxy_names = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                   'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
    for name in proxy_names:
        if name in os.environ:
            env[name] = os.environ[name]
    proxy = env.get('https_proxy') or env.get('HTTPS_PROXY') or env.get('http_proxy') or env.get('HTTP_PROXY')
    if proxy:
        env['CARGO_HTTP_PROXY'] = proxy
    git = Path(shutil.which('git', path=HOST_PATH) or '/missing/git')
    if not git.is_file() or not os.access(git, os.X_OK):
        raise base.CosmicBuildError('Git executable required for source acquisition')
    return root / 'bin/cargo', env, {
        'rust_root': str(root), 'rustc_version': version,
        'rustc': {'path': str(root / 'bin/rustc'), 'sha256': base.digest(root / 'bin/rustc')},
        'git': {'path': str(git), 'sha256': base.digest(git)},
        'git_fetch_with_cli': True, 'proxy_environment_names': sorted(set(env) & set(proxy_names)),
    }


def tools_and_sysroot(sysroot, recipe, *, rust_root=None, host_cc=None):
    if rust_root is None and host_cc is None:
        return base.tools_and_sysroot(sysroot, recipe)
    selected = base.ports.user_target(recipe['target'])
    env = base.clean_environment(HOST_PATH)
    root, version = rust_toolchain(rust_root)
    host = next(line.split(': ', 1)[1] for line in version.splitlines() if line.startswith('host: '))
    llvm = root / 'lib/rustlib' / host / 'bin'
    libdir = root / 'lib/rustlib' / selected.rust_target / 'lib'
    std = list(libdir.glob('libstd-*.rlib'))
    if len(std) != 1:
        raise base.CosmicBuildError('exactly one official target libstd archive is required')
    base.ports.architecture(std[0], rust_archive=True, target=selected)
    # Distribution-installed Clang commonly uses a versioned system symlink.
    # Record its actual destination; explicitly supplied paths remain strict.
    compiler = base.no_symlink_path(host_cc if host_cc is not None else DEFAULT_HOST_CC.resolve(strict=True))
    tools = {
        'rustc': root / 'bin/rustc', 'cargo': root / 'bin/cargo',
        'target_cc': selected.cc(sysroot),
        'target_cxx': sysroot / 'bin' / (selected.c_target + '-cxx'),
        'target_ar': sysroot / 'bin' / (selected.c_target + '-ar'),
        'target_ranlib': sysroot / 'bin' / (selected.c_target + '-ranlib'),
        'host_cc': compiler, 'strip': llvm / 'llvm-strip',
        'pkg_config': Path(shutil.which('pkg-config', path=HOST_PATH) or '/missing/pkg-config'),
    }
    for name, path in tools.items():
        if name == 'target_cxx' and not path.exists():
            continue
        if not path.is_file() or not os.access(path, os.X_OK):
            raise base.CosmicBuildError('required tool missing: ' + name)
    native, declared = [], set()
    required = {'sysroot/usr/lib/' + name for name in
                ('libc.a', selected.builtins_archive, 'crt1.o', 'crti.o', 'crtn.o')}
    for item in recipe['native_inputs']:
        relative = str(base.dependencies.relative_path(item['path']))
        if relative in declared:
            raise base.CosmicBuildError('duplicate native input')
        declared.add(relative)
        path = sysroot / relative
        if not path.resolve().is_relative_to(sysroot.resolve()) or base.digest(path) != item['sha256']:
            raise base.CosmicBuildError('native input identity mismatch: ' + relative)
        if path.suffix == '.a':
            base.ports.architecture(path, target=selected)
        elif path.suffix == '.o':
            base.ports.elf_header(path.read_bytes(), (1,), selected)
        native.append({'path': relative, 'sha256': item['sha256']})
    if not required.issubset(declared):
        raise base.CosmicBuildError('recipe lacks pinned target musl/CRT/compiler runtime inputs')
    unwind = libdir / 'self-contained/libunwind.a'
    base.ports.architecture(unwind, target=selected)
    return tools, {
        'target': selected.rust_target, 'architecture': selected.architecture,
        'rustc_version': version, 'host': host,
        'selection': {'schema_version': 1, 'rust_root': str(root), 'host_cc': str(compiler)},
        'host_cc_version': subprocess.check_output([str(compiler), '--version'],
                                                   env=env, text=True, timeout=30),
        'std': {'path': str(std[0]), 'sha256': base.digest(std[0])},
        'static_link_inputs': base.static_link_inputs(recipe),
        'unwind': {'path': str(unwind), 'sha256': base.digest(unwind)},
        'native_inputs': native,
        'tools': {name: {'path': str(path), 'sha256': base.digest(path) if path.is_file() else None,
                         'available': path.is_file()} for name, path in tools.items()},
    }
