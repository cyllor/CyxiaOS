"""Build the caller's current prototype library for source-derived host seams."""
import json
from pathlib import Path
import subprocess

from doctor import ROOT, RUST_BIN, env


def _build_host_libraries(packages):
    environment = env()
    version = subprocess.run(
        [str(RUST_BIN / 'rustc'), '-vV'], env=environment,
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout
    host = next(line.removeprefix('host: ') for line in version.splitlines()
                if line.startswith('host: '))
    command = [str(RUST_BIN / 'cargo'), 'build', '--locked', '--offline',
               '--manifest-path', str(ROOT / 'Cargo.toml'),
               * [arg for package in packages for arg in ('-p', package)],
               '--lib', '--target', host,
               '--message-format=json-render-diagnostics']
    result = subprocess.run(command, cwd=ROOT, env=environment,
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError('current prototype host build failed:\n'
                           + result.stdout + result.stderr)
    sources = {package.replace('-', '_'): (ROOT / 'crates' / package.removeprefix('cyxia-') / 'src/lib.rs').resolve()
               for package in packages}
    libraries = {name: set() for name in sources}
    dependencies = set()
    for line in result.stdout.splitlines():
        message = json.loads(line)
        target = message.get('target', {})
        name = target.get('name')
        if (message.get('reason') == 'compiler-artifact'
                and name in sources
                and 'lib' in target.get('kind', [])
                and Path(target['src_path']).resolve() == sources[name]
                and not message.get('profile', {}).get('test', False)):
            libraries[name].update(Path(name).resolve(strict=True)
                             for name in message['filenames']
                             if Path(name).suffix == '.rlib')
            dependencies.update(Path(name).resolve(strict=True).parent
                                for name in message['filenames']
                                if Path(name).suffix == '.rmeta')
    if any(len(paths) != 1 for paths in libraries.values()) or len(dependencies) != 1:
        raise RuntimeError('Cargo did not report one current artifact per requested host library and a shared metadata directory')
    resolved = {name: paths.pop() for name, paths in libraries.items()}
    deps = dependencies.pop()
    if not all(library.is_file() for library in resolved.values()) or not deps.is_dir():
        raise RuntimeError('invalid Cargo host library artifact')
    return deps, resolved


def build_host_prototype_library():
    deps, libraries = _build_host_libraries(('cyxia-prototype',))
    return deps, libraries['cyxia_prototype']


def build_host_file_broker_libraries():
    # The production broker now calls the kernel-core path/capability guard.
    # Resolve both rlibs from the SAME current Cargo invocation, not a stale
    # target glob, and pass each direct dependency to rustc explicitly.
    deps, libraries = _build_host_libraries(('cyxia-prototype', 'cyxia-kernel-core'))
    return deps, libraries['cyxia_prototype'], libraries['cyxia_kernel_core']
