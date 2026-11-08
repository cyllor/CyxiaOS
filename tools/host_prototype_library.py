"""Build the caller's current prototype library for source-derived host seams."""
import json
from pathlib import Path
import subprocess

from doctor import ROOT, RUST_BIN, env


def build_host_prototype_library():
    environment = env()
    version = subprocess.run(
        [str(RUST_BIN / 'rustc'), '-vV'], env=environment,
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout
    host = next(line.removeprefix('host: ') for line in version.splitlines()
                if line.startswith('host: '))
    command = [str(RUST_BIN / 'cargo'), 'build', '--locked', '--offline',
               '--manifest-path', str(ROOT / 'Cargo.toml'),
               '-p', 'cyxia-prototype', '--lib', '--target', host,
               '--message-format=json-render-diagnostics']
    result = subprocess.run(command, cwd=ROOT, env=environment,
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError('current prototype host build failed:\n'
                           + result.stdout + result.stderr)
    source = (ROOT / 'crates/prototype/src/lib.rs').resolve()
    libraries = set()
    dependencies = set()
    for line in result.stdout.splitlines():
        message = json.loads(line)
        target = message.get('target', {})
        if (message.get('reason') == 'compiler-artifact'
                and target.get('name') == 'cyxia_prototype'
                and 'lib' in target.get('kind', [])
                and Path(target['src_path']).resolve() == source
                and not message.get('profile', {}).get('test', False)):
            libraries.update(Path(name).resolve(strict=True)
                             for name in message['filenames']
                             if Path(name).suffix == '.rlib')
            dependencies.update(Path(name).resolve(strict=True).parent
                                for name in message['filenames']
                                if Path(name).suffix == '.rmeta')
    if len(libraries) != 1 or len(dependencies) != 1:
        raise RuntimeError('Cargo did not report one current prototype host library and metadata directory')
    library = libraries.pop()
    deps = dependencies.pop()
    if not library.is_file() or not deps.is_dir():
        raise RuntimeError('invalid Cargo prototype library artifact')
    return deps, library
