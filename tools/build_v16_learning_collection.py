#!/usr/bin/env python3
"""Additive collection build wrapper; the fixed old builder remains unchanged."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from build_unified import code_source_map, sha
from check_elf import symbol
from verify_v13_model import loaded_bytes
from verify_smp import require

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {'full': 0, 'coreset-one-pair': 1, 'coreset-data-one-pair': 2}
# Only names below enter child processes. Values are never dumped in a manifest.
# Identity directory paths are explicit argv; no private key material is logged.
ENVIRONMENT = frozenset(('HOME', 'PATH', 'CARGO_HOME', 'RUSTUP_HOME', 'TMPDIR',
    'USER', 'LOGNAME', 'SHELL', 'LANG', 'LC_ALL', 'LC_CTYPE', 'SDKROOT',
    'DEVELOPER_DIR', 'MACOSX_DEPLOYMENT_TARGET', 'SOURCE_DATE_EPOCH',
    'CARGO', 'RUSTC', 'RUSTDOC', 'CC', 'CYXIA_CC', 'CC_aarch64_unknown_none',
    'AR', 'AR_aarch64_unknown_none', 'CARGO_TARGET_DIR'))
LAYOUT = (0x43594C434F4C3136, 1, None, 1024, 96)

def builder_closure():
    """Bind static local imports from the caller-trusted builder checkout."""
    pending = ['build_v16_learning_collection']
    found = {}
    while pending:
        name = pending.pop()
        if name in found:
            continue
        require(len(found) < 128, 'builder closure bound')
        path = ROOT/'tools'/(name+'.py')
        require(path.is_file() and not path.is_symlink(), 'linked/missing builder dependency')
        found[name] = sha(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports = ([node.module] if isinstance(node, ast.ImportFrom) else
                       [item.name for item in node.names] if isinstance(node, ast.Import) else [])
            for item in imports:
                if item and '.' not in item and (ROOT/'tools'/(item+'.py')).is_file():
                    pending.append(item)
    return {'tools/'+name+'.py': digest for name,digest in sorted(found.items())}

def profile_environment(profile, inherited):
    require(profile in PROFILES, 'unsupported collection profile')
    result = {key: value for key, value in inherited.items() if key in ENVIRONMENT}
    result['CYXIA_LEARNING_COLLECTION'] = profile
    return result

def elf_profile(path, profile):
    data = Path(path).read_bytes()
    entry = symbol(data, 'LEARNING_COLLECTION_V16_LAYOUT')
    require(entry['size'] == 40, 'wrong collection layout width')
    words = struct.unpack('<5Q', loaded_bytes(data, entry['va'], 40))
    require(words == (LAYOUT[0], 2 if profile == 'coreset-data-one-pair' else 1, PROFILES[profile], 1024, 96),
            'ELF collection profile/layout mismatch (stale profile cache)')
    return dict(symbol='LEARNING_COLLECTION_V16_LAYOUT', address=entry['va'],
                words=list(words), sha256=hashlib.sha256(struct.pack('<5Q', *words)).hexdigest())

def build(identity_a, identity_b, output, *, profile, target_dir=None,
          unix_seconds=None, cargo=None, cc=None):
    require(profile in PROFILES, 'unsupported collection profile')
    output = Path(output).resolve()
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())),
            'refuse existing build output')
    environment = profile_environment(profile, os.environ)
    base = Path(target_dir or environment.get('CARGO_TARGET_DIR', ROOT/'target')).expanduser().resolve()
    # Profile namespace complements Cargo rerun-if-env-changed. Even a stale
    # previous-profile target tree is never selected by this wrapper.
    cache = base / ('learning-collection-v1-' + profile)
    require(not cache.is_symlink(), 'linked profile cache')
    builder = ROOT/'tools/build_unified.py'
    before = code_source_map(ROOT)
    sources = builder_closure()
    command = [sys.executable, str(builder), '--identity-a', str(Path(identity_a).resolve(strict=True)),
        '--identity-b', str(Path(identity_b).resolve(strict=True)), '--output', str(output),
        '--fault', 'normal', '--selftest', '--target-dir', str(cache)]
    for name, value in (('--unix-seconds', unix_seconds), ('--cargo', cargo), ('--cc', cc)):
        if value is not None: command.extend((name, str(value)))
    subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=1800)
    original = output/'build-manifest.json'
    base_bytes = original.read_bytes()
    base_manifest = json.loads(base_bytes)
    require(base_manifest['code_source_map'] == before == code_source_map(ROOT),
            'source changed during collection build')
    require(builder_closure() == sources, 'collection builder closure changed')
    layouts = {node: elf_profile(output/f'node-{node}.elf', profile) for node in ('a','b')}
    require(base_manifest['profiles']['selftest'] and not base_manifest['profiles']['storage_fault']
            and not base_manifest['profiles']['memory_probe'], 'conflicting base profile')
    saved = output/'base-build-manifest.json'
    require(not saved.exists(), 'base manifest collision')
    saved.write_bytes(base_bytes); saved.chmod(0o600)
    report = dict(schema_version=1, contract=('v16-learning-collection-build-v2' if profile == 'coreset-data-one-pair' else 'v16-learning-collection-build-v1'), status='BUILT_NOT_RUN',
        collection_profile=profile, profile_id=PROFILES[profile], elf_layouts=layouts,
        base_manifest=dict(path=saved.name, bytes=len(base_bytes), sha256=hashlib.sha256(base_bytes).hexdigest()),
        builder_sources=sources, profile_environment={'CYXIA_LEARNING_COLLECTION': profile},
        inherited_environment_names=sorted(set(environment)-{'CYXIA_LEARNING_COLLECTION'}),
        command=command, build_cache_profile_namespace=str(cache),
        code_source_map=before, code_source_sha256=base_manifest['code_source_sha256'],
        scope='Collection schedule only; no trained model, full dataset or native acceptance claim.')
    if profile == 'coreset-data-one-pair':
        report['bounded_data_schema'] = 2
    # The old manifest remains byte-exact in its own file. The new manifest is
    # explicitly typed and cannot be interpreted as a legacy normal build.
    original.write_text(json.dumps(report, sort_keys=True, indent=2)+'\n'); original.chmod(0o600)
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity-a', type=Path, required=True)
    parser.add_argument('--identity-b', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=tuple(PROFILES), required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--unix-seconds', type=int)
    parser.add_argument('--cargo')
    parser.add_argument('--cc')
    args = parser.parse_args()
    build(**vars(args))
    print(args.output/'build-manifest.json')
if __name__ == '__main__': main()
