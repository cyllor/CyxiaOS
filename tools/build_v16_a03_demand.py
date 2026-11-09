#!/usr/bin/env python3
"""Build the explicit ordinary A03 demand scene, with learning collection off."""
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
from build_v16_learning_collection import ENVIRONMENT
from check_elf import symbol
from verify_v13_model import loaded_bytes
from verify_smp import require

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'ordinary-rise-fall'
LAYOUT = (0x4359413033443136, 1, 1, 1024, 10_000_000_000, 2_000_000_000)


def profile_environment(inherited):
    result = {key: value for key, value in inherited.items() if key in ENVIRONMENT}
    result.update(CYXIA_A03_DEMAND=PROFILE, CYXIA_LEARNING_COLLECTION='full')
    return result


def builder_closure():
    pending = ['build_v16_a03_demand']; found = {}
    while pending:
        name = pending.pop()
        if name in found: continue
        require(len(found) < 128, 'demand builder closure bound')
        path = ROOT/'tools'/(name+'.py')
        require(path.is_file() and not path.is_symlink(), 'linked/missing demand builder dependency')
        found[name] = sha(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports = ([node.module] if isinstance(node, ast.ImportFrom) else
                [item.name for item in node.names] if isinstance(node, ast.Import) else [])
            for item in imports:
                if item and '.' not in item and (ROOT/'tools'/(item+'.py')).is_file(): pending.append(item)
    return {'tools/'+name+'.py': digest for name, digest in sorted(found.items())}


def elf_profile(path):
    data = Path(path).read_bytes()
    entry = symbol(data, 'A03_DEMAND_V16_LAYOUT')
    require(entry['size'] == 48, 'wrong A03 demand layout width')
    raw = loaded_bytes(data, entry['va'], 48)
    words = struct.unpack('<6Q', raw)
    require(words == LAYOUT, 'ELF ordinary demand profile/layout mismatch (stale cache)')
    bank = symbol(data, 'A03_DEMAND_V16_EVIDENCE')
    require(bank['size'] == 1024, 'missing/wrong ordinary demand evidence bank')
    quiet = symbol(data, 'A03_QUIET_MODEL_V16_EVIDENCE')
    require(quiet['size'] == 5120, 'missing/wrong retained ordinary quiet model record')
    return dict(symbol='A03_DEMAND_V16_LAYOUT', address=entry['va'], words=list(words),
        sha256=hashlib.sha256(raw).hexdigest(), evidence=dict(address=bank['va'], bytes=bank['size']),
        quiet_model=dict(address=quiet['va'], bytes=quiet['size']))


def build(identity_a, identity_b, output, *, target_dir=None, unix_seconds=None, cargo=None, cc=None):
    output = Path(output).resolve()
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())), 'refuse existing demand build output')
    environment = profile_environment(os.environ)
    base = Path(target_dir or environment.get('CARGO_TARGET_DIR', ROOT/'target')).expanduser().resolve()
    cache = base/'a03-ordinary-demand-v1'
    require(not cache.is_symlink(), 'linked demand profile cache')
    sources = code_source_map(ROOT); builders = builder_closure()
    command = [sys.executable, str(ROOT/'tools/build_unified.py'),
        '--identity-a', str(Path(identity_a).resolve(strict=True)),
        '--identity-b', str(Path(identity_b).resolve(strict=True)), '--output', str(output),
        '--fault', 'normal', '--selftest', '--target-dir', str(cache)]
    for flag, value in (('--unix-seconds', unix_seconds), ('--cargo', cargo), ('--cc', cc)):
        if value is not None: command.extend((flag, str(value)))
    subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=1800)
    original = output/'build-manifest.json'; raw = original.read_bytes(); base_manifest = json.loads(raw)
    require(base_manifest['code_source_map'] == sources == code_source_map(ROOT), 'source changed during demand build')
    require(builder_closure() == builders, 'demand builder closure changed')
    p = base_manifest['profiles']
    require(p['fault'] == 'normal' and p['selftest'] is True and not p['storage_fault']
        and not p['memory_probe'] and not p['leave'] and p['service_fault'] == 'none', 'conflicting ordinary demand base profile')
    layouts = {node: elf_profile(output/f'node-{node}.elf') for node in ('a','b')}
    saved = output/'base-build-manifest.json'
    require(not saved.exists(), 'demand base manifest collision')
    saved.write_bytes(raw); saved.chmod(0o600)
    report = dict(schema_version=1, contract='v16-a03-ordinary-demand-build-v1', status='BUILT_NOT_RUN',
        demand_profile=PROFILE, elf_layouts=layouts, builder_sources=builders,
        base_manifest=dict(path=saved.name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
        profile_environment={'CYXIA_A03_DEMAND': PROFILE, 'CYXIA_LEARNING_COLLECTION': 'full'},
        inherited_environment_names=sorted(set(environment)-{'CYXIA_A03_DEMAND','CYXIA_LEARNING_COLLECTION'}),
        command=command, build_cache_profile_namespace=str(cache), code_source_map=sources,
        code_source_sha256=base_manifest['code_source_sha256'],
        scope='Ordinary paid stimulus only. Learning owner disabled; no trained model or A03 acceptance claim.')
    original.write_text(json.dumps(report, sort_keys=True, indent=2)+'\n'); original.chmod(0o600)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('identity-a','identity-b','output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--unix-seconds', type=int)
    parser.add_argument('--cargo'); parser.add_argument('--cc')
    args = parser.parse_args()
    build(**vars(args)); print(args.output/'build-manifest.json')


if __name__ == '__main__': main()
