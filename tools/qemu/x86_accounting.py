#!/usr/bin/env python3
"""Exact x86 Cyxia translated-TB clock ABI and independent source provenance.

This module never confers native accounting PASS: native busy/HLT/sibling and
fault observations must be captured and checked separately.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
UPSTREAM_COMMIT = 'f8ed81651e61d9c2166df6121ce2af0f44f06b3e'
PATCH = HERE / 'cyxia-x86-execution.patch'
MANIFEST = HERE / 'x86-execution-manifest.json'
SOURCE_FILES = frozenset(('cpu-common.c', 'include/hw/core/cpu.h',
    'accel/tcg/cpu-exec.c', 'target/i386/cpu.c', 'target/i386/cpu.h',
    'target/i386/tcg/system/misc_helper.c'))
CAPABILITY_WORDS = (0x43595831, 0x00010007, 0x4b595801, 1_000_000_000)
PROFILE = dict(accelerator='tcg', threads='multi', icount=False, migration=False)


def require(value, message):
    if not value:
        raise ValueError(message)


def unsigned(value, bits):
    require(type(value) is int and 0 <= value < 1 << bits, 'invalid unsigned integer')
    return value


def decode_capability(words):
    require(type(words) in (list, tuple) and len(words) == 4, 'missing capability')
    require(tuple(unsigned(w, 32) for w in words) == CAPABILITY_WORDS,
            'unsupported or unhealthy execution clock capability')
    return dict(abi=1, execution_msr=CAPABILITY_WORDS[2], monotonic_msr=CAPABILITY_WORDS[2] + 1,
                frequency_hz=1_000_000_000, flags=7)


def elapsed_ns(start, end):
    for stamp in (start, end):
        require(type(stamp) is dict and set(stamp) == {'cpu', 'source', 'ns'}, 'invalid execution stamp')
        unsigned(stamp['cpu'], 32)
        require(unsigned(stamp['source'], 32) == 1, 'unsupported execution source')
        unsigned(stamp['ns'], 64)
    require((start['cpu'], start['source']) == (end['cpu'], end['source']),
            'execution stamp CPU/source changed')
    require(end['ns'] >= start['ns'], 'execution clock regressed')
    return end['ns'] - start['ns']


def add_debit_ns(total, delta):
    result = unsigned(total, 64) + unsigned(delta, 64)
    require(result < 1 << 64, 'execution debit overflow')
    return result


def validate_profile(profile):
    require(type(profile) is dict and set(profile) == set(PROFILE)
            and all(type(profile[k]) is type(v) and profile[k] == v for k, v in PROFILE.items()),
            'execution clock requires MTTCG, no icount and no migration')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_manifest(value):
    require(type(value) is dict and set(value) == {'schema_version', 'upstream_commit',
            'patch_sha256', 'source_sha256', 'capability', 'profile', 'dependencies'}, 'invalid clock manifest fields')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['upstream_commit'] == UPSTREAM_COMMIT, 'wrong upstream clock revision')
    decode_capability(value['capability'])
    validate_profile(value['profile'])
    require(value['patch_sha256'] == sha(PATCH), 'clock patch digest mismatch')
    sources = value['source_sha256']
    require(type(sources) is dict and set(sources) == SOURCE_FILES, 'clock source set differs')
    require(all(type(v) is str and len(v) == 64 and all(c in '0123456789abcdef' for c in v)
                for v in sources.values()), 'invalid clock source digest')
    dependencies = value['dependencies']
    require(dependencies == {
        'berkeley-softfloat-3': {'url': 'https://gitlab.com/qemu-project/berkeley-softfloat-3.git',
                               'commit': 'b64af41c3276f97f0e181920400ee056b9c88037'},
        'berkeley-testfloat-3': {'url': 'https://gitlab.com/qemu-project/berkeley-testfloat-3.git',
                               'commit': 'e7af9751d9f9fd3b47911f51a5cfd08af256a9ab'},
        'keycodemapdb': {'url': 'https://gitlab.com/qemu-project/keycodemapdb.git',
                         'commit': 'f5772a62ec52591ff6870b7e8ef32482371f22c6'}}, 'wrong pinned build dependencies')
    return value


def load_manifest():
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON field')
            out[key] = value
        return out
    return validate_manifest(json.loads(MANIFEST.read_text(), object_pairs_hook=pairs))


def command(argv, *, timeout=30):
    return subprocess.run([str(x) for x in argv], check=True, text=True,
                          capture_output=True, timeout=timeout).stdout


def attest_source(source):
    manifest = load_manifest()
    source = Path(source).resolve(strict=True)
    require(command(['git', '-C', source, 'rev-parse', 'HEAD']).strip() == UPSTREAM_COMMIT,
            'QEMU source base differs')
    status = command(['git', '-C', source, 'status', '--short', '--untracked-files=no'])
    require(set(status.splitlines()) == {' M ' + name for name in SOURCE_FILES}
            and len(status.splitlines()) == len(SOURCE_FILES), 'QEMU tracked modifications differ')
    require(all(sha(source / name) == digest for name, digest in manifest['source_sha256'].items()),
            'QEMU source contents differ')
    command(['git', '-C', source, 'diff', '--check'])
    command(['git', '-C', source, 'apply', '--reverse', '--check', PATCH])
    return dict(upstream_commit=UPSTREAM_COMMIT, patch_sha256=manifest['patch_sha256'],
                source_sha256=manifest['source_sha256'], source_directory=str(source))


def validate_version(first):
    # Fresh exact-commit clones need not contain a tag ref. Patch identity is
    # established by attest_source and source-build binding, never this suffix.
    require(first in ('QEMU emulator version 10.2.2',
                      'QEMU emulator version 10.2.2 (v10.2.2-dirty)'), 'x86 QEMU version differs')
    return first


def attest(binary, source):
    proof = attest_source(source)
    source = Path(source).resolve(strict=True)
    built = source / 'build/qemu-system-x86_64'
    binary = Path(binary).resolve(strict=True)
    require(binary.is_file() and built.is_file() and sha(binary) == sha(built),
            'x86 QEMU binary is not the selected source build')
    first = command([binary, '--version'], timeout=10).splitlines()[0]
    validate_version(first)
    receipt_path = source / 'x86-accounting-build.json'
    receipt = json.loads(receipt_path.read_text())
    require(receipt.get('status') == 'BUILT_NOT_RUN' and receipt.get('binary_sha256') == sha(binary)
            and receipt.get('source') == proof and receipt.get('builder_sha256') == sha(HERE / 'build_x86_accounting.py'),
            'x86 QEMU build receipt differs')
    proof.update(binary=str(binary), binary_sha256=sha(binary), version=first,
                 build_receipt_sha256=sha(receipt_path), capability=decode_capability(CAPABILITY_WORDS),
                 profile=PROFILE, status='SOURCE_AND_BINARY_BOUND_NOT_NATIVE_VERIFIED')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(attest(args.binary, args.source), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
