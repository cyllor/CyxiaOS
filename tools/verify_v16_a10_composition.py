#!/usr/bin/env python3
"""Independently replay a caller-selected fixed A10 chain; never grant full A10."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from check_prototype_evidence import read_json, require, safe_path, sha256
from verify_v13_a10_native_receipt import document, verify_native_child
from verify_v16_a10_write_v2 import verify_native_write_child
from v16_a10_composition import legacy_preflight, validate_links


def _keys(value, keys, label):
    require(type(value) is dict and value.keys() == keys, 'invalid trusted plan '+label+' keys')


def _digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'invalid trusted plan sha256')


def _directory(value):
    require(type(value) is str and value and not Path(value).is_symlink(), 'invalid trusted plan directory')
    require(Path(value).is_absolute(), 'trusted plan directory must be absolute and canonical')
    path = Path(value).resolve(strict=True)
    require(path.is_dir() and str(path) == value, 'trusted plan directory must be absolute and canonical')
    return path


def _plan(trusted_plan, initial_disk):
    _keys(trusted_plan, {'schema_version','test_id','profile','external_seed','cut','recovery'}, 'root')
    require(type(trusted_plan['schema_version']) is int and trusted_plan['schema_version'] == 1
            and trusted_plan['test_id'] == 'A10'
            and trusted_plan['profile'] == 'strict-write-cut-recovery-v1', 'unsupported trusted plan profile')
    _keys(trusted_plan['external_seed'], {'sha256'}, 'external_seed')
    _keys(trusted_plan['cut'], {'directory','summary_sha256','expected_write'}, 'cut')
    _keys(trusted_plan['recovery'], {'directory','summary_sha256'}, 'recovery')
    selector = trusted_plan['cut']['expected_write']
    _keys(selector, {'cut','offset','length','data_sha256'}, 'WRITE selector')
    require(all(type(selector[k]) is int for k in ('cut','offset','length'))
            and selector['cut'] > 0 and selector['offset'] >= 0 and selector['offset'] % 512 == 0
            and 0 < selector['length'] <= 1024**2 and selector['length'] % 512 == 0
            and selector['offset'] + selector['length'] <= 512*1024**2,
            'invalid trusted plan WRITE selector')
    _digest(selector['data_sha256'])
    _digest(trusted_plan['external_seed']['sha256'])
    require(not Path(initial_disk).is_symlink() and Path(initial_disk).is_file(), 'invalid caller seed disk')
    seed = Path(initial_disk).resolve(strict=True)
    require(sha256(seed) == trusted_plan['external_seed']['sha256'], 'trusted plan seed disk hash mismatch')
    directories = []
    for kind in ('cut','recovery'):
        selection = trusted_plan[kind]
        _digest(selection['summary_sha256'])
        root = _directory(selection['directory'])
        require(sha256(safe_path(root, 'summary.json')) == selection['summary_sha256'],
                'trusted plan '+kind+' summary hash mismatch')
        directories.append(root)
    require(directories[0] != directories[1] and seed not in
            [root/name for root in directories for name in ('disk.raw','initial.raw')],
            'trusted plan aliases seed or captures')
    return seed, directories


def _record(root, child):
    # The original verifiers have already replayed these bytes. Bind our reads to
    # that exact verified inventory too, rather than trusting a detached sidecar.
    manifest = document(root, 'summary.json')['artifacts']
    for name in ('binding.json','native-identity.json','native-provenance.jsonl'):
        require(sha256(safe_path(root, name)) == manifest[name], 'composition record inventory changed: '+name)
    lifecycle = {}
    for line in safe_path(root, 'native-provenance.jsonl').read_text().splitlines():
        row = json.loads(line)
        if row['event'] in ('identity-before','backend-open','spawn','final-disk','identity-after'):
            require(row['event'] not in lifecycle, 'duplicate composition lifecycle event')
            lifecycle[row['event']] = row
    require(len(lifecycle) == 5, 'missing composition lifecycle event')
    return dict(directory=str(root), inputs=child.inputs, context=child.context, nonce=child.nonce,
                summary=child.summary, binding=document(root, 'binding.json'),
                identity=document(root, 'native-identity.json'), lifecycle=lifecycle)


def verify_chain(trusted_plan, *, source_root, build_manifest, qemu_binary, qemu_source, initial_disk,
                 same_host_monotonic_session=False):
    """Only the fixed strict v2 cut and original v1 completion checkers are used."""
    require(same_host_monotonic_session is True, 'explicit caller same-host-monotonic-session acknowledgement required')
    seed, (cut_root, recovery_root) = _plan(trusted_plan, initial_disk)
    context = dict(source_root=Path(source_root).resolve(strict=True),
                   build_manifest=Path(build_manifest).resolve(strict=True),
                   qemu_binary=Path(qemu_binary).resolve(strict=True),
                   qemu_source=Path(qemu_source).resolve(strict=True))
    cut = verify_native_write_child(cut_root, **context, initial_disk=seed,
                                   expected_write=trusted_plan['cut']['expected_write'])
    recovery = verify_native_child(recovery_root, **context)
    result = validate_links(seed, trusted_plan['external_seed']['sha256'],
                            _record(cut_root, cut), _record(recovery_root, recovery),
                            same_host_monotonic_session=same_host_monotonic_session)
    for kind, root in (('cut',cut_root),('recovery',recovery_root)):
        require(sha256(safe_path(root,'summary.json')) == trusted_plan[kind]['summary_sha256'],
                'trusted plan summary changed during verification')
    result.update(schema_version=1, test_id='A10', profile=trusted_plan['profile'],
                  trusted_plan=trusted_plan, initial_disk=str(seed),
                  trusted_context={key:str(value) for key,value in context.items()})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    chain = commands.add_parser('chain', help='replay a fixed caller-trusted seed/cut/recovery plan')
    chain.add_argument('trusted_plan', type=Path)
    chain.add_argument('--same-host-monotonic-session', action='store_true',
                       help='caller asserts captures share one host monotonic epoch; raw custody does not attest this')
    for flag in ('source-root','build-manifest','qemu-binary','qemu-source','initial-disk'):
        chain.add_argument('--'+flag, required=True, type=Path)
    preflight = commands.add_parser('preflight', help='advisory counts/caps only; never launches a VM')
    preflight.add_argument('inputs', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'chain':
            result = verify_chain(read_json(args.trusted_plan), **{key:getattr(args,key) for key in
                ('source_root','build_manifest','qemu_binary','qemu_source','initial_disk','same_host_monotonic_session')})
        else:
            result = legacy_preflight(**read_json(args.inputs))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if result.get('status') == 'REFUSED_RESOURCE_BUDGET' else 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print('a10-composition: '+str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
