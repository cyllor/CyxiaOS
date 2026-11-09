#!/usr/bin/env python3
"""Replay fixed v3 ancestry using caller-local native checkers only."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from check_prototype_evidence import require, safe_path, sha256, read_json
from verify_v13_a10_native_receipt import document, read_rows, verify_native_child
from verify_v16_a10_reordered_write_v3 import verify_native_reordered_write_child
from v16_a10_reordered_chain_v3 import (ROLES, PROBES, MODES, canonical_path, validate_plan,
    validate_links, select_overwrite_write, select_mount_replay_write)


def record(root, child):
    """Read only inventory-bound facts already checked by fixed native code."""
    root=Path(root);manifest=document(root,'summary.json')['artifacts']
    for name in ('binding.json','native-identity.json','native-provenance.jsonl','model.bin'):
        require(sha256(safe_path(root,name))==manifest[name],'v3 record inventory changed: '+name)
    events={}
    for row in read_rows(safe_path(root,'native-provenance.jsonl'),child.inputs):
        kind=row['event']
        if kind in ('identity-before','backend-open','spawn','final-disk','identity-after'):
            require(kind not in events,'v3 duplicate chain lifecycle')
            events[kind]=row
    require(len(events)==5,'v3 incomplete chain lifecycle')
    return dict(directory=str(root),inputs=child.inputs,context=child.context,nonce=child.nonce,
        summary=child.summary,binding=document(root,'binding.json'),identity=document(root,'native-identity.json'),
        model_sha256=sha256(safe_path(root,'model.bin')),lifecycle=events)


def disk_snapshot(paths):
    result={};seen=set()
    for path in paths:
        path=canonical_path(str(path));stat=path.stat()
        require(stat.st_nlink==1 and stat.st_size==512*1024**2,'v3 mutable disk link/size mismatch')
        identity=(stat.st_dev,stat.st_ino)
        require(identity not in seen,'v3 aliased/hard-linked mutable disks')
        seen.add(identity)
        result[str(path)]=(identity,sha256(path))
    return result


def verify_chain(plan, *, source_root, build_manifest, qemu_binary, qemu_source, initial_disk,
                 same_host_monotonic_session):
    validate_plan(plan)
    require(same_host_monotonic_session is True,'v3 explicit same-host monotonic session required')
    context={key:canonical_path(str(value),directory=key in ('source_root','qemu_source'))
        for key,value in dict(source_root=source_root,build_manifest=build_manifest,
            qemu_binary=qemu_binary,qemu_source=qemu_source).items()}
    seed=canonical_path(str(initial_disk));roots={role:canonical_path(plan[role]['directory'],directory=True) for role in ROLES}
    require(all(not left.is_relative_to(right) for a,left in roots.items() for b,right in roots.items() if a!=b),
        'v3 nested capture directories')
    paths=[seed]+[root/name for root in roots.values() for name in ('initial.raw','disk.raw')]
    frozen=disk_snapshot(paths)
    require(frozen[str(seed)][1]==plan['seed']['sha256'],'v3 caller seed hash mismatch')
    for role,root in roots.items():
        entry=plan[role]
        require(sha256(safe_path(root,'summary.json'))==entry['summary_sha256']
            and frozen[str(root/'initial.raw')][1]==entry['initial_sha256']
            and frozen[str(root/'disk.raw')][1]==entry['final_sha256'],'v3 planned child hash mismatch: '+role)
    records={}
    for role in ROLES:
        root=roots[role]
        if role in PROBES:
            parent=roots[plan[role]['parent']]/'disk.raw'
            # Probe is already independently accepted earlier in fixed order.
            selected=(select_overwrite_write(roots['overwrite_probe']) if role=='overwrite_cut' else
                select_mount_replay_write(roots['recovery_probe'],roots['overwrite_cut']/'disk.raw'))
            require(selected==plan[role]['expected_write'],'v3 caller selection differs from raw semantic probe')
            child=verify_native_reordered_write_child(root,**context,initial_disk=parent,
                expected_write=selected,expected_mode=MODES[role])
        else:
            child=verify_native_child(root,**context)
        records[role]=record(root,child)
        require(disk_snapshot(paths)==frozen,'v3 disks changed during independent replay')
    result=validate_links(plan,records,seed,same_host_monotonic_session=same_host_monotonic_session)
    # No child summary can confer final recovery. Its independently rebuilt file
    # observation must preserve the original object and highest committed bytes.
    original=records['prepare']['summary']['observation'];final=records['final_recovery']['summary']['observation']
    require(final['object']==original['object'] and final['durable_write_seq']>=original['durable_write_seq'],
        'v3 final recovery replaced object or lost durable sequence')
    for role,root in roots.items():
        require(sha256(safe_path(root,'summary.json'))==plan[role]['summary_sha256'],
            'v3 summary changed during chain replay')
    result.update(schema_version=3,test_id='A10',profile=plan['profile'],trusted_plan=plan,
        initial_disk=str(seed),trusted_context={key:str(value) for key,value in context.items()},
        selected_writes={role:plan[role]['expected_write'] for role in PROBES},final_observation=final)
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('plan',type=Path)
    for flag in ('source-root','build-manifest','qemu-binary','qemu-source','initial-disk'):
        p.add_argument('--'+flag,type=Path,required=True)
    p.add_argument('--same-host-monotonic-session',action='store_true')
    args=p.parse_args(argv)
    result=verify_chain(read_json(args.plan),**{key:getattr(args,key) for key in
        ('source_root','build_manifest','qemu_binary','qemu_source','initial_disk','same_host_monotonic_session')})
    print(json.dumps(result,indent=2,sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
