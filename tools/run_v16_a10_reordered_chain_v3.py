#!/usr/bin/env python3
"""Bounded five-child A10 experiment; accepted preparation is caller-selected.

No command, module or checker is loaded from an evidence directory. On any
failure, stop with the failing raw child preserved. Child producers own all
process cleanup, including exception paths. Full A10 remains NOT_RUN.
"""
from __future__ import annotations
import argparse
import ast
import json
from pathlib import Path
import shutil
import time

from doctor import ROOT
from build_unified import code_source_map
from check_prototype_evidence import require, safe_path, sha256, read_json
from run_v13_a10 import run as run_clean
from run_v16_a10_reordered_write_v3 import run as run_cut
from verify_v13_a10_native_receipt import verify_native_child, qemu_identity
from verify_v16_a10_reordered_write_v3 import verify_native_reordered_write_child
from verify_v16_a10_reordered_chain_v3 import verify_chain
from v16_a10_reordered_write_v3 import bounded_inventory, CAPTURE_DIRS
from v16_a10_reordered_chain_v3 import (ROLES, NEW_ROLES, PARENTS, PROBES, CATEGORIES, MODES,
    MIN_STORAGE, canonical_path, validate_resources, select_overwrite_write, select_mount_replay_write)


def tool_closure():
    pending=['run_v16_a10_reordered_chain_v3','verify_v16_a10_reordered_chain_v3','v16_a10_reordered_chain_v3']
    found={}
    while pending:
        name=pending.pop()
        if name+'.py' in found:continue
        path=safe_path(ROOT,'tools/'+name+'.py');found[name+'.py']=sha256(path)
        # Store module identities consistently; AST imports are data parsed from
        # caller-local reviewed code, never evaluated from archived source.
        for node in ast.walk(ast.parse(path.read_text())):
            names=([node.module] if isinstance(node,ast.ImportFrom) else
                [entry.name for entry in node.names] if isinstance(node,ast.Import) else [])
            for imported in names:
                if imported and imported+'.py' not in found and (ROOT/'tools'/(imported+'.py')).is_file():pending.append(imported)
    return dict(sorted(found.items()))


def save(path,value):
    # Caller-owned plan is frozen on disk before a selected cut starts.
    with Path(path).open('w') as stream:
        json.dump(value,stream,sort_keys=True,indent=2,allow_nan=False);stream.write('\n')


def usage(root):
    directories=set(NEW_ROLES)|{role+'/'+name for role in NEW_ROLES for name in CAPTURE_DIRS}
    total=0
    for path,info in bounded_inventory(root,allowed_dirs=directories):
        require(path.parent!=Path(root) or path.name in ('plan.json','campaign-summary.json'),
            'v3 extra campaign root file')
        total+=info.st_blocks*512
    return total


def entry(root,parent,selection=None):
    value=dict(directory=str(root),summary_sha256=sha256(root/'summary.json'),parent=parent,
        initial_sha256=sha256(root/'initial.raw'),final_sha256=sha256(root/'disk.raw'))
    if selection is not None:value.update(selection)
    return value


def run(*,prepare,initial_disk,output,source_root,build_manifest,qemu_binary,qemu_source,
        same_host_monotonic_session,resource_caps,artifact_cache=None):
    validate_resources(resource_caps)
    require(same_host_monotonic_session is True,'v3 explicit same-host monotonic session required')
    source_root=canonical_path(str(source_root),directory=True)
    # A fixed source snapshot keeps original v1 and additive v3 tool closures
    # separately visible without changing old global ROOT constants.
    require(source_root==ROOT.resolve(),'v3 producer requires its caller-local frozen source snapshot')
    build_manifest=canonical_path(str(build_manifest));qemu_binary=canonical_path(str(qemu_binary))
    qemu_source=canonical_path(str(qemu_source),directory=True);seed=canonical_path(str(initial_disk))
    prepare=canonical_path(str(prepare),directory=True);output=canonical_path(str(output),exists=False)
    require(not output.exists() and not output.is_relative_to(prepare) and not prepare.is_relative_to(output),
        'v3 output must be a new independent campaign root')
    require(seed.stat().st_nlink==1 and seed.stat().st_size==512*1024**2,'v3 immutable seed link/size mismatch')
    build=read_json(build_manifest)
    require(build['code_source_map']==code_source_map(source_root)
        and build['builder_sha256']==sha256(source_root/'tools/build_unified.py'),
        'v3 compiled source/builder mismatch before launch')
    context=dict(source_root=source_root,build_manifest=build_manifest,qemu_binary=qemu_binary,qemu_source=qemu_source)
    accepted=verify_native_child(prepare,**context)
    require(accepted.inputs['mode']==1 and accepted.inputs['cut']==0
        and accepted.summary['status']=='PASS' and accepted.summary['native_mode_verified'] is True
        and accepted.context['initial_source']==str(seed)
        and accepted.inputs['initial_disk_sha256']==sha256(seed),'v3 preparation/seed admission mismatch')
    frozen=dict(sources=code_source_map(source_root),tools=tool_closure(),build_sha256=sha256(build_manifest),
        seed_sha256=sha256(seed),prepare_summary_sha256=sha256(prepare/'summary.json'),
        prepare_disk_sha256=sha256(prepare/'disk.raw'),qemu=qemu_identity(qemu_binary,qemu_source))
    output.parent.mkdir(parents=True,exist_ok=True)
    require(shutil.disk_usage(output.parent).free>=MIN_STORAGE,'v3 insufficient available campaign storage')
    output.mkdir(mode=0o700)
    started=time.monotonic();completed=[]
    plan=dict(schema_version=3,test_id='A10',profile='reordered-before-write-recut-v3',
        seed={'sha256':frozen['seed_sha256']},prepare=entry(prepare,'seed'))
    report=dict(native_acceptance_status='NOT_RUN',A10_complete=False,legacy_mandatory_slots=0,
        strict_partial_chain_verified=False,completed_roles=completed,resource_caps=resource_caps,
        source_root=str(source_root),frozen_identity=frozen)
    def unchanged():
        require(code_source_map(source_root)==frozen['sources'] and tool_closure()==frozen['tools']
            and sha256(build_manifest)==frozen['build_sha256'] and sha256(seed)==frozen['seed_sha256']
            and sha256(prepare/'summary.json')==frozen['prepare_summary_sha256']
            and sha256(prepare/'disk.raw')==frozen['prepare_disk_sha256']
            and qemu_identity(qemu_binary,qemu_source)==frozen['qemu'],'v3 source/parent/tool identity changed')
    primary_error=None
    try:
        for role in NEW_ROLES:
            unchanged()
            require(len(completed)<5 and time.monotonic()-started+1920<=resource_caps['max_runtime_seconds'],
                'v3 campaign runtime/child cap exceeded before launch')
            require(usage(output)+MIN_STORAGE//5<=resource_caps['max_storage_bytes']
                and shutil.disk_usage(output).free>=MIN_STORAGE//5,'v3 campaign storage cap exceeded before launch')
            parent=PARENTS[role];parent_root=prepare if parent=='prepare' else output/parent
            parent_disk=parent_root/'disk.raw';parent_hash=sha256(parent_disk)
            child_root=output/role;selection=None
            if role in PROBES:
                selected=(select_overwrite_write(output/'overwrite_probe') if role=='overwrite_cut' else
                    select_mount_replay_write(output/'recovery_probe',output/'overwrite_cut'/'disk.raw'))
                selection=dict(expected_write=selected,selection=dict(
                    probe_summary_sha256=plan[PROBES[role]]['summary_sha256'],category=CATEGORIES[role]))
                # Partial plan is data only, retained on failure; final verifier
                # accepts only the complete closed six-role schema.
                plan[role]=dict(directory=str(child_root),parent=parent,**selection)
                save(output/'plan.json',plan)
                result=run_cut(build_manifest,parent_disk,child_root,mode=MODES[role],source_root=source_root,
                    timeout=1920,cut=selected['cut'],phase='before',unflushed='reverse-half',reverse_replies=True,
                    artifact_cache=artifact_cache,sample_ms=30000,qemu=qemu_binary,qemu_source=qemu_source,
                    expected_write=selected)
                child=verify_native_reordered_write_child(child_root,**context,initial_disk=parent_disk,
                    expected_write=selected,expected_mode=MODES[role])
            else:
                result=run_clean(build_manifest,parent_disk,child_root,mode=MODES[role],source_root=source_root,
                    timeout=1920,cut=0,phase='before',unflushed='reverse-half',reverse_replies=True,
                    artifact_cache=artifact_cache,sample_ms=30000,qemu=qemu_binary,qemu_source=qemu_source)
                child=verify_native_child(child_root,**context)
                require(child.summary['status']=='PASS' and child.summary['native_mode_verified'] is True,
                    'v3 clean child did not independently complete')
            require(sha256(parent_disk)==parent_hash,'v3 child changed its selected parent')
            unchanged()
            plan[role]=entry(child_root,parent,selection);completed.append(role)
            save(output/'plan.json',plan)
            require(usage(output)<=resource_caps['max_storage_bytes'],'v3 campaign retained storage exceeded cap')
        result=verify_chain(plan,**context,initial_disk=seed,same_host_monotonic_session=True)
        report.update(result)
    except BaseException as error:
        primary_error=error
        report.update(status='FAIL',strict_partial_chain_verified=False,
            error=type(error).__name__+': '+str(error))
        raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started
        accounting_error=None
        try:
            retained=usage(output)
            require(retained<=resource_caps['max_storage_bytes'],'v3 final retained storage exceeded cap')
            report.update(retained_allocated_bytes=retained,accounting_complete=True)
        except (OSError,ValueError) as error:
            accounting_error=error
            report.update(status='FAIL',strict_partial_chain_verified=False,
                retained_allocated_bytes=None,accounting_complete=False,
                accounting_error=type(error).__name__+': '+str(error))
            report.setdefault('error',report['accounting_error'])
        try:
            save(output/'campaign-summary.json',report)
        except (OSError,ValueError) as error:
            # A write failure cannot be represented on an unwritable disk, but
            # must not replace the child/accounting exception already in flight.
            failure=primary_error if primary_error is not None else accounting_error
            if failure is None:raise
            failure.add_note('campaign summary persistence failed: '+type(error).__name__+': '+str(error))
        if accounting_error is not None and primary_error is None:raise accounting_error
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('prepare','initial-disk','output','source-root','build-manifest','qemu-binary','qemu-source'):
        p.add_argument('--'+flag,type=Path,required=True)
    for flag in ('max-children','max-runtime-seconds','max-storage-bytes'):p.add_argument('--'+flag,type=int,required=True)
    p.add_argument('--same-host-monotonic-session',action='store_true');p.add_argument('--artifact-cache',type=Path)
    args=p.parse_args(argv);values=vars(args)
    caps={key:values.pop(key) for key in ('max_children','max_runtime_seconds','max_storage_bytes')}
    result=run(**values,resource_caps=caps);print(json.dumps(result,sort_keys=True,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
