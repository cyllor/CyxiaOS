#!/usr/bin/env python3
"""Run a bounded prefix of the unchanged all/all native A10 Cartesian matrix.

Each invocation launches at most 2..16 new children. A pause is IN_PROGRESS,
not PASS. --resume replays every credited native child and all frozen parents;
failed/uncredited existing child directories are preserved and never retried.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

from doctor import ROOT
from check_prototype_evidence import require, read_json, safe_path, sha256 as entry_digest
from run_v13_a10 import run as run_clean
from run_v16_a10_cut_v4 import run as run_cut
from v13_a10_budget import scenario_budget
from v16_a10_live_watch_v1 import run_monitored_clean, OperatorDiagnosticStop
from v16_a10_matrix_v4 import (PER_CHILD_RESERVE, MAX_CHILDREN, canonical, snapshot,
    inspect_progress, load_progress, entry, check_child)


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name+'.tmp')
    require(not temporary.exists(), 'v4 matrix existing interrupted metadata write')
    with temporary.open('x') as stream:
        json.dump(value,stream,sort_keys=True,separators=(',',':'),allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)


def retained_bytes(root):
    total = count = 0
    for parent, directories, files in os.walk(root,followlinks=False):
        for name in directories+files:
            path = Path(parent)/name
            st = path.lstat()
            require(not stat.S_ISLNK(st.st_mode) and
                    (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)),
                    'v4 matrix retained special/symlink entry')
            count += 1
            require(count <= MAX_CHILDREN*8192, 'v4 matrix retained entry bound')
            total += st.st_blocks*512
    return total


def idle_native_host():
    rows = subprocess.run(['ps','-axo','pid=,comm='],capture_output=True,text=True,check=True).stdout
    busy = [row.strip() for row in rows.splitlines() if row.split()
            and Path(row.strip().split(None,1)[-1]).name in
                ('qemu-system-aarch64','cargo','rustc','clang')]
    require(not busy,'v4 matrix native/build exclusion: '+repr(busy))


def run(*, output, seed, prepare, overwrite_probe, source_root, build_manifest,
        qemu_binary, qemu_source, native_lock, max_new_children, max_storage_bytes,
        resume=False, operator_diagnose_stalled_cache=False):
    require(type(max_new_children) is int and 2 <= max_new_children <= 16,
            'v4 matrix invocation requires 2..16 new-child cap')
    require(type(operator_diagnose_stalled_cache) is bool,'v4-r2 operator diagnostic switch must be bool')
    require(source_root == ROOT.resolve(), 'v4 matrix producer requires its frozen caller-local source')
    context = dict(source_root=source_root,build_manifest=build_manifest,
                   qemu_binary=qemu_binary,qemu_source=qemu_source)
    if resume:
        require(output.is_dir(),'v4 matrix resume campaign missing')
    else:
        require(not output.exists(),'v4 matrix output exists; explicit resume required')
        output.mkdir(parents=True,mode=0o700)
    require(native_lock.parent.is_dir() and not native_lock.is_symlink(), 'v4 matrix native lock parent')
    with native_lock.open('a') as native_lease, (output/'campaign.lock').open('a') as campaign_lease:
        fcntl.flock(native_lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        fcntl.flock(campaign_lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        idle_native_host()
        if resume:
            previous=output/'campaign-summary.json'
            require(not previous.exists() or (read_json(previous).get('status') != 'FAIL'
                    and not read_json(previous).get('operator_interrupted',False)),
                    'v4 matrix preserves original failed campaign; refuse automatic retry')
            request=read_json(safe_path(output,'matrix-input.json'))
            require(request['seed']['path']==str(seed)
                    and request['prepare']['directory']==str(prepare)
                    and request['overwrite_probe']['directory']==str(overwrite_probe)
                    and request['max_storage_bytes']==max_storage_bytes
                    and request['operator_diagnose_stalled_cache'] is operator_diagnose_stalled_cache,
                    'v4 matrix resumed caller parents/storage differ')
            progress=load_progress(output)
        else:
            request=snapshot(**context,seed=seed,prepare=prepare,
                             overwrite_probe=overwrite_probe,max_storage_bytes=max_storage_bytes,
                             operator_diagnose_stalled_cache=operator_diagnose_stalled_cache)
            progress=dict(schema_version=4,status='IN_PROGRESS',completed={})
            save(output/'matrix-input.json',request); save(output/'progress.json',progress)
        initial_verified=len(progress['completed'])
        launched=0; pause='invocation child cap reached'; started=time.monotonic()
        report={}
        try:
            while True:
                report,ready=inspect_progress(output,request,progress,context=context)
                if report['A10_complete']:
                    progress['status']='COMPLETE'; save(output/'progress.json',progress)
                    pause=None; break
                if launched>=max_new_children:
                    break
                require(ready,'v4 matrix incomplete graph has no runnable task')
                task=ready[0];directory=output/task.name
                require(not directory.exists(),
                        'v4 matrix preserves failed/uncredited existing child; refuse retry: '+task.name)
                retained=retained_bytes(output)
                if retained+PER_CHILD_RESERVE>max_storage_bytes:
                    pause='retained-storage reservation exhausted'; break
                if shutil.disk_usage(output).free<PER_CHILD_RESERVE:
                    pause='available-storage reservation exhausted'; break
                idle_native_host()
                timeout=scenario_budget(source_root,task.mode)['capture_timeout_seconds']
                print(json.dumps(dict(event='launch',slot=task.name,mode=task.mode,
                    cut=task.selector,phase=task.phase,loss=task.loss,
                    source_capture_timeout_seconds=timeout)),flush=True)
                launched+=1
                if task.mode == 4 and task.selector is None and operator_diagnose_stalled_cache:
                    argv=[sys.executable,'-B',str(source_root/'tools/run_v13_a10.py'),
                        '--build-manifest',str(build_manifest),'--source-root',str(source_root),
                        '--initial-disk',str(task.parent),'--output',str(directory),'--mode','4',
                        '--timeout',str(timeout),'--cut','0','--phase','before','--unflushed','drop',
                        '--reverse-replies','--sample-ms','30000','--qemu',str(qemu_binary),
                        '--qemu-source',str(qemu_source)]
                    result=run_monitored_clean(argv,cwd=source_root,environment=dict(os.environ),capture=directory,
                        diagnostics=output.parent/(output.name+'-operator-diagnostics')/task.name,
                        qemu_binary=qemu_binary)
                elif task.selector is None:
                    result=run_clean(build_manifest,task.parent,directory,mode=task.mode,
                        source_root=source_root,timeout=timeout,cut=0,phase='before',
                        unflushed='drop',reverse_replies=True,sample_ms=30000,
                        qemu=qemu_binary,qemu_source=qemu_source)
                else:
                    result=run_cut(build_manifest,task.parent,directory,mode=task.mode,
                        source_root=source_root,timeout=timeout,cut=task.selector['cut'],
                        phase=task.phase,unflushed=task.loss,reverse_replies=True,sample_ms=30000,
                        qemu=qemu_binary,qemu_source=qemu_source,expected_mutation=task.selector)
                require(result['status']==('NOT_RUN' if task.selector else 'PASS'),
                        'v4 matrix native child failed; preserve and stop: '+task.name)
                ref=entry(directory)
                check_child(task,ref,context=context)
                # Reverify the immutable context/parents immediately before
                # crediting a newly completed slot; no summary can mint credit.
                inspect_progress(output,request,progress,context=context)
                progress['completed'][task.name]=ref
                save(output/'progress.json',progress)
                print(json.dumps(dict(event='verified-child',slot=task.name,
                                      new_children=launched)),flush=True)
            report.update(invocation_new_children=launched,
                          invocation_verified_children=len(progress['completed'])-initial_verified,
                          invocation_count_semantics='bounded producer invocations; failed attempts are retained',
                          matrix_input_sha256=entry_digest(output/'matrix-input.json'),
                          progress_sha256=entry_digest(output/'progress.json'),pause_reason=pause,
                          invocation_elapsed_seconds=time.monotonic()-started)
            save(output/'campaign-summary.json',report)
            return report
        except OperatorDiagnosticStop as stopped:
            # Live hints supply no native failure/completion verdict and cannot
            # credit or delete this uncompleted mandatory cache slot.
            report.update(status='NOT_RUN',A10_complete=False,native_filesystem_fault_matrix_complete=False,
                native_acceptance_status='NOT_RUN',execution_state='IN_PROGRESS',
                operator_interrupted=True,operator_diagnostic=str(stopped.diagnostics),
                cache_eviction_verified=False,invocation_new_children=launched,
                invocation_verified_children=len(progress['completed'])-initial_verified,
                invocation_elapsed_seconds=time.monotonic()-started)
            save(output/'campaign-summary.json',report)
            return report
        except BaseException as error:
            report.update(status='FAIL',A10_complete=False,native_filesystem_fault_matrix_complete=False,
                native_acceptance_status='NOT_RUN',execution_state='IN_PROGRESS',
                error=type(error).__name__+': '+str(error),invocation_new_children=launched,
                invocation_elapsed_seconds=time.monotonic()-started)
            save(output/'campaign-summary.json',report)
            raise


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('output','seed','prepare','overwrite-probe','source-root','build-manifest',
                 'qemu-binary','qemu-source','native-lock'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--max-new-children',type=int,required=True)
    p.add_argument('--max-storage-bytes',type=int,required=True)
    p.add_argument('--resume',action='store_true')
    p.add_argument('--operator-diagnose-stalled-cache',action='store_true',
        help='operator-only early stop from repeated existing live hints; default off; never native acceptance')
    a=p.parse_args(argv)
    values=vars(a)
    for name in ('source_root','qemu_source','prepare','overwrite_probe'):
        values[name]=canonical(str(values[name]),directory=True)
    for name in ('seed','build_manifest','qemu_binary'):
        values[name]=canonical(str(values[name]))
    values['output']=canonical(str(a.output),exists=a.resume,directory=a.resume)
    values['native_lock']=canonical(str(a.native_lock),exists=a.native_lock.exists())
    result=run(**values)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 2 if result.get('operator_interrupted') else 0

if __name__=='__main__':
    raise SystemExit(main())
