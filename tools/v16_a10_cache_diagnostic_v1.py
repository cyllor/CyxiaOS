"""Existing C4 banks, stopped observations only; no A10 acceptance authority."""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
import struct

from doctor import ROOT
from check_prototype_evidence import require, safe_path, sha256
from run_v13_a10 import PENDING_DIAGNOSTICS as ORIGINAL_PENDING, profile as original_profile
from check_elf import symbol
from verify_v13_a10_native_receipt import poll_bound

VERSION='a10-cache-overrun-diagnostic-v1-r2'
PENDING_DIAGNOSTICS=ORIGINAL_PENDING+('task-overrun','control-credit')
TASK_MAGIC=0x43595441534b0001
OVERRUN_MAGIC=0x43594f5645520001


def diagnostic_profile(image):
    layout=original_profile(image)
    for name,key in (('NETWORK_PIECE_EVIDENCE','network-piece'),
                     ('NETWORK_SETTLEMENT_EVIDENCE','network-settlement')):
        try:location=symbol(image,name)
        except ValueError:continue
        require(location['size']==512,'wrong optional network diagnostic width: '+name)
        layout['diagnostics'][key]=location
    return layout


def tool_closure(source_root=ROOT):
    pending=['run_v16_a10_cache_diagnostic_v1','v16_a10_cache_diagnostic_v1'];found={}
    while pending:
        name=pending.pop()
        if name in found:continue
        path=safe_path(source_root,'tools/'+name+'.py');found[name]=sha256(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports=([node.module] if isinstance(node,ast.ImportFrom) else
                     [item.name for item in node.names] if isinstance(node,ast.Import) else [])
            for imported in imports:
                if imported and (Path(source_root)/'tools'/(imported+'.py')).is_file():pending.append(imported)
    return {name+'.py':value for name,value in sorted(found.items())}


def capture_limits(inputs):
    polls=poll_bound(inputs)
    # Only the host transcript allowance changes: two added original reads per
    # poll, one stop/status pair, and two complete stopped diagnostic sweeps.
    commands=polls*7+128
    return dict(bytes=polls*12288+16*1024**2,commands=commands,witness_rows=commands*3+64)


def periodic_capture(save,layout):
    return {key:save('pending-'+key+'.bin',layout['diagnostics'][key]['pa'],
                     layout['diagnostics'][key]['size']) for key in PENDING_DIAGNOSTICS}


def cpu0_hint(banks):
    domain=banks.get('domain-task',b'');overrun=banks.get('task-overrun',b'')
    reasons=[]
    if len(domain)==256:
        w=struct.unpack('<32Q',domain)
        if w[0]==TASK_MAGIC and w[2]&1 and w[3]>0:reasons.append('live CPU0 quarantine/overrun')
    if len(overrun)==256:
        w=struct.unpack('<32Q',overrun)
        if w[0]==OVERRUN_MAGIC and w[1]>0 and all(w[i]>0 for i in (2,3,4,5)):
            reasons.append('live published CPU0 consumed Budget row')
    return dict(live_hint_only=True,reasons=reasons) if reasons else None


def nbd_boundary(backend):
    # Cross-field host hints only. The retained raw timestamped NBD stream is
    # needed to reconstruct exact order, including QMP-stop-related writes.
    return dict(requests=backend.requests,mutations=backend.mutations,acks=backend.acks,
                flushes=backend.flushes,fault_mutations=backend.fault_mutations,
                closed=backend.closed,atomic_snapshot=False)


def stopped_capture(qmp,save,layout,backend,witness):
    before=nbd_boundary(backend)
    witness.record('diagnostic-stop-request',backend=before)
    qmp.execute('stop')
    require(qmp.execute('query-status')=={'running':False,'status':'paused'},
            'diagnostic QMP stop not confirmed paused')
    after=nbd_boundary(backend)
    witness.record('diagnostic-paused',backend=after)
    ranges={key:layout['diagnostics'][key] for key in
            ('task-overrun','domain-task','control-credit','unified-service-stage')}
    ranges.update({key:layout[key] for key in ('capture','progress','consumption')})
    ranges.update(layout['diagnostics'])
    first={};second={};errors={}
    for round_,target in ((1,first),(2,second)):
        for key,location in ranges.items():
            try:
                raw=save(f'stopped-{round_}-{key}.bin',location['pa'],location['size'])
                require(len(raw)==location['size'],'diagnostic stopped bank width')
                target[key]=raw
            except (OSError,ValueError,RuntimeError) as error:
                errors[f'{round_}:{key}']=type(error).__name__+': '+str(error)
    unequal=[key for key in ranges if key not in first or key not in second or first[key]!=second[key]]
    report=dict(stopped_confirmed=True,stopped_banks_equal=not unequal and not errors,
        unequal_banks=unequal,capture_errors=errors,backend_before_stop=before,backend_after_pause=after,
        first_sha256={key:hashlib.sha256(raw).hexdigest() for key,raw in first.items()},
        second_sha256={key:hashlib.sha256(raw).hexdigest() for key,raw in second.items()},
        scope='QMP-stop diagnostic; stop may cause host device FLUSH; not a powercut prefix')
    if report['stopped_banks_equal']:
        report['cpu0_overrun_observation']=decode_cpu0_overrun(first['task-overrun'])
    return report,first


def decode_cpu0_overrun(raw):
    require(len(raw)==256,'wrong C4 task-overrun width')
    w=struct.unpack('<32Q',raw)
    if w[0]!=OVERRUN_MAGIC or w[1]==0 or not all(w[i]>0 for i in (2,3,4,5)):return None
    names=('sequence','thread_id','thread_generation','reserved_ns','actual_ns','started_ns',
           'finished_ns','window','core_generation','optional')
    row=dict(zip(names,w[2:12]));row['bank_event_count']=w[1]
    row['actual_exceeds_reservation']=row['actual_ns']>row['reserved_ns']
    row['finishes_after_dispatch_window']=row['finished_ns']>(row['window']+1)*100_000_000
    row['scope']='C4 stopped diagnostic row; last per CPU, not a first-cause latch or A10 verdict'
    return row


class _CleanupReport(dict):
    """Retain every legacy cleanup error assignment, including overwrites."""
    def __init__(self):
        super().__init__();self.errors=[]
    def __setitem__(self,key,value):
        if key=='error':self.errors.append(str(value))
        super().__setitem__(key,value)


def finish_capture(cleanup,output,report,raw,serial):
    # The primary producer error never enters the legacy mutable error sink.
    # Legacy kill/wait/backend-close ordering is unchanged and invoked once.
    sink=_CleanupReport();errors=report.setdefault('cleanup_errors',[])
    try:
        cleanup(sink)
    except BaseException as error:
        errors.append('legacy cleanup raised '+type(error).__name__+': '+str(error))
    errors.extend(sink.errors)
    report['serial_saved']={}
    for name,data in (('serial.bin',raw),('serial.txt',serial)):
        try:
            (Path(output)/name).write_bytes(data)
            report['serial_saved'][name]=True
        except BaseException as error:
            report['serial_saved'][name]=False
            errors.append(name+': '+type(error).__name__+': '+str(error))


def finalize_diagnostic(output,report):
    import json
    import os
    output=Path(output);errors=report.setdefault('persistence_errors',[])
    artifacts={};inventory_errors=[]
    try:
        paths=sorted(output.rglob('*'))
    except OSError as error:
        paths=[];inventory_errors.append('inventory walk: '+str(error))
    for path in paths:
        if path.name=='summary.json':continue
        try:
            if path.is_symlink():raise ValueError('symlink in diagnostic output')
            if path.is_file():artifacts[path.relative_to(output).as_posix()]=sha256(path)
        except (OSError,ValueError) as error:
            inventory_errors.append(str(path)+': '+type(error).__name__+': '+str(error))
    report['artifacts']=artifacts
    report['artifact_inventory_complete']=not inventory_errors
    errors.extend(inventory_errors)
    report['summary_saved']=True
    try:
        target=output/'summary.json';temporary=output/'.summary.json.tmp'
        require(not target.exists(),'refuse existing diagnostic summary')
        with temporary.open('x') as stream:
            json.dump(report,stream,sort_keys=True,separators=(',',':'),allow_nan=False)
            stream.write('\n');stream.flush();os.fsync(stream.fileno())
        temporary.replace(target)
    except BaseException as error:
        report['summary_saved']=False
        errors.append('summary: '+type(error).__name__+': '+str(error))
    return report
