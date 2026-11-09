"""Exact all-point A10 graph and independent incremental native review.

No archive code is imported. Every edge uses the actual damaged parent; clean
recovery-probe media are only observations, never replacement parents. A bounded
invocation pauses execution, not the declared all/all coverage requirement.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import re
from dataclasses import dataclass

from build_unified import code_source_map
from check_prototype_evidence import require, safe_path, sha256, read_json
from doctor import ROOT
from verify_v13_a10_native_receipt import verify_native_child, qemu_identity
from verify_v16_a10_cut_v4 import verify_native_cut_child
from verify_v13_a10_matrix import PHASES, LOSSES, result_scope, mutation_schedule
from verify_v13_a10 import decode
from verify_v13_a10_faults import overwrite_window
from v13_a10_fault_scope import mutation_scope
from v16_a10_reordered_chain_v3 import read_requests
from v16_a10_cut_v4 import validate_selector

VERSION = 'a10-all-matrix-native-v4-r2'
PER_CHILD_RESERVE = 3 * 512 * 1024**2
MAX_PROGRESS_BYTES = 256 * 1024**2
MAX_CHILDREN = 1_000_000


def canonical(value, *, exists=True, directory=False):
    require(type(value) is str and value and len(value) <= 2048, 'v4 matrix path required')
    p = Path(value)
    require(p.is_absolute() and str(p) == value and '..' not in p.parts
            and str(p.resolve(strict=exists)) == value and not p.is_symlink(),
            'v4 matrix noncanonical/symlink path')
    if exists:
        require(p.is_dir() if directory else p.is_file(), 'v4 matrix path kind mismatch')
    return p


def tool_closure(source_root=ROOT):
    pending = ['run_v16_a10_matrix_v4', 'verify_v16_a10_matrix_v4', 'v16_a10_matrix_v4']
    found = {}
    while pending:
        name = pending.pop()
        if name in found:
            continue
        path = safe_path(source_root, 'tools/' + name + '.py')
        found[name] = sha256(path)
        for node in ast.walk(ast.parse(path.read_text())):
            names = ([node.module] if isinstance(node, ast.ImportFrom) else
                     [entry.name for entry in node.names] if isinstance(node, ast.Import) else [])
            for imported in names:
                if imported and (Path(source_root)/'tools'/(imported+'.py')).is_file():
                    pending.append(imported)
    return {name+'.py': digest for name, digest in sorted(found.items())}


def digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'v4 matrix digest required')
    return value


def entry(directory):
    directory = Path(directory)
    return dict(directory=str(directory), summary_sha256=sha256(directory/'summary.json'),
                initial_sha256=sha256(directory/'initial.raw'), final_sha256=sha256(directory/'disk.raw'))


def validate_entry(value):
    require(type(value) is dict and value.keys() ==
            {'directory','summary_sha256','initial_sha256','final_sha256'}, 'v4 matrix entry schema')
    canonical(value['directory'], directory=True)
    for key in ('summary_sha256','initial_sha256','final_sha256'):
        digest(value[key])
    return value


def validate_progress(value):
    require(type(value) is dict and value.keys() == {'schema_version','status','completed'}
            and type(value['schema_version']) is int and value['schema_version'] == 4
            and value['status'] in ('IN_PROGRESS','COMPLETE')
            and type(value['completed']) is dict and len(value['completed']) <= MAX_CHILDREN,
            'v4 matrix progress schema/bound')
    for name, row in value['completed'].items():
        require(type(name) is str and name and len(name) <= 256 and not Path(name).is_absolute()
                and Path(name).as_posix() == name and '..' not in Path(name).parts,
                'v4 matrix unsafe progress child')
        validate_entry(row)
    return value


def load_progress(directory):
    path = safe_path(directory, 'progress.json')
    require(path.stat().st_size <= MAX_PROGRESS_BYTES, 'v4 matrix progress byte bound')
    return validate_progress(read_json(path))


def snapshot(*, source_root, build_manifest, qemu_binary, qemu_source,
             seed, prepare, overwrite_probe, max_storage_bytes, operator_diagnose_stalled_cache=False):
    require(type(max_storage_bytes) is int and max_storage_bytes >= 2*PER_CHILD_RESERVE,
            'v4 matrix insufficient retained-storage cap')
    require(type(operator_diagnose_stalled_cache) is bool,'v4-r2 operator diagnostic switch must be bool')
    sources = code_source_map(source_root)
    build = read_json(build_manifest)
    require(build['code_source_map'] == sources
            and build['builder_sha256'] == sha256(Path(source_root)/'tools/build_unified.py'),
            'v4 matrix build/source mismatch')
    return dict(schema_version=5, test_id='A10', version=VERSION,
                operator_diagnose_stalled_cache=operator_diagnose_stalled_cache,
                overwrite_points='all', recovery_points='all', phases=list(PHASES), losses=list(LOSSES),
                sample_ms=30000, reverse_replies=True,
                source_root=str(source_root), build_manifest=str(build_manifest),
                build_manifest_sha256=sha256(build_manifest),
                code_source_sha256=hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                qemu_binary=str(qemu_binary), qemu_source=str(qemu_source),
                qemu_identity=qemu_identity(qemu_binary,qemu_source), tools=tool_closure(),
                seed=dict(path=str(seed),sha256=sha256(seed)),
                prepare=entry(prepare), overwrite_probe=entry(overwrite_probe),
                max_storage_bytes=max_storage_bytes, per_child_reserve_bytes=PER_CHILD_RESERVE)


def validate_snapshot(request, *, source_root, build_manifest, qemu_binary, qemu_source):
    expected = {'schema_version','test_id','version','overwrite_points','recovery_points',
                'phases','losses','sample_ms','reverse_replies','source_root','build_manifest',
                'build_manifest_sha256','code_source_sha256','qemu_binary','qemu_source',
                'qemu_identity','tools','seed','prepare','overwrite_probe',
                'max_storage_bytes','per_child_reserve_bytes','operator_diagnose_stalled_cache'}
    require(type(request) is dict and request.keys() == expected, 'v4 matrix request schema')
    require(request['schema_version'] == 5 and type(request['schema_version']) is int
            and request['test_id'] == 'A10' and request['version'] == VERSION
            and request['overwrite_points'] == request['recovery_points'] == 'all'
            and request['phases'] == list(PHASES) and request['losses'] == list(LOSSES)
            and type(request['sample_ms']) is int and request['sample_ms'] == 30000
            and request['reverse_replies'] is True, 'v4 matrix full/all declaration required')
    for name, supplied in (('source_root',source_root), ('build_manifest',build_manifest),
                           ('qemu_binary',qemu_binary), ('qemu_source',qemu_source)):
        require(request[name] == str(Path(supplied).resolve(strict=True)), 'v4 matrix caller identity '+name)
        canonical(request[name], directory=name in ('source_root','qemu_source'))
    validate_entry(request['prepare']); validate_entry(request['overwrite_probe'])
    seed = request['seed']
    require(type(seed) is dict and seed.keys() == {'path','sha256'}, 'v4 matrix seed schema')
    canonical(seed['path']); digest(seed['sha256'])
    require(Path(seed['path']).stat().st_nlink == 1 and sha256(Path(seed['path'])) == seed['sha256'],
            'v4 matrix seed identity changed')
    reconstructed = snapshot(source_root=source_root, build_manifest=build_manifest,
        qemu_binary=qemu_binary, qemu_source=qemu_source, seed=Path(seed['path']),
        prepare=Path(request['prepare']['directory']),
        overwrite_probe=Path(request['overwrite_probe']['directory']),
        max_storage_bytes=request['max_storage_bytes'],
        operator_diagnose_stalled_cache=request['operator_diagnose_stalled_cache'])
    require(request == reconstructed and request['tools'] == tool_closure(source_root),
            'v4 matrix frozen source/tool/parent/context changed')
    return request


@dataclass(frozen=True)
class Task:
    name: str
    mode: int
    parent: Path
    selector: dict | None = None
    phase: str = 'before'
    loss: str = 'drop'


def selector_rows(directory):
    """Reconstruct every eligible post-resume mutation and exact request bytes."""
    scope = mutation_scope(Path(directory))
    _, raw = read_requests(Path(directory))
    chosen = {r['mutation']: validate_selector(dict(cut=r['mutation'],kind=r['kind'],
                    offset=r['offset'],length=r['length'],data_sha256=r['data_sha256']))
              for r, body in raw if r['mutation'] in scope['post_resume_points']}
    require(list(chosen) == scope['post_resume_points'] and chosen,
            'v4 matrix incomplete/duplicate eligible mutation stream')
    return chosen


def verify_overwrite_scope(probe, child, selected):
    window=overwrite_window(decode((Path(probe)/'trace.bin').read_bytes(),child.summary['binding']),
                            mutation_schedule(Path(probe)))
    require(set(window['points']) <= set(selected),
            'v4 matrix all-point scope omitted protected overwrite transaction')


def tasks(root, prepare, probe, verified, *, selectors=selector_rows):
    """Lazy exact graph: never invent R before its actual recovery probe exists."""
    overwrite = selectors(probe)
    cache = Task('cache-eviction',4,Path(probe)/'disk.raw')
    for index,(point, row) in enumerate(overwrite.items()):
        for phase in PHASES:
            for loss in LOSSES:
                case = f'overwrite/p{point:04}-{phase}-{loss}'
                cut = case+'/cut'
                yield Task(cut,2,Path(prepare)/'disk.raw',row,phase,loss)
                recovery = case+'/recovery-probe'
                yield Task(recovery,3,Path(root)/cut/'disk.raw')
                # After the first cut/recovery pair, close the independent
                # cache obligation. Bounded first calls can stop before it.
                if index == 0 and phase == PHASES[0] and loss == LOSSES[0]:
                    yield cache
                if recovery not in verified:
                    continue
                for rp, rr in selectors(Path(root)/recovery).items():
                    for rphase in PHASES:
                        for rloss in LOSSES:
                            name = case+f'/recovery/r{rp:04}-{rphase}-{rloss}'
                            yield Task(name+'/cut',3,Path(root)/cut/'disk.raw',rr,rphase,rloss)
                            yield Task(name+'/final',3,Path(root)/name/'cut'/'disk.raw')


def check_child(task, ref, *, context, loader=None):
    validate_entry(ref)
    directory = Path(ref['directory'])
    require(ref == entry(directory), 'v4 matrix child summary/media changed')
    require(sha256(task.parent) == ref['initial_sha256'], 'v4 matrix child initial edge mismatch')
    if loader is None:
        child = (verify_native_cut_child(directory, **context, initial_disk=task.parent,
                    expected_mutation=task.selector, expected_mode=task.mode)
                 if task.selector is not None else verify_native_child(directory, **context))
    else:
        child = loader(task, directory, context)
    inputs, summary = child.inputs, child.summary
    require(child.context['initial_source'] == str(task.parent)
            and inputs['initial_disk_sha256'] == sha256(task.parent)
            and type(inputs['mode']) is int and inputs['mode'] == task.mode
            and type(inputs['cut']) is int and inputs['cut'] == (task.selector['cut'] if task.selector else 0)
            and inputs['phase'] == task.phase and inputs['unflushed'] == task.loss
            and inputs['reverse_replies'] is True and type(inputs['sample_ms']) is int
            and inputs['sample_ms'] == 30000, 'v4 matrix child mode/phase/loss/parent mismatch')
    if task.selector is not None:
        require(inputs['caller_mutation'] == task.selector
                and summary['cut_observed'] is True and summary['status'] == 'NOT_RUN'
                and summary['native_matrix_cut_custody_verified'] is True,
                'v4 matrix selected mutation lacks verified cut custody')
    else:
        require(summary['status'] == 'PASS' and summary['native_mode_verified'] is True
                and summary['cut_observed'] is False, 'v4 matrix clean child lacks native completion')
    return child


def inspect_progress(root, request, progress, *, context, loader=None, selectors=selector_rows,
                     verify_snapshot=True, window_validator=verify_overwrite_scope):
    """Rebuild every credited edge; partial reports never inherit producer counts."""
    root = canonical(str(root),directory=True)
    if verify_snapshot:
        validate_snapshot(request, **context)
    validate_progress(progress)
    seed = Path(request['seed']['path'])
    prepare, probe = (Path(request[n]['directory']) for n in ('prepare','overwrite_probe'))
    require(len({str(root),str(prepare),str(probe)}) == 3,
            'v4 matrix reused parent/campaign directory')
    prep = check_child(Task('prepare',1,seed),request['prepare'],context=context,loader=loader)
    ref = check_child(Task('overwrite-probe',2,prepare/'disk.raw'),request['overwrite_probe'],context=context,loader=loader)
    require(prep.summary['observation']['consumption_boundary']['present'] is True
            and ref.summary['observation']['consumption_boundary']['present'] is True,
            'v4 matrix preparation/reference lack actual sequence consumption')
    entries = progress['completed']
    verified = {}
    verified_disks = {prepare/'disk.raw', probe/'disk.raw'}
    known = set()
    ready = []
    recovered = set()
    recuts = set()
    cache = False
    reordered = bool(ref.summary.get('nbd_trace',{}).get('reordered_replies'))
    consumed = False
    primary_cases = recovery_mutations = secondary_cases = 0
    for task in tasks(root,prepare,probe,verified,selectors=selectors):
        require(task.name not in known and len(known) < MAX_CHILDREN, 'v4 matrix duplicate/oversized graph')
        known.add(task.name)
        parent_ok = task.parent in verified_disks
        if task.name not in entries:
            if parent_ok and len(ready) < 16:
                ready.append(task)
            continue
        require(parent_ok, 'v4 matrix child exists before verified damaged parent: '+task.name)
        expected_dir = root/task.name
        require(entries[task.name]['directory'] == str(expected_dir), 'v4 matrix child outside exact campaign slot')
        child = check_child(task,entries[task.name],context=context,loader=loader)
        verified[task.name] = child
        verified_disks.add(root/task.name/'disk.raw')
        reordered |= bool(child.summary.get('nbd_trace',{}).get('reordered_replies'))
        if task.selector is not None:
            if task.mode == 2:
                consumed |= bool(child.summary.get('consumption_boundary',{}).get('present'))
                primary_cases += 1
            else:
                require(not child.summary.get('consumption_boundary',{}).get('present',False),
                        'v4 matrix recut reconsumed original fsync')
                recuts.add(task.name.rsplit('/',1)[0])
        elif task.name.endswith('/recovery-probe'):
            require(child.summary['observation']['consumption_boundary']['present'] is False,
                    'v4 matrix recovery reconsumed original fsync')
            recovered.add(task.name)
            recovery_mutations += len(selectors(root/task.name))
        elif task.name.endswith('/final'):
            require(child.summary['observation']['consumption_boundary']['present'] is False,
                    'v4 matrix final recovery reconsumed original fsync')
            require(task.name.rsplit('/',1)[0] in recuts, 'v4 matrix final without exact recut')
            secondary_cases += 1
        elif task.name == 'cache-eviction':
            obs = child.summary['observation']
            require(obs.get('cache_eviction_verified') is True and obs.get('pressure_pages') == 4096,
                    'v4 matrix cache lacks actual pressure/miss/backing reads')
            cache = True
    require(entries.keys() <= known, 'v4 matrix unknown/orphan progress child')
    overwrite = selectors(probe)
    window_validator(probe,ref,overwrite)
    primary_required = len(overwrite)*len(PHASES)*len(LOSSES)
    exact_total = (1+2*primary_required+8*recovery_mutations
                   if len(recovered) == primary_required else None)
    result = result_scope(request,list(overwrite),list(overwrite),primary_cases,
                          recovery_mutations,secondary_cases,consumed,reordered)
    complete = result['A10_complete'] and cache and not ready and len(verified) == len(known)
    require(progress['status'] != 'COMPLETE' or complete, 'v4 matrix falsely completed progress')
    result.update(schema_version=4,verifier_version=VERSION,status='PASS' if complete else 'NOT_RUN',
        native_acceptance_status='NOT_RUN',A10_complete=bool(complete),
        native_filesystem_fault_matrix_complete=bool(complete),runtime_truth_attested=False,
        catalogue_enrolled=False,legacy_mandatory_slots=0,
        execution_state='COMPLETE' if complete else 'IN_PROGRESS',cache_eviction_verified=cache,
        verified_children=len(verified),verified_primary_recovery_probes=len(recovered),
        required_primary_cases=primary_required,eligible_overwrite_mutations=len(overwrite),
        exact_total_new_children=exact_total,
        remaining_known_children=len(known)-len(verified),
        scope='independently verified full Cartesian coverage' if complete else
              'independently verified incremental coverage; every missing Cartesian obligation remains open')
    return result, ready
