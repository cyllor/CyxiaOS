"""V4 native admission for mode2/3 WRITE/FLUSH matrix cuts.

Frozen v2 protocol primitives are reused without rebinding globals. Its fixed
native admission is never called. This is a partial child, never full A10.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
from check_prototype_evidence import safe_path, sha256, require
from doctor import ROOT
from verify_unified import PINNED_QEMU_COMMIT, PINNED_QEMU_PATCH_SHA256, PATCHED_QEMU_SOURCE_SHA256
from verify_v13_a10_native_receipt import (document, NativeChild, strict_nbd_events,
    qemu_identity, validate_launch, FRAME_LIMIT, SERIAL_LIMIT)
import verify_v13_a10_native_receipt as v1
from verify_v16_a10_write_v2 import (V1_INPUT_GUARD_SHA256, QEMU_ERROR_PATHS,
    capture_limits, read_rows, transactions, Lifecycle)
from v16_a10_cut_protocol_v4 import validate_observations, validate_protocol
from v16_a10_cut_v4 import VERSION, validate_selector, validate_profile, bounded_inventory

def verify_cut_causality(root,context,inputs,protocol,replayed,scope,expected_mutation):
    """Final gate, only AFTER the generic every-byte NBD + FS replay passed."""
    from check_v13_fault_disk import read_events
    validate_selector(expected_mutation)
    validate_profile(inputs)
    trace=replayed['nbd_trace'];actual=trace.get('cut');rows=read_events(root/'nbd')
    require(type(actual) is dict and rows[-1]==actual
        and sum(r['event']=='cut' for r in rows)==1,'v2 lacks unique final actual NBD cut')
    requests=[r for r in rows if r['event']=='request'];acks={r['id'] for r in rows if r['event']=='ack'}
    selected=[r for r in requests if r['id']==actual['id']]
    require(len(selected)==1,'v2 ambiguous selected request');request=selected[0]
    require(request['kind']==expected_mutation['kind'] and request['scope']=='armed'
        and all(request[k]==expected_mutation[k] for k in ('offset','length','data_sha256'))
        and request['mutation']==actual['mutation']==inputs['cut']==expected_mutation['cut']
        and actual['phase']==inputs['phase'],
        'v4 not caller-selected exact reordered matrix mutation')
    completed={r['id'] for r in rows if r['event']=='complete'}
    if inputs['phase']=='before':
        require([r['id'] for r in requests if r['kind']!=2 and r['id'] not in acks]==[request['id']]
            and request['id'] not in completed, 'v4 before cut executed/ACKed selected request')
    else:
        # Reverse replies may ACK the selected request before older requests.
        # The raw disk replay already proves every prior execution and survivor.
        require(request['id'] in completed and request['id'] in acks
            and rows[-2]['event']=='ack' and rows[-2]['id']==request['id'],
            'v4 after-ack cut lacks immediate completed selected ACK')
    ack_order=[r['id'] for r in rows if r['event']=='ack']
    require(trace['reordered_replies'] is any(right<left for left,right in zip(ack_order,ack_order[1:])),
        'v4 actual reordering differs from raw ACK order')
    lifecycle=protocol['lifecycle'];cut=lifecycle['backend-cut'];obs=protocol['transport']
    require(trace['run_id']==cut['run_id']==obs['closed']['run_id']==context['backend_run_id']
        and all(cut[k]==actual[k] for k in ('id','mutation','phase'))
        and inputs['cut'] in scope['post_resume_points']
        and scope['resume_monotonic_ns']<=request['monotonic_ns']<=actual['monotonic_ns']
        <=cut['monotonic_ns']<=obs['closed']['shutdown_begin_ns']
        and cut['seq']<obs['backend_return']['seq']<obs['closed']['seq']<obs['quit']['seq']
        and obs['backend_return']['requests']==len(requests)
        and obs['backend_return']['acks']==len(acks),
        'v2 cut/run/resume/actual disconnect does not close')
    require(len(protocol['fault_io_events'])==len(obs['errors'])
        and [(e['qmp_row'],e['sha256']) for e in protocol['fault_io_events']]
            ==[(e['qmp_row'],e['sha256']) for e in obs['errors']],
        'v2 unmatched error or receive witness')


def tool_closure(source_root=ROOT):
    pending=['verify_v16_a10_cut_v4','run_v16_a10_cut_v4','v16_a10_cut_v4']
    found={}
    while pending:
        name=pending.pop()
        if name in found:continue
        path=safe_path(source_root,'tools/'+name+'.py');found[name]=sha256(path)
        for node in ast.walk(ast.parse(path.read_text())):
            names=([node.module] if isinstance(node,ast.ImportFrom) else [x.name for x in node.names] if isinstance(node,ast.Import) else [])
            for imported in names:
                if imported and (source_root/'tools'/(imported+'.py')).is_file():pending.append(imported)
    return {name+'.py':digest for name,digest in sorted(found.items())}

def verify_native_cut_child(directory, *, source_root, build_manifest, qemu_binary, qemu_source, initial_disk, expected_mutation, expected_mode):
    from build_unified import code_source_map
    from run_v13_a02 import config_write_packet
    from run_v13_a10 import profile, config_bytes, result_scope, validate_build_profile
    from verify_v13_model import loaded_bytes
    from verify_v13_a10_receipt import replay_child, replay_serial, normalized
    from v13_a10_budget import scenario_budget
    require(not Path(directory).is_symlink(), 'native receipt root is a symlink')
    root = Path(directory).resolve(strict=True)
    source_root, build_manifest = Path(source_root).resolve(strict=True), Path(build_manifest).resolve(strict=True)
    context = document(root, 'native-context.json')
    require(context.get('version') == VERSION, 'missing native context version')
    require(sha256(Path(v1.__file__))==V1_INPUT_GUARD_SHA256
        and sha256(source_root/'tools/verify_v13_a10_native_receipt.py')==V1_INPUT_GUARD_SHA256,
        'v2 common v1 input guard changed without explicit version review')
    validate_selector(expected_mutation)
    inputs, binding = document(root, 'input.json'), document(root, 'binding.json')
    require(inputs.get('caller_mutation')==expected_mutation,'v4 frozen input differs from caller WRITE')
    validate_profile(inputs,expected_mode,capture=True)
    require(inputs['cut'] == expected_mutation['cut'] and type(inputs['cut']) is int and inputs['cut'] > 0, 'v2 caller cut mismatch')
    require(not Path(initial_disk).is_symlink() and Path(initial_disk).is_file()
        and Path(initial_disk).stat().st_nlink==1 and Path(initial_disk).stat().st_size==512*1024**2
        and sha256(Path(initial_disk)) == inputs['initial_disk_sha256'], 'v2 caller immutable parent mismatch')
    require(context['capture_root']==str(root) and context['initial_source']==str(Path(initial_disk).resolve(strict=True)),
        'v4 caller parent/capture path mismatch')
    disk_paths=[Path(initial_disk),safe_path(root,'initial.raw'),safe_path(root,'disk.raw')]
    require(len({(path.stat().st_dev,path.stat().st_ino) for path in disk_paths})==3,
        'v4 parent/initial/backing disk aliases')
    budget = scenario_budget(source_root, inputs['mode'])
    require(inputs['capture_timeout_seconds'] <= budget['capture_timeout_seconds']
            and all(inputs[key] == budget[key] for key in
                    ('client_deadline_ns', 'capture_margin_ns', 'client_poll_ns')),
            'native source-bound budget mismatch')
    sources = code_source_map(source_root)
    build = document(build_manifest.parent, build_manifest.name)
    validate_build_profile(build)
    require(build['profiles'].get('service_fault') == 'none'
            and build['code_source_map'] == sources == document(root, 'source-manifest.json')
            and build['code_source_sha256'] == hashlib.sha256(json.dumps(sources,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            and build['builder_sha256'] == sha256(source_root / 'tools/build_unified.py')
            and sha256(build_manifest) == sha256(safe_path(root, 'build-manifest.json')),
            'native caller source/build mismatch')
    require({'cargo', 'rustc', 'clang', 'installed_targets', 'llvm_objdump'} <= build['tools'].keys()
            and build.get('commands'), 'missing native build provenance')
    for name in ('node-a.elf', 'service-a.elf', 'task.elf'):
        require(sha256(safe_path(root, name)) == sha256(safe_path(build_manifest.parent, name))
                == build['artifacts'][name]['sha256'], 'native caller image mismatch: ' + name)
    closure = tool_closure()
    require(document(root, 'native-tools.json') == closure == tool_closure(source_root),
            'native reviewed tool closure mismatch')
    for name, digest in closure.items():
        require(sha256(safe_path(root, 'native-tools/' + name)) == digest,
                'native archived tool changed: ' + name)
    build_inputs = ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                    'crates/prototype/src/features.rs', 'crates/prototype/src/policy_wire.rs')
    for name in build_inputs:
        require(sha256(safe_path(root, 'build-inputs/' + name)) == sha256(safe_path(source_root, name)),
                'native build input mismatch: ' + name)
    identity = qemu_identity(qemu_binary, qemu_source)
    require(all(sha256(Path(qemu_source)/name)==digest for name,digest in QEMU_ERROR_PATHS.items()),
            'v2 pinned QEMU error-path source mismatch')
    require(document(root, 'qemu-source.json') == identity
            and context['binary'] == str(Path(qemu_binary).resolve(strict=True))
            and context['binary_sha256'] == identity['binary_sha256'], 'native caller QEMU mismatch')
    tools = document(root, 'tools.json')
    require(safe_path(root, 'qemu-version.txt').stat().st_size <= FRAME_LIMIT,
            'native QEMU version output bound')
    require(tools['qemu_sha256'] == identity['binary_sha256']
            and tools['qemu_version'] == safe_path(root, 'qemu-version.txt').read_text()
            and tools['qemu_version'].splitlines()[0] == 'QEMU emulator version 10.2.2 (v10.2.2-dirty)'
            and tools['qemu_source_commit'] == PINNED_QEMU_COMMIT
            and tools['qemu_source_sha256'] == PATCHED_QEMU_SOURCE_SHA256
            and tools['qemu_patch_sha256'] == PINNED_QEMU_PATCH_SHA256
            and tools['qemu_pmu_patch_attested'] is True, 'native QEMU capture identity mismatch')
    image = safe_path(root, 'node-a.elf').read_bytes()
    layout = profile(image)
    for name, size in (('config.bin', 512), ('config-observed.bin', 512),
                       ('model.bin', layout['model']['size'])):
        require(safe_path(root, name).stat().st_size == size, 'native preboot file size: ' + name)
    launch = document(root, 'launch.json')
    require(launch['symbols'] == normalized(layout), 'native ELF-derived symbols mismatch')
    validate_launch(launch['argv'], context, inputs)
    config = config_bytes(binding)
    injection = document(root, 'config-injection.json')
    require(injection == dict(request_hex=config_write_packet(config, layout['config']['pa']).hex(),
                             received_hex='2b244f4b233961', ack_hex='2b')
            and safe_path(root, 'config.bin').read_bytes()
            == safe_path(root, 'config-observed.bin').read_bytes() == config,
            'native exact preboot packet/ACK/OK/readback mismatch')
    model = layout['model']
    require(safe_path(root, 'model.bin').read_bytes() == loaded_bytes(image, model['va'], model['size']),
            'native linked model mismatch')
    nbd = document(root, 'nbd/start.json')
    require(all(safe_path(root, name).stat().st_nlink == 1 for name in ('initial.raw', 'disk.raw')),
            'native mutable backing/initial disk has a shared hardlink')
    require(context['backend_run_id'] == nbd['run_id']
            and re.fullmatch('[0-9a-f]{32}', nbd['run_id']) and int(nbd['run_id'], 16)
            and context['backing_path'] == context['capture_root'] + '/disk.raw'
            and context['backing_sha256'] == nbd['disk_initial_sha256']
                == inputs['initial_disk_sha256'] == sha256(safe_path(root, 'initial.raw'))
            and context['backing_size'] == nbd['size'] == 512 * 1024**2
            and nbd['max_pending_sectors'] == 32768
            and nbd.get('event_clock') == 'host-monotonic-ns-v1'
            and nbd['reverse_replies'] is inputs['reverse_replies'], 'native endpoint/backing lineage mismatch')
    protocol = validate_protocol(root, context, layout, inputs,
        read_rows(safe_path(root, 'qmp.jsonl'), inputs),
        read_rows(safe_path(root, 'native-provenance.jsonl'), inputs))
    def one(event):
        require(event in protocol['lifecycle'], 'missing native lifecycle: ' + event)
        return protocol['lifecycle'][event]
    require(one('final-disk')['sha256'] == sha256(safe_path(root, 'disk.raw')),
            'native final disk hash differs after backend close')
    snapshot = document(root, 'native-identity.json')
    expected = dict(source_sha256=binding['source_sha256'], build_sha256=sha256(build_manifest),
                    input_sha256=binding['input_sha256'], initial_sha256=context['backing_sha256'],
                    image_sha256=binding['image_sha256'], qemu=identity, tools=closure)
    require(snapshot == expected and one('identity-before')['identity'] == snapshot
            == one('identity-after')['identity'] and one('identity-before')['seq'] == 1
            and one('identity-after')['seq'] == protocol['witness_count'], 'native before/after identity mismatch')
    opened, created, connected, spawned = (one(event) for event in
        ('backend-open', 'endpoint-created', 'endpoint-connected', 'spawn'))
    require(opened['run_id'] == created['run_id'] == connected['run_id'] == nbd['run_id']
            and opened['path'] == context['backing_path']
            and opened['sha256'] == context['backing_sha256'] and opened['size'] == context['backing_size']
            and created['endpoint'] == connected['endpoint'] == context['endpoints']['nbd']
            and opened['seq'] < created['seq'] < spawned['seq']
            and created['seq'] < connected['seq'] < one('wait')['seq'],
            'native backend endpoint lifecycle mismatch')
    if context['host_platform'] in ('darwin', 'linux'):
        require(type(connected['peer_pid']) is int and connected['peer_pid'] == context['pid']
                and connected['peer_identity'] == 'kernel-pid', 'native NBD peer is not the spawned QEMU')
    else:
        require(connected['peer_pid'] is None
                and connected['peer_identity'] == 'private-directory-one-connection-unsupported',
                'invalid unsupported-host peer identity boundary')
    required = {'initial.raw', 'disk.raw', 'binding.json', 'input.json', 'build-manifest.json',
                'source-manifest.json', 'node-a.elf', 'service-a.elf', 'task.elf', 'config.bin',
                'config-injection.json', 'model.bin', 'launch.json', 'platform.json', 'tools.json',
                'qmp.jsonl', 'serial.bin', 'serial.txt', 'qemu-stderr.log', 'disk-before.json',
                'disk-after.json', 'native-context.json', 'native-provenance.jsonl',
                'native-identity.json', 'native-tools.json', 'qemu-source.json', 'qemu-version.txt',
                'nbd/start.json', 'nbd/capture.json', 'nbd/events.jsonl.gz', 'nbd/requests.bin.gz', 'qmp-wire.bin'}
    from run_v16_a10_cut_v4 import TOOL_NAMES
    required |= protocol['capture_names'] | {'tools/' + name for name in TOOL_NAMES}
    required |= {'native-tools/' + name for name in closure}
    required |= {'build-inputs/' + name for name in build_inputs}
    summary = document(root, 'summary.json')
    actual_names = {path.relative_to(root).as_posix()
        for path,_ in bounded_inventory(root,allowed_files=required|{'summary.json'})}
    require(set(summary['artifacts']) == required and actual_names == required | {'summary.json'},
            'native inventory missing/extra file')
    require(safe_path(root, 'serial.txt').stat().st_size <= SERIAL_LIMIT,
            'native decoded serial limit')
    strict_nbd_events(root)
    matrix = dict(build_manifest_sha256=sha256(build_manifest), source_manifest_sha256=binding['source_sha256'],
                  filesystem_uuid=binding['uuid'])
    replayed = replay_child(root, matrix)
    from v13_a10_fault_scope import mutation_scope, require_post_resume_cut
    scope = (require_post_resume_cut(root, inputs['cut']) if inputs['cut']
             else mutation_scope(root))
    require(replayed.get('mutation_scope') == scope,
            'native producer mutation scope differs from lifecycle evidence')
    replay_serial(root, complete=not protocol['cut_observed'])
    if protocol['cut_observed']:
        actual = replayed['nbd_trace']['cut']
        require(all(one('backend-cut')[key] == actual[key] for key in ('id', 'mutation', 'phase')),
                'native cut witness differs from actual NBD stream')
    # Only now has replay_child independently rebuilt every NBD request,
    # loss/survivor and final disk byte, plus the committed filesystem oracle.
    # A collected QMP event is never sufficient before that closure completes.
    verify_cut_causality(root, context, inputs, protocol, replayed, scope, expected_mutation)
    control = safe_path(root, 'control-header.bin').read_bytes()
    magic = struct.unpack_from('<Q', control)[0]
    # initialize() publishes this aligned atomic magic last, after both hashes.
    # An earlier cut can retain an unpublished diagnostic prefix.
    require(magic in (0, 0x435958444f4d3031)
            and (protocol['cut_observed'] or magic != 0), 'native control publication mismatch')
    if magic:
        require(struct.unpack_from('<Q', control, 16)[0] == binding['boot_epoch']
                and control[128:160].hex() == sha256(safe_path(root, 'model.bin'))
                and control[160:192].hex() == sources['crates/prototype/src/features.rs'],
                'native model/schema/BootEpoch capture mismatch')
    classification = dict(result_scope(protocol['cut_observed']),
        status='NOT_RUN' if protocol['cut_observed'] else 'PASS',
        cut_observed=protocol['cut_observed'], native_mode_verified=not protocol['cut_observed'],
        capture_status='FAULT_CAPTURED' if protocol['cut_observed'] else 'VERIFIED')
    require(all(type(replayed.get(key)) is type(value) and replayed[key] == value
                for key, value in classification.items()),
            'native producer summary classification/scope differs')
    derived = dict(replayed, **classification)
    derived.update(native_matrix_cut_custody_verified=True, native_execution_verified=True,
                   native_filesystem_fault_matrix_complete=False, native_acceptance_status='NOT_RUN')
    return NativeChild(derived, inputs, context, binding['nonce'])


def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence',type=Path)
    for name in ('source-root','build-manifest','qemu-binary','qemu-source','initial-disk'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--mode',type=int,choices=(2,3),required=True)
    for name in ('cut','kind','write-offset','write-length'):p.add_argument('--'+name,type=int,required=True)
    p.add_argument('--write-sha256',required=True)
    a=p.parse_args()
    checked=verify_native_cut_child(a.evidence,source_root=a.source_root,
        build_manifest=a.build_manifest,qemu_binary=a.qemu_binary,qemu_source=a.qemu_source,
        initial_disk=a.initial_disk,expected_mode=a.mode,
        expected_mutation=dict(cut=a.cut,kind=a.kind,offset=a.write_offset,length=a.write_length,data_sha256=a.write_sha256))
    print(json.dumps(dict(status='VERIFIED_NATIVE_REORDERED_WRITE_CUT',
        native_acceptance_status='NOT_RUN',A10_complete=False,summary=checked.summary),indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
