"""Versioned A10 native WRITE-cut custody. v1 is neither edited nor relaxed.

Only caller-selected mode3/nonreordered/before-WRITE cuts can enter. All
common native identity, launch, DTB, protected injection, inventory, raw NBD
and filesystem checks below are retained from the fixed v1 implementation.
The separate v2 protocol additionally requires real owned close, complete
raw QMP receive stream through normal quit/EOF/wait0 and syscall timestamps.
No complete-A10 catalogue PASS is granted by this child verifier.
"""
from __future__ import annotations
import ast
import base64
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from check_prototype_evidence import _pairs, safe_path, sha256, read_json, require
from doctor import ROOT
from transport import FrameDecoder
from verify_unified import PINNED_QEMU_COMMIT, PINNED_QEMU_PATCH_SHA256, PATCHED_QEMU_SOURCE_SHA256
from verify_v13_a10_native_receipt import (document, finite_tree, validate_dtb, validate_launch,
    qemu_identity, strict_nbd_events, NativeChild, Forward, status, poll_bound, read_rows,
    FRAME_LIMIT, SERIAL_LIMIT)
from v16_a10_write_v2 import VERSION, MAX_ERRORS, MAX_WIRE, typed_error, canonical
from run_v13_a10 import PENDING_DIAGNOSTICS, terminal_ready
import verify_v13_a10_native_receipt as v1

# The shared guards below are a static versioned copy, not rebound globals.
# A later v1 guard change needs explicit AST-equivalence review before v2 can
# consume it; transitive fixed helpers remain normal caller-local imports.
V1_INPUT_GUARD_SHA256='2e03caf4be43d0f7ad5f3597f89ab47cde1aad36680031b73f8cdd8e3968f527'

QEMU_ERROR_PATHS={
    'hw/block/virtio-blk.c':'6dfeb198cdbc4d717d4361689f21ac960e5e73baa05bc2e27c733e7ad15c2840',
    'block/block-backend.c':'f2abf4f9055688976e3dd5e378512e53a78b72ad76e5b4f3d3116e8591946859',
    'block/nbd.c':'0e7ba3dd33e33610255f40ba6b73b421a4d8457cfa52746198b19759b3019c7f',
}


def capture_limits(inputs):
    limits=v1.capture_limits(inputs)
    # Each actual recv chunk and parsed message has a separate observation.
    # This versions the byte/row resource envelope, never the guest budget.
    limits['witness_rows']=limits['commands']*8+128
    return limits


def read_rows(path,inputs):
    limits=capture_limits(inputs)
    require(path.stat().st_size<=limits['bytes'],'v2 transcript byte bound')
    with path.open('rb') as stream:
        for index,line in enumerate(stream,1):
            require(index<=limits['witness_rows'] and len(line)<=FRAME_LIMIT and line.endswith(b'\n'),
                    'v2 witness/frame bound')
            value=finite_tree(json.loads(line,object_pairs_hook=_pairs,
                parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite v2 JSON'))),integer_only=True)
            require(type(value) is dict,'v2 transcript object required')
            yield value


def transactions(rows,limit,events,*,fault_events):
    iterator=iter(rows);first=next(iterator,{})
    require(first.keys()=={'direction','message'} and first['direction']=='receive'
            and first['message'].keys()=={'QMP'},'missing v2 greeting')
    hello=first['message']['QMP']
    require(hello=={'version':{'qemu':{'major':10,'minor':2,'micro':2},'package':'v10.2.2-dirty'},
                   'capabilities':hello.get('capabilities')}
            and hello['capabilities'] in ([],['oob']),'wrong v2 pinned QMP greeting')
    pending=last=None;count=0
    for number,row in enumerate(iterator,2):
        require(type(row) is dict and row.keys()=={'direction','message'}
                and type(row['message']) is dict,'invalid v2 QMP row')
        message=row['message']
        if row['direction']=='send':
            require(pending is None and message.keys() in ({'execute','id'},{'execute','id','arguments'})
                    and type(message['id']) is int and message['id']==count+1 and count<limit,
                    'unordered v2 QMP request')
            pending=message
        elif row['direction']=='receive' and 'event' in message:
            event=message['event']
            if event=='BLOCK_IO_ERROR':
                require(events and events[0]=='RESUME' and typed_error(message)
                        and len(fault_events)<MAX_ERRORS,'untyped/unbounded v2 block event')
                fault_events.append(dict(qmp_row=number,sha256=canonical(message)))
                continue
            expected={'RESUME':('cont',[]),'STOP':('stop',['RESUME']),
                      'SHUTDOWN':('quit',['RESUME','STOP'])}
            require(event in expected,'unknown v2 asynchronous event')
            command,prior=expected[event];transition=pending or last
            require(events==prior and transition is not None and transition['execute']==command,
                    'v2 lifecycle event outside exact transition')
            require(type(message.get('timestamp')) is dict
                    and set(message['timestamp'])=={'seconds','microseconds'}
                    and all(type(x) is int and x>=0 for x in message['timestamp'].values())
                    and message['timestamp']['microseconds']<1000000,'invalid v2 event timestamp')
            if event=='SHUTDOWN':
                require(message.keys()=={'event','timestamp','data'}
                        and message['data']=={'guest':False,'reason':'host-qmp-quit'}
                        and message['data']['guest'] is False,'v2 requires host-qmp-quit shutdown')
            else:require(message.keys()=={'event','timestamp'},'v2 lifecycle extra fields')
            events.append(event)
        else:
            require(row['direction']=='receive' and pending is not None
                    and message.keys()=={'return','id'} and type(message['id']) is int
                    and message['id']==pending['id'],'orphan/failed v2 QMP reply')
            count+=1;last=pending;pending=None
            yield last,message['return']
    require(pending is None,'unanswered v2 QMP request')


class Lifecycle(v1.Lifecycle):
    EXTRA={
        'qmp-connected':{'peer_pid','endpoint','fd'},
        'qmp-observed':{'direction','qmp_row','sha256','append_entry_ns','recv_return_ns','parse_complete_ns'},
        'qmp-recv-chunk':{'offset','length','sha256','recv_begin_ns','recv_return_ns'},
        'qmp-eof':{'peer_pid','recv_begin_ns','recv_return_ns','wire_bytes','wire_sha256','buffer_bytes','fd'},
        'nbd-close-intent':{'fd','run_id','endpoint','peer_pid'},
        'nbd-backend-return':{'run_id','disk_closed','events_closed','wire_closed','requests','acks'},
        'nbd-close-complete':{'fd','fd_after','run_id','endpoint','peer_pid','shutdown_begin_ns',
            'shutdown_end_ns','close_begin_ns','close_end_ns','shutdown_errno','close_errno'},
        'wait-observed':{'pid','begin_ns','return_ns'},
    }
    FIELDS={**v1.Lifecycle.FIELDS,**EXTRA}

    def __init__(self,rows):
        super().__init__(rows);self.auxiliary={name:[] for name in self.EXTRA}

    def take(self,expected):
        for row in self.rows:
            self.count+=1
            require(type(row) is dict and type(row.get('seq')) is int and row['seq']==self.count
                and type(row.get('monotonic_ns')) is int and row['monotonic_ns']>=self.previous,
                'unordered v2 shared witness')
            self.previous=row['monotonic_ns'];kind=row.get('event')
            require(kind in self.FIELDS and row.keys()=={'seq','monotonic_ns','event'}|self.FIELDS[kind],
                    'unknown v2 witness fields/event')
            if kind in self.EXTRA:
                self.auxiliary[kind].append(row);continue
            if kind in ('qmp-request','qmp-response','save'):
                require(kind==expected,'v2 command/save witness order');return row
            require(kind!='qmp-block-error' and kind not in self.events,'v2 duplicate/v1-only lifecycle event')
            self.events[kind]=row
        require(expected is None,'missing v2 lifecycle '+str(expected))


def validate_observations(root,context,rows,lifecycle):
    aux=lifecycle.auxiliary
    def one(name):
        require(len(aux[name])==1,'missing/duplicate v2 '+name);return aux[name][0]
    connected,eof,closed,intent,wait,backend_return=(one(n) for n in
        ('qmp-connected','qmp-eof','nbd-close-complete','nbd-close-intent','wait-observed','nbd-backend-return'))
    require(connected['peer_pid']==eof['peer_pid']==wait['pid']==context['pid']
        and connected['endpoint']==context['endpoints']['qmp']
        and type(connected['fd']) is int and connected['fd']>=0 and eof['fd']==connected['fd'],
        'v2 QMP kernel peer/connection identity mismatch')
    require(all(closed[k]==intent[k] for k in ('fd','run_id','endpoint','peer_pid'))
        and closed['run_id']==context['backend_run_id'] and closed['endpoint']==context['endpoints']['nbd']
        and closed['peer_pid']==context['pid'] and closed['fd']>=0 and closed['fd']!=connected['fd']
        and closed['fd_after']==-1 and closed['shutdown_errno'] is closed['close_errno'] is None,
        'v2 actual owned NBD close mismatch')
    require(all(type(closed[k]) is int and closed[k]>=0 for k in
        ('fd','shutdown_begin_ns','shutdown_end_ns','close_begin_ns','close_end_ns'))
        and type(closed['fd_after']) is int, 'v2 close syscall numeric types')
    require(intent['seq']<closed['seq'] and intent['monotonic_ns']<=closed['shutdown_begin_ns']
        <=closed['shutdown_end_ns']<=closed['close_begin_ns']<=closed['close_end_ns']
        <=closed['monotonic_ns'],'v2 close syscall chronology')
    require(backend_return['run_id']==closed['run_id'] and backend_return['disk_closed'] is True
        and backend_return['events_closed'] is True and backend_return['wire_closed'] is True
        and backend_return['seq']<intent['seq']
        and backend_return['monotonic_ns']<=closed['shutdown_begin_ns'],
        'v2 backend files were not closed before transport shutdown')
    path=safe_path(root,'qmp-wire.bin')
    require(path.stat().st_size<=MAX_WIRE,'v2 raw QMP wire bound')
    wire=path.read_bytes();offset=0;buffer=b'';decoded=[];previous_return=0
    for chunk in aux['qmp-recv-chunk']:
        length=chunk['length']
        require(type(length) is int and 0<length<=65536 and chunk['offset']==offset
            and offset+length<=len(wire) and chunk['sha256']==hashlib.sha256(wire[offset:offset+length]).hexdigest()
            and previous_return<=chunk['recv_begin_ns']<=chunk['recv_return_ns']<=chunk['monotonic_ns']
            and type(chunk['recv_begin_ns']) is type(chunk['recv_return_ns']) is int
            and connected['seq']<chunk['seq']<eof['seq'],
            'v2 actual receive chunk/clock mismatch')
        previous_return=chunk['recv_return_ns']
        buffer+=wire[offset:offset+length];offset+=length
        while b'\n' in buffer:
            line,buffer=buffer.split(b'\n',1)
            if not line.strip():continue
            value=finite_tree(json.loads(line,object_pairs_hook=_pairs),integer_only=True)
            require(type(value) is dict,'v2 wire JSON object required')
            decoded.append((value,chunk['recv_return_ns']))
    require(not buffer and offset==len(wire)==eof['wire_bytes'] and eof['buffer_bytes']==0
        and eof['wire_sha256']==hashlib.sha256(wire).hexdigest()
        and previous_return<=eof['recv_begin_ns']<=eof['recv_return_ns']<=eof['monotonic_ns']
        and type(eof['recv_begin_ns']) is type(eof['recv_return_ns']) is int,
        'v2 missing/truncated actual QMP EOF')
    observations=aux['qmp-observed'];require(len(observations)==len(rows),'v2 unobserved raw QMP row')
    incoming=iter(decoded);errors=[];quit_row=None;quit_receive=None
    for number,(row,observed) in enumerate(zip(rows,observations),1):
        direction,message=row['direction'],row['message']
        require(observed['qmp_row']==number and observed['direction']==direction
            and observed['sha256']==canonical(message)
            and observed['append_entry_ns']<=observed['monotonic_ns']
            and connected['seq']<observed['seq']<eof['seq'],'v2 message/observation identity')
        if direction=='receive':
            actual,returned=next(incoming,(None,None))
            require(actual==message and returned==observed['recv_return_ns']
                and 0<returned<=observed['parse_complete_ns']<=observed['append_entry_ns'],
                'v2 actual recv/parse time or full wire differs')
            if message.get('event')=='BLOCK_IO_ERROR':errors.append(observed)
            if 'id' in message and quit_row is not None and message['id']==quit_row['message']['id']:
                quit_receive=observed
        else:
            require(observed['recv_return_ns'] is observed['parse_complete_ns'] is None,
                    'v2 send pretends to be socket receive')
            if message['execute']=='quit':quit_row=dict(message=message,observation=observed)
    require(next(incoming,None) is None and quit_row is not None and quit_receive is not None,
            'v2 dropped wire message or missing quit reply')
    require(closed['close_end_ns']<=quit_row['observation']['append_entry_ns']
        and closed['seq']<quit_row['observation']['seq']<eof['seq']<wait['seq']
        and quit_receive['parse_complete_ns']<=eof['recv_return_ns']<=wait['begin_ns']
        <=wait['return_ns']<=wait['monotonic_ns'],'v2 quit/EOF/owned wait chronology')
    require(1<=len(errors)<=MAX_ERRORS,'v2 missing/overflow error burst')
    require(all(closed['shutdown_begin_ns']<=e['recv_return_ns']<=eof['recv_return_ns'] for e in errors),
            'v2 event actual receive precedes close or follows EOF')
    return dict(errors=errors,closed=closed,eof=eof,quit=quit_row['observation'],wait=wait,backend_return=backend_return,
                complete_received_wire_verified=True)


def verify_write_cut_causality(root,context,inputs,protocol,replayed,scope,expected_write):
    """Final gate, only AFTER the generic every-byte NBD + FS replay passed."""
    from check_v13_fault_disk import read_events
    require(inputs['mode']==3 and inputs['phase']=='before' and inputs['reverse_replies'] is False
        and type(inputs['cut']) is int and inputs['cut']>0,'v2 unsupported causal profile')
    trace=replayed['nbd_trace'];actual=trace.get('cut');rows=read_events(root/'nbd')
    require(type(actual) is dict and rows[-1]==actual
        and sum(r['event']=='cut' for r in rows)==1,'v2 lacks unique final actual NBD cut')
    requests=[r for r in rows if r['event']=='request'];acks={r['id'] for r in rows if r['event']=='ack'}
    selected=[r for r in requests if r['id']==actual['id']]
    require(len(selected)==1,'v2 ambiguous selected request');request=selected[0]
    require(request['kind']==1 and request['scope']=='armed'
        and all(request[k]==expected_write[k] for k in ('offset','length','data_sha256'))
        and request['mutation']==actual['mutation']==inputs['cut']==expected_write['cut']
        and actual['phase']=='before' and trace['reordered_replies'] is False,
        'v2 not caller-selected exact nonreordered before-WRITE')
    require([r['id'] for r in requests if r['kind']!=2 and r['id'] not in acks]==[request['id']]
        and not any(r['event']=='complete' and r['id']==request['id'] for r in rows),
        'v2 WRITE was completed/ACKed or another request is outstanding')
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
    pending=['verify_v16_a10_write_v2','run_v16_a10_write_v2','v16_a10_write_v2']
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

def verify_native_write_child(directory, *, source_root, build_manifest, qemu_binary, qemu_source, initial_disk, expected_write):
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
    require(type(expected_write) is dict and expected_write.keys()=={'cut','offset','length','data_sha256'}
        and all(type(expected_write[k]) is int for k in ('cut','offset','length'))
        and expected_write['cut']>0 and expected_write['offset']>=0 and expected_write['offset']%512==0
        and 0<expected_write['length']<=1024**2 and expected_write['length']%512==0
        and expected_write['offset']+expected_write['length']<=512*1024**2
        and type(expected_write['data_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}',expected_write['data_sha256']), 'v2 invalid explicit caller WRITE selector')
    inputs, binding = document(root, 'input.json'), document(root, 'binding.json')
    require(inputs.get('caller_write')==expected_write,'v2 frozen input differs from caller WRITE')
    require(inputs['mode'] == 3 and inputs['phase'] == 'before' and inputs['unflushed'] == 'reverse-half'
            and inputs['reverse_replies'] is False and inputs['sample_ms'] == 30000
            and inputs['capture_timeout_seconds'] == 1920, 'v2 fixed WRITE-recut profile mismatch')
    require(inputs['cut'] == expected_write['cut'] and type(inputs['cut']) is int and inputs['cut'] > 0, 'v2 caller cut mismatch')
    require(not Path(initial_disk).is_symlink() and Path(initial_disk).is_file()
        and Path(initial_disk).stat().st_nlink==1 and Path(initial_disk).stat().st_size==512*1024**2
        and sha256(Path(initial_disk)) == inputs['initial_disk_sha256'], 'v2 caller immutable parent mismatch')
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
    from run_v16_a10_write_v2 import TOOL_NAMES
    required |= protocol['capture_names'] | {'tools/' + name for name in TOOL_NAMES}
    required |= {'native-tools/' + name for name in closure}
    required |= {'build-inputs/' + name for name in build_inputs}
    summary = document(root, 'summary.json')
    actual_names = set()
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'native inventory contains a symlink')
        require(path.is_dir() or path.is_file(), 'native inventory contains a special file')
        if path.is_file():
            name = path.relative_to(root).as_posix()
            require(name in required | {'summary.json'}, 'extra native inventory file: ' + name)
            actual_names.add(name)
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
    verify_write_cut_causality(root, context, inputs, protocol, replayed, scope, expected_write)
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
    derived.update(native_write_cut_custody_verified=True, native_execution_verified=True,
                   native_filesystem_fault_matrix_complete=False, native_acceptance_status='NOT_RUN')
    return NativeChild(derived, inputs, context, binding['nonce'])


def validate_protocol(root, context, layout, inputs, rows, witness):
    """Validate a capture protocol; this alone never grants native admission."""
    require(context['host_platform'] == sys.platform,
            'native host platform differs from trusted local context')
    require(safe_path(root, 'serial.bin').stat().st_size <= SERIAL_LIMIT,
            'native encoded serial size bound')
    rows = list(rows)
    events, fault_io_events = [], []
    require(type(inputs['cut']) is int and inputs['cut'] >= 0, 'invalid native cut ordinal')
    cut = inputs['cut'] > 0
    commands = Forward(transactions(rows, poll_bound(inputs) * 5 + 64, events,
                                   fault_events=fault_io_events if cut else None))
    require(type(context['capture_root']) is str and len(json.dumps(context['capture_root'])) <= 1024
            and Path(context['capture_root']).is_absolute(), 'invalid historic capture root')
    lifecycle = Lifecycle(witness)
    one = lifecycle.one
    latest = {}
    index = last_response = resume_request = 0
    injection_bounds = []
    stop_request = None
    def take(name, args=None):
        nonlocal index, last_response, resume_request, stop_request
        require(commands.current is not None, 'missing QMP command: ' + name)
        command, result = commands.pop()
        index += 1
        require(command['execute'] == name and command.get('arguments') == args
                and (args is None or all(type(command['arguments'][key]) is type(value)
                                        for key, value in args.items())),
                'unexpected QMP command/arguments: ' + name)
        request = lifecycle.take('qmp-request')
        response = lifecycle.take('qmp-response')
        require(request['id'] == response['id'] == index
                and one('spawn')['seq'] < request['seq'] < response['seq']
                and 'kill' not in lifecycle.events, 'QMP witness identity/order mismatch')
        if name == 'stop':
            stop_request = request
            require('backend-cut' in lifecycle.events
                    and one('backend-cut')['seq'] < request['seq'], 'cut observation must precede stop')
        if name == 'cont':
            resume_request = request['seq']
        if name == 'pmemsave' and args['filename'].endswith('/config-observed.bin'):
            injection_bounds.extend((last_response, request['seq']))
        last_response = response['seq']
        return command, result
    def empty(name):
        command, result = take(name)
        require(result == {}, 'nonempty QMP transition reply')
        return command
    def save(name, address, size):
        command, result = take('pmemsave', dict(val=address, size=size,
            filename=str(Path(context['capture_root']) / name)))
        require(result == {}, 'failed native save')
        row = lifecycle.take('save')
        require(row is not None and row.keys() ==
                {'seq', 'monotonic_ns', 'event', 'id', 'name', 'size', 'sha256'}
                and row['id'] == command['id'] and row['name'] == name and row['size'] == size
                and last_response < row['seq'] and 'kill' not in lifecycle.events,
                'save witness missing or out of order')
        latest[name] = row
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
                and safe_path(root, name).stat().st_size == size, 'invalid native save hash/size')
    empty('qmp_capabilities')
    status(take('query-status')[1], 'prelaunch')
    cpus = take('query-cpus-fast')[1]
    memory = take('query-memory-size-summary')[1]
    # Pinned QEMU qemu_get_thread_id() uses getpid() on Darwin. The PID is
    # also bound below to spawn/kill/wait and by the caller to the NBD peer.
    require(type(cpus) is list and len(cpus) == 4
            and [cpu.get('cpu-index') for cpu in cpus] == list(range(4))
            and all(cpu.keys() == {'cpu-index', 'thread-id', 'qom-path', 'qom-type', 'props', 'target'}
                    and cpu.get('target') == 'aarch64' and type(cpu.get('cpu-index')) is int
                    and cpu['qom-type'] == 'cortex-a53-arm-cpu'
                    and cpu['props'] == {'socket-id': 0, 'cluster-id': 0, 'core-id': index, 'thread-id': 0}
                    and all(type(value) is int for value in cpu['props'].values())
                    and type(cpu.get('thread-id')) is int and cpu['thread-id'] > 0
                    and cpu.get('qom-path') == f'/machine/unattached/device[{index}]'
                    for index, cpu in enumerate(cpus))
            and (all(cpu['thread-id'] == context['pid'] for cpu in cpus) if sys.platform == 'darwin'
                 else len({cpu['thread-id'] for cpu in cpus}) == 4)
            and type(memory) is dict and all(type(value) is int for value in memory.values())
            and memory == {'base-memory': 1024**3, 'plugged-memory': 0}, 'wrong QMP platform')
    require(read_json(safe_path(root, 'platform.json')) == dict(cpus=cpus, memory=memory),
            'captured platform differs from QMP')
    save('dtb-header.bin', 0x40000000, 40)
    header = safe_path(root, 'dtb-header.bin').read_bytes()
    require(len(header) == 40, 'short DTB header')
    magic, length = struct.unpack_from('>2I', header)
    require(magic == 0xd00dfeed and 40 <= length <= 2 * 1024 * 1024, 'invalid DTB bounds')
    save('platform.dtb', 0x40000000, length)
    require(safe_path(root, 'platform.dtb').read_bytes()[:40] == header, 'DTB header differs')
    validate_dtb(safe_path(root, 'platform.dtb').read_bytes())
    save('config-observed.bin', layout['config']['pa'], 512)
    require(injection_bounds[0] < one('injection')['seq'] < injection_bounds[1],
            'injection was not before config readback/resume')
    empty('cont')
    status(take('query-status')[1], 'running')
    serial = bytearray()
    decoder = FrameDecoder()
    def read_serial():
        encoded = take('ringbuf-read', dict(device='cyxlog', size=1048576, format='base64'))[1]
        require(type(encoded) is str and len(encoded) <= 1398104, 'oversized ringbuf reply')
        chunk = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(chunk).decode() == encoded
                and len(chunk) <= 1048576 and len(serial) + len(chunk) <= SERIAL_LIMIT,
                'native serial capture limit')
        serial.extend(chunk)
        decoder.feed(chunk)
        return not chunk and not decoder.buffer
    polls = 0
    while commands.current is not None and commands.current[0]['execute'] == 'ringbuf-read':
        polls += 1
        require(polls <= poll_bound(inputs), 'excessive native polls')
        read_serial()
        if cut and commands.current is not None and commands.current[0]['execute'] == 'stop':
            break
        save('pending-progress.bin', layout['progress']['pa'], 512)
        for name in PENDING_DIAGNOSTICS:
            location = layout['diagnostics'][name]
            save('pending-' + name + '.bin', location['pa'], location['size'])
    require(polls > 0, 'missing native polling')
    if cut:
        empty('stop')
        observed = one('backend-cut')
        require(resume_request < observed['seq']
                and observed['run_id'] == context['backend_run_id']
                and observed['mutation'] == inputs['cut'] and observed['phase'] == inputs['phase'],
                'cut observation differs from policy')
        status(take('query-status')[1], 'paused')
    else:
        require('backend-cut' not in lifecycle.events, 'clean protocol contains a cut')
        require(terminal_ready(safe_path(root, 'pending-progress.bin').read_bytes(), inputs['mode']),
                'terminal poll lacks actual selected role exits')
    for name, key in (('trace', 'capture'), ('progress', 'progress'), ('consumption', 'consumption')):
        location = layout[key]
        save(name + '.bin', location['pa'], location['size'])
    for name, location in layout['diagnostics'].items():
        save(name + '.bin', location['pa'], location['size'])
    if not cut:
        for name, key in (('trace', 'capture'), ('progress', 'progress'), ('consumption', 'consumption')):
            location = layout[key]
            save(name + '-confirm.bin', location['pa'], location['size'])
            require(safe_path(root, name + '.bin').read_bytes()
                    == safe_path(root, name + '-confirm.bin').read_bytes(),
                    'live terminal confirmation differs: ' + name)
        drains, drained = 0, False
        while commands.current is not None and commands.current[0]['execute'] == 'ringbuf-read':
            drains += 1
            require(drains <= 8 and not drained, 'excessive terminal serial drains')
            drained = read_serial()
        require(drained and decoder.loss == decoder.corrupt == 0 and not decoder.buffer,
                'terminal serial drain exhausted/nonempty or damaged/trailing frame')
        status(take('query-status')[1], 'running')
        require(safe_path(root, 'pending-progress.bin').read_bytes()
                == safe_path(root, 'progress.bin').read_bytes(), 'terminal poll differs from capture')
    empty('quit')
    require(commands.current is None, 'extra native command/save')
    lifecycle.take(None)
    require(events == ['RESUME', 'STOP', 'SHUTDOWN'],
            'missing/duplicate QMP lifecycle event')
    require(cut == ('backend-cut' in lifecycle.events), 'wrong cut lifecycle')
    spawn, wait, close = (one(name) for name in ('spawn', 'wait', 'backend-close'))
    require('kill' not in lifecycle.events and spawn['pid'] == wait['pid'] == context['pid']
            and type(context['pid']) is int and context['pid'] > 0 and wait['returncode'] == 0
            and spawn['seq'] < wait['seq'] < close['seq']
            and close['run_id'] == context['backend_run_id'], 'v2 requires owned normal wait0, never forced kill')
    require(wait['monotonic_ns'] - spawn['monotonic_ns'] <= inputs['capture_timeout_seconds'] * 1000000000,
            'v2 original source deadline exceeded')
    final = one('final-disk')
    require(final['seq'] > close['seq'] and final['size'] == 512*1024**2
            and type(final['sha256']) is str and re.fullmatch('[0-9a-f]{64}', final['sha256']),
            'final disk identity was not observed after backend close')
    for name, row in latest.items():
        path = safe_path(root, name)
        require(path.stat().st_size == row['size'] and sha256(path) == row['sha256'],
                'native save content mismatch: ' + name)
    require(bytes(serial) == safe_path(root, 'serial.bin').read_bytes(),
            'QMP serial reconstruction differs')
    transport = validate_observations(root, context, rows, lifecycle)
    return dict(cut_observed=cut, capture_names=set(latest), lifecycle=lifecycle.events,
                witness_count=lifecycle.count, fault_io_events=fault_io_events,
                stop_request=stop_request, transport=transport, auxiliary=lifecycle.auxiliary)


def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence',type=Path)
    for name in ('source-root','build-manifest','qemu-binary','qemu-source','initial-disk'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('cut','write-offset','write-length'):p.add_argument('--'+name,type=int,required=True)
    p.add_argument('--write-sha256',required=True)
    a=p.parse_args()
    try:
        checked=verify_native_write_child(a.evidence,source_root=a.source_root,build_manifest=a.build_manifest,
            qemu_binary=a.qemu_binary,qemu_source=a.qemu_source,initial_disk=a.initial_disk,
            expected_write=dict(cut=a.cut,offset=a.write_offset,length=a.write_length,data_sha256=a.write_sha256))
    except (OSError,ValueError,RuntimeError,KeyError,TypeError) as error:
        print('a10-write-v2: '+str(error),file=sys.stderr);return 1
    print(json.dumps(dict(status='VERIFIED_NATIVE_WRITE_CUT',native_write_cut_custody_verified=True,
        native_acceptance_status='NOT_RUN',A10_complete=False,summary=checked.summary),indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())

