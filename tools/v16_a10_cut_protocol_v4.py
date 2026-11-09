"""Static v4 transport validation; v2 remains strict and byte-identical.

An actual backend cut, closed socket, raw receive through EOF and owned wait0
prove the power-loss boundary independently of QEMU's optional IO-error event.
No delivered event is omitted or accepted before the backend is disconnected.
"""
import base64, hashlib, json, re, struct, sys
from pathlib import Path
from check_prototype_evidence import _pairs, read_json, require, safe_path, sha256
from verify_v13_a10_native_receipt import (Forward, finite_tree, status, poll_bound,
    validate_dtb, SERIAL_LIMIT)
from verify_v16_a10_write_v2 import Lifecycle, transactions
from v16_a10_write_v2 import MAX_ERRORS, MAX_WIRE, canonical
from run_v13_a10 import PENDING_DIAGNOSTICS, terminal_ready
from transport import FrameDecoder

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
    require(0<=len(errors)<=MAX_ERRORS,'v4 overflow error burst')
    require(all(closed['shutdown_begin_ns']<=e['recv_return_ns']<=eof['recv_return_ns'] for e in errors),
            'v2 event actual receive precedes close or follows EOF')
    return dict(errors=errors,closed=closed,eof=eof,quit=quit_row['observation'],wait=wait,backend_return=backend_return,
                complete_received_wire_verified=True)

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
