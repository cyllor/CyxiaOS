"""Two-node Full collection custody; native handoff is not A03/Active proof."""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import math
import re
import stat
import struct
from pathlib import Path

from boot_reboot_contract import DISK_BYTES, verify_origin
from check_elf import symbol
from check_prototype_evidence import _pairs, _finite_float, read_json, require
from run_v13_a02 import config_write_packet
from transport import FrameDecoder
from verify_v13_boot_recovery import CONFIG_MAGIC, verify_samples
from verify_v13_model import loaded_bytes
import v16_a03_full_retry_v2 as retry
from v16_a03_focus import sha, write_json
from v16_a03_collection_journal import inspect_journals

VERSION = 'v16-a03-full-collection-capture-v1'
CHECKER_VERSION = 'v16-a03-full-collection-checker-v1'
TOOL_ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_DEFAULT = 172800
MAX_TIMEOUT = 259200
POLL_SECONDS = 5
MAX_SERIAL_BYTES = 64*1024**2
MAX_QMP_BYTES = 128*1024**2
QMP_TRANSCRIPT_BYTES = 256*1024**2
MAX_ARCHIVES = 4096
MAX_ARCHIVE_BYTES = 256*1024**2
FAMILIES = ((1,1),(1,2),*( (n,1) for n in range(2,16)),(16,1),(16,2))
BANKS = dict(retry.BANKS, learning=('LEARNING_V13_EVIDENCE',1024))
LIVE_BANKS = dict(replay=512,collection=512,control=4096,tasks=256,learning=1024)


def validate_timeout(value):
    require(type(value) in (int,float) and math.isfinite(value) and 5 <= value <= MAX_TIMEOUT,
            'Full collection host timeout must be finite and within 5..259200 seconds')


def unique_identity(value, seen, label):
    require(type(value) is str and re.fullmatch('[0-9a-f]{32}',value) is not None,
            'Full '+label+' must be canonical 128-bit hex')
    raw=bytes.fromhex(value)
    require(any(raw) and raw not in seen,'Full reused/zero '+label)
    seen.add(raw)


def verify_journal_counts(journals, terminal):
    regular=sum(j['kind']=='regular' and not j['excluded'] for j in journals)
    excluded=sum(j['kind'] in ('regular','preparation') and j['excluded'] for j in journals)
    require(len(journals)==terminal['archived'] and regular==terminal['verified']
            and excluded==terminal['excluded'],'Full committed journals differ from native counters')


def read_transcript(path):
    require(path.stat().st_size <= QMP_TRANSCRIPT_BYTES,'Full collection transcript exceeds bounded size')
    return json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=_pairs,
                      parse_float=_finite_float,
                      parse_constant=lambda value: require(False,'nonfinite QMP JSON '+value))


def _words(raw, size):
    if not isinstance(raw,bytes) or len(raw) != size:return None
    return struct.unpack('<%dQ' % (size//8),raw)


def progress_snapshot(probe):
    w=_words(probe.get('replay'),512)
    if w is None or not w[0] or w[0]%2:return None
    require(w[1] == 0x435952504c593133,'unsupported Full collection replay ABI')
    require(w[2] <= 27 and (w[3],w[4]) in FAMILIES and w[5] < 12,
            'Full collection phase/family/group out of range')
    require(w[19] <= 216 and all(v<=8 for v in w[24:42]) and all(v<=4 for v in w[42:60])
            and w[11] <= MAX_ARCHIVES and w[10] <= MAX_ARCHIVES and w[17] <= MAX_ARCHIVES,
            'Full collection counter/archive bound exceeded')
    return dict(phase=w[2],family=[w[3],w[4]],group=w[5],trial_id=w[7],
                verified=w[10],excluded=w[11],owner_error=w[12],archived=w[17],
                data_phase=w[18],paired=w[19],pending_baseline=bool(w[20]),data_error=w[21],
                peer_paused=bool(w[22]),training_per_family=list(w[24:42]),
                validation_per_family=list(w[42:60]))


def fatal_evidence(probe):
    p=progress_snapshot(probe)
    if p is not None:
        require(p['phase'] != 18,'native Full collector failed; preserve stopped diagnostics')
        require(p['phase'] < 25,'focused collection terminal cannot satisfy Full profile')
        require(p['data_phase'] != 12,'native dataset/training/validation rejected')
        # Ordinary verification exclusions and preparation drain/archive are
        # genuine native retry work, including Evidence and Conflict results.
    if 'tasks' in probe:
        w=_words(probe['tasks'],256)
        require(w is not None and not w[2] and not w[3],'native CPU quarantine/overrun')
    if 'control' in probe:
        raw=probe['control']
        require(len(raw) in (4096,BANKS['control'][1]),'Full control diagnostic width')
        w=struct.unpack('<%dQ' % (len(raw)//8),raw)
        require(not(w[160]==0x43594f5053540001 and w[161]==1 and w[162]>0
                    and w[191]>0 and not w[191]%2),'native optimization-stop observed')
    if 'learning' in probe:
        w=_words(probe['learning'],1024)
        require(w is not None and not w[10],'native learning worker fault')


def terminal_hint(probe, until='validated'):
    require(until in ('collected','validated'),'unsupported Full terminal goal')
    p=progress_snapshot(probe)
    c=_words(probe.get('collection'),512)
    if p is None or c is None or not c[0] or c[0]%2:return None
    if (p['phase'] != 17 or p['family'] != [16,2] or p['group'] != 0
            or p['paired'] != 216 or p['pending_baseline'] or p['data_error'] or p['owner_error']
            or p['training_per_family'] != [8]*18 or p['validation_per_family'] != [4]*18
            or p['verified'] < 432 or p['archived'] < p['verified']+p['excluded']
            or not 2 <= p['data_phase'] <= 11 or until=='validated' and p['data_phase'] != 11):
        return None
    if (c[1:6] != (0x43594c434f4c3136,1,0,17,0) or c[6:9] != (16,2,0)
            or c[9:13] != (p['verified'],p['archived'],216,0) or c[13:15] != (1,1)
            or not c[47]):return None
    return dict(p,collection_owner_all_resources_clear=True,work_quiescent=True,
                validation_handoff_observed=p['data_phase']==11,
                active_model_verified=False,final_credit_release_verified=False,
                scope='Full collector released its own scratch; validated handoff does not prove Active promotion.')


def terminal_boundary(probe, until='validated'):
    value=terminal_hint(probe,until)
    if value is None:return None
    boot=_words(probe.get('boot'),512);runtime=_words(probe.get('runtime'),8192)
    if boot is None or runtime is None or boot[2]%2 or not runtime[2] or runtime[2]%2:return None
    fatal_evidence(probe)
    return value


def closure(root=TOOL_ROOT):
    root=Path(root).resolve(strict=True)
    pending=['run_v16_a03_full_collection','v16_a03_full_collection','verify_v16_a03_full_collection']
    found={}
    while pending:
        name=pending.pop()
        if name in found:continue
        require(len(found)<128,'Full collection tool closure bound')
        path=root/'tools'/(name+'.py')
        require(path.is_file() and not path.is_symlink(),'missing/linked Full collection tool '+name)
        found[name]=sha(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports=([node.module] if isinstance(node,ast.ImportFrom) else
                     [x.name for x in node.names] if isinstance(node,ast.Import) else [])
            for item in imports:
                if item and (root/'tools'/(item+'.py')).is_file():pending.append(item)
    result={'tools/'+n+'.py':v for n,v in sorted(found.items())}
    result['tools/qemu/cyxia-per-vcpu-pmu.patch']=sha(root/'tools/qemu/cyxia-per-vcpu-pmu.patch')
    return result


def trusted_context(*,source_root,build_manifest,formatter,qemu_binary,qemu_source,producer_tools_root=None):
    context=retry.trusted_context(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
                                  qemu_binary=qemu_binary,qemu_source=qemu_source,
                                  producer_tools_root=producer_tools_root)
    build=Path(build_manifest).resolve(strict=True)
    base=read_json(build.parent/'base-build-manifest.json')
    nodes=base['nodes']
    require(nodes['a']['node_id'] != nodes['b']['node_id']
            and nodes['a']['peer_node_id']==nodes['b']['node_id']
            and nodes['b']['peer_node_id']==nodes['a']['node_id'],'Full needs reciprocal distinct node identities')
    context['version']=VERSION
    context['tools']=closure(TOOL_ROOT if producer_tools_root is None else producer_tools_root)
    for name in ('node-b.pub',):
        path=build.parent/name
        require(path.is_file() and not path.is_symlink()
                and sha(path)==base['artifacts'][name]['sha256'],'Full peer public artifact mismatch')
        context['artifacts'][name]=sha(path)
    context['node_symbols']={}
    for node in ('a','b'):
        image=(build.parent/f'node-{node}.elf').read_bytes()
        symbols={k:symbol(image,name) for k,(name,size) in BANKS.items()}
        require(all(symbols[k]['size']==size for k,(_,size) in BANKS.items()),'Full node bank ABI mismatch')
        model=symbol(image,'A02_BOOT_MODEL')
        require(model['size']==2772 and hashlib.sha256(loaded_bytes(image,model['va'],2772)).hexdigest()
                ==context['model_sha256'],'Full peer model differs')
        require(sha(build.parent/f'node-{node}.pub')==nodes[node]['node_id'],'Full node public identity mismatch')
        context['node_symbols'][node]=symbols
    return context


def launch_argv(qemu,folder,qpath,gpath,port,node):
    require(node in ('a','b'),'Full node role must be a or b')
    argv=retry.launch_argv(qemu,folder,qpath,gpath,port)
    if node=='b':
        argv=[(v.replace('listen=127.0.0.1:','connect=127.0.0.1:') if v.startswith('socket,id=net0,') else
               v.replace('mac=02:00:00:00:00:01','mac=02:00:00:00:00:02') if v.startswith('virtio-net-device,') else
               str(folder/'node-b.elf') if v==str(folder/'node-a.elf') else v) for v in argv]
    return argv


def bounded_inventory(directory):
    require(not Path(directory).is_symlink(),'linked Full artifact root')
    root=Path(directory).resolve(strict=True);result={};total=0
    for path in sorted(root.rglob('*')):
        st=path.lstat()
        require(not stat.S_ISLNK(st.st_mode),'linked Full artifact')
        if stat.S_ISDIR(st.st_mode):continue
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'special/aliased Full artifact')
        if path==root/'summary.json':continue
        name=str(path.relative_to(root))
        limit=(DISK_BYTES if path.name=='disk.raw' else QMP_TRANSCRIPT_BYTES if path.name=='qmp-transcript.json'
               else MAX_QMP_BYTES if path.name in ('qmp-sent.bin','qmp-received.bin')
               else MAX_SERIAL_BYTES if path.name in ('serial.bin','serial.txt') else 32*1024**2)
        require(st.st_size<=limit,'Full artifact exceeds size bound: '+name)
        total+=st.st_size
        require(len(result)<10000 and total<=4*1024**3,'Full capture inventory bound')
        result[name]=dict(bytes=st.st_size,sha256=sha(path))
    return result


def verify_node_qmp(folder,context,node,platform,dtb,until='validated'):
    rows=read_transcript(folder/'qmp-transcript.json')
    require(type(rows) is list and rows and rows[0].get('direction')=='receive'
            and 'QMP' in rows[0].get('message',{}),'missing Full QMP greeting')
    for direction,name in (('send','qmp-sent.bin'),('receive','qmp-received.bin')):
        raw=(folder/name).read_bytes()
        require(len(raw)<=MAX_QMP_BYTES,'Full raw QMP bound')
        require(retry.raw_qmp_messages(raw)==[r['message'] for r in rows if r.get('direction')==direction],
                'Full raw QMP/transcript mismatch')
    pending=None;last_id=0;running=False;paused=False;quit_seen=False;resumed=False
    setup=set();preboot=set();rounds={};stops=0;serial=bytearray();events_allowed=set();responses={}
    allowed={'qmp_capabilities','query-cpus-fast','query-memory-size-summary','pmemsave','ringbuf-read','cont','stop','query-status','quit'}
    for row in rows[1:]:
        require(type(row) is dict and row.get('direction') in ('send','receive')
                and type(row.get('message')) is dict,'malformed Full QMP row')
        m=row['message']
        if row['direction']=='receive':
            if 'event' in m:
                event=m['event']
                require(event in ('STOP','RESUME','SHUTDOWN')
                        and {'STOP':'stop','RESUME':'cont','SHUTDOWN':'quit'}[event] in events_allowed,
                        'unexpected Full QMP lifecycle event')
                require((event=='STOP' and not running) or (event=='RESUME' and running)
                        or (event=='SHUTDOWN' and quit_seen),'contradictory Full QMP event')
                if event=='SHUTDOWN':require(m.get('data')=={'guest':False,'reason':'host-qmp-quit'},'guest shutdown')
                else:require(m.get('data',{})=={},'unexpected Full QMP event data')
                continue
            require(pending is not None and m.get('id')==pending['id'] and 'return' in m and 'error' not in m,
                    'unmatched/failed Full QMP response')
            command=pending['execute']
            if command=='query-status':require(m['return'].get('status')=='paused','Full guest not paused');paused=True
            elif command=='ringbuf-read':
                serial.extend(base64.b64decode(m['return'],validate=True))
                require(len(serial)<=MAX_SERIAL_BYTES,'Full serial bound')
            elif command in ('query-cpus-fast','query-memory-size-summary'):responses[command]=m['return']
            pending=None;continue
        require(not quit_seen and pending is None and m.get('execute') in allowed
                and type(m.get('id')) is int and m['id']==last_id+1
                and set(m)<={'execute','id','arguments'},'unauthorized/outstanding Full QMP command')
        pending=m;last_id=m['id'];command=m['execute']
        if command not in ('pmemsave','ringbuf-read'):require('arguments' not in m,'unexpected QMP arguments')
        if command in ('qmp_capabilities','query-cpus-fast','query-memory-size-summary'):
            require(not resumed and command not in setup
                    and (command=='qmp_capabilities' or 'qmp_capabilities' in setup),'Full setup order')
            setup.add(command)
        elif command=='ringbuf-read':
            require(resumed and m.get('arguments')==dict(device='cyxlog',size=1048576,format='base64'),'Full serial profile')
        elif command=='cont':
            require(not running and setup=={'qmp_capabilities','query-cpus-fast','query-memory-size-summary'}
                    and preboot=={'dtb-header.bin','platform.dtb','config-observed.bin'},'Full resume before setup')
            if resumed:
                require(paused and len(rounds[stops])==2*len(BANKS),'Full resumed without complete double probe')
                previous={key:rounds[stops][key,False] for key in BANKS}
                fatal_evidence(previous)
                if node=='a':
                    require(terminal_boundary(previous,until) is None,'resumed already-complete Full terminal')
            running=True;resumed=True;paused=False;events_allowed.add('cont')
        elif command=='stop':
            require(resumed and running and stops<64,'Full stopped probe bound/order')
            stops+=1;rounds[stops]={};running=False;paused=False;events_allowed.add('stop')
        elif command=='query-status':require(stops>0 and not running,'Full status without stop')
        elif command=='pmemsave':
            a=m.get('arguments',{});path=Path(a.get('filename',''))
            require(set(a)=={'val','size','filename'} and type(a['val']) is int and type(a['size']) is int
                    and path.parent==folder and not path.is_symlink(),'external Full physical read')
            if path.name in ('dtb-header.bin','platform.dtb','config-observed.bin'):
                require(not resumed and path.name not in preboot,'duplicate/late Full setup read')
                address,size=((context['node_symbols'][node]['config']['pa'],512) if path.name=='config-observed.bin'
                              else (0x40000000,40 if path.name=='dtb-header.bin' else len(dtb)))
                require(path.name=='dtb-header.bin' or 'dtb-header.bin' in preboot,'Full DTB read order')
                preboot.add(path.name)
            elif path.name.startswith('pending-'):
                key=path.stem[len('pending-'):]
                require(running and key in LIVE_BANKS,'Full live read outside running scope')
                address=context['node_symbols'][node][key]['pa'];size=LIVE_BANKS[key]
            else:
                match=re.fullmatch(r'probe-([0-9]{2})-(confirm-)?(.+)\.bin',path.name)
                require(match is not None and paused and not running and int(match[1])==stops,'unbound Full stopped read')
                key=match[3];confirm=bool(match[2])
                require(key in BANKS and (key,confirm) not in rounds[stops],'duplicate/unknown Full bank')
                if confirm:require(all((k,False) in rounds[stops] for k in BANKS),'confirm before whole first probe')
                value=path.read_bytes();rounds[stops][key,confirm]=value
                if confirm:require(value==rounds[stops][key,False],'Full paused bytes changed')
                address=context['node_symbols'][node][key]['pa'];size=BANKS[key][1]
            require(a['val']==address and a['size']==size and path.stat().st_size==size,'Full physical range/width mismatch')
        elif command=='quit':
            require(paused and not running and len(rounds[stops])==2*len(BANKS),'Full quit before stopped double capture')
            quit_seen=True;events_allowed.add('quit')
    require(quit_seen and pending is None and stops>0,'incomplete Full QMP lifecycle')
    require(responses.get('query-cpus-fast')==platform['cpus']
            and responses.get('query-memory-size-summary')==platform['memory'],'Full QMP platform mismatch')
    final={}
    for key in BANKS:
        raw=(folder/(key+'.bin')).read_bytes()
        require(raw==rounds[stops][key,False]==rounds[stops][key,True],'Full final bank differs from stopped reads')
        final[key]=raw
    fatal_evidence(final)
    return final,bytes(serial),stops


def verify_capture(directory,*,source_root,build_manifest,formatter,qemu_binary,qemu_source,
                   producer_tools_root=None,allow_unsaved_exports=False):
    require(not Path(directory).is_symlink(),'linked Full capture root')
    root=Path(directory).resolve(strict=True);inventory=bounded_inventory(root);checker=closure()
    paths=dict(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
               qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    context=trusted_context(**paths)
    require(read_json(root/'native-context.json')==context,'Full caller/source/tool context mismatch')
    require(read_json(root/'source-manifest.json')==context['source_map'],'Full source map mismatch')
    require(sha(root/'build-manifest.json')==context['build_sha256']
            and sha(root/'base-build-manifest.json')==context['base_build_sha256'],'Full captured build changed')
    for name,digest in context['artifacts'].items():require(sha(root/name)==digest,'Full artifact changed')
    for prefix,key in (('source-inputs','source_map'),('producer-tools','tools')):
        for name,digest in context[key].items():require(sha(root/prefix/name)==digest,'Full captured source/tool changed')
    request=read_json(root/'capture.json');until=request['until'];timeout=request['timeout_seconds']
    validate_timeout(timeout)
    require(request==dict(version=VERSION,until=until,timeout_seconds=timeout,nodes=['a','b'])
            and until in ('collected','validated'),'Full capture contract mismatch')
    uuids=set();nonces=set();ports=set();processes=set();finals={};archives={};files={};stops={}
    for node in ('a','b'):
        folder=root/('node-'+node);inputs=read_json(folder/'input.json')
        uuid=inputs['disk_uuid'];nonce=inputs['nonce'];origin=inputs['disk_origin']
        require(origin=={'kind':'fresh'},'Full requires fresh independent media')
        require(inputs==dict(version=VERSION,until=until,timeout_seconds=timeout,poll_seconds=POLL_SECONDS,
                            serial_seconds=POLL_SECONDS,nonce=nonce,disk_uuid=uuid,disk_origin=origin,
                            mode=0,collection_profile='full',node=node,max_stopped_attempts=64),
                'Full node input contract mismatch')
        unique_identity(uuid,uuids,'UUID');unique_identity(nonce,nonces,'nonce')
        image_name=f'node-{node}.elf'
        require(sha(folder/image_name)==context['artifacts'][image_name],'Full launched image differs')
        require(sha(folder/'model.bin')==context['model_sha256'],'Full model changed')
        config=struct.pack('<4Q',CONFIG_MAGIC,1,0,0)+bytes.fromhex(nonce)+bytes.fromhex(context['artifacts'][image_name])+bytes.fromhex(sha(folder/'input.json'))+bytes.fromhex(sha(root/'source-manifest.json'))+bytes(368)
        require((folder/'config.bin').read_bytes()==config==(folder/'config-observed.bin').read_bytes(),'Full node config mismatch')
        injection=read_json(folder/'config-injection.json')
        require(injection==dict(request_hex=config_write_packet(config,context['node_symbols'][node]['config']['pa']).hex(),
                               received_hex=injection['received_hex'],ack_hex='2b')
                and bytes.fromhex(injection['received_hex']).lstrip(b'+')==b'$OK#9a','Full node injection mismatch')
        require(read_json(folder/'formatter-command.json')==dict(argv=[context['paths']['formatter'],str(folder/'disk.raw'),uuid]),'Full formatter command mismatch')
        verify_origin(origin,read_json(folder/'disk-before.json'),(folder/'format.log').read_bytes())
        require(read_json(folder/'disk-after.json')==dict(bytes=(folder/'disk.raw').stat().st_size,sha256=sha(folder/'disk.raw'))
                and (folder/'disk.raw').stat().st_size==DISK_BYTES,'Full disk custody mismatch')
        process=read_json(folder/'process-exit.json')
        require(process['schema']==1 and type(process['pid']) is int and process['pid']>0
                and process['pid'] not in processes and process['peer_pid']==process['pid']
                and process['returncode']==0 and process['forced'] is False and process['quit_ok'] is True
                and process['eof'] is True and not process['errors']
                and type(process['started_ns']) is int and type(process['exited_ns']) is int
                and 0<process['started_ns']<process['exited_ns'],'Full owned process lacks quit/EOF/wait0')
        processes.add(process['pid'])
        launch=read_json(folder/'launch.json');ports.add(launch['port'])
        require(type(launch['port']) is int and 0<launch['port']<65536 and launch['qmp']!=launch['gdb']
                and launch['symbols']==context['node_symbols'][node]
                and launch['argv']==launch_argv(context['paths']['qemu_binary'],folder,launch['qmp'],launch['gdb'],launch['port'],node),
                'Full exact two-node launch mismatch')
        platform=read_json(folder/'platform.json')
        require(len(platform['cpus'])==4 and {c['cpu-index'] for c in platform['cpus']}==set(range(4))
                and platform['memory']['base-memory']==1024**3,'Full native platform mismatch')
        dtb=(folder/'platform.dtb').read_bytes();header=(folder/'dtb-header.bin').read_bytes()
        require(header==dtb[:40] and len(header)==40 and 40<=len(dtb)<=2*1024**2
                and struct.unpack_from('>2I',dtb)==(0xd00dfeed,len(dtb)),'Full DTB mismatch')
        final,serial,count=verify_node_qmp(folder,context,node,platform,dtb,until)
        decoder=FrameDecoder();text=b''.join(payload+b'\n' for payload in decoder.feed(serial))
        require(serial==(folder/'serial.bin').read_bytes() and text==(folder/'serial.txt').read_bytes()
                and decoder.loss==decoder.corrupt==0 and not decoder.buffer
                and not any(x in serial or x in text for x in (b'PANIC',b'SMP_ERROR',b'UNIFIED_FAIL')),'Full serial fault/loss')
        verify_samples(final['boot'],final['boot'],final['control'][:4096],final['runtime'],final['unified'],config)
        require(struct.unpack_from('<Q',final['boot'],48)[0]==1,'Full requires first boot on independent media')
        fatal_evidence(final);finals[node]=final;stops[node]=count
        archive=inspect_journals(folder/'disk.raw',disk_uuid=uuid,max_archives=MAX_ARCHIVES,
                                 max_archive_bytes=MAX_ARCHIVE_BYTES,allow_empty=node=='b')
        archives[node]=archive['manifest']
        if node=='a':leader_journals=archive['journals']
        for name,value in archive['exports'].items():files['node-'+node+'/'+name]=value
    require(len(ports)==1,'Full guests do not share one private link')
    terminal=terminal_boundary(finals['a'],until)
    require(terminal is not None,'Full leader did not close requested collection boundary')
    verify_journal_counts(leader_journals,terminal)
    archive_manifest=dict(version=VERSION,nodes=archives,scope='Committed journal bytes/framing only; labels and complete numeric replay unverified')
    exports=root/'collection-archives'
    if exports.exists():
        require(exports.is_dir() and not exports.is_symlink(),'linked Full journal exports')
        actual={str(p.relative_to(exports)) for p in exports.rglob('*') if p.is_file()}
        require(actual==set(files)|{'manifest.json'} and read_json(exports/'manifest.json')==archive_manifest,
                'Full saved journal inventory/manifest differs')
        for name,value in files.items():require((exports/name).read_bytes()==value,'Full exported journal bytes changed')
    else:require(allow_unsaved_exports,'missing Full committed journal exports')
    require(trusted_context(**paths)==context and closure()==checker,'Full identity changed during verification')
    require(bounded_inventory(root)==inventory,'Full inventory changed during verification')
    return dict(version=VERSION,checker_version=CHECKER_VERSION,status='FULL_COLLECTION_CAPTURE_VERIFIED',
                capture_complete=True,full_collection_verified=True,terminal=terminal,
                validation_handoff_observed=terminal['validation_handoff_observed'],
                stopped_attempts=stops,archive_manifest=archive_manifest,archive_files=files,
                committed_archive_inventory_verified=True,full_dataset_verified=False,
                accepted_training_sample_verified=False,model_trained=False,active_model_verified=False,
                final_credit_release_verified=False,native_acceptance_status='NOT_RUN',A03_complete=False,
                source_event_hash_recomputed=False,source_custody_replay_verified=False,
                initial_image_reexecution_verified=False,captured_inventory=inventory,
                checker_identity=dict(version=CHECKER_VERSION,tools=checker))
