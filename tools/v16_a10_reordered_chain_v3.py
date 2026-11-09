"""Closed A10 ancestry and raw journal selectors; no native verdict on fixtures.

The parent graph uses damaged media directly. Probe results select mutations;
probe-completed media never replace the selected cut's actual parent.
"""
from __future__ import annotations
import gzip
import hashlib
from pathlib import Path
import re
import struct

from check_prototype_evidence import require, safe_path, sha256
from check_v13_disk import BLOCK, COUNT, checksum, committed_volume, crc32c, superblock
from check_v13_fault_disk import read_events, trace_encoding
from verify_v13_a10_faults import overwrite_window
from verify_v13_a10 import decode
from verify_v13_a10_native_receipt import document
from v16_a10_reordered_write_v3 import validate_selector

ROLES=('prepare','overwrite_probe','overwrite_cut','recovery_probe','recovery_cut','final_recovery')
NEW_ROLES=ROLES[1:]
PARENTS=dict(prepare='seed',overwrite_probe='prepare',overwrite_cut='prepare',
    recovery_probe='overwrite_cut',recovery_cut='overwrite_cut',final_recovery='recovery_cut')
MODES=dict(prepare=1,overwrite_probe=2,overwrite_cut=2,recovery_probe=3,recovery_cut=3,final_recovery=3)
PROBES=dict(overwrite_cut='overwrite_probe',recovery_cut='recovery_probe')
CATEGORIES=dict(overwrite_cut='overwrite-redo',recovery_cut='mount-replay-home')
MAX_RAW=128*1024**2
MIN_STORAGE=5*(1024**3+512*1024**2)  # two 512MiB disks + bounded raw/tools allowance


def keys(value, expected, label):
    require(type(value) is dict and value.keys()==set(expected),'v3 invalid '+label+' keys')


def digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'v3 invalid digest')
    return value


def canonical_path(value, *, exists=True, directory=False):
    require(type(value) is str and value and Path(value).is_absolute(),'v3 path must be absolute')
    path=Path(value)
    # resolve rejects symlinks in *any* component, dot-dot and aliases, not just
    # a final symlink. Caller paths must already name canonical local objects.
    require(str(path.resolve(strict=exists))==value and not path.is_symlink(),
        'v3 noncanonical or symlink path')
    if exists:
        require(path.is_dir() if directory else path.is_file(),'v3 path kind mismatch')
    return path


def validate_plan(plan):
    keys(plan,{'schema_version','test_id','profile','seed',*ROLES},'plan')
    require(type(plan['schema_version']) is int and plan['schema_version']==3
        and plan['test_id']=='A10' and plan['profile']=='reordered-before-write-recut-v3',
        'v3 unsupported chain profile')
    keys(plan['seed'],{'sha256'},'seed');digest(plan['seed']['sha256'])
    directories=[]
    for role in ROLES:
        entry=plan[role]
        expected={'directory','summary_sha256','parent','initial_sha256','final_sha256'}
        if role in PROBES:expected|={'expected_write','selection'}
        keys(entry,expected,role)
        require(entry['parent']==PARENTS[role],'v3 wrong parent for '+role)
        value=entry['directory']
        require(type(value) is str and value==str(Path(value)) and Path(value).is_absolute()
            and '..' not in Path(value).parts,'v3 noncanonical planned directory')
        directories.append(value)
        for field in ('summary_sha256','initial_sha256','final_sha256'):digest(entry[field])
        if role in PROBES:
            validate_selector(entry['expected_write'])
            keys(entry['selection'],{'probe_summary_sha256','category'},role+' selection')
            require(entry['selection']['category']==CATEGORIES[role], 'v3 invalid semantic category')
            digest(entry['selection']['probe_summary_sha256'])
            require(entry['selection']['probe_summary_sha256']==plan[PROBES[role]]['summary_sha256'],
                'v3 selected probe summary mismatch')
    require(len(set(directories))==len(ROLES),'v3 reused capture directory')
    return plan


def validate_resources(limits):
    keys(limits,{'max_children','max_runtime_seconds','max_storage_bytes'},'resource caps')
    require(all(type(v) is int and v>0 for v in limits.values()),'v3 invalid resource cap')
    require(limits['max_children']==5 and limits['max_runtime_seconds']>=5*1920
        and limits['max_storage_bytes']>=MIN_STORAGE,'v3 insufficient five-child resource caps')
    return limits


def read_requests(root):
    """Map every WRITE to its own raw body; never infer bytes from a digest."""
    directory=Path(root)/'nbd';rows=read_events(directory)
    path=safe_path(directory,'requests.bin'+('.gz' if trace_encoding(directory)=='gzip' else ''))
    require(path.stat().st_size<=MAX_RAW,'v3 compressed request bound')
    result=[];total=0
    with (gzip.open(path,'rb') if path.suffix=='.gz' else path.open('rb')) as stream:
        for row in rows:
            if row['event']!='request':continue
            raw=stream.read(28);require(len(raw)==28,'v3 truncated request header')
            magic,flags,kind,handle,offset,length=struct.unpack('>IHHQQI',raw)
            require(magic==0x25609513 and flags==0 and kind in (0,1,2,3)
                and type(length) is int and 0<=length<=1024**2
                and offset+length<=BLOCK*COUNT and offset%512==length%512==0,
                'v3 invalid raw request header')
            body=stream.read(length) if kind==1 else b''
            total+=28+len(body);require(total<=MAX_RAW,'v3 expanded raw request bound')
            require(len(body)==(length if kind==1 else 0) and row['wire_offset']==total-28-len(body)
                and (kind,handle,offset,length)==tuple(row[k] for k in ('kind','handle','offset','length'))
                and hashlib.sha256(body).hexdigest()==row['data_sha256'],'v3 raw body/receipt mapping mismatch')
            result.append((row,body))
        require(stream.read(1)==b'','v3 trailing raw request bytes')
    return rows,result


def selector(row):
    return validate_selector(dict(cut=row['mutation'],offset=row['offset'],length=row['length'],data_sha256=row['data_sha256']))


def _record(data, expected_kind):
    require(len(data)==(2*BLOCK if expected_kind==2 else BLOCK),'v3 short raw journal record')
    head=data[:64];checksum(head,56)
    magic,version,kind,length,payload_crc,txid,lsn,epoch,home,index,count=struct.unpack_from('<IHHIIQQQQII',head)
    size={1:16,2:4096,3:64}[expected_kind]
    require(magic==0x43594c47 and version==1 and kind==expected_kind and length==64+size
        and head[60:64]==bytes(4) and txid>0 and lsn>0 and epoch>0,
        'v3 invalid raw journal header')
    body=data[64:64+size]
    require(crc32c(body)==payload_crc and not any(data[64+size:]),'v3 raw journal payload CRC/padding')
    return dict(txid=txid,lsn=lsn,epoch=epoch,home=home,index=index,count=count,body=body)


def decode_overwrite_transaction(blocks):
    """Decode the six actual log blocks, including ordered COMMIT digest."""
    require(len(blocks)==6 and all(len(b)==BLOCK for b in blocks),'v3 invalid overwrite block count')
    begin=_record(blocks[0],1)
    require((begin['home'],begin['index'],begin['count'])==(0,0,0)
        and struct.unpack('<IIQ',begin['body'])==(2,0,2*BLOCK),'v3 overwrite BEGIN is not two REDOs')
    redos=[_record(b''.join(blocks[1:3]),2),_record(b''.join(blocks[3:5]),2)]
    ordered=hashlib.sha256()
    for index,redo in enumerate(redos):
        require(redo['txid']==begin['txid'] and redo['epoch']==begin['epoch']
            and redo['lsn']==begin['lsn']+index+1 and redo['index']==index and redo['count']==2
            and 4098<=redo['home']<COUNT,'v3 invalid overwrite REDO chain')
        ordered.update(struct.pack('<Q',redo['home']));ordered.update(redo['body'])
    require(redos[0]['home']!=redos[1]['home'],'v3 duplicate overwrite home')
    commit=_record(blocks[5],3)
    require(commit['txid']==begin['txid'] and commit['epoch']==begin['epoch']
        and commit['lsn']==begin['lsn']+3 and (commit['home'],commit['index'],commit['count'])==(0,0,0)
        and struct.unpack_from('<QQQII',commit['body'])==(begin['txid'],begin['lsn'],begin['lsn']+2,2,0)
        and commit['body'][32:]==ordered.digest(),'v3 invalid overwrite COMMIT chain')
    return redos


def _prior_inversion(rows, request_id):
    ack_ids=[r['id'] for r in rows if r['event']=='ack' and r['id']<request_id]
    return any(right<left for left,right in zip(ack_ids,ack_ids[1:]))


def select_overwrite_write(clean_probe):
    """Requires a separately admitted clean mode2 probe before use."""
    root=Path(clean_probe);rows,requests=read_requests(root)
    binding=document(root,'binding.json')
    capture=decode(safe_path(root,'trace.bin').read_bytes(),binding)
    mutations=[r for r,_ in requests if r['kind'] in (1,3) and r.get('scope')=='armed']
    window=overwrite_window(capture,mutations)
    chosen=[(r,b) for r,b in requests if r['mutation'] in window['points'] and r['kind'] in (1,3)]
    writes=[(r,b) for r,b in chosen if r['kind']==1]
    require(len(writes)==48,'v3 overwrite journal write shape')
    blocks=[b''.join(body for _,body in writes[i:i+8]) for i in range(0,48,8)]
    decode_overwrite_transaction(blocks)
    # Pure REDO payload sectors in the second REDO, after an earlier actual
    # reversed ACK batch. The partial tail sector/header is not selected.
    candidates=[r for r,_ in writes[25:31] if _prior_inversion(rows,r['id'])]
    require(candidates,'v3 no observed reordered REDO-payload candidate')
    return selector(candidates[-1])


def replay_homes(initial_disk):
    """Return latest committed after-images in the guest's first-home order."""
    initial_disk=Path(initial_disk)
    with committed_volume(initial_disk) as (current,meta):
        require(meta['committed_transactions']>0 and meta['replayed_blocks']>0,
            'v3 parent has no committed mount replay homes')
        cursor=2;homes={}
        with initial_disk.open('rb') as stream:
            for _ in range(meta['committed_transactions']):
                stream.seek(cursor*BLOCK);begin=stream.read(BLOCK)
                count=struct.unpack_from('<I',begin,64)[0]
                require(1<=count<=128,'v3 committed BEGIN count bound')
                for index in range(count):
                    at=cursor+1+2*index;stream.seek(at*BLOCK);head=stream.read(64)
                    home=struct.unpack_from('<Q',head,40)[0]
                    require(4098<=home<COUNT,'v3 committed home range')
                    homes[home]=current(home)
                cursor+=2+2*count
        require(len(homes)==meta['replayed_blocks'],'v3 committed replay home-set mismatch')
        return homes,meta


def select_mount_replay_write(recovery_probe, initial_disk):
    """Prove complete mount home writes + FLUSH + next superblock + FLUSH.

    Only this exact initial committed-home prefix is eligible. Later boot-epoch
    or ordinary transactions are outside it even if their data hash matches.
    """
    rows,requests=read_requests(Path(recovery_probe));homes,meta=replay_homes(initial_disk)
    mutations=[(r,b) for r,b in requests if r['kind'] in (1,3) and r.get('scope')=='armed']
    home_count=len(homes)*8;needed=home_count+10
    require(len(mutations)>=needed,'v3 missing complete mount checkpoint prefix')
    for index,(home,image) in enumerate(homes.items()):
        for sector in range(8):
            row,body=mutations[index*8+sector]
            require(row['kind']==1 and row['offset']==home*BLOCK+sector*512 and row['length']==512
                and body==image[sector*512:(sector+1)*512], 'v3 mount replay home order/body mismatch')
    barrier,_=mutations[home_count]
    require(barrier['kind']==3,'v3 mount replay homes lack FLUSH fence')
    sb_rows=mutations[home_count+1:home_count+9]
    first=sb_rows[0][0]['offset']
    require(first in (0,BLOCK) and all(r['kind']==1 and r['length']==512 and r['offset']==first+i*512
        for i,(r,_) in enumerate(sb_rows)),'v3 mount checkpoint superblock sector order')
    with Path(initial_disk).open('rb') as stream:
        copies=[]
        for index in (0,1):
            stream.seek(index*BLOCK)
            try:copies.append((index,superblock(stream.read(BLOCK))))
            except ValueError:pass
    highest=max(value['generation'] for _,value in copies)
    active=next(index for index,value in copies if value['generation']==highest)
    require(first==(1-active)*BLOCK,'v3 checkpoint did not write inactive superblock')
    sb=superblock(b''.join(b for _,b in sb_rows))
    require(sb['uuid'].hex()==meta['uuid'] and sb['generation']==meta['generation']+1
        and sb['checkpoint']==meta['last_commit_lsn'] and sb['epoch']==meta['log_epoch']+1
        and mutations[home_count+9][0]['kind']==3,'v3 mount superblock/FLUSH mismatch')
    candidates=[r for r,_ in mutations[:home_count] if _prior_inversion(rows,r['id'])]
    require(candidates,'v3 mount replay has no candidate after actual ACK inversion')
    return selector(candidates[-1])


def validate_links(plan, records, initial_disk, *, same_host_monotonic_session):
    """Pure graph checks AFTER each role's fixed native verifier succeeds."""
    validate_plan(plan)
    require(same_host_monotonic_session is True,'v3 explicit same-host monotonic session required')
    require(set(records)==set(ROLES),'v3 missing/extra independently verified roles')
    seed=canonical_path(str(initial_disk));seed_hash=plan['seed']['sha256']
    require(sha256(seed)==seed_hash,'v3 seed digest mismatch')
    reference=records['prepare'];nonces=set();runs=set();endpoints=set()
    for role in ROLES:
        record=records[role];entry=plan[role];context=record['context'];inputs=record['inputs']
        parent=PARENTS[role]
        parent_disk=seed if parent=='seed' else Path(plan[parent]['directory'])/'disk.raw'
        parent_hash=seed_hash if parent=='seed' else plan[parent]['final_sha256']
        require(record['directory']==entry['directory']==context['capture_root']
            and context['backing_path']==entry['directory']+'/disk.raw'
            and context['initial_source']==str(parent_disk),'v3 actual disk ancestry/path mismatch: '+role)
        require(entry['initial_sha256']==inputs['initial_disk_sha256']==record['identity']['initial_sha256']==parent_hash
            and record['summary']['nbd_trace']['disk_final_sha256']==entry['final_sha256'],
            'v3 parent/child disk digest mismatch: '+role)
        require(type(inputs['mode']) is int and inputs['mode']==MODES[role]
            and type(inputs['cut']) is int and (inputs['cut']>0 if role in PROBES else inputs['cut']==0)
            and inputs['phase']=='before' and (role=='prepare' or inputs['unflushed']=='reverse-half'),
            'v3 fixed role profile mismatch: '+role)
        require(role=='prepare' or inputs['reverse_replies'] is True
            and record['summary']['nbd_trace']['reordered_replies'] is True,'v3 missing actual reordered child: '+role)
        if role in PROBES:
            require(context['version']=='a10-reordered-write-native-v3'
                and record['summary']['native_reordered_write_cut_custody_verified'] is True
                and record['summary']['status']=='NOT_RUN','v3 strict cut admission missing')
        else:
            require(context['version']=='a10-native-v1' and record['summary']['native_mode_verified'] is True
                and record['summary']['status']=='PASS','v3 clean native role admission missing')
        for field in ('source_sha256','build_sha256','image_sha256','qemu'):
            require(record['identity'][field]==reference['identity'][field],'v3 common identity mismatch: '+field)
        require(record['binding']['uuid']==reference['binding']['uuid']
            and record['model_sha256']==reference['model_sha256'],'v3 UUID/model mismatch')
        require(record['nonce'] not in nonces and context['backend_run_id'] not in runs,
            'v3 reused nonce/backend run')
        nonces.add(record['nonce']);runs.add(context['backend_run_id'])
        child_endpoints=set(context['endpoints'].values())
        require(len(child_endpoints)==3 and child_endpoints.isdisjoint(endpoints),'v3 reused endpoint')
        endpoints.update(child_endpoints)
        dependencies=([parent] if parent!='seed' else [])+([PROBES[role]] if role in PROBES else [])
        for dependency in dependencies:
            prior=records[dependency]['lifecycle'];current=record['lifecycle']
            end=[prior[k]['monotonic_ns'] for k in ('identity-after','final-disk')]
            begin=[current[k]['monotonic_ns'] for k in ('identity-before','backend-open','spawn')]
            require(all(type(t) is int and t>0 for t in end+begin) and max(end)<min(begin),
                'v3 parent/probe chronology inversion: '+role)
    return dict(strict_partial_chain_verified=True,legacy_mandatory_slots=0,native_acceptance_status='NOT_RUN',
        A10_complete=False,native_filesystem_fault_matrix_complete=False,roles=list(ROLES),
        chronology_trust='explicit-caller-same-host-monotonic-session',
        scope='one reordered before-WRITE overwrite and mount-replay recut with independent final recovery')
