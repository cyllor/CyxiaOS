"""Decode protected native file replies. Full A10 receipt admission remains closed."""
from __future__ import annotations
import hashlib
import struct
from verify_smp import require

HEADER = 512
RECORD = 768
MAX_EVENTS = 256
TRACE_MAGIC = 0x4359584131305452
EVENT_MAGIC = 0x4359584131304556
EMPTY_HASH = hashlib.sha256(b'').digest()


def payload(version: int) -> bytes:
    require(version in (1,2,3), 'unknown A10 payload version')
    return b''.join(struct.pack('<Q', 0xa100000000000000 | version << 32 | index) for index in range(512))


def verify_boot(page: bytes, before: dict, serial: bytes) -> dict:
    """Native mount/replay counters against the independent original prefix."""
    require(len(page) == 4096, 'invalid native A10 storage boot bank')
    words = struct.unpack('<512Q', page)
    first = before['boot_epoch'] == 0
    epoch = before['boot_epoch'] + 1
    require(words[:3] == (0x43595853544f3133,1,epoch) and page[24:40].hex() == before['uuid'],
            'wrong native A10 recovered volume identity')
    require(words[5:8] == (before['committed_transactions'],before['replayed_blocks'],int(before['discarded_tail'])),
            'native A10 replay counters disagree with independent committed prefix')
    require(words[8:11] == (before['last_commit_lsn']+(6 if first else 4),before['generation']+1,before['log_epoch']+1),
            'native A10 boot/checkpoint COMMIT chain mismatch')
    require(words[11] >= 4096 and words[12] == before['replayed_blocks']+(11 if first else 7)
            and words[13] == 4 and words[14] > 0 and not any(words[15:]),
            'native A10 recovery I/O counts incomplete')
    expected = [b'STORAGE_V13_BOOT_DURABLE',b'SMP_BOOT_OK a=4 b=15 c=0']
    expected += [f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode() for cpu in (1,2,3)]
    lines = serial.splitlines()
    require(all(lines.count(line) == 1 for line in expected)
            and not any(token in serial for token in (b'PANIC',b'SMP_ERROR',b'FAIL')), 'missing/failed native A10 boot markers')
    return dict(epoch=epoch,uuid=before['uuid'],committed_transactions=words[5],replayed_blocks=words[6],
                discarded_tail=bool(words[7]),commit_lsn=words[8],generation=words[9],log_epoch=words[10],
                reads=words[11],writes=words[12],flushes=words[13],elapsed_guest_ms=words[14])


def verify_terminal(raw: bytes, binding: dict, capture: dict) -> dict:
    require(len(raw) == 512, 'wrong A10 terminal bank length')
    result = {}
    for role, name in ((1,'writer'), (2,'reader')):
        slot = raw[(role-1)*256:role*256]
        if role == 1 and binding['mode'] == 3:
            require(not any(slot), 'recovery has an unexpected writer exit')
            continue
        (tag, owner_id, owner_generation, code, at, serial, magic, version, mode,
         seen_role, boot, stage, object_id, object_generation, consumed, observed,
         verified, error) = struct.unpack_from('<18Q', slot)
        require(tag == 0x4359584131305052 and (owner_id,owner_generation) == capture[name]
                and code == 0 and at > 0 and serial > 0 and serial % 2 == 0
                and magic == 0x4359584131305553 and version == 1
                and mode == binding['mode'] and seen_role == role and boot == binding['boot_epoch']
                and stage == 8 and object_id > 0 and object_generation > 0 and error == 0
                and not any(slot[144:]), 'incomplete/mismatched A10 task exit')
        expected = 2 if mode == 1 else 3
        require((consumed == expected and verified == 0 and observed == expected) if role == 1
                else (consumed == 0 and verified == 4096 and (observed in (2,3) if mode == 3 else observed == 2)),
                'invalid A10 consumed/observed sequence')
        owned = [row for row in capture['records'] if row['owner'] == capture[name]]
        require(owned and at >= owned[-1]['at_ns'], 'A10 exit predates delivered replies')
        result[name] = dict(owner=capture[name],object=(object_id,object_generation),at_ns=at,
                            consumed_sequence=consumed,observed_sequence=observed,verified_bytes=verified)
    return result


def decode(raw: bytes, binding: dict) -> dict:
    require(HEADER <= len(raw) <= 200704, 'incomplete/oversized A10 capture')
    magic, version, width, count, overflow, epoch, mode = struct.unpack_from('<7Q', raw)
    require((magic, version, width) == (TRACE_MAGIC, 1, RECORD) and 0 < count <= MAX_EVENTS
            and overflow == 0, 'invalid/overflowed A10 capture')
    require(epoch == binding['boot_epoch'] > 0 and mode == binding['mode'] in (1, 2, 3), 'wrong A10 boot/mode')
    for at, width, key in ((56,16,'nonce'),(72,16,'uuid'),(120,32,'image_sha256'),
                           (152,32,'input_sha256'),(184,32,'source_sha256')):
        wanted = bytes.fromhex(binding[key])
        require(len(wanted) == width and any(wanted) and raw[at:at+width] == wanted, 'A10 run identity mismatch')
    writer = struct.unpack_from('<2Q', raw, 88)
    reader = struct.unpack_from('<2Q', raw, 104)
    require(all(reader) and writer != reader and (all(writer) if mode != 3 else writer == (0,0)), 'invalid A10 task owners')
    require(not any(raw[216:HEADER]), 'A10 header reserved bytes')
    end = HEADER+count*RECORD
    require(len(raw) >= end and not any(raw[end:]), 'truncated/unpublished A10 record suffix')
    previous = (0,0,0,0,0)
    request_ids, authorities, records = {}, {}, []
    for index in range(count):
        row = raw[HEADER+index*RECORD:HEADER+(index+1)*RECORD]
        tag, sequence, at, boot, owner_id, owner_generation, lsn, reads, writes, flushes, transferred, misses = struct.unpack_from('<12Q',row)
        owner = owner_id, owner_generation
        require(tag == EVENT_MAGIC and sequence == index+1 and boot == epoch and owner in (writer,reader)
                and owner != (0,0) and at > 0 and lsn > 0, 'invalid A10 event identity/order')
        counters = at, lsn, reads, writes, flushes
        require(all(value >= old for value,old in zip(counters,previous)), 'nonmonotonic A10 evidence')
        previous = counters
        frame = row[128:]
        fmagic,fversion,length,operation,open_mode = struct.unpack_from('<Q4H',frame)
        request,auth_id,auth_generation,handle_id,handle_generation,offset,address = struct.unpack_from('<7Q',frame,16)
        data_length,path_length,flags = struct.unpack_from('<IHH',frame,72)
        result,count_bytes,object_id,object_generation,write_seq,durable_seq = struct.unpack_from('<q5Q',frame,80)
        require((fmagic,fversion,length) == (0x435946494c453031,1,640) and operation in range(1,12)
                and request > request_ids.get(owner,0) and auth_id > 0 and auth_generation > 0
                and flags == 0 and path_length <= 512 and not any(frame[128+path_length:]), 'invalid A10 file reply frame')
        authority = auth_id,auth_generation
        require(authorities.get(owner,authority) == authority, 'A10 authority changed within task')
        authorities[owner] = authority; request_ids[owner] = request
        path = frame[128:128+path_length].decode('utf-8')
        require((path.startswith('/') and '\0' not in path) if operation in (1,2,7,9,10) else not path,
                'invalid A10 reply path')
        require(data_length <= 65536 and transferred <= data_length and result <= 0, 'invalid A10 transfer/result')
        if result == 0:
            require((object_id > 0 and object_generation > 0) or operation == 6, 'A10 success missing file object')
            if operation in (3,4):
                require(transferred == count_bytes and address > 0, 'A10 transferred data mismatch')
            else:
                require(transferred == 0, 'unexpected A10 result data')
            if operation == 5:
                require(write_seq == durable_seq, 'inconsistent fsync receipt')
        else:
            require(transferred == 0, 'failed A10 request has result data')
        if transferred == 0:
            require(row[96:128] == EMPTY_HASH, 'nonempty A10 zero-transfer digest')
        records.append(dict(sequence=sequence,at_ns=at,owner=owner,request=request,
            operation=operation,open_mode=open_mode,result=result,path=path,handle=(handle_id,handle_generation),
            object=(object_id,object_generation),offset=offset,count=count_bytes,
            write_seq=write_seq,durable_seq=durable_seq,commit_lsn=lsn,
            reads=reads,writes=writes,flushes=flushes,cache_misses=misses,
            data_length=transferred,data_sha256=row[96:128].hex()))
    return dict(version=1,writer=writer,reader=reader,boot_epoch=epoch,mode=mode,
                records=records,A10_complete=False)


def verify_visibility(raw: bytes, binding: dict, path: str, sequence: int, payload: bytes) -> dict:
    capture = decode(raw,binding)
    require(sequence > 0 and len(payload) == 4096, 'invalid visibility expectation')
    handles = {}
    receipt = observed = None
    expected_hash = hashlib.sha256(payload).hexdigest()
    for row in capture['records']:
        if row['result'] != 0:
            continue
        owner, operation = row['owner'], row['operation']
        key = owner, row['handle']
        if operation == 2:
            require(all(row['handle']) and key not in handles, 'duplicate A10 open handle')
            handles[key] = row['path'], row['object']
        elif operation == 6:
            require(key in handles, 'A10 close without open')
            del handles[key]
        elif operation in (3,4,5):
            require(handles.get(key) == (path,row['object']), 'A10 data/receipt handle identity mismatch')
            if owner == capture['writer'] and operation == 5 and row['durable_seq'] == sequence:
                receipt = row
            if owner == capture['reader'] and operation == 3 and receipt is not None:
                require(row['object'] == receipt['object'] and row['offset'] == 0
                        and row['data_length'] == len(payload) and row['data_sha256'] == expected_hash,
                        'cross-endpoint read does not match acknowledged contents')
                observed = row
    require(receipt is not None and observed is not None, 'missing acknowledged cross-endpoint read')
    return dict(object=receipt['object'],durable_write_seq=sequence,commit_lsn=receipt['commit_lsn'],
                writer=capture['writer'],reader=capture['reader'],read_event=observed['sequence'],
                cache_misses=observed['cache_misses'],A10_complete=False,
                scope='one protected fsync receipt and cross-endpoint read; no complete fault matrix')


def verify_filesystem(raw: bytes, binding: dict, progress: bytes, oracle: dict) -> dict:
    """Check one clean native mode against independently decoded durable bytes.

    Fault prefixes must be checked separately: a clean terminal is never inferred
    from a cut or from an acknowledged backend FLUSH.
    """
    capture = decode(raw, binding)
    terminal = verify_terminal(progress, binding, capture)
    mode = binding['mode']
    path = '/a10/value'
    marker = f"/a10/seen-{binding['boot_epoch']:016x}"
    durable = oracle['files'].get(path)
    require(durable is not None and oracle['uuid'] == binding['uuid']
            and oracle['boot_epoch'] == binding['boot_epoch']
            and oracle['last_commit_lsn'] >= capture['records'][-1]['commit_lsn'],
            'durable image does not cover protected native prefix')
    sequence = durable['durable_write_seq']
    require((sequence == 2 if mode == 1 else sequence == 3) if mode != 3 else sequence in (2,3),
            'wrong final durable sequence')
    obj = durable['inode'], durable['generation']
    require(durable['size'] == 4096 and durable['sha256'] == hashlib.sha256(payload(sequence)).hexdigest()
            and all(item['object'] == obj for item in terminal.values()),
            'durable data/object disagrees with consumed native result')
    expected_read = sequence if mode == 3 else 2
    require(terminal['reader']['observed_sequence'] == expected_read, 'recovery read chose a different durable version')
    expected_acks = [1,2] if mode == 1 else [3] if mode == 2 else []
    handles, writes, receipts, stats = {}, {}, [], []
    read = closed = marker_created = marker_seen = None
    for row in capture['records']:
        owner, operation = row['owner'], row['operation']
        key = owner, row['handle']
        if row['result'] != 0:
            require(operation == 10 and row['result'] == -2, 'failed operation in clean A10 scenario')
            continue
        if operation == 2:
            require(row['path'] == path and row['object'] == obj and all(row['handle']) and key not in handles,
                    'A10 open targets wrong object/handle')
            handles[key] = obj
        elif operation in (3,4,5,6):
            require(key in handles and (row['object'] == obj or operation == 6), 'A10 data operation lacks owned handle')
            if operation == 6:
                del handles[key]
                if owner == capture['reader'] and read is not None: closed = row
            elif operation == 4:
                require(owner == capture['writer'] and row['offset'] == 0 and row['data_length'] == 4096,
                        'unexpected A10 write')
                writes[key] = row
            elif operation == 5:
                require(owner == capture['writer'] and len(receipts) < len(expected_acks)
                        and row['durable_seq'] == expected_acks[len(receipts)] and key in writes,
                        'wrong or duplicate acknowledged fsync sequence')
                write = writes.pop(key)
                require(write['data_sha256'] == hashlib.sha256(payload(row['durable_seq'])).hexdigest(),
                        'fsync did not acknowledge prescribed overwritten contents')
                if mode == 2:
                    require(marker_seen is not None and marker_seen['sequence'] < write['sequence'],
                            'writer overwrote before observing current reader marker')
                receipts.append(row)
            elif operation == 3:
                require(owner == capture['reader'] and read is None and row['offset'] == 0
                        and row['data_length'] == 4096 and row['data_sha256'] == hashlib.sha256(payload(expected_read)).hexdigest()
                        and stats and stats[-1]['sequence'] < row['sequence'], 'wrong A10 reader data/stat order')
                if mode == 1:
                    require(len(receipts) == 2, 'reader did not follow acknowledged sequence 2')
                read = row
        elif operation == 10 and row['path'] == path and owner == capture['reader']:
            # Polls before preparation finishes may legitimately observe older
            # versions; only the two stable observations around READ certify it.
            if row['durable_seq'] == expected_read and row['write_seq'] == expected_read:
                require(row['object'] == obj and row['open_mode'] == 1 and row['count'] == 4096,
                        'reader stable STAT has wrong metadata')
                stats.append(row)
        elif operation == 1 and row['path'] == marker:
            require(owner == capture['reader'] and mode != 3 and read is not None and closed is not None
                    and stats[-1]['sequence'] > closed['sequence'], 'reader marker precedes completed stable observation')
            marker_created = row
        elif operation == 10 and row['path'] == marker and owner == capture['writer']:
            require(mode == 2 and marker_created is not None and row['object'] == marker_created['object'],
                    'writer observed stale or unowned marker')
            marker_seen = row
    require(not handles and not writes and len(receipts) == len(expected_acks)
            and read is not None and closed is not None and len(stats) >= 2
            and stats[-1]['sequence'] > closed['sequence'], 'incomplete native fsync/read/close/stat sequence')
    if mode != 3:
        retained = oracle['files'].get(marker)
        require(marker_created is not None and retained is not None
                and (retained['inode'],retained['generation']) == marker_created['object']
                and retained['size'] == retained['durable_write_seq'] == 0
                and retained['sha256'] == EMPTY_HASH.hex(), 'durable reader marker missing/mismatched')
    return dict(mode=mode,boot_epoch=binding['boot_epoch'],object=obj,durable_write_seq=sequence,
                highest_commit_lsn=oracle['last_commit_lsn'],acknowledged_sequences=expected_acks,
                reader_sequence=expected_read,reader_data_sha256=read['data_sha256'],terminal=terminal,
                A10_complete=False,scope='one clean ordinary EL0 mode; fault/replay/eviction matrix incomplete')
