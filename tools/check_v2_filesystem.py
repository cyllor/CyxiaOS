#!/usr/bin/env python3
"""Read-only v2 filesystem, ordered-redo and immutable-snapshot verifier.

This decoder is independent of the Rust implementation. It never repairs or
mounts an image. Durable metadata is selected from the complete committed redo
prefix; business bytes are always read at their immutable physical address.
Allocated unreachable business blocks are reported as garbage, not corruption.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import struct

from check_v13_disk import BLOCK, COUNT, checksum, crc32c
from check_v13_disk import committed_volume as _committed_volume
from verify_smp import require

BITMAP_START, INODE_START = 4098, 4102
CONTROL_START, CATALOG_START, SNAPSHOT_START = 4118, 4119, 4120
DATA_START, FIRST_BUSINESS_BLOCK = 4240, 8354
SYSTEM_ROOT, BOOT_INODE, REQUEST_INODE = 224, 225, 228
REQUEST_START = 8338
SYSTEM_NAMES = ('.cyxia-boot', '.cyxia-cluster-a', '.cyxia-cluster-b', '.cyxia-snapshot-requests')
SECOND = 1_000_000_000


def unpack(kind, data, offset=0):
    return struct.unpack_from('<' + kind, data, offset)


def u32(data, offset):
    return unpack('I', data, offset)[0]


def u64(data, offset):
    return unpack('Q', data, offset)[0]


def header(data, magic, version, length, crc):
    require(len(data) == BLOCK, 'short metadata page')
    checksum(data, crc)
    require(unpack('IHH', data) == (magic, version, length), 'invalid metadata header/version')


def superblock(data):
    header(data, 0x43594653, 2, 112, 108)
    require(unpack('II', data, 8) == (BLOCK, COUNT), 'wrong disk capacity')
    require(unpack('13I', data, 56) == (4098, 4102, 4240, 256, 0, 4118, 4119, 4120, 8, 15, 224, 224, 0), 'wrong v2 disk layout')
    require(not any(data[112:]), 'superblock reserved bytes')
    generation, checkpoint, epoch = unpack('3Q', data, 32)
    require(generation > 0 and epoch > 0 and any(data[16:32]), 'zero disk identity/generation')
    return dict(uuid=data[16:32], generation=generation, checkpoint=checkpoint, epoch=epoch)


@contextmanager
def committed_volume(path):
    with _committed_volume(path, superblock_decoder=superblock, redo_end=FIRST_BUSINESS_BLOCK) as volume:
        yield volume


def inode(identity, slot, current):
    require(len(slot) == 256, 'short inode')
    checksum(slot, 252)
    magic, kind = unpack('IH', slot)
    generation, size, sequence = unpack('QQQ', slot, 8)
    count = unpack('H', slot, 32)[0]
    parent, parent_generation = unpack('IQ', slot, 36)
    ext_block, ext_count = unpack('IH', slot, 240)
    require(magic == 0x4359494e and kind in (0, 1, 2) and generation > 0, 'invalid inode identity')
    require(not any(slot[6:8] + slot[34:36] + slot[246:252]), 'inode reserved bytes')
    require(count <= 16 and ext_count <= 338, 'inode extent count')
    extents = [unpack('III', slot, 48 + index * 12) for index in range(count)]
    require(not any(slot[48 + count * 12:240]), 'inode unused extent suffix')
    if kind == 0:
        require(identity not in (0, SYSTEM_ROOT) and not any(slot[16:252]), 'allocated fields in free inode')
    else:
        business = identity < SYSTEM_ROOT
        require(parent < 256 and parent_generation > 0 and business == (parent < SYSTEM_ROOT), 'cross-namespace inode parent')
        if identity in (0, SYSTEM_ROOT):
            require((kind, generation, parent, parent_generation) == (2, 1, identity, 1), 'invalid namespace root')
        else:
            require(parent != identity, 'self-parent inode')
        require((kind == 1 and size <= 8 * 1024 * 1024) or (kind == 2 and size <= 32768 and size % 128 == 0), 'inode size/type bound')
        require((ext_block == 0) == (ext_count == 0), 'inconsistent indirect extent reference')
        if ext_count:
            require(business and count == 16 and FIRST_BUSINESS_BLOCK <= ext_block < COUNT, 'invalid indirect extent address')
            page = current(ext_block)
            header(page, 0x43594558, 2, 32, 4092)
            require(unpack('IH', page, 8) == (identity, ext_count) and u64(page, 16) == generation, 'indirect extent identity mismatch')
            require(not any(page[14:16] + page[24:32] + page[32 + 12 * ext_count:4092]), 'indirect extent reserved bytes')
            extents += [unpack('III', page, 32 + index * 12) for index in range(ext_count)]
        logical_end = 0
        physical = set()
        for logical, start, blocks in extents:
            lower, upper = (FIRST_BUSINESS_BLOCK, COUNT) if business else (DATA_START, FIRST_BUSINESS_BLOCK)
            require(logical == logical_end and blocks > 0 and lower <= start < start + blocks <= upper, 'invalid extent namespace/coverage')
            logical_end += blocks
            for block in range(start, start + blocks):
                require(block not in physical and block != ext_block, 'duplicate inode physical ownership')
                physical.add(block)
        require(logical_end == (size + BLOCK - 1) // BLOCK, 'inode extent coverage mismatch')
    return dict(inode=identity, kind=kind, generation=generation, size=size, durable_write_seq=sequence,
                parent=parent, parent_generation=parent_generation, extents=extents,
                ext_block=ext_block, ext_count=ext_count)


def entry(slot):
    checksum(slot, 124)
    identity, length = unpack('IH', slot)
    generation = u64(slot, 8)
    require(length <= 63 and not any(slot[6:8] + slot[16 + length:124]), 'directory entry padding')
    name = slot[16:16 + length].decode('utf-8')
    if identity == 0xffffffff:
        require(length == generation == 0, 'invalid empty directory entry')
        return None
    require(identity < 256 and generation > 0 and name not in ('', '.', '..') and '\0' not in name and '/' not in name, 'invalid directory identity/name')
    return identity, generation, name


def content(node, current):
    remaining = node['size']
    for _, start, blocks in node['extents']:
        for block in range(start, start + blocks):
            data = current(block)
            amount = min(remaining, BLOCK)
            require(not any(data[amount:]), 'nonzero bytes beyond inode size')
            yield data[:amount]
            remaining -= amount


def validate_view(nodes, root_id, bitmap, current):
    by_id = {node['inode']: node for node in nodes}
    require(by_id[root_id]['kind'] == 2, 'missing namespace root')
    owned, references = set(), {}
    for identity, node in by_id.items():
        if not node['kind']:
            continue
        blocks = [block for _, start, count in node['extents'] for block in range(start, start + count)]
        if node['ext_block']:
            blocks.append(node['ext_block'])
        for block in blocks:
            require(block not in owned, 'duplicate physical ownership within view')
            require(bitmap[block // 8] & (1 << (block % 8)), 'reachable block missing allocation')
            owned.add(block)
        if identity != root_id:
            seen, child = {identity}, node
            while True:
                parent_id = child['parent']
                require(parent_id in by_id, 'cross-namespace parent reference')
                parent = by_id[parent_id]
                require(parent['kind'] == 2 and parent['generation'] == child['parent_generation'], 'stale inode parent')
                if parent_id == root_id:
                    break
                require(parent_id not in seen, 'cyclic inode parent')
                seen.add(parent_id)
                child = parent
        if node['kind'] != 2:
            continue
        directory, names = b''.join(content(node, current)), set()
        for index in range(node['size'] // 128):
            found = entry(directory[index * 128:(index + 1) * 128])
            if found is None:
                continue
            child_id, generation, name = found
            require(name not in names, 'duplicate directory name')
            names.add(name)
            require(child_id in by_id and child_id != root_id, 'cross-namespace directory reference')
            child = by_id[child_id]
            require(child['kind'] and child['generation'] == generation and child['parent'] == identity
                    and child['parent_generation'] == node['generation'], 'stale directory reference')
            require(child_id not in references, 'duplicate inode directory reference')
            references[child_id] = identity, name
    require(set(references) == {identity for identity, node in by_id.items() if identity != root_id and node['kind']}, 'missing inode directory reference')
    paths = {root_id: ''}
    def pathname(identity):
        if identity not in paths:
            parent, name = references[identity]
            paths[identity] = pathname(parent) + '/' + name
        return paths[identity]
    files, directories = {}, {}
    for identity, node in by_id.items():
        if not node['kind']:
            continue
        path = pathname(identity) or '/'
        if node['kind'] == 2:
            directories[path] = node
        else:
            digest = hashlib.sha256()
            for chunk in content(node, current):
                digest.update(chunk)
            files[path] = dict(node, sha256=digest.hexdigest())
    return files, directories, owned


def snapshot_key(data, uuid, allow_zero=False):
    if not any(data) and allow_zero:
        return None
    require(len(data) == 40 and data[:16] == uuid and u32(data, 28) == 0, 'snapshot key identity')
    result = dict(snapshot_id=u64(data, 16), slot=u32(data, 24), slot_generation=u64(data, 32))
    require(result['snapshot_id'] > 0 and result['slot'] < 8 and result['slot_generation'] > 0, 'snapshot key bounds')
    return result


def request_key(data, uuid, allow_zero=False):
    if not any(data) and allow_zero:
        return None
    require(len(data) == 36 and data[:16] == uuid, 'request key identity')
    result = dict(client_slot=u32(data, 16), client_generation=u64(data, 20), request_seq=u64(data, 28))
    require(result['client_slot'] < 16 and result['client_generation'] > 0 and result['request_seq'] > 0, 'request key bounds')
    return result


def control(data, uuid):
    header(data, 0x43594643, 2, 256, 240)
    require(data[8:24] == uuid and not any(data[124:128] + data[244:248] + data[256:]), 'control identity/reserved bytes')
    result = {name: u64(data, offset) for name, offset in (
        ('control_generation', 24), ('live_view_epoch', 32), ('next_snapshot_id', 40), ('online_age_ns', 48),
        ('age_generation', 56), ('short_last_auto_age_ns', 64), ('gc_generation', 104),
        ('gc_base_checkpoint_generation', 112), ('protection_generation', 128), ('restore_target_epoch', 220),
        ('restore_old_epoch', 232), ('long_last_auto_age_ns', 248))}
    require(all(result[name] > 0 for name in ('control_generation', 'live_view_epoch', 'next_snapshot_id', 'protection_generation')), 'zero control counter')
    require(unpack('3Q', data, 72) == (86400 * SECOND, 3600 * SECOND, 21600 * SECOND)
            and u32(data, 100) == 1, 'snapshot retention policy mismatch')
    result.update(cleanup_freeze=u32(data, 96), gc_phase=u32(data, 120), restore_phase=u32(data, 136),
                  restore_mode=u32(data, 140), business_write_gate=u32(data, 228))
    require(result['cleanup_freeze'] in (0, 1) and result['business_write_gate'] in (0, 1)
            and result['gc_phase'] in (0, 1, 2) and result['restore_phase'] in (0, 1, 2)
            and result['restore_mode'] in (0, 1, 2), 'unknown control state')
    require(result['online_age_ns'] % SECOND == 0 and result['short_last_auto_age_ns'] <= result['online_age_ns']
            and result['long_last_auto_age_ns'] <= result['online_age_ns'], 'invalid online age')
    if result['gc_phase']:
        require(result['gc_generation'] > 0 and result['gc_base_checkpoint_generation'] > 0, 'invalid GC phase counters')
    source = snapshot_key(data[144:184], uuid, allow_zero=True)
    request = request_key(data[184:220], uuid, allow_zero=True)
    result.update(restore_source=source, restore_request=request)
    if result['restore_phase'] == 0:
        require(result['restore_mode'] == result['restore_old_epoch'] == result['restore_target_epoch'] == 0
                and source is request is None, 'idle restore contains intent')
    else:
        require(source is not None and request is not None and request['client_slot'] == 15
                and result['restore_mode'] in (1, 2) and result['business_write_gate'] == 1
                and result['restore_old_epoch'] > 0 and result['restore_target_epoch'] == result['restore_old_epoch'] + 1, 'invalid restore intent')
        expected_epoch = result['restore_old_epoch'] if result['restore_phase'] == 1 else result['restore_target_epoch']
        require(result['live_view_epoch'] == expected_epoch, 'restore epoch mismatch')
    return result


def requests(current, uuid):
    page = current(REQUEST_START)
    header(page, 0x43595251, 1, 512, 508)
    require(page[8:24] == uuid and unpack('6I', page, 24) == (64, 512, 16, 128, 1, 512)
            and not any(page[48:508] + page[2560:]), 'request object header')
    watermarks = []
    for index in range(16):
        row = page[512 + index * 128:640 + index * 128]
        checksum(row, 124)
        require(unpack('IHHI', row) == (0x4359574d, 1, 128, index)
                and not any(row[12:16] + row[32:124]) and u64(row, 16) > 0, 'request watermark')
        watermarks.append((u64(row, 16), u64(row, 24)))
    result, seen = [], set()
    for index in range(64):
        row = current(REQUEST_START + 1 + index // 8)[index % 8 * 512:(index % 8 + 1) * 512]
        checksum(row, 508)
        require(unpack('IHH', row) == (0x43594652, 1, 512) and not any(row[14:16] + row[84:88] + row[348:508]), 'request record header/reserved')
        state, operation, length = u32(row, 8), unpack('H', row, 12)[0], u32(row, 216)
        require(state in range(6) and length <= 128 and not any(row[220 + length:348]), 'request record state/payload')
        if state == 0:
            require(not any(row[8:508]), 'nonempty FREE request')
            continue
        require(operation in (0x20, 0x21, 0x22, 0x23, 0x27, 0x28, 0x29) and u32(row, 180) in (0, 1, 2), 'unknown request operation/mode')
        key = request_key(row[16:52], uuid)
        slot = key['client_slot']
        require((slot < 14 and index < 48) or (slot == 14 and 48 <= index < 56) or (slot == 15 and 56 <= index < 64), 'request partition violation')
        require((key['client_generation'], key['request_seq']) <= watermarks[slot]
                and key['client_generation'] == watermarks[slot][0], 'request exceeds watermark')
        identity = (slot, key['client_generation'], key['request_seq'])
        require(identity not in seen, 'duplicate durable request key')
        seen.add(identity)
        snapshot_key(row[88:128], uuid, allow_zero=True)
        transaction = row[144:176]
        if any(transaction):
            require(transaction[:16] == uuid and u64(transaction, 16) > 0 and u64(transaction, 24) > 0, 'request transaction identity')
        if state == 2:
            require(any(transaction), 'DONE request missing transaction')
        if state in (2, 3, 4):
            canonical = bytearray(row)
            canonical[184:216] = bytes(32)
            canonical[508:512] = bytes(4)
            require(hashlib.sha256(canonical).digest() == row[184:216], 'request result digest mismatch')
        else:
            require(not any(row[184:216]), 'nonterminal request contains result digest')
        result.append(dict(index=index, state=state, operation=operation, **key))
    for block in range(REQUEST_START + 9, REQUEST_START + 16):
        require(not any(current(block)), 'nonzero request recovery reserve')
    return result


def inspect(path: Path):
    with committed_volume(Path(path)) as (current, metadata):
        return inspect_committed(current, metadata)


def inspect_committed(current, metadata):
    uuid = bytes.fromhex(metadata['uuid'])
    bitmap = b''.join(current(BITMAP_START + index) for index in range(4))
    require(all(bitmap[block // 8] & (1 << (block % 8)) for block in range(FIRST_BUSINESS_BLOCK)), 'fixed/system capacity missing allocation')
    table = b''.join(current(INODE_START + index) for index in range(16))
    nodes = [inode(identity, table[identity * 256:(identity + 1) * 256], current) for identity in range(256)]
    files, directories, reachable = validate_view(nodes[:SYSTEM_ROOT], 0, bitmap, current)
    system_files, _, _ = validate_view(nodes[SYSTEM_ROOT:], SYSTEM_ROOT, bitmap, current)
    root = nodes[SYSTEM_ROOT]
    require(root['size'] == 512 and root['extents'] == [(0, DATA_START, 1)], 'invalid system root layout')
    require(set(system_files) == {'/' + name for name in SYSTEM_NAMES}
            and all(node['kind'] == 0 for node in nodes[229:]), 'unexpected system objects')
    for index, name in enumerate(SYSTEM_NAMES):
        require(system_files['/' + name]['inode'] == BOOT_INODE + index, 'system object identity mismatch')
        require(entry(current(DATA_START)[index * 128:(index + 1) * 128]) == (BOOT_INODE + index, nodes[BOOT_INODE + index]['generation'], name), 'system directory slot mismatch')
    boot = nodes[BOOT_INODE]
    require(boot['kind'] == boot['generation'] == 1 and boot['size'] == 64 and boot['extents'] == [(0, DATA_START + 1, 1)], 'invalid boot inode')
    body = current(DATA_START + 1)
    boot_epoch = u64(body, 24)
    require(body[:8] == b'CYXBOOT1' and body[8:24] == uuid and not any(body[36:])
            and u32(body, 32) == crc32c(body[:32]) and boot['durable_write_seq'] == boot_epoch, 'invalid durable boot body/sequence')
    cluster_records = []
    for index in range(2):
        node = nodes[226 + index]
        require(node['kind'] == node['generation'] == 1 and node['extents'] == ([] if node['size'] == 0 else [(0, DATA_START + 2 + index * 2048, (node['size'] + BLOCK - 1) // BLOCK)]), 'invalid cluster inode')
        stream, at, count = b''.join(content(node, current)), 0, 0
        while at < len(stream):
            require(at + 16 <= len(stream), 'truncated cluster record')
            head = stream[at:at + 16]
            magic, length, crc, head_crc = unpack('4sIII', head)
            require(magic == b'CXV1' and 0 < length <= 33200 and crc32c(head[:12]) == head_crc, 'cluster record header')
            at += 16
            require(at + length <= len(stream) and crc32c(stream[at:at + length]) == crc, 'cluster record body')
            cluster_records.append(stream[at:at + length].hex())
            at += length
            count += 1
        require(count == node['durable_write_seq'], 'cluster durable sequence mismatch')
    request = nodes[REQUEST_INODE]
    require(request['kind'] == 1 and request['size'] == 65536 and request['extents'] == [(0, REQUEST_START, 16)], 'invalid request object inode')
    request_records = requests(current, uuid)
    ctl = control(current(CONTROL_START), uuid)
    catalog = current(CATALOG_START)
    header(catalog, 0x43595343, 2, 512, 40)
    require(unpack('HHI', catalog, 8) == (448, 8, 0) and catalog[16:32] == uuid
            and u64(catalog, 32) > 0 and not any(catalog[44:512]), 'catalog header/identity')
    snapshots, ids = [], set()
    for slot in range(8):
        row = catalog[512 + slot * 448:512 + (slot + 1) * 448]
        state, slot_class = unpack('II', row)
        require(state in (0, 1, 2) and slot_class == (1 if slot < 6 else 2)
                and not any(row[68:72] + row[144:]), 'catalog state/class/reserved')
        if state == 0:
            # FREE retains only class and slot generation.
            require(not any(row[:4] + row[8:16] + row[24:]), 'nonempty FREE snapshot')
            continue
        snapshot_id, generation, captured_epoch, capture_lsn, age, retain = unpack('6Q', row, 8)
        require(snapshot_id not in ids and 0 < snapshot_id < ctl['next_snapshot_id'] and generation > 0
                and 0 < captured_epoch <= ctl['live_view_epoch'] and capture_lsn <= metadata['last_commit_lsn']
                and age <= ctl['online_age_ns'] and retain >= age and unpack('II', row, 56) == (1, 1)
                and u32(row, 64) < 16 and u64(row, 72) > 0 and u64(row, 80) > 0
                and u64(row, 128) > 0, 'catalog snapshot identity/retention')
        ids.add(snapshot_id)
        first = SNAPSHOT_START + slot * 15
        require(unpack('II', row, 88) == (first, first + 1), 'catalog slot address')
        dropped = u64(row, 136)
        require((state == 1 and dropped == 0) or (state == 2 and 0 < dropped <= metadata['last_commit_lsn']), 'catalog root-drop proof')
        descriptor = current(first)
        require(hashlib.sha256(descriptor).digest() == row[96:128], 'snapshot descriptor digest mismatch')
        header(descriptor, 0x43595352, 2, 128, 120)
        require(descriptor[8:24] == uuid and u64(descriptor, 24) == snapshot_id and u32(descriptor, 32) == slot
                and not any(descriptor[36:40] + descriptor[124:]) and unpack('3Q', descriptor, 40) == (generation, captured_epoch, capture_lsn)
                and unpack('4I', descriptor, 64) == (224, 14, first + 1, 0) and u64(descriptor, 112) == age, 'snapshot descriptor identity')
        image = b''.join(current(first + 1 + index) for index in range(14))
        require(hashlib.sha256(image).digest() == descriptor[80:112], 'snapshot inode image digest mismatch')
        # DELETING retains its immutable identity proof but is no longer an
        # openable persistent root. FREE_COMMITTED may already have cleared its
        # data bits; read-only inspection must not resurrect that old tree.
        historical_files, historical_dirs = {}, {}
        if state == 1:
            historical = [inode(identity, image[identity * 256:(identity + 1) * 256], current) for identity in range(224)]
            historical_files, historical_dirs, owned = validate_view(historical, 0, bitmap, current)
            reachable.update(owned)
        snapshots.append(dict(slot=slot, snapshot_id=snapshot_id, slot_generation=generation, state=state,
                              captured_live_view_epoch=captured_epoch, capture_commit_lsn=capture_lsn,
                              created_online_age_ns=age, retain_until_ns=retain, root_drop_commit_lsn=dropped,
                              files=historical_files, directories=historical_dirs))
    if ctl['restore_source']:
        require(any(all(row[name] == value for name, value in ctl['restore_source'].items()) for row in snapshots), 'restore source missing from catalog')
    allocated = {block for block in range(FIRST_BUSINESS_BLOCK, COUNT) if bitmap[block // 8] & (1 << (block % 8))}
    return dict(metadata, format_version=2, boot_epoch=boot_epoch, files=files, directories=directories,
                system_files=system_files, cluster_records=cluster_records, control=ctl, snapshots=snapshots,
                request_records=request_records, allocated_business_blocks=len(allocated),
                reachable_business_blocks=len(reachable), garbage_blocks=len(allocated - reachable))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.image), ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
