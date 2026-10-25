"""Independent read-only ordinary-volume decoder over the accepted redo prefix."""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
from check_v13_disk import BLOCK, COUNT, checksum, committed_volume, crc32c
from verify_smp import require

DATA_START = 4118
ORDINARY_START = 8216
RESERVED_NAMES = ('.cyxia-boot', '.cyxia-cluster-a', '.cyxia-cluster-b')


def inode(identity: int, slot: bytes) -> dict:
    checksum(slot, 252)
    magic, kind = struct.unpack_from('<IH', slot)
    generation, size, sequence = struct.unpack_from('<QQQ', slot, 8)
    count, = struct.unpack_from('<H', slot, 32)
    parent, parent_generation = struct.unpack_from('<IQ', slot, 36)
    extents = [struct.unpack_from('<III', slot, 48+index*12) for index in range(16)]
    require(magic == 0x4359494e and kind in (0, 1, 2) and generation > 0, 'invalid inode identity')
    require(slot[6:8] == slot[34:36] == bytes(2) and not any(slot[240:252]), 'inode reserved bytes')
    if kind == 0:
        require(identity != 0 and not any(slot[16:252]), 'allocated fields in free inode')
    else:
        require(parent < 256 and parent_generation > 0 and (identity == 0 or parent != identity), 'invalid inode parent')
        require(count <= 16 and not any(any(extent) for extent in extents[count:]), 'inode extent count/suffix')
        require((kind == 1 and size <= 8*1024*1024)
                or (kind == 2 and size <= 32768 and size % 128 == 0), 'inode size/type bound')
        end = 0
        for logical, start, blocks in extents[:count]:
            require(logical == end and blocks > 0 and DATA_START <= start < start+blocks <= COUNT, 'invalid inode extent')
            end += blocks
        require(end == (size+BLOCK-1)//BLOCK, 'inode extent coverage mismatch')
    return dict(inode=identity, kind=kind, generation=generation, size=size,
                durable_write_seq=sequence, parent=parent, parent_generation=parent_generation,
                extents=extents[:count])


def entry(slot: bytes):
    checksum(slot, 124)
    identity, length = struct.unpack_from('<IH', slot)
    generation, = struct.unpack_from('<Q', slot, 8)
    require(length <= 63 and slot[6:8] == bytes(2) and not any(slot[16+length:124]), 'directory entry padding')
    name = slot[16:16+length].decode('utf-8')
    if identity == 0xffffffff:
        require(length == generation == 0, 'invalid empty directory entry')
        return None
    require(identity < 256 and generation > 0 and name not in ('', '.', '..')
            and '\0' not in name and '/' not in name, 'invalid directory entry identity/name')
    return identity, generation, name


def inspect(path: Path) -> dict:
    with committed_volume(path) as (current, metadata):
        table = b''.join(current(4102+index) for index in range(16))
        nodes = [inode(identity, table[identity*256:(identity+1)*256]) for identity in range(256)]
        root = nodes[0]
        require((root['kind'], root['generation'], root['parent'], root['parent_generation']) == (2, 1, 0, 1), 'invalid root identity')
        if root['size']:
            require(root['extents'] and root['extents'][0] == (0, DATA_START, 1), 'invalid reserved root extent')
        expected = bytearray(16384)
        for block in range(DATA_START):
            expected[block//8] |= 1 << (block % 8)
        for identity, node in enumerate(nodes):
            if not node['kind']:
                continue
            if identity == 1:
                require(node['kind'] == node['generation'] == 1 and node['size'] == 64
                        and node['extents'] == [(0, 4119, 1)], 'invalid boot inode')
            if identity in (2, 3):
                require(node['kind'] == 1 and node['size'] > 0 and node['parent'] == 0 and node['parent_generation'] == 1
                        and node['extents'] == [(0, 4120+(identity-2)*2048, (node['size']+BLOCK-1)//BLOCK)], 'invalid cluster inode')
            for _, start, blocks in node['extents']:
                for block in range(start, start+blocks):
                    require(not expected[block//8] & (1 << (block % 8)), 'duplicate physical ownership')
                    require((identity < 4 and not (identity == 0 and block != DATA_START)) or block >= ORDINARY_START,
                            'ordinary inode uses reserved physical ownership')
                    expected[block//8] |= 1 << (block % 8)
            if identity:
                parent = nodes[node['parent']]
                require(parent['kind'] == 2 and parent['generation'] == node['parent_generation'], 'stale inode parent')
                ancestors = {identity}
                ancestor = node['parent']
                while ancestor:
                    require(ancestor not in ancestors, 'cyclic inode parent')
                    ancestors.add(ancestor)
                    parent = nodes[ancestor]
                    next_parent = nodes[parent['parent']]
                    require(next_parent['kind'] == 2 and next_parent['generation'] == parent['parent_generation'], 'stale ancestor parent')
                    ancestor = parent['parent']
        require(b''.join(current(4098+i) for i in range(4)) == expected, 'volume allocation bitmap disagrees with inode ownership')
        require(nodes[1]['kind'] != 0 or root['size'] == 0, 'root allocated without durable boot inode')

        def content(node):
            remaining = node['size']
            for _, start, blocks in node['extents']:
                for block in range(start, start+blocks):
                    data = current(block)
                    yield data[:min(remaining, BLOCK)]
                    remaining -= min(remaining, BLOCK)

        references = {}
        for parent, node in enumerate(nodes):
            if node['kind'] != 2:
                continue
            directory = b''.join(content(node))
            names = set()
            for index in range(node['size']//128):
                found = entry(directory[index*128:(index+1)*128])
                if found is None:
                    continue
                identity, generation, name = found
                require(name not in names, 'duplicate directory name')
                names.add(name)
                target = nodes[identity]
                require(identity != 0 and target['kind'] != 0 and target['generation'] == generation
                        and target['parent'] == parent and target['parent_generation'] == node['generation'], 'stale directory reference')
                if identity < 4:
                    require(parent == 0 and index == identity-1 and name == RESERVED_NAMES[identity-1], 'reserved directory reference mismatch')
                else:
                    require(parent != 0 or index >= 3, 'ordinary directory reference occupies reserved slot')
                require(identity not in references, 'duplicate inode directory reference')
                references[identity] = parent, name
        require(set(references) == {identity for identity, node in enumerate(nodes) if identity and node['kind']}, 'missing inode directory reference')
        paths = {0: ''}
        def pathname(identity):
            if identity not in paths:
                parent, name = references[identity]
                paths[identity] = pathname(parent)+'/'+name
            return paths[identity]
        files, directories = {}, {}
        for identity, node in enumerate(nodes):
            if node['kind'] == 0:
                continue
            name = pathname(identity) or '/'
            if node['kind'] == 2:
                directories[name] = node
                continue
            digest = hashlib.sha256()
            for block in content(node):
                digest.update(block)
            files[name] = dict(node, sha256=digest.hexdigest())
            if identity in (2, 3):
                stream = b''.join(content(node)); at = records = 0
                while at < len(stream):
                    require(at+16 <= len(stream), 'truncated cluster header')
                    head = stream[at:at+16]
                    magic, length, body_crc, header_crc = struct.unpack('<4sIII', head)
                    require(magic == b'CXV1' and 0 < length <= 33200 and crc32c(head[:12]) == header_crc, 'invalid cluster header')
                    at += 16
                    require(at+length <= len(stream) and crc32c(stream[at:at+length]) == body_crc, 'invalid cluster body')
                    at += length; records += 1
                require(records == node['durable_write_seq'], 'cluster record count/sequence mismatch')
        epoch = 0
        if nodes[1]['kind']:
            body = current(4119)
            epoch, = struct.unpack_from('<Q', body, 24)
            require(body[:8] == b'CYXBOOT1' and body[8:24].hex() == metadata['uuid'] and epoch > 0
                    and not any(body[36:]) and struct.unpack_from('<I', body, 32)[0] == crc32c(body[:32])
                    and nodes[1]['durable_write_seq'] == epoch, 'invalid durable boot body/sequence')
        return dict(metadata, boot_epoch=epoch, files=files, directories=directories)
