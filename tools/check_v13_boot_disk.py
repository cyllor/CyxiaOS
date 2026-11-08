"""A01 boot/cluster identity over a fully validated ordinary filesystem.

The reserved-only decoder remains unchanged. Ordinary directories, tombstones
and inode reuse are checked by the general raw filesystem oracle in the same
committed-volume view, rather than accepted through a root-size allowlist.
"""
from pathlib import Path
import struct

from check_v13_disk import BLOCK, committed_volume, crc32c, inspect_reserved_committed
from check_v13_filesystem import inspect_committed
from verify_smp import require

TOOL_FILES = ('check_v13_boot_disk.py', 'check_v13_filesystem.py', 'check_v13_disk.py')


def inspect(path: Path) -> dict:
    with committed_volume(path) as (current, metadata):
        filesystem = inspect_committed(current, metadata)
        root = filesystem['directories']['/']
        files = filesystem['files']
        if root['size'] <= 384:
            # Ordinary creation starts at slot3 and directory removal never
            # shrinks size. These roots retain the full original contract.
            return inspect_reserved_committed(current, metadata)
        for identity, name in enumerate(
                ('/.cyxia-boot', '/.cyxia-cluster-a', '/.cyxia-cluster-b'), 1):
            node = files.get(name) or filesystem['directories'].get(name)
            require(node is None or node['inode'] == identity,
                    'ordinary inode impersonates reserved root name')
        boot = files.get('/.cyxia-boot')
        require(root['durable_write_seq'] > 0 and boot is not None
                and filesystem['boot_epoch'] > 0, 'missing durable boot identity')
        live_root_entries = sum(node['inode'] != 0 and node['parent'] == 0
                                for node in (*files.values(), *filesystem['directories'].values()))
        require(root['durable_write_seq'] >= live_root_entries,
                'durable root sequence below live entries')
        require(boot['inode'] == boot['generation'] == 1
                and boot['parent'] == 0 and boot['parent_generation'] == 1,
                'wrong reserved boot identity')
        # Preserve zero padding in the reserved root allocation. Its logical
        # size and durable mutation sequence are independent once tombstones
        # and ordinary directory slots exist.
        remaining = root['size']
        for _, start, count in root['extents']:
            for block in range(start, start + count):
                data = current(block)
                used = min(remaining, BLOCK)
                require(not any(data[used:]), 'root directory unused suffix not zero')
                remaining -= used
        table = b''.join(current(4102 + index) for index in range(16))
        sizes, records = [], []
        names = ('/.cyxia-cluster-a', '/.cyxia-cluster-b')
        require(names[1] not in files or names[0] in files,
                'cluster-b allocated without cluster-a')
        for index, name in enumerate(names):
            node = files.get(name)
            kind, generation = struct.unpack_from('<H2xQ', table, (index + 2) * 256 + 4)
            require(generation == 1, 'reserved cluster inode generation changed')
            if node is None:
                require(kind == 0, 'reserved cluster inode has no directory reference')
                size = sequence = 0
            else:
                require(node['inode'] == index + 2 and node['generation'] == 1
                        and node['parent'] == 0 and node['parent_generation'] == 1,
                        'wrong reserved cluster identity')
                size, sequence = node['size'], node['durable_write_seq']
                sizes.append(size)
            start = 4120 + index * 2048
            stream = b''.join(current(start + block) for block in range(2048))
            require(not any(stream[size:]), 'cluster file unused suffix not zero')
            at = count = 0
            while at < size:
                require(at + 16 <= size, 'truncated cluster record header')
                header = stream[at:at + 16]
                magic, length, body_crc, header_crc = struct.unpack('<4sIII', header)
                require(magic == b'CXV1' and 0 < length <= 33200
                        and crc32c(header[:12]) == header_crc,
                        'invalid cluster record header/CRC')
                at += 16
                require(at + length <= size, 'truncated cluster record body')
                body = stream[at:at + length]
                require(crc32c(body) == body_crc, 'cluster record body CRC mismatch')
                records.append(body.hex())
                at += length
                count += 1
            require(count == sequence, 'cluster inode durable sequence differs from record count')
        return dict(metadata, boot_epoch=filesystem['boot_epoch'],
                    cluster_files=len(sizes), cluster_file_sizes=sizes,
                    cluster_records=records)
