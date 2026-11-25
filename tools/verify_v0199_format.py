#!/usr/bin/env python3
"""Two fresh native QEMU processes, one dedicated all-zero scratch image.

Boot 1 runs the frozen baseline-v1 §9.2.1 formatter contract against a real
VirtIO block device: full 512 MiB zero scan, fixed TEST manifest publication,
and the exact device FLUSH ordering (34 metadata writes -> FLUSH -> 4096 log
writes -> FLUSH -> superblock 0 -> FLUSH -> superblock 1 -> FLUSH), proven from
a physical dump of the guest device operation trace. Boot 2 accepts the
persisted image after a forced process stop and validates it on disk without
writing. Both boots run file_mount_v1 validation and reject a reformat of
existing content before any write. Stock QEMU 10.2.2 is sufficient; no PMU
accounting is claimed. Never accepts an existing disk path or production
authority. No production format/mount claim.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import verify_smp

BLOCK = 4096
CAPACITY = 512 * 1024 * 1024
BLOCK_COUNT = 131072
UUID = b'CYX-TEST-FORMAT!'
ROOT = 4118
BOOT_HOME = 4119
RECEIPTS_HOME = 4120
ACL_HOME = 4127
SECURITY_HOME = 4131
MAGIC = struct.unpack('<Q', b'CYXFMT01')[0]
TRACE_ENTRIES = 4136
TRACE_WRITE = 1 << 32
TRACE_FLUSH = 2 << 32
FLUSH_BOUNDARIES = (34, 4130, 4131, 4132)


def crc(b):
    c = 0xffffffff
    for byte in b:
        c ^= byte
        for _ in range(8):
            c = (c >> 1) ^ (0x82f63b78 if c & 1 else 0)
    return c ^ 0xffffffff


def put(b, at, fmt, *v):
    struct.pack_into('<' + fmt, b, at, *v)


def superblock():
    b = bytearray(BLOCK)
    put(b, 0, 'IHHII', 0x43594653, 1, 80, 4096, BLOCK_COUNT)
    b[16:32] = UUID
    put(b, 32, 'QQQIIIIII', 1, 0, 1, 4098, 4102, 4118, 256, 0, 0)
    put(b, 76, 'I', crc(b))
    return bytes(b)


def security_state():
    # Initial trusted-manifest image: generation 1, boot epoch 0, config
    # generation 1 with the fixed test digest; all service generations 1.
    b = bytearray(BLOCK)
    put(b, 0, 'IHH', 0x43595353, 2, 248)
    b[8:24] = UUID
    put(b, 24, 'QQQQQQ', 1, 1, 1, 1, 0, 0)
    put(b, 80, 'Q', 1)
    b[88:120] = bytes([0x5a]) * 32
    put(b, 120, '16Q', *([1] * 16))
    put(b, 72, 'I', crc(b))
    return bytes(b)


def boot_store(epoch):
    b = bytearray(BLOCK)
    put(b, 0, 'IHH', 0x43594245, 1, 40)
    b[8:24] = UUID
    put(b, 24, 'Q', epoch)
    put(b, 32, 'I', crc(b))
    return bytes(b)


def inode(kind=0, generation=0, size=0, physical=0, count=0):
    b = bytearray(256)
    put(b, 0, 'IHHQ', 0x4359494e, kind, 0, generation)
    if kind:
        put(b, 16, 'QQHHIQ', size, 0, int(bool(count)), 0, 0, 1)
        if count:
            put(b, 48, 'III', 0, physical, count)
    put(b, 252, 'I', crc(b))
    return bytes(b)


def index_block():
    b = bytearray(BLOCK)
    put(b, 0, 'IHH', 0x43595349, 4, 64)
    b[8:24] = UUID
    put(b, 24, 'QQ', 0, 1)
    for i in range(16):
        put(b, 64 + i * 24, 'IIQQ', 0, 0, 0, i + 1)
    put(b, 4092, 'I', crc(b))
    return bytes(b)


def acl_store():
    acl = bytearray(4 * BLOCK)
    for i in range(256):
        b = bytearray(64)
        if i == 0:
            owner, system = 1 << 14, 0
        elif 2 <= i <= 5:
            owner, system = 0, (1 << 8) | (1 << 9) | (1 << 13)
        else:
            owner, system = 0, 0
        live = int(i == 0 or 2 <= i <= 5)
        put(b, 0, 'IIQQQIIQIII', i, live, live, live, live, owner, system, live, 0, 0, 0)
        put(b, 60, 'I', crc(b))
        acl[i * 64:(i + 1) * 64] = b
    return bytes(acl)


def root_directory():
    # One 4 KiB root block: 256 sealed empty slots (inode_id=0xFFFFFFFF+CRC).
    root = bytearray(BLOCK)
    for s in range(32):
        slot = bytearray(128)
        put(slot, 0, 'I', 0xffffffff)
        put(slot, 124, 'I', crc(slot))
        root[s * 128:(s + 1) * 128] = slot
    return bytes(root)


def fixed_metadata():
    # Independent reference derived from the frozen §9.2/§9.2.1 layouts and
    # the fixed TEST manifest, not from the formatter implementation.
    bitmap = bytearray(4 * BLOCK)
    for k in list(range(4118)) + list(range(ROOT, SECURITY_HOME + 1)):
        bitmap[k // 8] |= 1 << (k % 8)
    inodes = [inode(2, 1, 128, ROOT, 1), inode(),
              inode(1, 1, BLOCK, BOOT_HOME, 1),
              inode(1, 1, 7 * BLOCK, RECEIPTS_HOME, 7),
              inode(1, 1, 4 * BLOCK, ACL_HOME, 4),
              inode(1, 1, BLOCK, SECURITY_HOME, 1)]
    inodes += [inode()] * (256 - len(inodes))
    return {4098: bytes(bitmap), 4102: b''.join(inodes),
            ROOT: root_directory(), BOOT_HOME: boot_store(0),
            RECEIPTS_HOME: bytes(6 * BLOCK) + index_block(),
            ACL_HOME: acl_store(), SECURITY_HOME: security_state()}


def expected_trace():
    metadata = (list(range(4098, 4102)) + list(range(4102, 4118))
                + [ROOT, BOOT_HOME] + list(range(RECEIPTS_HOME, RECEIPTS_HOME + 7))
                + list(range(ACL_HOME, ACL_HOME + 4)) + [SECURITY_HOME])
    assert len(metadata) == 34
    ops = [(TRACE_WRITE, b) for b in metadata] + [(TRACE_FLUSH, 0)]
    ops += [(TRACE_WRITE, b) for b in range(2, 4098)]
    ops += [(TRACE_FLUSH, 0), (TRACE_WRITE, 0), (TRACE_FLUSH, 0),
            (TRACE_WRITE, 1), (TRACE_FLUSH, 0)]
    assert len(ops) == TRACE_ENTRIES
    return tuple(kind | block for kind, block in ops)


def create_disk(path):
    assert crc(b'123456789') == 0xe3069283 and len(UUID) == 16
    with path.open('xb') as f:
        f.truncate(CAPACITY)
    require_zero_file(path, 0, BLOCK_COUNT)


def require_zero_file(path, first_block, blocks):
    with path.open('rb') as f:
        require_zero(f, first_block, blocks)


def require_zero(f, first_block, blocks):
    f.seek(first_block * BLOCK)
    remaining = blocks * BLOCK
    while remaining:
        n = min(remaining, 1024 * 1024)
        verify_smp.require(f.read(n) == bytes(n), 'scratch region is not all zero')
        remaining -= n


def check_disk(path, out):
    require = verify_smp.require
    with path.open('rb') as f:
        original = f.read(2 * BLOCK)
        require(original == superblock() * 2, 'published superblock pair differs from frozen reference')
        for block, data in fixed_metadata().items():
            f.seek(block * BLOCK)
            require(f.read(len(data)) == data, 'formatted metadata differs at block ' + str(block))
        require_zero(f, 2, 4096)
        require_zero(f, SECURITY_HOME + 1, BLOCK_COUNT - SECURITY_HOME - 1)
    (out / 'superblocks.bin').write_bytes(original)
    (out / 'metadata.bin').write_bytes(b''.join(
        data for _, data in sorted(fixed_metadata().items())))


class FormatFixture:
    # verify_smp.run gates scratch-disk attachment on this historical flag.
    scratch_epoch_disk = True
    completion = b'V0199_FORMAT_FIXTURE_PASS production=false\n'

    def __init__(self, boot):
        self.boot = boot

    @staticmethod
    def profile(elf):
        return verify_smp.profile(elf)

    @staticmethod
    def metadata():
        return dict(scope='v0199-native-format-fixture', production_format=False,
                    signed_catalog=False, production_mount=False,
                    production_filesystem_verified=False, durable_boot_epoch=False)

    @staticmethod
    def success():
        return dict(native_format_flush_fixture_verified=True, native_smp_mechanism_verified=False)

    def validate(self, serial, page, cpu_count):
        require = verify_smp.require
        require(cpu_count == 4 and len(page) == 4096, 'wrong topology/evidence extent')
        w = struct.unpack('<512Q', page)
        boot = self.boot
        reads, writes, flushes = (131114, 4132, 4) if boot == 1 else (41, 0, 0)
        trace_len = TRACE_ENTRIES if boot == 1 else 0
        require(w[0] == MAGIC and w[1] == boot and w[2] == 1, 'wrong format fixture identity/seal')
        require(w[3] == BLOCK_COUNT and w[4] == BLOCK_COUNT * 8, 'wrong device capacity evidence')
        require(w[5:9] == (reads, writes, flushes, trace_len), 'wrong block I/O or trace accounting')
        require(w[9:24] == (ROOT, 13, 14, 5, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1),
                'wrong formatted structure/mount evidence')
        boundaries = FLUSH_BOUNDARIES if boot == 1 else (0, 0, 0, 0)
        require(w[24:28] == boundaries, 'wrong §9.2.1 FLUSH boundary write counts')
        require(page[32 * 8:36 * 8] == hashlib.sha256(superblock()).digest(),
                'committed superblock digest mismatch')
        require(page[36 * 8:40 * 8] == hashlib.sha256(security_state()).digest(),
                'committed security state digest mismatch')
        require(page[40 * 8:44 * 8] == hashlib.sha256(boot_store(0)).digest(),
                'committed boot epoch store digest mismatch')
        require(w[44] == 256 and w[45] == 16, 'wrong ACL/principal inspection accounting')
        if boot == 1:
            require(0x40200000 <= w[46] and w[46] % 8 == 0 and w[46] + TRACE_ENTRIES * 8 <= 0x44000000,
                    'device trace span outside the kernel DMA arena')
            require(w[47] == TRACE_ENTRIES * 8, 'wrong device trace extent')
        else:
            require(w[28:32] == (0, 0, 0, 0) and w[47] == 0, 'received boot must not write a trace')
        require(all(v == 0 for v in w[48:]), 'nonzero reserved evidence')
        require(b'FAIL' not in serial and b'SMP_ERROR' not in serial, 'guest reported failure')
        lines = serial.decode('ascii').splitlines()

        def rows(label):
            return verify_smp._rows(lines, label)

        require(rows('SMP_BOOT_OK') == [(4, 15, 0)], 'missing boot handshake')
        require(rows('V0199_FORMAT_DEVICE') == [(BLOCK_COUNT * 8, BLOCK_COUNT, 0)], 'wrong device evidence')
        require(rows('V0199_FORMAT_BOOT') == [(boot, int(boot == 2), 0)], 'wrong boot mode evidence')
        require(rows('V0199_FORMAT_MOUNT') == [(5, 14, 0)], 'wrong on-disk mount evidence')
        require(rows('V0199_FORMAT_REFORMAT_REJECTED') == [(1, 1, 0)], 'missing reformat rejection')
        require(rows('V0199_FORMAT_COMMITTED') == [(boot, flushes, writes)], 'UART/QMP commit disagreement')
        if boot == 1:
            require(rows('V0199_FORMAT_SCAN') == [(BLOCK_COUNT, BLOCK_COUNT + 2, 0)], 'missing full zero scan')
            require(rows('V0199_FORMAT_PUBLISHED') == [(1, 1, 0)], 'wrong initial superblock publication')
            require(rows('V0199_FORMAT_FLUSH') == [(i + 1, b, i + 1) for i, b in enumerate(FLUSH_BOUNDARIES)],
                    'wrong §9.2.1 FLUSH ordering evidence')
        else:
            require(rows('V0199_FORMAT_RECEIVED') == [(1, 1, 0)], 'wrong persisted image acceptance')
            require(not any(line.startswith(('V0199_FORMAT_SCAN ', 'V0199_FORMAT_PUBLISHED ', 'V0199_FORMAT_FLUSH '))
                            for line in lines), 'received boot performed format publication')
        scope = 'V0199_FORMAT_SCOPE production_format=false signed_catalog=false production_mount=false'
        require(lines.count(scope) == 1 and sum(line.startswith('V0199_FORMAT_SCOPE') for line in lines) == 1,
                'fixture scope must not claim production format authority')
        require(lines.count('V0199_FORMAT_FIXTURE_PASS production=false') == 1, 'missing/duplicate completion')

        def first(label):
            return next(i for i, line in enumerate(lines) if line.startswith(label + ' '))

        order = ['V0199_FORMAT_DEVICE', 'V0199_FORMAT_BOOT']
        order += ['V0199_FORMAT_SCAN', 'V0199_FORMAT_PUBLISHED', 'V0199_FORMAT_FLUSH'] if boot == 1 \
            else ['V0199_FORMAT_RECEIVED']
        order += ['V0199_FORMAT_MOUNT', 'V0199_FORMAT_REFORMAT_REJECTED', 'V0199_FORMAT_COMMITTED']
        positions = [first(label) for label in order]
        require(positions == sorted(positions), 'evidence published out of fixture order')
        require(positions[-1] < lines.index(scope) < lines.index('V0199_FORMAT_FIXTURE_PASS production=false'),
                'scope/completion published out of order')
        return dict(boot=boot, block_reads=reads, block_writes=writes, actual_flush_completions=flushes,
                    full_zero_scan_verified=boot == 1, flush_boundary_writes=list(boundaries),
                    formatted_v1_structure_verified=True, on_disk_mount_validation_verified=True,
                    system_objects_verified=4, acl_slots_verified=256, reformat_rejected=True,
                    superblock_generation=1, checkpoint_lsn=0, boot_epoch=0,
                    device_trace_entries=trace_len)

    def capture_extra(self, qmp, out, page):
        # Runs after validate() with all four CPUs stopped. Boot 1 dumps the
        # actual device operation trace from guest physical memory and checks
        # every entry against the independent §9.2.1 reference sequence.
        w = struct.unpack('<512Q', page)
        require = verify_smp.require
        if self.boot == 2:
            require(w[8] == 0 and w[47] == 0, 'received boot wrote a device trace')
            return dict(device_trace_physical_dump_verified=False, received_boot_write_free_verified=True)
        path = out / 'device-trace.bin'
        qmp.execute('pmemsave', {'val': w[46], 'size': w[47], 'filename': str(path)})
        raw = path.read_bytes()
        require(len(raw) == TRACE_ENTRIES * 8, 'incomplete device trace physical dump')
        require(struct.unpack('<%dQ' % TRACE_ENTRIES, raw) == expected_trace(),
                'device FLUSH/write ordering differs from the frozen §9.2.1 sequence')
        require(hashlib.sha256(raw).digest() == page[28 * 8:32 * 8], 'trace digest disagrees with QMP page')
        return dict(device_trace_physical_dump_verified=True,
                    device_trace_sha256=hashlib.sha256(raw).hexdigest(),
                    native_flush_order_verified=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    disk = out / 'scratch.raw'
    result = dict(status='FAIL', scope='§9.2.1 format fixture; no production format authority', boots=[])
    try:
        create_disk(disk)
        previous = verify_smp.sha(disk)
        for boot in (1, 2):
            capture = out / f'boot-{boot}'
            summary = verify_smp.run(a.elf, capture, 60, 4, acceptance=FormatFixture(boot),
                                     ram_mib=1024, scratch_disk=disk)
            result['boots'].append(summary)
            verify_smp.require(summary['status'] == 'PASS' and summary.get('forced_process_stop'),
                               'native format or forced process stop failed')
            verify_smp.require(summary.get('scratch_disk_before_sha256') == previous,
                               'disk changed between processes')
            check_disk(disk, capture)
            previous = verify_smp.sha(disk)
            verify_smp.require(summary.get('scratch_disk_after_sha256') == previous,
                               'disk changed after capture')
        result['status'] = 'PASS'
        result['native_format_flush_order_verified'] = True
        result['cross_process_format_durability_verified'] = True
        result['on_disk_mount_validation_verified'] = True
        result['reformat_rejection_verified'] = True
    except (OSError, ValueError, RuntimeError) as e:
        result['error'] = str(e)
    (out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
