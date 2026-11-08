#!/usr/bin/env python3
"""Independent A01 configuration-1.3 verifier; producer booleans never confer PASS."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

from verify_v13_boot_recovery import require

MAGIC = 0x4359413031463031
VERSION = 'v15-a01-authority-v1'
WORDS = 256


def verify_formal_samples(formal: bytes, boot: bytes) -> dict:
    require(len(formal) == WORDS * 8 and len(boot) == 512, 'wrong A01 formal bank size')
    f, b = struct.unpack('<256Q', formal), struct.unpack('<64Q', boot)
    require(f[:3] == (MAGIC, 1, WORDS), 'missing A01 actual authority/architecture evidence')
    require(f[3:8] == (b[5], b[6], b[7], b[14], b[15]) and f[16:30] == b[32:46],
            'A01 formal bank differs from run/boot identity')
    require(f[3] in (0, 1, 2, 3) and f[10] == 0, 'A01 authority ordering violation')
    require(not any(f[11:16] + f[30:32] + f[152:160] + f[185:]),
            'nonzero A01 reserved words')
    el0 = {}
    for cpu in range(4):
        r = f[32 + cpu * 24:56 + cpu * 24]
        require(r[0] == 2 and r[1] == cpu and r[2] > 0 and r[3] == 4
                and r[4] & 0x1005 == 0x1005 and r[6] != 0 and r[6] & 0xfff == 0
                and r[7] >= 0xffff000000000000 and r[7] & 0x7ff == 0
                and r[8] & 0xff == cpu and not any(r[9:12]) and r[23] == 0,
                f'CPU{cpu} lacks actual EL1/MMU/vector initialization')
        if not any(r[12:23]):
            continue
        require(r[12] == 2 and r[13] > r[2] and r[14] & 0x1f == 0
                and r[16] in (8, 9) and 0 < r[17] < 0x40000000
                and 0x40000000 <= r[18] < 0x80000000 and r[18] & 0xfff == 0
                and r[19] & ((1 << 48) - 1) == r[18] and r[20] & 0x80 != 0
                and r[21] == 4 and r[22] in (1, 2),
                f'CPU{cpu} lacks an actual protected EL0 return')
        require(r[16] != 8 or r[15] >> 26 == 0x15, 'EL0 completion was not SVC64')
        el0[cpu] = {'role': r[22], 'root': r[18], 'return_ticks': r[13]}
    require(any(cpu in (2, 3) and row['role'] == 1 for cpu, row in el0.items()),
            'business EL0 never actually ran')
    if f[3] in (0, 3):
        require(1 in el0 and el0[1]['role'] == 2, 'control EL0 model never actually ran')
        require(all(el0[1]['root'] != row['root'] for cpu, row in el0.items() if row['role'] == 1),
                'control/business EL0 share an address-space root')
    if f[3] == 0:
        require(f[8] > 0 and f[9] > 0, 'missing actual new AI key/publication')
        key, pub = f[128:152], f[160:185]
        require(key[0] == pub[0] == 2 and b[6] > 0 and 0 < b[7] <= b[14] <= b[15]
                and key[1] >= b[15] and pub[1] >= key[1],
                'AI key/publication preceded durable BootEpoch/model activation')
        require(key[2] == pub[2] == b[6] and key[3] > 0 and pub[3] > 0
                and key[4] > 0 and pub[4] > 0 and min(key[5:7] + pub[5:7]) > 0
                and key[7] < 4 and pub[7] < 4 and key[8] > 0 and pub[10] > 0
                and key[9] in range(1, 17) and pub[11] in range(1, 17)
                and key[10] > 0 and pub[12] > 0 and key[11] == 0
                and all(any(key[i:i + 4]) for i in (12, 16))
                and all(any(pub[i:i + 4]) for i in (13, 17))
                and pub[8] > 0 and pub[9] > key[20] and pub[21] > 0
                and key[21] > 0 and key[22] > 0 and pub[22] > 0 and pub[23] > 0
                and key[23] & (1 << key[7]) and pub[24] & (1 << pub[7]),
                'AI key/publication missing complete epoch/target/model/root/owner identity')
        if key[3] == pub[3]:
            require(key[4] <= pub[4], 'first published decision predates first registered decision')
        if key[3:5] == pub[3:5]:
            require(key[5:7] == pub[5:7] and key[9:11] == pub[11:13]
                    and key[8] == pub[10]
                    and key[12:16] == pub[13:17] and key[16:20] == pub[17:21],
                    'same DecisionKey changed candidate/model/target at publication')
    else:
        require(f[8] == f[9] == 0 and not any(f[128:152] + f[160:185]),
                'failed boot created a new AI key or publication')
    return {'mode': f[3], 'architecture_verified': True, 'el0': el0,
            'key_count': f[8], 'publication_count': f[9],
            'first_key_ticks': f[129], 'first_publication_ticks': f[161]}


def verify_acceptance(directory: Path, *, source_root: Path, qemu_source: Path) -> dict:
    from check_prototype_evidence import safe_path, sha256
    from verify_v13_boot_reboots import verify_chain
    chain = verify_chain(directory, source_root=source_root, qemu_source=qemu_source,
                         formal=True)
    root = Path(directory).resolve(strict=True)
    images, sources, boots = set(), set(), {}
    for name in chain['boots']:
        child = root / name
        get = lambda filename: safe_path(child, filename)
        boot = get('last.bin').read_bytes()
        facts = verify_formal_samples(get('formal-last.bin').read_bytes(), boot)
        images.add(sha256(get('node-a.elf')))
        sources.add(sha256(get('source-manifest.json')))
        boots[name] = dict(facts, issued_epoch=chain['boots'][name]['issued_epoch'],
                           run_nonce=chain['boots'][name]['run_nonce'],
                           formal_sha256=sha256(get('formal-last.bin')))
    require(len(images) == len(sources) == 1, 'A01 mixed image/source')
    return dict(verifier_version=VERSION, test_id='A01', status='PASS',
                native_execution_verified=True, native_acceptance_status='PASS',
                runtime_truth_attested=False, full_v13_acceptance=False,
                scope='A01 configuration 1.3 actual boot/EL/authority and same-disk epoch continuity',
                image_sha256=images.pop(), source_sha256=sources.pop(),
                reboot_chain_verified=True, boots=boots)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory', 'source-root', 'qemu-source'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_acceptance(args.directory, source_root=args.source_root,
                                   qemu_source=args.qemu_source)
    except (OSError, ValueError, TypeError, KeyError, struct.error) as error:
        print(json.dumps(dict(status='FAIL', test_id='A01', error=str(error),
                              native_acceptance_status='NOT_RUN')))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
