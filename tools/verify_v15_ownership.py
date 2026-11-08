#!/usr/bin/env python3
"""A03 actual-owner chain structure. This module alone never confers native PASS.

Full acceptance additionally requires exact model/Plan replay and stopped QMP,
ELF/build/source/config provenance. A04 device-intersection coverage is separate.
"""
from __future__ import annotations

import struct
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

MAGIC = 0x43594f574e313531
ROW_WORDS = 896
SLOTS = 8
WORDS = 128 + SLOTS * ROW_WORDS


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_structure(data: bytes) -> dict:
    require(len(data) == WORDS * 8, 'wrong ownership evidence length')
    w = struct.unpack('<' + str(WORDS) + 'Q', data)
    require(w[:3] == (MAGIC, 1, WORDS) and w[3] > 0 and 2 <= w[4] <= SLOTS
            and w[5] == w[6] == w[7] == 0 and w[8:10] == (ROW_WORDS, SLOTS),
            'missing/lost/wrong-profile actual ownership trace')
    require(any(w[16:18]) and all(any(w[i:i + 4]) for i in (18, 22, 26))
            and not any(w[12:16] + w[30:128]), 'missing frozen run identity or reserved header')
    require(w[10] == w[11] == w[4], 'an accepted transition lacks completion/model witness')
    require(not any(w[128 + w[4] * ROW_WORDS:]), 'unexpected uncounted ownership record')
    results, operations, applies = [], set(), set()
    for i in range(w[4]):
        r = w[128 + i * ROW_WORDS:128 + (i + 1) * ROW_WORDS]
        require(r[0] > 0 and r[0] % 2 == 0 and r[1] == 31 and r[15:17] == (2, 32)
                and not any(r[13:14] + r[20:32] + r[96:128] + r[160:192] + r[832:]),
                'partial or noncanonical owner/model completion')
        require(r[2] == w[3] and min(r[3:5] + r[6:8]) > 0 and r[5] == 0
                and r[8] in (2, 6) and r[9] > 0 and r[10] >= r[9]
                and r[11] > 0 and r[12] > 0 and r[14] > 0 and r[17] < 64,
                'missing complete ApplyId/operation/version')
        require(r[2:8] not in applies and r[11] not in operations, 'reused ApplyId or operation')
        applies.add(r[2:8]); operations.add(r[11])
        snaps = [r[32 + j * 16:48 + j * 16] for j in range(4)]
        for j, s in enumerate(snaps):
            require(s[0] > 0 and s[1] == 15 and s[2] & s[3] == 0
                    and s[2] | s[3] | s[4] | s[5] == 15
                    and s[2] & (s[4] | s[5]) == s[3] & (s[4] | s[5]) == 0
                    and s[8] > 0 and s[9] > 0 and s[11] >= s[12] and s[11] <= 900,
                    'owner partition or per-CPU capacity is invalid')
            if j:
                previous = snaps[j - 1]
                require(s[0] >= previous[0] and s[8] >= previous[8]
                        and s[9] >= previous[9], 'owner time/generation regressed')
                if s[10] == previous[10]:
                    require(s[12] >= previous[12], 'source CPU spending was refunded inside its window')
        before, drain, published, complete = snaps
        require(before[0] == r[10] and before[2] != r[8] and before[4:8] == (0, 0, 0, 0)
                and drain[2:4] == before[2:4] and drain[6] == 4 and drain[7] == 0
                and drain[11] >= before[11] and drain[14] == r[11],
                'DRAIN changed owner, lost source reservation or operation binding')
        require(published[2] == complete[2] == r[8] and published[3] == complete[3] == 15 ^ r[8]
                and published[4:8] == complete[4:8] == (0, 0, 0, 0)
                and published[8] > drain[8] and published[13] == 63
                and published[14] == published[15] == r[11]
                and published[0] - drain[0] < 200_000_000,
                'proposal lacks actual generation-bound quiescence/owner publication')
        h, model = r[128:160], r[192:832]
        inp = model[32:544]
        require(h[:3] == (0x435958444f4d3031, 1, w[3])
                and h[3] == (1 << 18) - 1 and h[12:15] == (64, 640, inp[13])
                and h[25] == h[28] == 0 and any(h[16:20]) and any(h[20:24]),
                'model/schema registration or native execution failed')
        require(model[639] % 2 == 0 and model[0] == model[1] == r[14]
                and model[2:8] == (1, 2, r[6], r[7], r[3], r[2])
                and model[13] == r[12] and model[14:16] == (2, 0)
                and model[19] == model[30] == 1 and model[28] >= model[9]
                and before[0] >= model[9] and complete[0] <= model[28]
                and any(model[21:25]), 'no matching actual APPLIED model receipt/output digest')
        require(inp[0:2] == (0x4359585254494e31, 3) and inp[2:4] == (r[14], r[3])
                and inp[4] == r[9] and inp[8:12] == (1, 2, r[6], r[7])
                and inp[6]==r[18]==before[8] and inp[7]==r[19]
                and inp[14] == r[2] and inp[36:39] == (r[14], r[4], r[14])
                and inp[400:404] == (before[2], before[3], 15, 0),
                'scripted fixture or wrong DecisionKey/Plan/input/owner binding')
        results.append({'apply': list(r[2:8]), 'operation': r[11], 'desired': r[8],
                        'before_control': before[2], 'actual_control': published[2],
                        'core_generation': published[8], 'model_sequence': r[14]})
    require([results[0]['before_control'], results[0]['actual_control'],
             results[1]['actual_control']] == [2, 6, 2]
            and results[1]['before_control'] == 6, 'missing model-driven actual 1-to-2-to-1 ownership')
    return dict(status='STRUCTURE_VALID', native_acceptance_status='NOT_RUN',
                control_sets=[2, 6, 2], attempts=results,
                scope='raw ownership structure only; model and native provenance remain mandatory')


def verify_native(directory:Path, *, source_root:Path, qemu_source:Path) -> dict:
    from check_prototype_evidence import safe_path, sha256
    from doctor import RUST_BIN, env
    from verify_v13_boot_receipt import verify_receipt
    root=Path(directory).resolve(strict=True)
    source=Path(source_root).resolve(strict=True)
    provenance=verify_receipt(root,source_root=source,qemu_source=qemu_source,ownership=True)
    get=lambda name:safe_path(root,name)
    first=get('ownership-first.bin').read_bytes();last=get('ownership-last.bin').read_bytes()
    a,b=validate_structure(first),validate_structure(last)
    fw,lw=(struct.unpack('<'+str(WORDS)+'Q',raw) for raw in (first,last))
    config=get('config.bin').read_bytes()
    require(provenance['mode']==0 and provenance['observations']['online_mask']==15,
            'A03 requires an actual normal four-vCPU boot')
    require(first[16*8:30*8]==last[16*8:30*8]==config[32:144],
            'ownership bank differs from frozen run/source/image/input')
    require(lw[3]==fw[3] and lw[4]>=fw[4] and last[128*8:(128+fw[4]*ROW_WORDS)*8]
            ==first[128*8:(128+fw[4]*ROW_WORDS)*8], 'actual owner/model facts changed across stopped captures')
    # Compile the caller-selected reviewed source, never run an executable
    # named by the evidence archive. The model package was independently
    # reconstructed from the exact built ELF by the provenance verifier.
    target=source/'target/ownership-verifier'
    environment=env()
    environment.pop('RUSTFLAGS',None);environment.pop('CARGO_ENCODED_RUSTFLAGS',None)
    command=[str(RUST_BIN/'cargo'),'build','--locked','--offline','--manifest-path',
             str(source/'Cargo.toml'),'--target-dir',str(target),'-p','cyxia-prototype',
             '--example','verify-ownership-evidence']
    built=subprocess.run(command,cwd=source,env=environment,capture_output=True,text=True,timeout=180)
    require(built.returncode==0,'trusted ownership model verifier failed to build: '+built.stderr[-4000:])
    checker=target/'debug/examples/verify-ownership-evidence'
    results=[]
    for name in ('ownership-first.bin','ownership-last.bin'):
        completed=subprocess.run([str(checker),str(get(name)),str(get('model.bin'))],
            cwd=source,env=environment,capture_output=True,text=True,timeout=15)
        require(completed.returncode==0,'actual model/Plan replay failed: '+completed.stderr[-4000:])
        result=json.loads(completed.stdout)
        require(result.get('status')=='MODEL_REPLAY_VALID' and result.get('full_integer_mlp') is True,
                'missing exact full MLP/Plan replay')
        results.append(result)
    return dict(status='PASS',test_id='A03',verifier_version='v15-model-owner-v1',
        native_acceptance_status='PASS',native_execution_verified=True,full_v13_acceptance=False,
        runtime_truth_attested=False,a04_device_intersection_verified=False,
        scope='A03 actual model-driven 1-to-2-to-1 owner/publication/executor chain',
        source_sha256=provenance['source_sha256'],image_sha256=provenance['image_sha256'],
        run_nonce=provenance['run_nonce'],control_sets=b['control_sets'],attempts=b['attempts'],
        checker_sha256=sha256(checker),model_replay=results,
        ownership_first_sha256=hashlib.sha256(first).hexdigest(),ownership_last_sha256=hashlib.sha256(last).hexdigest())


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('directory','source-root','qemu-source'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(argv)
    try: result=verify_native(args.directory,source_root=args.source_root,qemu_source=args.qemu_source)
    except (OSError,ValueError,TypeError,KeyError,struct.error,subprocess.SubprocessError) as error:
        print(json.dumps(dict(status='FAIL',test_id='A03',native_acceptance_status='NOT_RUN',error=str(error))))
        return 1
    print(json.dumps(result,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
