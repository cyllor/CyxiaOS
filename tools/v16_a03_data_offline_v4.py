"""Additive offline v4; frozen producer v3 and original FAIL remain immutable."""
from __future__ import annotations
import ast
import hashlib
import json
import re
from pathlib import Path
import struct
import v16_a03_data as producer_v3
import v16_a03_focus as strict_v5
from v16_a03_focus import (require,MAX_FILE,OWNER,EMPTY_SHARED,word,words,digest,sha,SCHEMAS,
    coreset_workload_hash,_request,_closing,_execution,core_action,select_model,
    OBSERVATION_NS,performance,cpu_union,reward_values)
from v16_a03_data import (bounded_inventory,_verify_data_capture_custody,_schema_context,MAX_ATTEMPTS,
    decode_data_ledger,focus_diagnostic_files,verify_supplement,baseline_provenance,
    match_sample_witness,core_image,paid_bank_facts,trusted_context)

VERSION='v16-a03-bounded-data-offline-checker-v4-r2'
CHECKER_VERSION=VERSION
strict=strict_v5
PRODUCER_VERSION='v16-a03-coreset-data-one-pair-v3'
TOOL_ROOT=Path(__file__).resolve().parents[1]
FROZEN_PRODUCER_FILES={
    'tools/run_v16_a03_data.py':'83d59d0385b09be7e2d89deec6e9b8bb5b0d4a923ccc41500e37b49044a3fc31',
    'tools/v16_a03_data.py':'423a3c82adad5d31e2b8b0e611a7bf3adb2fb38d054881e8072b7eb626b30ab0',
    'tools/verify_v16_a03_data.py':'efb3acb6d97a8f25873472b54564b56e812dda673b340a957dfef86ef48a5b84',
    'tools/test_v16_a03_data.py':'e947b632c652b64b7f41aaa9d7a35691a888852096116fd81c24b45e24eb3a1f',
    'tools/v16_a03_focus.py':'0b7c3582f366c111de6f8ee1335626a735dd62521278dbdab95e450cd9a174df',
}
ORIGINAL_ERROR='ValueError: invalid actual CoreSet prewarm row'
NATIVE_CONTRACT_SOURCES={
    'kernel/src/domain_control.rs':'3693aac71603595deb61d5c2112224327dfdca076f10d74c242c6493c30a5eaa',
    'user/prototype-runtime/native.rs':'1a6dd3c88bd32a5334e0fbb73a0537e3aab1c8199860ee50a61295eadf65acaf',
    'crates/prototype/src/features.rs':'8b68c6f4e977aa844174a9ed4c37404faf05ce151fa67ed02106611704643854',
    'crates/prototype/src/policy.rs':'c7172ed4755f57e8c41a7d5914d7f2bd4321ff2e1d4153308def98fe7b86993e',
    'kernel/src/learning_prewarm.rs':'4f30e9f33da59355fedc69b8978cf592f88bc53f76d951ae3a2982ddd323c2b5',
    'kernel/src/learning_replay/archive.rs':'4bb0581b06c1c2f03ff924a33b81798ebd30dfc16d0685f896fd77774c1c7f3a',
    'kernel/src/learning_workload.rs':'bd730e80f14cce49ba1ec5c492e3fa82e6396cc576eef2f0e11d12786dda3465',
    'kernel/src/domain_control/core_replay.rs':'4679ce95cbf320c95d06667766b57445a8cbad7b149cd8c11bf4b2d6f5bd2a96',
    'kernel/src/domain_evidence.rs':'d85001b7de8b2eb9380edb008748c8674c6047c83b09036badcf5f21b67e26f9',
    'kernel/src/learning_history.rs':'bfb355de07940adabc35f19a9d8ab5e1f08e22989c3b4ad732e5448163069b03',
    'kernel/src/prototype_runtime/native.rs':'3e784e7d4687124b42b2e5bc44e06c584dea1c6548fb6c3283c23bf8d10abbbe',
    'kernel/src/domain_services.rs':'3b277429f41619a1c8bf34da2da5a761848efad233344ebb955a44fef8267daf',
    'crates/arch-aarch64/src/timer.rs':'199de281a35642ada3aaf61be10f588e393de17e848ddf82c014eaaccdcf2511',
}


def require_native_contract(source_root):
    root=Path(source_root).resolve(strict=True)
    for relative,expected in NATIVE_CONTRACT_SOURCES.items():
        path=root/relative
        require(path.is_file() and not path.is_symlink() and sha(path)==expected,
            'native prewarm/direct-capacity contract changed: '+relative)


def tool_closure(tool_root=TOOL_ROOT):
    """Hash fixed caller-local checker code; never import captured modules."""
    root=Path(tool_root).resolve(strict=True)
    pending=['v16_a03_data_offline_v4','verify_v16_a03_data_offline_v4','test_v16_a03_data_offline_v4'];found={}
    while pending:
        name=pending.pop()
        if name in found:continue
        path=root/'tools'/(name+'.py')
        require(path.is_file() and not path.is_symlink(),'missing/linked offline checker input '+name)
        found[name]=sha(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports=[node.module] if isinstance(node,ast.ImportFrom) else [n.name for n in node.names] if isinstance(node,ast.Import) else []
            for item in imports:
                if item and (root/'tools'/(item+'.py')).is_file():pending.append(item)
    result={'tools/'+name+'.py':value for name,value in sorted(found.items())}
    patch='tools/qemu/cyxia-per-vcpu-pmu.patch';result[patch]=sha(root/patch)
    return result


def require_frozen_producer_tools(producer_tools_root,capture_root):
    require(producer_tools_root is not None,'explicit frozen producer v3 tools root required')
    root=Path(producer_tools_root).resolve(strict=True);capture=Path(capture_root).resolve(strict=True)
    require(root!=capture and capture not in root.parents,'producer tools root must be caller-local outside capture')
    require(producer_v3.VERSION==PRODUCER_VERSION,'unexpected imported producer contract')
    for relative,expected in FROZEN_PRODUCER_FILES.items():
        for parent in (root,TOOL_ROOT):
            path=parent/relative
            require(path.is_file() and not path.is_symlink() and sha(path)==expected,
                'frozen producer/strict helper changed: '+relative)
    return root


def original_producer_failure(root,inventory,expected_summary_sha256):
    require(type(expected_summary_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_summary_sha256),
        'caller must pin original summary SHA256')
    path=Path(root)/'summary.json'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size<=128*1024**2
        and sha(path)==expected_summary_sha256,'original producer summary custody mismatch')
    summary=json.loads(path.read_text())
    require(summary.get('version')==PRODUCER_VERSION and summary.get('status')=='FAIL'
        and summary.get('capture_complete') is False and summary.get('released_pair_observed') is False
        and summary.get('error')==ORIGINAL_ERROR,'unexpected original producer outcome')
    require(summary.get('artifacts')=={name:value for name,value in inventory.items() if name!='summary.json'},
        'original producer inventory membership/bytes mismatch')
    return dict(version=summary['version'],status=summary['status'],error=summary['error'],
        capture_complete=False,released_pair_observed=False,summary_sha256=expected_summary_sha256)

def _prewarm(raw, header):
    require(len(header)==2048 and len(raw)%64==0 and len(raw)//64==word(header,752)<=768,
        'prewarm section width/count bound')
    require(word(header,616)==4,'exact CoreSet prewarm source manifest count')
    sources=[struct.unpack_from('<4Q',header,768+i*32) for i in range(4)]
    require(sources==[(0x434f5245,1,0,7),(0x434f5245,1,1,15),
        (OWNER,1,2,1),(0x5245504c434f,1,2,6)],'exact CoreSet prewarm source role/generation/mask')
    work={(owner,generation):mask for owner,generation,role,mask in sources if role==2}
    seen=set(); last={}; total=0
    for at in range(0,len(raw),64):
        owner,gen,core,event,start,end=struct.unpack_from('<6Q',raw,at)
        require(((owner,gen,core)==(OWNER,1,0) or (owner,gen)==(0x5245504c434f,1) and core in (1,2))
            and (owner,gen) in work and work[(owner,gen)]&(1<<core)
            and event>0 and event not in seen
            and word(header,104)<=start<=end<=word(header,96) and not any(raw[at+48:at+64])
            and start>=last.get(core,0),'invalid actual CoreSet prewarm row')
        seen.add(event); last[core]=end; total+=end-start
    require(total==word(header,176),'prewarm raw CPU total mismatch')

def _record(row, header, context):
    flags = word(row, 0)
    require(flags in (40, 31, 64), 'unsupported history flags')
    target = tuple(word(row, x) for x in (184, 192))
    require(target == (0x434f5245, 1) and all(word(row, x) > 0 for x in (8, 152, 160, 168, 176)),
            'history snapshot/target mismatch')
    count, selected = struct.unpack_from('<HH', row, 204)
    require(1 <= count <= 2 and selected < count, 'candidate alternatives bound')
    weights = [core_action(row[512 + i * 24:536 + i * 24], i) for i in range(count)]
    require(not any(row[512 + count * 24:1280]), 'unused history action slots')
    if flags == 40:
        require(header['side'] == 'Baseline' and count == 1 and selected == 0
                and row[200:204] == bytes(4) and not any(row[16:152])
                and word(row, 344) == header['boot_epoch'] and word(row, 440) == 1,
                'baseline metadata mismatch')
        _execution(row, header)
        return dict(kind='Baseline', sha256=digest(row), model_binding='trusted capture context')
    require(header['side'] == 'Candidate' and row[200:204] == b'\x01\0\x02\0'
            and word(row, 80) == context['model_generation']
            and row[88:120].hex() == context['model_sha256']
            and row[120:152].hex() == context['schema_hash'], 'history model/family mismatch')
    require(weights == sorted(set(weights)), 'unsorted/duplicate candidate alternatives')
    inp = row[2048:]
    require(digest(inp) == row[48:80].hex(), 'raw input hash mismatch')
    w = struct.unpack('<512Q', inp)
    expected_magic = int.from_bytes(b'CXPROBE1', 'little') if flags == 64 else 0x4359585254494e31
    require(w[0] == expected_magic and w[1] == 3 and w[2] == word(row, 8)
            and w[4] == word(row, 160) and (w[6], w[7]) == (word(row, 176), word(row, 168))
            and w[8:12] == (1, 2, 0x434f5245, 1) and w[13:16] == (1, header['boot_epoch'], count)
            and inp[128:160] == row[88:120] and inp[160:192] == row[16:48]
            and w[40] == 15 and w[31] <= 1, 'input identity/features mismatch')
    canonical = bytearray(b'CYXIA_CANDIDATES_V1.3\0')
    canonical += words(*(word(row, i) for i in (152, 160, 168, 176, 184, 192, 80)), count)
    canonical += row[88:152]
    for i, weight in enumerate(weights):
        at = 64 + 10 * i
        payload = inp[(at + 1) * 8:(at + 3) * 8]
        require(w[at] == 10 and payload[:10] == struct.pack('<HQ', i, weight)
                and not any(payload[10:]) and w[at + 7] <= 15 and w[at + 8] == weight.bit_count()*1000 and w[at + 9] == 0,
                'candidate input action/target mismatch')
        canonical += struct.pack('<4HQ', 1, 2, 10, i, weight) + words(*w[24:36]) + bytes([w[40]])
        for j in range(4):
            present = (w[at + 7] >> j) & 1
            value = w[at + 3 + j]
            require((present or value == 0) and (j != 3 or value <= 1), 'illegal target features')
            canonical += bytes([present]) + words(value)
        canonical += bytes([1]) + words(w[at+8])
    require(digest(canonical) == row[16:48].hex(), 'CandidateSet integrity mismatch')
    prior = inp[405 * 8:407 * 8]
    require(w[404] == 10 and prior[:2] == bytes(2) and not any(prior[10:])
            and struct.unpack_from('<Q', prior, 2)[0] in (2,6), 'invalid prior action')
    if flags == 64:
        require(selected == 0 and word(row, 8) == word(row, 152)
                and not any(row[208:512]) and not any(row[1280:2048])
                and all(w[i] == 0 for i in (3, 5, 12, 36, 37, 38, 39)), 'probe has publication fields')
    else:
        apply = tuple(word(row, i) for i in range(272, 320, 8))
        require(apply[0] == header['boot_epoch'] and apply[1] == w[3] > 0 and apply[2] > 0
                and apply[3:] == (0, 0x434f5245, 1) and row[1280:1328] == row[272:320]
                and not any(row[1328:2048]) and word(row, 440) == 1 and word(row, 480) == 0
                and row[448:480] == EMPTY_SHARED and word(row, 496) in (0, 1)
                and not any(row[504:512]), 'unsupported publication/shared action')
        _execution(row, header)
    return dict(kind='Probe' if flags == 64 else 'Candidate', sha256=digest(row),
                candidate_set_sha256=row[16:48].hex(), input_sha256=row[48:80].hex(),
                candidate_set_integrity_verified=True)

def encode_core_features(row,index):
    w=struct.unpack('<512Q',row[2048:]); at=64+10*index
    mask=core_action(row[512+24*index:536+24*index],index)
    out=[0]*64; out[0]=256
    def normalize(position,value,limit): out[position]=(512*min(value,limit)+limit)//(2*limit)
    for i,limit in enumerate((1000,1000,64,1000,1000,1000,100,1)): normalize(16+i,w[24+i],limit)
    for i,limit in enumerate((64,100000,1000,10000)):
        require(w[40]&(1<<i),'missing CoreSet domain feature')
        normalize(24+i,w[32+i],limit); out[32+i]=256
    normalize(40,2,255); normalize(41,mask.bit_count(),4)
    require(w[at+8]==mask.bit_count()*1000 and w[at+9]==0,'CoreSet actual capacity binding')
    normalize(42,w[at+8],4000); out[48]=out[49]=out[50]=256
    for i,limit in enumerate((4000,1000,100000,1)):
        if w[at+7]&(1<<i): normalize(56+i,w[at+3+i],limit); out[60+i]=256
    return out

def _core_adoptions(rows,header,model):
    candidate=bool(word(header,152)); adopted=[r for r in rows if word(r,0)==(31 if candidate else 40)]
    require(len(adopted)==1,'CoreSet one-shot requires one actual adoption')
    row=adopted[0]; count,selected=struct.unpack_from('<HH',row,204)
    received,accepted,started,finished=(word(row,p) for p in (352,360,400,416))
    issued=word(row,488) if candidate else received
    require(word(row,160)==word(header,96)==word(header,112)==issued and issued<=received<=accepted<=started<=finished
        and finished<=word(row,384) and 0<=word(row,384)-accepted<=200000000
        and finished-accepted<=200000000 and word(row,376)==0,'CoreSet one-shot timing/receipt mismatch')
    if candidate:
        require(word(row,320)==word(row,344)>0 and word(row,328)==word(row,160)
            and word(row,336)==0 and accepted<=word(row,368)<=word(row,160)+100000000
            and word(row,480)==0 and word(row,496)==1,'CoreSet candidate stamp/expiry mismatch')
        inputs=[encode_core_features(row,i) for i in range(count)]
        scores,best=select_model(model,inputs)
        require(scores==list(struct.unpack_from('<'+'h'*count,row,208)) and best==selected,
                'CoreSet full integer MLP/first maximum mismatch')
        evaluated=[dict(inputs=inputs,scores=scores,selected=selected)]
    else:
        require(word(row,440)==1,'CoreSet baseline request binding')
        evaluated=[None]
    return adopted,evaluated

def _side(raw, context):
    require(len(raw) >= 2048, 'truncated archive header')
    h = raw[:2048]
    require(h[:17] == b'CYXIA_REPLAY_1.3\0' and not any(h[17:32])
            and not any(h[232:256]) and not any(h[1280:1792]), 'unsupported archive header')
    boot, trial, generation, domain, kind, target, target_gen, seed, first, warm, observation, closing = struct.unpack_from('<12Q', h, 32)
    records, cpu, requests, candidate = struct.unpack_from('<4Q', h, 128)
    require(boot == context['boot_epoch'] and trial > 0 and generation > 0 and seed == 1
            and (domain, kind, target, target_gen) == (1, 2, 0x434f5245, 1)
            and candidate in (0, 1) and 0 < first == observation < closing
            and warm == observation - 1000000000
            and closing >= observation + 10000000000, 'unsupported archive run identity/timing')
    require(1 <= records <= 64 and cpu <= 8192 and requests == 100
            and all(word(h, i) == 0 for i in (160, 168, 192, 224, 608, 624, 744))
            and word(h, 632) == 2048, 'unsupported archive counts/peer/prewarm/exclusion')
    prewarm = word(h,752)
    require(prewarm <= 768, "prewarm row bound")
    length = 2048 + records * 6144 + cpu * 64 + requests * 128 + prewarm * 64
    require(length <= MAX_FILE and length <= len(raw), 'truncated/unbounded archive side')
    require(tuple(h[448 + i * 32:480 + i * 32].hex() for i in range(4)) == tuple(context['schema_hashes'])
            and struct.unpack_from('<4Q', h, 576) == (13,) * 4
            and h[640:672].hex() == context['node_id'], 'archive schema/node mismatch')
    require(h[256:288].hex() == coreset_workload_hash()
            and all(any(h[i:i + 32]) for i in (288, 320, 352, 384, 416)), 'archive group/hash mismatch')
    count = word(h, 616)
    require(0 < count <= 16 and not any(h[768 + count * 32:1280])
            and word(h, 728) == 100 and word(h, 736) == count, 'archive source closure mismatch')
    sources = [struct.unpack_from('<4Q', h, 768 + i * 32) for i in range(count)]
    require(sources == [(0x434f5245, 1, 0, 7), (0x434f5245, 1, 1, 15), (OWNER, 1, 2, 1),
                        (0x5245504c434f, 1, 2, 6)], 'unsupported CoreSet source manifest')
    coverage = struct.unpack_from('<7Q', h, 672)
    require(coverage == (first, observation, observation + 10000000000, closing, 3, 3, 1),
            'invalid local coverage')
    _closing(h[1792:], boot, closing)
    result = dict(boot_epoch=boot, trial_id=trial, capture_generation=generation,
                  family=[1, 2], target=[0x434f5245, 1], seed=seed, side='Candidate' if candidate else 'Baseline',
                  first_ns=first, observation_ns=observation, closing_ns=closing, length=length,
                  workload_sha256=h[256:288].hex(), initial_image_sha256=h[288:320].hex(),
                  frozen_other_domains_sha256=h[320:352].hex(), frozen_scope_sha256=h[352:384].hex(),
                  event_sha256=h[384:416].hex(), producer_verification_sha256=h[416:448].hex(),
                  schema_hashes=list(context['schema_hashes']), node_id=context['node_id'])
    result['records'] = [_record(raw[2048 + i * 6144:2048 + (i + 1) * 6144], result, context) for i in range(records)]
    require(any(r['kind'] == result['side'] for r in result['records']), 'missing adopted/baseline history')
    at = 2048 + records * 6144
    for i in range(cpu):
        row = raw[at + i * 64:at + (i + 1) * 64]
        core, start, end, cls = struct.unpack_from('<4Q', row, 32)
        require(row[:32] == h[640:672] and core < 4 and cls <= 2
                and first <= start <= end <= closing
                and any(s[2] == cls and s[3] & (1 << core) for s in sources), 'invalid local CPU row')
    at += cpu * 64
    canonical = bytearray(b'CYXIA_NATIVE_WORKLOAD_SCOPE_1.3\0')
    canonical += words(boot, trial, domain, kind, target, target_gen, seed, first, observation) + h[256:352]
    for source in sources:
        canonical += words(*source)
    arrivals = []
    for i in range(requests):
        row = raw[at + i * 128:at + (i + 1) * 128]
        identity, owner, gen, relative = _request(row, i, first, observation, closing)
        canonical += words(identity, owner, gen, relative)
        arrivals.append([identity, relative])
    _prewarm(raw[at+requests*128:length], h)
    require(digest(canonical) == h[352:384].hex(), 'frozen scope integrity mismatch')
    result.update(relative_arrivals=arrivals, scope_hash_recomputed=True,
                  sha256=digest(raw[:length]), raw_bytes=bytes(raw[:length]))
    return result

def numeric_core_side(raw, model):
    """Recompute the retained Trial only; caller custody is checked separately."""
    require(isinstance(raw, (bytes, bytearray)) and len(raw) >= 2048, 'truncated numeric side')
    require(isinstance(model, (bytes, bytearray)) and len(model) == 2772, 'invalid model length')
    raw = bytes(raw)
    context = dict(boot_epoch=1, model_generation=1, model_sha256=digest(model),
                   schema_hash=SCHEMAS[0], schema_hashes=SCHEMAS, node_id=raw[640:672].hex())
    side = _side(raw, context)
    require(len(raw) == side['length'], 'extra numeric side bytes')
    h = raw[:2048]
    observation, closing = word(h, 112), word(h, 120)
    require(closing - observation - OBSERVATION_NS <= 5_000_000_000
            and word(h, 760) <= 1024 * 1024, 'closing/workspace bound')
    rows = [raw[2048 + i * 6144:2048 + (i + 1) * 6144] for i in range(word(h, 128))]
    adopted, evaluated = _core_adoptions(rows, h, model)
    # Probe records carry candidate registration, not published inference
    # scores. The existing structural checker validates their raw binding;
    # only actual adopted rows enter the Trial and the score comparison.
    at = 2048 + len(rows) * 6144
    intervals = []
    raw_four = [0] * 4
    for i in range(word(h, 136)):
        row = raw[at + i * 64:at + (i + 1) * 64]
        core, start, end, cls = struct.unpack_from('<4Q', row, 32)
        if cls == 2:
            require(observation <= start <= end <= observation + OBSERVATION_NS,
                    'work CPU outside observation')
        raw_four[cls] += end - start
        intervals.append((row[:32], core, start, end, cls))
    require(raw_four[0] == word(h, 200) and raw_four[1] == word(h, 208)
            and raw_four[2] + word(h, 176) + word(h, 184) == word(h, 216)
            and raw_four[3] == word(h, 224), 'raw CPU/warm/later totals disagree')
    at += len(intervals) * 64
    requests = [struct.unpack_from('<4Q', raw, at + i * 128) for i in range(word(h, 144))]
    perf = performance(requests, observation)
    cpu = cpu_union(intervals)
    candidate = side['side'] == 'Candidate'
    canonical = bytearray(b'CYXIA_FULL_CPU_TRIAL_1.3\0') + bytes([candidate])
    canonical += words(word(h, 40), 1, 2, word(h, 88), observation,
                       observation + OBSERVATION_NS, word(h, 104), closing,
                       word(h, 176), word(h, 184), word(h, 760))
    canonical += h[256:352]
    for i in range(4):
        canonical += words(word(h, 576 + 8 * i)) + h[448 + 32 * i:480 + 32 * i]
    node = h[640:672]
    canonical += node + words(1) + node
    canonical += words(len(adopted) if candidate else 0, 0 if candidate else len(adopted),
                       len(requests), 1, len(intervals), 0)
    input64 = None
    for index, row in enumerate(adopted):
        count, selected = struct.unpack_from('<HH', row, 204)
        weight = core_action(row[512+24*selected:536+24*selected], selected)
        if candidate:
            e = evaluated[index]
            for inp, score in zip(e['inputs'], e['scores']):
                canonical += struct.pack('<64hh', *inp, score)
            if index == 0:
                input64 = e['inputs'][selected]
            canonical += words(word(row, 8), *(word(row, p) for p in range(272, 320, 8)),
                               word(row, 344), word(row, 392), word(row, 488), word(row, 360),
                               word(row, 368), word(row, 376), 1, word(row, 400), word(row, 416),
                               word(row, 336), word(row, 384), selected, count, 1, 0)
            canonical += row[1280:1328]
            canonical += row[16:48] + row[88:152] + words(word(row, 80))
        else:
            canonical += words(*(word(row, p) for p in (344, 8, 184, 192, 392, 152, 160, 176, 168,
                                                        352, 360)), word(row,440),
                               *(word(row, p) for p in (400, 416, 376, 384)))
        canonical += struct.pack('<3HQ', 1, 2, 0, weight)
    for identity, arrived, code, finished in requests:
        canonical += words(identity, arrived, code - 1, finished)
    canonical += node + words(*(word(h, p) for p in range(672, 720, 8)))
    for node, core, start, end, cls in intervals:
        canonical += node + words(core, start, end, cls)
    calculated = digest(canonical)
    require(calculated == h[416:448].hex(), 'Trial canonical differs from original native offset416')
    return dict(trial_id=word(h, 40), trial_canonical_sha256=calculated,
                original_native_canonical_sha256=h[416:448].hex(),
                original_source_event_sha256=h[384:416].hex(),
                performance=perf, cpu=cpu, input64=input64,
                model_scores=[e for e in evaluated if e is not None],
                warm_cpu_ns=word(h, 176), later_cpu_ns=word(h, 184),
                raw_source_tagged_ns=[word(h, p) for p in (200, 208, 216, 224)])

def numeric_core_pair(candidate_raw, baseline_raw, model):
    require(len(candidate_raw) >= 2048 and len(baseline_raw) >= 2048, 'truncated pair')
    require(word(candidate_raw, 152) == 1 and word(baseline_raw, 152) == 0,
            'wrong candidate/baseline sides')
    for begin, end in ((32, 40), (56, 96), (256, 352), (448, 608), (640, 672)):
        require(candidate_raw[begin:end] == baseline_raw[begin:end], 'pair identity mismatch')
    require(word(candidate_raw, 40) != word(baseline_raw, 40)
            and word(candidate_raw, 48) != word(baseline_raw, 48), 'same trial/generation pair')
    candidate, baseline = (numeric_core_side(raw, model) for raw in (candidate_raw, baseline_raw))
    # The fixed archive schedule checker already checks all 100 relative
    # arrivals independently on each side, so their pairing is exact here.
    cp, bp = candidate['performance'], baseline['performance']
    calculated = reward_values(cp, bp, candidate['cpu']['union_ns'])
    reward = calculated['value']
    evidence = digest(b'CYXIA_PAIRED_LABEL_1.3\0' + bytes.fromhex(candidate['trial_canonical_sha256'])
                      + bytes.fromhex(baseline['trial_canonical_sha256']) + words(reward.bits))
    return dict(schema=1, family=[1, 2], candidate=candidate, baseline=baseline,
                reward={name: value.report() for name, value in calculated.items()},
                prospective_paired_label_sha256=evidence,
                model_sha256=digest(model), model_scores_verified=True,
                reward_numeric_verified=True, trial_canonical_matches_native=True,
                native_acceptance_inferred_from_trusted_producer=False,
                source_event_hash_recomputed=False, event_hash_recomputed=False,
                source_custody_replay_verified=False, protected_sample_export_verified=False,
                accepted_training_sample_verified=False, reward_replay_verified=False,
                native_label_imported=False, model_trained=False, native_acceptance_status='NOT_RUN',
                formal_acceptance={name: 'NOT_RUN' for name in ('A03', 'A08', 'A10', 'A16')})

def parse_attempt_journal(raw,attempt,kind,context):
    # Nonselected/error journals retain the original v3 parser verbatim.
    if kind!='regular' or attempt['outcome']=='excluded':
        return producer_v3.parse_attempt_journal(raw,attempt,kind,context)
    require(0<len(raw)<=MAX_FILE and len(raw)>=2048 and raw[:17]==b'CYXIA_REPLAY_1.3\0'
        and tuple(word(raw,p) for p in (32,40,48))==(attempt['boot_epoch'],attempt['trial_id'],attempt['generation'])
        and tuple(word(raw,p) for p in (56,64,72,80,88,152))==(1,2,0x434f5245,1,1,int(attempt['kind']==1))
        and word(raw,128)<=64 and word(raw,136)<=8192 and word(raw,144)==100
        and word(raw,624)==word(raw,744)==0 and word(raw,752)<=768
        and len(raw)==2048+word(raw,128)*6144+word(raw,136)*64+100*128+word(raw,752)*64,
        'regular journal original RunKey/family/count/length mismatch')
    side=_side(raw,context)
    require(side['producer_verification_sha256']==attempt['verified_canonical_sha256'],
        'successful journal canonical differs from ledger')
    return dict(kind=kind,trial_id=attempt['trial_id'],closed_ns=side['closing_ns'],negative_plans=[],
        raw_sha256=digest(raw),side=side,original_domain_error_verified=attempt['original_domain_error_code']==0,
        native_replay_authority_reconstructed=False)


def read_committed_data(disk,context,ledger):
    from check_v13_disk import committed_volume,BLOCK
    from check_v13_filesystem import inspect_committed
    require(sha(disk)==context['disk_sha256'],'data disk custody mismatch')
    files={};total=0
    with committed_volume(Path(disk)) as (current,metadata):
        volume=inspect_committed(current,metadata)
        require(volume['uuid']==context['disk_uuid'] and volume['boot_epoch']==context['boot_epoch'], 'data volume identity mismatch')
        for name in sorted(set(volume['files'])|set(volume['directories'])):
            if not any(part.startswith(('lr-','lp-','lf-','ld-','ls-')) for part in name.split('/')):continue
            require(name in volume['files'] and re.fullmatch(r'/(?:l[rpf]-[0-9a-f]{16}-[0-9a-f]{4}|ld-[0-9a-f]{16})',name), 'unknown/malformed data journal path')
            node=volume['files'][name];require(0<node['size']<=MAX_FILE and node['durable_write_seq']>0,'journal not bounded/durable')
            total+=node['size'];require(total<=MAX_ATTEMPTS*2*MAX_FILE+4096,'expanded data journal bound')
            raw=bytearray()
            for _,start,blocks in node['extents']:
                require(blocks<=MAX_FILE//BLOCK,'journal extent bound')
                for block in range(start,start+blocks):raw+=current(block)[:min(BLOCK,node['size']-len(raw))]
            require(len(raw)==node['size'] and digest(raw)==node['sha256'],'committed data journal hash mismatch')
            key=(node['inode'],node['generation']);require(key not in files,'aliased data journal object')
            files[key]=dict(path=name,node=node,raw=bytes(raw),used=[])
    supplement_key=tuple(ledger['supplement_object']);require(supplement_key in files,'missing durable data supplement object')
    supplement=files.pop(supplement_key)
    require(supplement['path']=='/ld-%016x'%context['boot_epoch'],'wrong supplement path/boot')
    verify_supplement(supplement['raw'],ledger)
    journals=[];selected={};plan_ids=set()
    for attempt in ledger['attempts']:
        require(attempt['boot_epoch']==context['boot_epoch'],'attempt belongs to another boot')
        for kind in ('regular','preparation','late'):
            ref=attempt[kind]
            if ref is None:continue
            key=(ref['object_id'],ref['object_generation']);require(key in files,'missing excluded/preparation/late journal object')
            file=files[key];raw=file['raw'];start=ref['offset'];end=start+ref['bytes']
            prefix={'regular':'lr','preparation':'lp','late':'lf'}[kind]
            require(re.fullmatch('/'+prefix+'-%016x-[0-9a-f]{4}'%context['boot_epoch'],file['path']) is not None
                and end<=len(raw) and digest(raw[start:end])==ref['sha256'],'journal object/path/range/hash mismatch')
            parsed=parse_attempt_journal(raw[start:end],attempt,kind,context)
            require(parsed['closed_ns']<=ledger['sampled_ns'],'journal closure follows terminal boundary')
            for negative in parsed['negative_plans']:
                identity=tuple(negative['plan_id']);require(identity not in plan_ids,'sealed PlanID reused across attempts');plan_ids.add(identity)
            file['used'].append((start,end));journals.append(parsed)
            if attempt['outcome'].startswith('selected_'):selected[attempt['outcome']]=parsed['side']
    for file in files.values():
        cursor=0
        for start,end in sorted(file['used']):require(start==cursor,'orphan/gapped/reused excluded journal range');cursor=end
        require(cursor==len(file['raw']),'unreferenced failed/preparation/late journal bytes')
    require(sha(disk)==context['disk_sha256'],'disk changed during data extraction')
    return journals,selected

def _verify_data_capture(directory,*,source_root,build_manifest,formatter,qemu_binary,qemu_source,producer_tools_root=None):
    root=Path(directory);require(not root.is_symlink(),'linked data capture root');root=root.resolve(strict=True)
    before=bounded_inventory(root)
    paths=dict(source_root=source_root,build_manifest=build_manifest,formatter=formatter,qemu_binary=qemu_binary,
        qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    checked=_verify_data_capture_custody(root,terminal_contract='bounded-data-terminal',**paths)
    context=_schema_context(checked['trusted_context']);ledger=decode_data_ledger((root/'bounded_data.bin').read_bytes())
    diagnostics=focus_diagnostic_files(root);journals,selected=read_committed_data(root/'disk.raw',context,ledger)
    negative_count=baseline_provenance(ledger,journals,diagnostics)
    numeric=None;image=None;runtime=None
    collected=ledger['collection_succeeded']
    if collected:
        require(set(selected)=={'selected_baseline','selected_candidate'},'actual final pair is missing')
        b,c=selected['selected_baseline'],selected['selected_candidate'];model=(root/'model.bin').read_bytes()
        numeric=numeric_core_pair(c['raw_bytes'],b['raw_bytes'],model)
        match_sample_witness(ledger['witness'],numeric,b,c)
        image=core_image(b,model)
        for side in (b,c):
            raw=side['raw_bytes'];masks=[strict.core_action(raw[2048+i*6144+512:2048+i*6144+536],0)
                for i in range(word(raw,128)) if word(raw,2048+i*6144)==40]
            if side is b:require(masks==[image['control']],'selected baseline changed actual original CoreImage')
            require(struct.unpack_from('<Q',raw,1792+34)[0]==image['control'],'selected close did not restore original actual CoreImage')
        runtime=actual_candidate_runtime_v4((root/'control.bin').read_bytes(),(root/'runtime.bin').read_bytes(),c,context)
        paid_bank_facts((root/'tasks.bin').read_bytes(),(root/'credit.bin').read_bytes(),(root/'settlement.bin').read_bytes())
    common={k:v for k,v in checked['trusted_context'].items() if k not in ('boot_epoch','input_sha256','config_sha256','nonce','disk_uuid','disk_sha256','released_boundary','stopped_banks')}
    require(trusted_context(**paths)==common and bounded_inventory(root)==before,'data source/tool/capture changed during replay')
    public_ledger={key:value for key,value in ledger.items() if key not in ('raw_bytes','witness_raw')}
    public_journals=[{key:value for key,value in journal.items() if key!='side'} for journal in journals]
    return dict(version=VERSION,status=ledger['status'],profile='coreset-data-one-pair',profile_id=2,
        data_collection_verified=collected,closed_bounded_collection_verified=True,
        capture_complete=collected,released_pair_observed=collected,samples=int(collected),
        retained_stored_sample_observed=ledger['stored'] and not collected,
        ledger=public_ledger,journals=public_journals,diagnostic_facts=diagnostics,baseline_rejections_bound=negative_count,
        original_core_image=image,numeric=numeric,native_runtime=runtime,
        protected_sample_export_verified=collected,reward_numeric_verified=collected,
        trial_canonical_matches_native=collected,model_scores_verified=collected,
        native_acceptance_inferred_from_trusted_producer=False,
        native_exclusion_authority_reconstructed=False,source_event_hash_recomputed=False,event_hash_recomputed=False,
        accepted_training_sample_verified=False,source_custody_replay_verified=False,native_label_imported=False,
        model_trained=False,native_acceptance_status='NOT_RUN',ordinary_demand_verified=False,
        minimum_training_samples=144,minimum_validation_samples=72,family_count_required=18,
        formal_acceptance={name:'NOT_RUN' for name in ('A03','A08','A10','A16')},raw_inventory=before,
        checker_identity=dict(version=CHECKER_VERSION,tools=tool_closure()))

def verify_offline_capture(directory,*,source_root,build_manifest,formatter,qemu_binary,qemu_source,
                           producer_tools_root,expected_original_summary_sha256):
    """Separate offline verification; the original producer still failed."""
    root=Path(directory)
    require(not root.is_symlink(),'linked offline capture root');root=root.resolve(strict=True)
    producer_root=require_frozen_producer_tools(producer_tools_root,root)
    require_native_contract(source_root)
    inventory=bounded_inventory(root);checker=tool_closure()
    original=original_producer_failure(root,inventory,expected_original_summary_sha256)
    result=_verify_data_capture(root,source_root=source_root,build_manifest=build_manifest,
        formatter=formatter,qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_root)
    require(tool_closure()==checker and bounded_inventory(root)==inventory,'offline checker/capture changed during replay')
    require_frozen_producer_tools(producer_root,root)
    require_native_contract(source_root)
    require(original_producer_failure(root,inventory,expected_original_summary_sha256)==original,
        'original producer outcome changed during offline verification')
    # A protected stored pair and matching arithmetic do not reconstruct
    # native authority, ingress order, sample import or model training.
    result['native_acceptance_inferred_from_trusted_producer']=False
    runtime=result.get('native_runtime') or {}
    result.update(bank_applied_verified=runtime.get('bank_applied_verified',False),
        global_refusal_free_verified=False,full_native_runtime_verified=False,full_output_bytes_reconstructed=False)
    return dict(version=VERSION,status='OFFLINE_PARTIAL_PROTECTED_SAMPLE_VERIFIED' if result['data_collection_verified'] else 'OFFLINE_CLOSED_WITHOUT_SAMPLE',
        original_producer=original,offline_verification=result,authorizes_replay=False,
        bank_applied_verified=runtime.get('bank_applied_verified',False),global_refusal_free_verified=False,
        full_native_runtime_verified=False,full_output_bytes_reconstructed=False,
        native_authority_reconstructed=False,accepted_training_sample_verified=False,
        source_event_hash_recomputed=False,source_custody_replay_verified=False,native_label_imported=False,
        model_trained=False,native_acceptance_status='NOT_RUN',
        formal_acceptance={name:'NOT_RUN' for name in ('A03','A08','A10','A16')},
        checker_identity=dict(version=VERSION,tools_root=str(TOOL_ROOT),tools=checker),
        producer_tools_root=str(producer_root),raw_inventory=inventory)


def actual_candidate_runtime_v4(control,runtime,candidate,context):
    """Model publication plus exact archived execution, not bank/global Applied.

    The full output page is not reconstructed from the retained prefix. No
    particular deferred-delivery or reconciliation error is inferred.
    """
    from verify_domains import parse_control
    facts=parse_control(control,context['boot_epoch'])
    require(facts is not None,'missing complete native control bank')
    cw=struct.unpack('<'+'Q'*(len(control)//8),control)
    require(cw[14]==context['model_generation'] and control[16*8:20*8].hex()==context['model_sha256']
            and control[20*8:24*8].hex()==context['schema_hash'] and cw[24]==0,
            'native runtime changed seed/model/schema identity')
    raw=candidate['raw_bytes']; rows=[raw[2048+i*6144:2048+(i+1)*6144] for i in range(word(raw,128))]
    adopted=[row for row in rows if word(row,0)==31]
    require(len(adopted)==1,'missing actual candidate runtime link')
    row=adopted[0]; matching=[]
    for slot in range(64):
        at=512+slot*640; receipt=cw[at:at+640]
        if receipt[0]!=word(row,8):continue
        require(receipt[639]>0 and not receipt[639]%2 and receipt[0]==receipt[1]
            and receipt[2:6]==(1,2,0x434f5245,1) and receipt[7]==context['boot_epoch']
            and receipt[13]==word(row,344)>0 and receipt[15]==0 and receipt[19]==1 and receipt[30]==1
            and receipt[16:18]==struct.unpack_from('<HH',row,204)
            and struct.pack('<512Q',*receipt[32:544])==row[2048:]
            and struct.pack('<4Q',*receipt[608:612])==row[48:80]
            and receipt[10]>0 and receipt[11]>0 and receipt[10]+receipt[11]+receipt[29]<=2000000
            and receipt[12]<=500000 and receipt[12]+receipt[29]<=500000 and receipt[18]==0,
            'actual native full MLP/publication receipt mismatch')
        apply_id=tuple(word(row,p) for p in (272,280,288,296,304,312))
        accepted,started,observed,finished=(word(row,p) for p in (360,400,408,416))
        closing=word(raw,120);deadline=word(row,384)
        require(apply_id==(receipt[7],receipt[6],receipt[0],0,receipt[4],receipt[5])
            and word(row,320)==word(row,344)==receipt[13]
            and word(row,328)==word(row,160)==receipt[8] and word(row,336)==0
            and word(row,392)==context['boot_epoch'] and word(row,424)==1 and word(row,432)==0
            and closing==candidate['closing_ns'] and 0<accepted<=started<=observed==finished
            and finished<=min(closing,deadline),
            'archived Applied does not bind exact model publication identity/stamp/epoch/timing')
        if receipt[14]==2:
            bank_applied=True
        elif receipt[14]==1:
            require(receipt[28]==0 and finished<receipt[9]<=min(closing,deadline),
                'Pending diagnostic lacks exact earlier archived Applied and late finish proof')
            bank_applied=False
        else:
            require(False,'candidate diagnostic is neither Applied nor source-proven late Pending')
        matching.append(dict(slot=slot,sequence=receipt[0],inference_cpu_ns=receipt[10],encoding_cpu_ns=receipt[11],
            decoding_cpu_ns=receipt[29],publication_cpu_ns=receipt[12],approved_version=receipt[13],
            cumulative_publication_cpu_ns=receipt[12]+receipt[29],bank_state_code=receipt[14],bank_progress_ns=receipt[28],
            bank_finish_ns=receipt[9],bank_applied_verified=bank_applied,diagnostic_progress_missing=receipt[28]==0,
            archived_applied_verified=True,
            archive_apply_id=list(apply_id),archive_stamp=[word(row,p) for p in (320,328,336)],
            archive_executor_generation=word(row,392),archive_published_ns=accepted,
            archive_started_ns=started,archive_observed_ns=observed,archive_finished_ns=finished,
            archive_deadline_ns=deadline,archive_closing_ns=closing))
    require(len(matching)==1,'actual candidate publication missing/overwritten in bounded native bank')
    rt=struct.unpack('<1024Q',runtime)
    require(rt[0]==0x43595852554e3133 and rt[1]==3 and rt[2]>0 and not rt[2]%2 and rt[32]==context['boot_epoch']
        and rt[14]>0 and rt[19]>0 and rt[20]>0 and rt[28]>=4 and rt[29]==0
        and all(rt[i]==0 for i in (9,15,18,38,56))
        and rt[4]>=1000 and all(v<=rt[4]//100 for v in rt[39:42]) and rt[35]<=700,
        'native runtime fault/quarantine/cost/model execution mismatch')
    require(rt[31]==rt[14]+rt[15]+rt[17] and rt[13]>=rt[31],
        'native runtime completed/zero-version-reply counters inconsistent')
    return dict(candidate=matching[0],runtime_publication=rt[2],inferences=rt[14],
        control_mask=rt[6],business_mask=rt[7],quarantined_mask=rt[9],
        bank_applied_verified=matching[0]['bank_applied_verified'],archived_applied_verified=True,
        zero_version_reply_count=rt[17],zero_version_reply_classification='UNCLASSIFIED',
        completed_reply_count=rt[31],started_job_count=rt[13],runtime_fault_count=rt[15],
        global_refusal_free_verified=False,full_native_runtime_verified=False,
        full_output_bytes_reconstructed=False,exact_delivery_or_reconcile_error_observed=False)
