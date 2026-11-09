"""Independent D01(1,1) arithmetic and Trial projection, without native authority.

This module never constructs an AcceptedSample. Canonical agreement with the
original producer result is a numeric/content comparison. Lost ingress events
and the protected sample object are explicitly outside this archive format.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import json
from pathlib import Path
import re
import struct

from v16_learning_archive import (SCHEMAS, _side, digest, word, words,
                                  verify_pair_capture)
from v16_learning_pair import sha
from verify_v13_boot_recovery import require

OBSERVATION_NS = 10_000_000_000
U64_MAX = (1 << 64) - 1
SIGN = 1 << 63


def uint(value):
    require(type(value) is int and 0 <= value <= U64_MAX, 'integer out of u64 range')
    return value


@dataclass(frozen=True)
class Binary64:
    """Finite binary64 using exact integer ratios and per-operation RN-even.

    No host floating-point operation participates in the calculation. Signed
    zero follows the production finite F64 operations. Decimal display, when
    requested by the report, is separate from these stored authoritative bits.
    """
    bits: int

    def __post_init__(self):
        uint(self.bits)
        require((self.bits >> 52) & 2047 != 2047, 'nonfinite binary64')

    @classmethod
    def ratio(cls, value, *, negative_zero=False):
        value = Fraction(value)
        negative = value < 0 or (not value and negative_zero)
        n, d = abs(value.numerator), value.denominator
        sign = SIGN if negative else 0
        if not n:
            return cls(sign)
        high = n.bit_length() - d.bit_length()
        below_power = n < (d << high) if high >= 0 else (n << -high) < d
        if below_power:
            high -= 1
        require(high <= 1023, 'binary64 overflow')
        exponent = max(high - 52, -1074)
        if exponent >= 0:
            d <<= exponent
        else:
            n <<= -exponent
        q, r = divmod(n, d)
        q += int(2 * r > d or (2 * r == d and q & 1))
        if high < -1022:
            return cls(sign | q)  # includes subnormal carry into first normal
        if q >= 1 << 53:
            q >>= 1
            high += 1
        require(high <= 1023, 'binary64 overflow')
        return cls(sign | ((high + 1023) << 52) | (q & ((1 << 52) - 1)))

    @classmethod
    def integer(cls, value):
        return cls.ratio(uint(value))

    def exact(self):
        field = (self.bits >> 52) & 2047
        m = self.bits & ((1 << 52) - 1)
        exponent = -1074
        if field:
            m |= 1 << 52
            exponent = field - 1075
        value = Fraction(m << exponent) if exponent >= 0 else Fraction(m, 1 << -exponent)
        return -value if self.bits & SIGN else value

    def neg(self):
        return Binary64(self.bits ^ SIGN)

    def add(self, other):
        a, b = self.exact(), other.exact()
        return self.ratio(a + b, negative_zero=not a and not b and bool(self.bits & other.bits & SIGN))

    def sub(self, other):
        return self.add(other.neg())

    def mul(self, other):
        return self.ratio(self.exact() * other.exact(), negative_zero=bool((self.bits ^ other.bits) & SIGN))

    def div(self, other):
        require(other.exact() != 0, 'binary64 division by zero')
        return self.ratio(self.exact() / other.exact(), negative_zero=bool((self.bits ^ other.bits) & SIGN))

    def clamp(self, low, high):
        require(low.exact() <= high.exact(), 'invalid binary64 clamp')
        return low if self.exact() < low.exact() else high if self.exact() > high.exact() else self

    def report(self):
        # Decoding for presentation does not feed subsequent arithmetic.
        return dict(bits=f'{self.bits:016x}', value=struct.unpack('<d', words(self.bits))[0])


def round_neuron(value):
    require(type(value) is int, 'invalid integer neuron')
    rounded = (1 if value >= 0 else -1) * ((abs(value) + 32) // 64)
    return min(32767, max(-32768, rounded))


def model_score(model, input64):
    require(isinstance(model, (bytes, bytearray)) and len(model) == 2772,
            'invalid integer model length')
    require(len(input64) == 64 and all(type(v) is int and -32768 <= v <= 32767 for v in input64),
            'invalid model input64')
    weights = struct.unpack('<2576b', model[:2576])
    biases = struct.unpack('<49i', model[2576:])

    def layer(inputs, offset, bias_at, count, relu):
        outputs = []
        for row in range(count):
            at = offset + row * len(inputs)
            z = 64 * biases[bias_at + row]
            z += sum(w * x for w, x in zip(weights[at:at + len(inputs)], inputs))
            value = round_neuron(z)
            outputs.append(max(0, value) if relu else value)
        return outputs

    h1 = layer(input64, 0, 0, 32, True)
    h2 = layer(h1, 2048, 32, 16, True)
    return layer(h2, 2560, 48, 1, False)[0]


def select_model(model, inputs):
    require(1 <= len(inputs) <= 32, 'invalid candidate count')
    scores = [model_score(model, inp) for inp in inputs]
    return scores, max(range(len(scores)), key=lambda i: scores[i])


def encode_weight_features(row, index):
    """Independent fixed-schema D01 CpuWeight normalization from raw fields."""
    w = struct.unpack('<512Q', row[2048:])
    at = 64 + 10 * index
    weight = struct.unpack_from('<H', row, 512 + 24 * index + 10)[0]
    out = [0] * 64
    out[0] = 256

    def set_value(position, value, upper):
        out[position] = (512 * min(value, upper) + upper) // (2 * upper)

    for i, limit in enumerate((1000, 1000, 64, 1000, 1000, 1000, 100, 1)):
        set_value(16 + i, w[24 + i], limit)
    for i, limit in enumerate((64, 100000, 1000, 10000)):
        require(w[40] & (1 << i), 'missing D01 domain feature')
        set_value(24 + i, w[32 + i], limit)
        out[32 + i] = 256
    set_value(40, 1, 255)
    set_value(41, weight, 8)
    out[48] = out[49] = 256
    for i, limit in enumerate((4000, 1000, 100000, 1)):
        if w[at + 7] & (1 << i):
            set_value(56 + i, w[at + 3 + i], limit)
            out[60 + i] = 256
    return out


def performance(requests, start):
    require(100 <= len(requests) <= 4096, 'insufficient/unbounded requests')
    uint(start)
    end = uint(start + OBSERVATION_NS)
    seen = set()
    counts = [0] * 4
    actual = []
    for identity, arrived, code, finished in requests:
        require(uint(identity) > 0 and identity not in seen and start <= uint(arrived) < end
                and type(code) is int and 1 <= code <= 4, 'invalid request identity/window/result')
        seen.add(identity)
        counts[code - 1] += 1
        if code == 1:
            require(arrived <= uint(finished) <= end, 'completed request outside observation')
            actual.append(finished - arrived)
        else:
            require(finished == 0, 'noncompleted request has finish')
    actual.sort()
    penalized = sorted(actual + [OBSERVATION_NS] * (len(requests) - len(actual)))

    def p99(values):
        return values[(99 * len(values) + 99) // 100 - 1] if values else None

    return dict(emitted=len(requests), completed=counts[0], rejected=counts[1],
                timed_out=counts[2], pending=counts[3], penalty_p99_ns=p99(penalized),
                actual_completed_p99_ns=p99(actual))


def cpu_union(intervals):
    require(len(intervals) <= 8192, 'unbounded CPU intervals')
    raw = [0] * 3
    events = []
    for node, core, start, end, cls in intervals:
        require(isinstance(node, bytes) and len(node) == 32 and any(node)
                and type(core) is int and 0 <= core < 64
                and type(cls) is int and 0 <= cls <= 3 and uint(start) <= uint(end),
                'invalid CPU interval')
        union_class = (0, 1, 1, 2)[cls]
        raw[union_class] = uint(raw[union_class] + end - start)
        events.extend(((node, core, start, 0, union_class), (node, core, end, 1, union_class)))
    events.sort()  # Starts precede ends at equal timestamps, as native does.
    active = [0] * 3
    classified = [0] * 3
    previous = None
    for node, core, at, ending, cls in events:
        if previous is not None:
            oldnode, oldcore, oldat = previous
            if (oldnode, oldcore) == (node, core):
                owner = next((i for i, count in enumerate(active) if count), None)
                if owner is not None:
                    classified[owner] = uint(classified[owner] + at - oldat)
            else:
                require(active == [0] * 3, 'unclosed CPU union')
        active[cls] += -1 if ending else 1
        require(active[cls] >= 0, 'invalid CPU event balance')
        previous = (node, core, at)
    require(active == [0] * 3, 'unclosed CPU union')
    return dict(union_ns=uint(sum(classified)), policy_ns=classified[0], executor_ns=classified[1],
                optional_ns=classified[2], raw_tagged_ns=raw)


def _adoptions(rows, header, model):
    candidate = bool(word(header, 152))
    adopted = [r for r in rows if word(r, 0) == (31 if candidate else 40)]
    require(1 <= len(adopted) <= 32, 'invalid adopted row count')
    observation, warm, closing = (word(header, p) for p in (112, 104, 120))
    until = 0
    previous = None
    weight0 = None
    identities = set()
    evaluated = []
    for index, row in enumerate(adopted):
        count, selected = struct.unpack_from('<HH', row, 204)
        weight = struct.unpack_from('<H', row, 512 + 24 * selected + 10)[0]
        snapshot, issued, accepted, finished = (word(row, p) for p in (160, 352, 360, 416))
        installed, deadline = word(row, 376), word(row, 384)
        require(accepted <= deadline and deadline - accepted <= 50_000_000
                and snapshot <= issued and snapshot < observation + OBSERVATION_NS
                and finished <= installed and deadline >= finished
                and installed == snapshot + OBSERVATION_NS,
                'invalid D01 adoption deadline/installation')
        require(weight0 is None or weight == weight0, 'renewal changed action')
        if index == 0:
            require(snapshot == word(header, 96) and finished <= warm
                    and finished - snapshot <= 5_000_000_000, 'invalid first adoption/warmup')
        else:
            require(snapshot > word(previous, 160) and finished <= until,
                    'renewal order/coverage gap')
        weight0 = weight
        until = max(until, installed)
        if candidate:
            apply = tuple(word(row, p) for p in range(272, 320, 8))
            identity = apply
            require(word(row, 320) == word(row, 344) > 0 and word(row, 328) == snapshot
                    and word(row, 336) == installed
                    and accepted <= word(row, 368) <= snapshot + 100_000_000
                    and word(row, 488) == 0 and word(row, 480) == 0,
                    'stale/invalid candidate stamp/expiry/request')
            if previous is not None:
                old = tuple(word(previous, p) for p in range(272, 320, 8))
                require(word(row, 344) > word(previous, 344) and apply[1] >= old[1]
                        and (apply[1] != old[1] or (apply[2] > old[2] and word(row, 8) > word(previous, 8))),
                        'stale candidate renewal')
            inputs = [encode_weight_features(row, i) for i in range(count)]
            scores, best = select_model(model, inputs)
            require(scores == list(struct.unpack_from('<' + 'h' * count, row, 208))
                    and best == selected, 'integer MLP score/first-maximum mismatch')
            evaluated.append(dict(inputs=inputs, scores=scores, selected=selected))
        else:
            identity = word(row, 8)
            require(word(row, 344) == word(header, 32), 'baseline boot mismatch')
            evaluated.append(None)
        require(identity not in identities, 'duplicate adoption identity')
        identities.add(identity)
        previous = row
    require(until >= observation + OBSERVATION_NS, 'adoption does not cover observation')
    return adopted, evaluated


def numeric_side(raw, model):
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
    adopted, evaluated = _adoptions(rows, h, model)
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
    canonical += words(word(h, 40), 1, 1, word(h, 88), observation,
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
        weight = struct.unpack_from('<H', row, 512 + 24 * selected + 10)[0]
        if candidate:
            e = evaluated[index]
            for inp, score in zip(e['inputs'], e['scores']):
                canonical += struct.pack('<64hh', *inp, score)
            if index == 0:
                input64 = e['inputs'][selected]
            canonical += words(word(row, 8), *(word(row, p) for p in range(272, 320, 8)),
                               word(row, 344), word(row, 392), word(row, 352), word(row, 360),
                               word(row, 368), word(row, 376), 0, word(row, 400), word(row, 416),
                               word(row, 336), word(row, 384), selected, count, 1, 0)
            canonical += row[1280:1328]
            canonical += row[16:48] + row[88:152] + words(word(row, 80))
        else:
            canonical += words(*(word(row, p) for p in (344, 8, 184, 192, 392, 152, 160, 176, 168,
                                                        352, 360)), 0,
                               *(word(row, p) for p in (400, 416, 376, 384)))
        canonical += struct.pack('<4H', 1, 1, 0, weight)
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


def reward_values(cp, bp, union_ns):
    """Pure specified software-binary64 operation order; no label/authority."""
    f = Binary64.integer
    zero, one, ten = f(0), f(1), f(10)
    x, x0 = f(cp['completed']).div(ten), f(bp['completed']).div(ten)
    floor = one.div(ten)
    dx = x.sub(x0).div(floor if x0.exact() < floor.exact() else x0)
    l = f(cp['penalty_p99_ns']).div(f(1_000_000_000))
    l0 = f(bp['penalty_p99_ns']).div(f(1_000_000_000))
    latency_floor = one.div(f(1_000_000))
    dl = l.sub(l0).div(latency_floor if l0.exact() < latency_floor.exact() else l0)
    raw_cost = f(uint(union_ns)).div(f(OBSERVATION_NS))
    cost = raw_cost.clamp(zero, one)
    four_tenths = Binary64(0x3fd999999999999a)
    fifth = Binary64(0x3fc999999999999a)
    reward = four_tenths.mul(dx.clamp(one.neg(), one)).sub(
        four_tenths.mul(dl.clamp(one.neg(), one))).sub(fifth.mul(cost))
    return dict(raw_cost=raw_cost, clipped_cost=cost, delta_throughput=dx,
                delta_latency=dl, value=reward)


def numeric_pair(candidate_raw, baseline_raw, model):
    require(len(candidate_raw) >= 2048 and len(baseline_raw) >= 2048, 'truncated pair')
    require(word(candidate_raw, 152) == 1 and word(baseline_raw, 152) == 0,
            'wrong candidate/baseline sides')
    for begin, end in ((32, 40), (56, 96), (256, 352), (448, 608), (640, 672)):
        require(candidate_raw[begin:end] == baseline_raw[begin:end], 'pair identity mismatch')
    require(word(candidate_raw, 40) != word(baseline_raw, 40)
            and word(candidate_raw, 48) != word(baseline_raw, 48), 'same trial/generation pair')
    candidate, baseline = (numeric_side(raw, model) for raw in (candidate_raw, baseline_raw))
    # The fixed archive schedule checker already checks all 100 relative
    # arrivals independently on each side, so their pairing is exact here.
    cp, bp = candidate['performance'], baseline['performance']
    calculated = reward_values(cp, bp, candidate['cpu']['union_ns'])
    reward = calculated['value']
    evidence = digest(b'CYXIA_PAIRED_LABEL_1.3\0' + bytes.fromhex(candidate['trial_canonical_sha256'])
                      + bytes.fromhex(baseline['trial_canonical_sha256']) + words(reward.bits))
    return dict(schema=1, family=[1, 1], candidate=candidate, baseline=baseline,
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


def verify_original_inventory(directory, inventory_path, inventory_sha256):
    """A caller-selected immutable anchor, never a self-selected receipt checker."""
    require(re.fullmatch('[0-9a-f]{64}', inventory_sha256 or '') is not None,
            'missing caller-selected inventory hash')
    inventory_path, root = Path(inventory_path), Path(directory)
    require(not inventory_path.is_symlink() and inventory_path.is_file()
            and inventory_path.stat().st_size <= 8 * 1024 * 1024
            and sha(inventory_path) == inventory_sha256, 'original inventory anchor mismatch')
    inventory = json.loads(inventory_path.read_text())
    require(isinstance(inventory, dict) and isinstance(inventory.get('files'), dict)
            and type(inventory.get('count')) is int and inventory['count'] == len(inventory['files'])
            and inventory['count'] > 0, 'invalid original inventory')
    require(not root.is_symlink() and root.is_dir(), 'linked/missing original capture')
    files = inventory['files']
    require({'summary.json', 'disk.raw', 'native-context.json', 'model.bin'} <= set(files),
            'inventory omits original summary/disk/context/model')
    for name, expected in files.items():
        require(isinstance(name, str) and isinstance(expected, str), 'invalid inventory file')
        path = Path(name)
        require(isinstance(name, str) and not path.is_absolute() and '..' not in path.parts
                and path.as_posix() == name and name != '.'
                and re.fullmatch('[0-9a-f]{64}', expected or '') is not None, 'invalid inventory file')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    require(actual == set(files) and all(not p.is_symlink() for p in root.rglob('*')),
            'original capture inventory membership changed')
    for name, expected in files.items():
        require(sha(root / name) == expected, 'original capture inventory changed: ' + name)
    return dict(sha256=inventory_sha256, files=len(files), summary_sha256=files['summary.json'],
                disk_sha256=files['disk.raw'])


def verify_reward_capture(directory, *, original_inventory, original_inventory_sha256,
                          source_root, build_manifest, formatter, qemu_binary, qemu_source,
                          producer_tools_root, exports_directory):
    """Read-only fixed checker + original inventory + independent numeric walk."""
    require(producer_tools_root is not None and exports_directory is not None,
            'explicit frozen producer root and separate derived exports required')
    root = Path(directory)
    anchor = verify_original_inventory(root, original_inventory, original_inventory_sha256)
    checked = verify_pair_capture(root, source_root=source_root, build_manifest=build_manifest,
                                  formatter=formatter, qemu_binary=qemu_binary, qemu_source=qemu_source,
                                  producer_tools_root=producer_tools_root,
                                  exports_directory=exports_directory)
    model = (root / 'model.bin').read_bytes()
    results = []
    for pair in checked['pairs']:
        sides = []
        for kind in ('candidate', 'baseline'):
            export = pair[kind]['raw_export']
            raw = (Path(exports_directory) / export['file']).read_bytes()
            require(digest(raw) == export['sha256'], 'numeric export changed after validation')
            sides.append(raw)
        result = numeric_pair(*sides, model)
        # Conditional statement about the trusted native program's success
        # branch (owner -> data::accept_bounded -> store), not a host authority.
        result['native_acceptance_inferred_from_trusted_producer'] = True
        result['native_acceptance_inference_basis'] = (
            'Frozen producer/source/build/run/disk custody and successful candidate archive verification; '
            'producer records success only after native pair acceptance/store. No protected sample bytes exported.')
        results.append(result)
    # Recheck both original membership and bytes after every parser/calculation.
    require(verify_original_inventory(root, original_inventory, original_inventory_sha256) == anchor,
            'original capture changed during numeric verification')
    return dict(schema=1, verifier='v16-learning-reward-v1', original_inventory=anchor,
                capture_directory=str(root.resolve()), producer_tools_root=checked['producer_tools_root'],
                archive_manifest_sha256=checked['archive_manifest_sha256'],
                structural_capture_verified=True, pairs=results,
                reward_numeric_verified=bool(results), trial_canonical_matches_native=bool(results),
                model_scores_verified=bool(results), source_event_hash_recomputed=False,
                protected_sample_export_verified=False, native_label_imported=False,
                model_trained=False, formal_acceptance=results[0]['formal_acceptance'])
