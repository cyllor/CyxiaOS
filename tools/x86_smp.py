"""Decode bounded PC SMP mechanism observations, never full runtime acceptance."""
import re

MAGIC = 0x003731565f504d53
WORDS = 128
RECORD = 28
MARKERS = ('SMP_DISCOVERY_OK', 'SMP_AP_ONLINE_OK', 'SMP_IPI_OK',
           'SMP_STOP_RESUME_OK', 'SMP_V17_OK')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validate_words(words):
    require(len(words) == WORDS and all(type(w) is int and 0 <= w < 1 << 64 for w in words),
            'invalid SMP word bank')
    require(words[:4] == [MAGIC, 1, WORDS, 4] and words[5:9] == [0x7000, 0x8000, 2, 0]
            and not any(words[10:16]), 'unsupported or failed SMP observation')
    require(0x10000000 <= words[4] < 1 << 32 and words[4] % 4096 == 0, 'invalid LAPIC page')
    ranges, apics, records = [], [], []

    def reserve(start, end, alignment):
        require(0x100000 <= start < end <= 0x4000000 and start % alignment == 0,
                'descriptor/stack outside kernel arena or misaligned')
        require(all(end <= a or b <= start for a, b in ranges), 'shared or overlapping per-CPU memory')
        ranges.append((start, end))

    for slot in range(4):
        r = words[16 + slot * RECORD:16 + (slot + 1) * RECORD]
        require(r[0] == slot and 0 <= r[1] < 255 and r[1] not in apics,
                'missing or duplicate CPU identity')
        require(r[12] == 1 and r[26:] == [0, 0], 'CPU did not complete its online generation')
        apics.append(r[1])
        reserve(r[2], r[2] + 56, 8)
        reserve(r[3], r[3] + 4096, 16)
        reserve(r[4], r[4] + 104, 8)
        require(r[7] == r[9] + 4096 and r[8] > r[7]
                and r[5] > r[10] + 4096 and r[6] > r[11] + 4096
                and all(v % 4096 == 0 for v in r[5:12]), 'invalid guarded stack bounds')
        for start, end in ((r[9], r[8]), (r[10], r[5]), (r[11], r[6])):
            require(end - start <= 1024 * 1024, 'unbounded per-CPU stack')
            reserve(start, end, 4096)
        if slot == 0:
            require(r[1] == words[9] and not any(r[13:26]), 'invalid BSP observation')
        else:
            require(r[13] >= 6 and (r[14], r[15], r[18], r[20], r[21], r[24]) == (2, 2, 3, 4, 4, 5),
                    'missing IPI or stale stop/resume generation')
            require(0 < r[16] == r[17] < r[19] <= r[22] == r[23] < r[25],
                    'old work ran after stop or resumed work never progressed')
        records.append(dict(slot=slot, apic_id=r[1], ipis=r[13],
                            first_stop_progress=r[16], second_stop_progress=r[22],
                            resumed_progress=r[25]))
    return dict(status='SMP_STRUCTURE_VALID', apic_ids=apics, records=records, stopped_rounds=2,
                lapic_base=words[4], native_acceptance_status='NOT_RUN', unified_runtime_supported=False)


def decode(lines):
    selected = [line for line in lines if line.startswith('SMP_V17 ')]
    require(len(selected) == WORDS, 'missing or duplicated SMP evidence words')
    words = []
    for index, line in enumerate(selected):
        match = re.fullmatch(r'SMP_V17 ([0-9]{1,3}) ([0-9a-f]{16})', line)
        require(match is not None and int(match[1]) == index, 'malformed or reordered SMP evidence')
        words.append(int(match[2], 16))
    return validate_words(words)
