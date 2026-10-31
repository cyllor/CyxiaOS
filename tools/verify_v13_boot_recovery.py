#!/usr/bin/env python3
"""Raw A01 boot-recovery contract; not a complete native acceptance adapter.

Both stopped samples must independently satisfy their terminal-state contract.
Identity and settled boot facts cannot change between samples. Recovery progress
is measured separately; producer PASS fields never authorize catalogue changes.
"""
from __future__ import annotations
import struct

MAGIC = 0x435958424f4f5431
CONFIG_MAGIC = 0x4359584130314346
MODES = {'normal': 0, 'epoch-write': 1, 'epoch-flush': 2, 'model-corrupt': 3}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _model_sample(words, passed):
    require(0 < words[20] <= 8_000_000 and words[21] == 8
            and words[22] == 1 and words[23] > 0
            and words[24] == (1 if passed else 2),
            'missing bounded, completed control-EL0 model self-test')


def verify_samples(first: bytes, last: bytes, control: bytes, runtime: bytes,
                   unified: bytes, config: bytes) -> dict:
    require(all(len(x) == 512 for x in (first, last, config)), 'invalid boot record length')
    require(len(control) == len(unified) == 4096 and len(runtime) == 8192,
            'invalid authority capture length')
    a, b, c = (struct.unpack('<64Q', x) for x in (first, last, config))
    require(c[0] == CONFIG_MAGIC and c[1] == 1 and c[2] in MODES.values() and c[3] == 0,
            'wrong injection contract')
    require(any(c[4:6]) and all(any(c[i:i+4]) for i in (6, 10, 14)) and not any(c[18:]),
            'missing run identity or nonzero reserved config')
    mode = c[2]
    for h in (a, b):
        require(h[:2] == (MAGIC, 1) and h[2] % 2 == 0, 'unsealed boot sample')
        require(h[5] == mode and h[32:46] == c[4:18], 'mixed boot/source/input/image')
        require(h[19] == 0 and not any(h[25:32]) and not any(h[46:]),
                'nonzero reserved boot record')
        if mode == 0:
            require(h[3] == 3 and h[4] == 0, 'boot activation failed')
            require(h[9] == 15, 'normal boot lacks four registered guest CPUs')
            require(h[6] > 0 and 0 < h[7] <= h[14] <= h[15],
                    'AI activation preceded durable epoch or completed self-test')
            _model_sample(h, True)
            require(not any(h[16:19]), 'unexpected storage injection')
        else:
            require(h[3] == 2 and h[4] == (5 if mode == 3 else 4),
                    'wrong safe recovery reason')
            require(h[9] == 15 and h[8] > 0 and h[2] > 0,
                    'no four-CPU recovery progress')
            require(h[14] == h[15] == 0, 'failed boot acquired model/activation authority')
            if mode in (1, 2):
                require(h[6] == h[7] == 0 and h[16] == mode and h[18] > 0,
                        'epoch failure missing or reused an unconfirmed identity')
                require((mode == 1 and h[17] < 131072) or (mode == 2 and h[17] == 0),
                        'invalid device fault boundary')
                require(not any(h[20:25]), 'model executed despite failed epoch allocation')
            else:
                require(h[6] > 0 and h[7] > 0, 'model failure lacks durable epoch')
                _model_sample(h, False)
                require(not any(h[16:19]), 'wrong model-failure injection source')
    require(a[3:8] == b[3:8] and a[14:25] == b[14:25],
            'settled boot facts changed between stopped samples')
    require(b[2] >= a[2], 'boot publication sequence regressed')
    if mode != 0:
        require(b[8] > a[8] and b[2] > a[2], 'no recovery progress between samples')
        require(all(b[i] > a[i] for i in (10, 11, 12, 13)),
                'EL0 business or private timer stopped during recovery')
        require(not any(control) and not any(runtime), 'new AI root/job exists after failed boot')
        u = struct.unpack('<512Q', unified)
        require(u[0] == u[1] == 0 and not any(u[2:24]),
                'cluster service/authorization initialized after failed boot')
    return dict(mode=mode, boot_recovery_contract_valid=True, online_mask=b[9],
                business_progress=[b[10]-a[10], b[11]-a[11]],
                timer_progress=[b[12]-a[12], b[13]-a[13]],
                model_cpu_ns=b[20], native_acceptance_status='NOT_RUN',
                scope='A01 raw boot recovery regression; complete receipt admission remains separate')
