#!/usr/bin/env python3
"""Raw A01 boot-recovery regression contract; not a complete native receipt adapter.

The native runner retains process/QMP/build provenance. This decoder validates
only the stopped records and does not promote A01 in the formal catalogue.
"""
from __future__ import annotations
import struct

MAGIC = 0x435958424f4f5431
CONFIG_MAGIC = 0x4359584130314346
MODES = {'normal': 0, 'epoch-write': 1, 'epoch-flush': 2, 'model-corrupt': 3}


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
    for h in (a, b):
        require(h[:2] == (MAGIC, 1) and h[2] % 2 == 0, 'unsealed boot sample')
        require(h[5] == c[2] and h[32:46] == c[4:18], 'mixed boot/source/input/image')
        require(not any(h[25:32]) and not any(h[46:]), 'nonzero reserved boot record')
    mode = c[2]
    if mode == 0:
        require(a[3] == b[3] == 3 and a[4] == b[4] == 0, 'boot activation failed')
        require(a[6] == b[6] > 0 and 0 < b[7] <= b[14] <= b[15],
                'AI activation preceded durable epoch or completed self-test')
        require(b[20] > 0 and b[20] <= 8_000_000 and b[22] == 1 and b[23] > 0 and b[24] == 1,
                'missing actual control-EL0 model self-test')
        require(not any(b[16:19]), 'unexpected storage injection')
    else:
        reason = 5 if mode == 3 else 4
        require(a[3] == b[3] == 2 and a[4] == b[4] == reason, 'wrong safe recovery reason')
        require(a[9] == b[9] == 15 and b[8] > a[8] > 0 and b[2] > a[2] > 0,
                'no four-CPU recovery progress')
        require(all(b[i] > a[i] for i in (10, 11, 12, 13)),
                'EL0 business or private timer stopped during recovery')
        require(not any(control) and not any(runtime), 'new AI root/job exists after failed boot')
        u = struct.unpack('<512Q', unified)
        require(u[0] == u[1] == 0 and not any(u[2:24]),
                'cluster service/authorization initialized after failed boot')
        require(b[14] == b[15] == 0, 'failed boot acquired model/activation authority')
        if mode in (1, 2):
            require(a[6] == b[6] == b[7] == 0 and b[16] == mode and b[18] > 0,
                    'epoch failure missing or reused an unconfirmed identity')
            require(not any(b[20:25]), 'model executed despite failed epoch allocation')
        else:
            require(a[6] == b[6] > 0 and b[7] > 0 and b[20] > 0 and b[22] == 1
                    and b[23] > 0 and b[24] == 2, 'corrupt model was not actually tested on C')
            require(not any(b[16:19]), 'wrong model-failure injection source')
    return dict(mode=mode, boot_recovery_contract_valid=True,
                business_progress=[b[10]-a[10], b[11]-a[11]],
                timer_progress=[b[12]-a[12], b[13]-a[13]],
                model_cpu_ns=b[20], native_acceptance_status='NOT_RUN',
                scope='A01 raw boot recovery regression; complete receipt admission remains separate')
