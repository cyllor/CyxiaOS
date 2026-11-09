"""All native A10 matrix cut shapes, with the original guest budgets."""
from v16_a10_reordered_write_v3 import (bounded_inventory, BUILD_INPUTS, CAPTURE_DIRS)
from v16_a10_write_v2 import Server, Qmp, Witness, close_capture, validate_capture_commands
from verify_smp import require
import re

VERSION = 'a10-matrix-cut-native-v4'


def validate_selector(value):
    require(type(value) is dict and value.keys() == {'cut','kind','offset','length','data_sha256'}
        and all(type(value[k]) is int for k in ('cut','kind','offset','length'))
        and value['cut'] > 0 and value['kind'] in (1,3)
        and type(value['data_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}', value['data_sha256']), 'v4 invalid mutation selector')
    if value['kind'] == 1:
        require(value['offset'] >= 0 and value['offset'] % 512 == 0
            and 0 < value['length'] <= 1024**2 and value['length'] % 512 == 0
            and value['offset'] + value['length'] <= 512*1024**2, 'v4 invalid WRITE range')
    else:
        require(value['offset'] == value['length'] == 0
            and value['data_sha256'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'v4 invalid FLUSH selector')
    return value


def validate_profile(inputs, expected_mode=None, *, capture=False):
    require(type(inputs['mode']) is int and inputs['mode'] in (2,3)
        and (expected_mode is None or type(expected_mode) is int and inputs['mode'] == expected_mode)
        and type(inputs['cut']) is int and inputs['cut'] > 0
        and inputs['phase'] in ('before','after-ack')
        and inputs['unflushed'] in ('drop','reverse-half') and inputs['reverse_replies'] is True,
        'v4 unsupported matrix cut profile')
    if capture:
        require(type(expected_mode) is int and expected_mode in (2,3), 'v4 caller mode required')
        require(type(inputs['sample_ms']) is int and inputs['sample_ms'] == 30000
            and type(inputs['capture_timeout_seconds']) in (int,float)
            and inputs['capture_timeout_seconds'] == 1920, 'v4 original source capture bound required')
