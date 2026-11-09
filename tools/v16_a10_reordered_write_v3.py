"""Strict v3 profile; transport custody primitives remain frozen v2 imports."""
import os
from pathlib import Path
import re
import stat
from v16_a10_write_v2 import CloseOwner, Server, Qmp, Witness, close_capture, validate_capture_commands
from verify_smp import require

VERSION='a10-reordered-write-native-v3'


def validate_selector(value):
    require(type(value) is dict and value.keys()=={'cut','offset','length','data_sha256'}
        and all(type(value[k]) is int for k in ('cut','offset','length'))
        and value['cut']>0 and value['offset']>=0 and value['offset']%512==0
        and 0<value['length']<=1024**2 and value['length']%512==0
        and value['offset']+value['length']<=512*1024**2
        and type(value['data_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['data_sha256']),
        'v3 invalid explicit caller WRITE selector')
    return value


def validate_profile(inputs, expected_mode=None, *, capture=False):
    require(type(inputs['mode']) is int and inputs['mode'] in (2,3)
        and (expected_mode is None or type(expected_mode) is int and inputs['mode']==expected_mode)
        and type(inputs['cut']) is int and inputs['cut']>0 and inputs['phase']=='before'
        and inputs['unflushed']=='reverse-half' and inputs['reverse_replies'] is True,
        'v3 unsupported reordered before-WRITE profile')
    if capture:
        require(type(expected_mode) is int and expected_mode in (2,3),'v3 caller mode required')
        require(type(inputs['sample_ms']) is int and inputs['sample_ms']==30000
            and type(inputs['capture_timeout_seconds']) in (int,float)
            and inputs['capture_timeout_seconds']==1920, 'v3 fixed capture bound mismatch')


# Fixed native output topology; empty directories outside it are not evidence.
BUILD_INPUTS=('Cargo.toml','Cargo.lock','rust-toolchain.toml','.cargo/config.toml',
    'crates/prototype/src/features.rs','crates/prototype/src/policy_wire.rs')
CAPTURE_DIRS=frozenset({'nbd','tools','native-tools','build-inputs','build-inputs/.cargo',
    'build-inputs/crates','build-inputs/crates/prototype','build-inputs/crates/prototype/src'})


def bounded_inventory(root, *, allowed_files=None, allowed_dirs=None,
                      max_entries=8192, max_dirs=128, max_files=8192, max_depth=8):
    """Yield regular files/stat pairs; reject before retaining excess entries.

    scandir is streamed one entry at a time. Counters include empty directories;
    recursion and simultaneously open iterators are bounded by max_depth. The
    caller may tighten caps, never enlarge these reviewed hard limits.
    """
    for value,limit in ((max_entries,8192),(max_dirs,128),(max_files,8192),(max_depth,8)):
        require(type(value) is int and 0<value<=limit,'v3 invalid inventory cap')
    root=Path(root)
    require(stat.S_ISDIR(root.lstat().st_mode),'v3 inventory root is not a real directory')
    if allowed_files is not None:
        allowed_files=frozenset(allowed_files)
        if allowed_dirs is None:
            allowed_dirs={parent.as_posix() for name in allowed_files
                for parent in Path(name).parents if parent!=Path('.')}
    if allowed_dirs is not None:allowed_dirs=frozenset(allowed_dirs)
    counts=dict(entries=0,dirs=0,files=0)
    def visit(directory,depth):
        with os.scandir(directory) as stream:
            for entry in stream:
                counts['entries']+=1
                require(counts['entries']<=max_entries,'v3 inventory entry bound')
                require(depth<=max_depth,'v3 inventory depth bound')
                path=directory/entry.name;name=path.relative_to(root).as_posix()
                info=entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode),'v3 inventory contains a symlink')
                if stat.S_ISDIR(info.st_mode):
                    counts['dirs']+=1
                    require(counts['dirs']<=max_dirs,'v3 inventory directory bound')
                    require(allowed_dirs is None or name in allowed_dirs,
                        'v3 extra inventory directory: '+name)
                    yield from visit(path,depth+1)
                else:
                    require(stat.S_ISREG(info.st_mode),'v3 inventory contains a special file')
                    counts['files']+=1
                    require(counts['files']<=max_files,'v3 inventory file bound')
                    require(allowed_files is None or name in allowed_files,
                        'v3 extra inventory file: '+name)
                    yield path,info
    yield from visit(root,1)
