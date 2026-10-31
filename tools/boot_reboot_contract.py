"""A01 sequential disk custody; host provenance, never power-loss attestation."""
from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess

from check_prototype_evidence import read_json, safe_path, sha256
from verify_v13_boot_recovery import require

DISK_BYTES = 512 * 1024 * 1024
HANDOFF_LOG = b'Existing disk copied after predecessor process exit; formatter not invoked.\n'
SCENARIOS = (
    ('cold', 0), ('restart', 0), ('epoch-write', 1), ('after-write', 0),
    ('epoch-flush', 2), ('after-flush', 0), ('model-corrupt', 3), ('after-model', 0),
)


def disk_identity(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == DISK_BYTES,
            'missing, redirected or wrong-sized reboot disk')
    return {'bytes': DISK_BYTES, 'sha256': sha256(path)}


def verify_process(record: dict) -> None:
    require(type(record) is dict and record.keys() ==
            {'schema', 'started_ns', 'exited_ns', 'returncode', 'forced'},
            'invalid process-exit record')
    require(type(record['schema']) is int and record['schema'] == 1
            and type(record['returncode']) is int and record['returncode'] == 0
            and record['forced'] is False
            and type(record['started_ns']) is int and type(record['exited_ns']) is int
            and 0 < record['started_ns'] < record['exited_ns'],
            'guest process did not exit normally before disk handoff')


def handoff_origin(previous: Path) -> dict:
    """The caller selects the predecessor; no receipt-controlled path is used."""
    previous = Path(previous).resolve(strict=True)
    receipt = read_json(safe_path(previous, 'summary.json'))
    process = read_json(safe_path(previous, 'process-exit.json'))
    verify_process(process)
    identity = disk_identity(safe_path(previous, 'disk.raw'))
    require(receipt['files']['disk.raw'] == identity, 'predecessor disk changed')
    for name in ('process-exit.json', 'input.json'):
        path = safe_path(previous, name)
        require(receipt['files'][name] == {'bytes': path.stat().st_size, 'sha256': sha256(path)},
                'predecessor custody changed: ' + name)
    inputs = read_json(safe_path(previous, 'input.json'))
    return {'kind': 'handoff', 'parent_nonce': inputs['nonce'],
            'parent_receipt_sha256': sha256(safe_path(previous, 'summary.json')),
            'disk_sha256': identity['sha256'], 'parent_exited_ns': process['exited_ns']}


def prepare_disk(output: Path, formatter: Path, uuid: str, previous: Path | None = None) -> dict:
    """Copy only a closed predecessor. Never retry by formatting an existing disk."""
    disk = output / 'disk.raw'
    require(not disk.exists(), 'refuse to overwrite a boot disk')
    if previous is None:
        formatted = subprocess.run([str(formatter), str(disk), uuid], capture_output=True,
                                   timeout=60, check=True)
        (output / 'format.log').write_bytes(formatted.stdout + formatted.stderr)
        return {'kind': 'fresh'}
    origin = handoff_origin(previous)
    source = safe_path(Path(previous).resolve(strict=True), 'disk.raw')
    # Keep the predecessor immutable for independent replay. Only the new copy
    # is ever attached to QEMU; the predecessor process has already exited.
    with source.open('rb') as src, disk.open('xb') as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        # This is host fixture setup, before any guest starts. Do not make the
        # first guest FLUSH pay for 512 MiB of dirty host copy buffers. The
        # formatter similarly synchronizes its initial image. This does not
        # acknowledge any failed guest FLUSH or model unflushed power loss.
        dst.flush()
        os.fsync(dst.fileno())
    require(disk_identity(disk)['sha256'] == origin['disk_sha256']
            and handoff_origin(previous) == origin, 'disk changed during stopped handoff')
    (output / 'format.log').write_bytes(HANDOFF_LOG)
    return origin


def verify_origin(origin: dict, before: dict, format_log: bytes) -> None:
    require(type(before) is dict and before.keys() == {'bytes', 'sha256'}
            and type(before['bytes']) is int and before['bytes'] == DISK_BYTES,
            'invalid preboot disk identity')
    import re
    digest = lambda value: type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
    require(digest(before['sha256']), 'invalid preboot disk digest')
    require(type(origin) is dict, 'invalid frozen disk origin')
    if origin == {'kind': 'fresh'}:
        require(format_log != HANDOFF_LOG, 'fresh disk marked as handoff')
        return
    require(origin.keys() == {'kind', 'parent_nonce', 'parent_receipt_sha256',
                              'disk_sha256', 'parent_exited_ns'}
            and origin['kind'] == 'handoff'
            and type(origin['parent_nonce']) is str
            and re.fullmatch('[0-9a-f]{32}', origin['parent_nonce']) is not None
            and digest(origin['parent_receipt_sha256'])
            and origin['disk_sha256'] == before['sha256']
            and type(origin['parent_exited_ns']) is int and origin['parent_exited_ns'] > 0
            and format_log == HANDOFF_LOG, 'invalid frozen disk handoff')


def verify_transition(before: dict | None, after: dict, mode: int, issued_epoch: int) -> None:
    """Replayable filesystem epochs are not ACKs for an injected failed FLUSH."""
    if before is None:
        require(mode == 0 and issued_epoch == after['boot_epoch'] == 1,
                'cold boot did not allocate the first epoch')
        return
    require(before['uuid'] == after['uuid'], 'filesystem identity changed across reboot')
    old, new = before['boot_epoch'], after['boot_epoch']
    require(type(old) is int and type(new) is int and 0 < old < 2**64 - 1,
            'invalid prior persistent epoch')
    if mode in (0, 3):
        require(issued_epoch == new == old + 1, 'boot did not increment recovered epoch exactly once')
    else:
        require(mode in (1, 2) and issued_epoch == 0 and old <= new <= old + 1,
                'failed allocation issued an identity or reused/reset disk state')
