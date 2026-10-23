"""Exercise real VirtIO disk checkpoints and reboot recovery in the ARM guest.

The host creates an empty dedicated disk and corrupts one snapshot for a
negative recovery test. All filesystem commands and serialization run in guest.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import time

from doctor import ROOT
from check_elf import inspect_elf
from shell import Guest


def await_text(guest, start, marker, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        guest.poll()
        data = bytes(guest.text[start:])
        if marker in data:
            return data
        if any(item in data for item in (b'FAIL ', b'STORAGE_ERROR ', b'STORAGE_CHECKPOINT_REJECT')):
            raise AssertionError(data[-2000:])
        time.sleep(.01)
    raise TimeoutError(f'Missing {marker!r}: {data[-2000:]!r}')


def checkpoint(guest, generation):
    start = len(guest.text)
    guest.command('storage checkpoint')
    data = await_text(guest, start, f'STORAGE_DURABLE generation={generation}'.encode())
    assert b'memory_model=8194' in data and b'io_model=20481' in data, data
    assert b'budget_unit=new_operations_per_8ms' in data, data
    progress = data
    start = len(guest.text)
    guest.command('storage status')
    data = await_text(guest, start, b'STORAGE_STATUS ')
    assert b'state=Ready' in data and b'free_pages=128' in data, data
    match = re.search(rb'ai_grants=(\d+) io_plan_decisions=(\d+) io_submitted=(\d+).*flushes=(\d+)', data)
    assert match and all(int(v) > 0 for v in match.groups()), data
    return (progress+data).decode(errors='replace')


def verify(elf, output):
    output.mkdir(parents=True, exist_ok=True)
    image = elf.read_bytes()
    inspect_elf(image)
    report = {'status':'FAIL', 'scope':'bounded RAMFS checkpoint to actual VirtIO block; explicit save, no fsync/autosave',
              'kernel_sha256':hashlib.sha256(image).hexdigest(), 'checks':[]}
    disk = output/'cyxia-data.raw'
    try:
        # Never truncate a previous artifact or a user-supplied disk.
        with disk.open('xb') as stream:
            stream.truncate(2*1024*1024)
        with Guest(elf, output/'first', disk=disk) as guest:
            boot = guest.until(b'cyxia:/> ', timeout=30)
            assert b'STORAGE_READY VIRTIO_BLOCK FLUSH' in boot and b'STORAGE_EMPTY' in boot, boot
            guest.command('mkdir /durable')
            guest.command('write /durable/note first-generation')
            guest.command('write /durable/中文 UTF8-content')
            guest.command('write /durable/blob '+'B'*1024)
            for _ in range(3):
                guest.command('append /durable/blob '+'B'*1024)
            report['first_status'] = checkpoint(guest, 1)
            assert re.search(r'STORAGE_BUDGET .*operations=4 ', report['first_status']), report['first_status']
            guest.command('write /durable/note second-generation')
            guest.command('touch /durable/new')
            tasks = []
            for _ in range(2):
                reply = guest.command('proc spawn compute 1000000 1 1')
                task = re.search(rb'spawned pid=(\d+)', reply)
                assert task, reply
                tasks.append(int(task.group(1)))
            report['second_status'] = checkpoint(guest, 2)
            assert re.search(r'STORAGE_BUDGET .*runnable=[2-8] operations=1 ', report['second_status']), report['second_status']
            first_wait = int(re.search(r'deferred_polls=(\d+)', report['first_status']).group(1))
            second_wait = int(re.search(r'deferred_polls=(\d+)', report['second_status']).group(1))
            assert second_wait > first_wait, report['second_status']
            for task in tasks:
                reply = guest.command(f'proc kill {task}')
                assert b'error:' not in reply, reply
                reply = guest.command(f'proc reap {task}')
                assert b'error:' not in reply, reply
            guest.command('write /unsaved must-disappear')
        report['checks'].append('guest wrote two generations and reported durable only after real payload/header flushes; staging grants reclaimed')
        report['checks'].append('trusted runnable work changed I/O allowance from four to one new operations per 8 ms; live checkpoint consumed the allowance and deferred new submissions while preserving completion')
        with Guest(elf, output/'reboot', disk=disk) as guest:
            boot = guest.until(b'cyxia:/> ', timeout=30)
            assert b'STORAGE_RECOVERED generation=2' in boot, boot
            assert b'second-generation\r\n' in guest.command('cat /durable/note')
            assert b'UTF8-content\r\n' in guest.command('cat /durable/中文')
            assert b'B'*4096+b'\r\n' in guest.command('cat /durable/blob')
            assert b'NotFound' in guest.command('stat /unsaved')
            assert b'error:' not in guest.command('stat /durable/new')
            guest.command('rm /durable/new')
            report['third_status'] = checkpoint(guest, 3)
        report['checks'].append('new VM recovered latest generation, Unicode filename and file bytes; omitted changes after last checkpoint')
        # Corrupt only the newest slot payload in a copy, leaving the retained
        # prior committed slot intact. This is fault injection, not host mirroring.
        damaged = output/'corrupt-newest.raw'
        shutil.copyfile(disk, damaged)
        with damaged.open('r+b') as stream:
            stream.seek(512+40)
            value = stream.read(1)
            stream.seek(512+40)
            stream.write(bytes([value[0]^0x80]))
        with Guest(elf, output/'fallback', disk=damaged) as guest:
            boot = guest.until(b'cyxia:/> ', timeout=30)
            assert b'STORAGE_SNAPSHOT_INVALID slot=0' in boot and b'STORAGE_RECOVERED generation=2 slot=1' in boot, boot
            assert b'second-generation\r\n' in guest.command('cat /durable/note')
            assert b'error:' not in guest.command('stat /durable/new')
        report['checks'].append('corrupt newest snapshot fails CRC and guest recovers older valid slot')
        with Guest(elf, output/'readonly', disk=disk, disk_readonly=True) as guest:
            boot = guest.until(b'cyxia:/> ', timeout=30)
            assert b'STORAGE_RECOVERED generation=3' in boot, boot
            assert b'NotFound' in guest.command('stat /durable/new')
            start = len(guest.text)
            guest.command('storage checkpoint')
            deadline = time.monotonic()+5
            while b'STORAGE_CHECKPOINT_REJECT read-only' not in guest.text[start:] and time.monotonic()<deadline:
                guest.poll(); time.sleep(.01)
            assert b'STORAGE_CHECKPOINT_REJECT read-only' in guest.text[start:]
        report['checks'].append('third generation persists deletion; read-only disk restores files and rejects checkpoint')
        with Guest(elf, output/'no-disk') as guest:
            boot = guest.until(b'cyxia:/> ')
            assert b'STORAGE_UNAVAILABLE' in boot
            start = len(guest.text)
            guest.command('storage checkpoint')
            deadline = time.monotonic()+5
            while b'STORAGE_CHECKPOINT_REJECT Absent' not in guest.text[start:] and time.monotonic()<deadline:
                guest.poll(); time.sleep(.01)
            assert b'STORAGE_CHECKPOINT_REJECT Absent' in guest.text[start:]
            assert b'error:' not in guest.command('write /ram-only works')
        report['checks'].append('missing disk preserves RAM shell behavior and explicitly rejects durable save')
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report['kernel_sha256'], 'kernel changed during test'
        report['disk_sha256'] = hashlib.sha256(disk.read_bytes()).hexdigest()
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/storage-verified')
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status']=='PASS' else 1)
