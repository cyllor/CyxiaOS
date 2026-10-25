#!/usr/bin/env python3
"""Real VirtIO FLUSH and two native boots; not a power-loss/cluster certification."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import uuid
from check_elf import boot_profile, inspect_elf, symbol
from doctor import env
from check_v13_disk import inspect as inspect_disk
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import manifest, require, sha

ROOT = Path(__file__).resolve().parents[1]
MAGIC = 0x43595853544F3133

def validate(serial: bytes, page: bytes, cpus: int, epoch: int, identity: bytes) -> dict:
    require(cpus == 4 and len(page) == 4096, 'invalid CPU/evidence profile')
    h = struct.unpack('<512Q', page)
    require(h[:3] == (MAGIC, 1, epoch), 'wrong durable boot epoch')
    require(page[24:40] == identity, 'filesystem identity changed')
    require(h[5] == (0 if epoch == 1 else 1), 'missing committed transaction recovery')
    require(h[6] == (0 if epoch == 1 else 4), 'missing complete redo replay')
    require(h[7] == 0 and h[8] == (6 if epoch == 1 else 10), 'unexpected tail/commit LSN')
    require(h[9:11] == (epoch+1, epoch+1), 'checkpoint generation/epoch mismatch')
    require(h[11] >= 4096 and h[12] >= 7 and h[13] == 4 and h[14] > 0,
            'missing native reads/writes/FLUSH/duration')
    require(not any(h[15:]), 'nonzero reserved evidence')
    lines = serial.splitlines()
    for line in [b'STORAGE_V13_BOOT_DURABLE', b'STORAGE_V13_READY', b'SMP_BOOT_OK a=4 b=15 c=0']:
        require(lines.count(line) == 1, 'missing/duplicate native completion')
    for cpu in (1, 2, 3):
        require(lines.count(f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode()) == 1, 'missing secondary boot')
    require(not any(s in serial for s in (b'FAIL', b'PANIC', b'SMP_ERROR')), 'guest failure')
    return dict(epoch=epoch, uuid=identity.hex(), replayed_blocks=h[6], commit_lsn=h[8],
                reads=h[11], writes=h[12], flushes=h[13], elapsed_guest_ms=h[14])

def validate_recovery(serial: bytes, page: bytes, cpus: int, before: dict) -> dict:
    """Compare native replay with the independently decoded durable prefix."""
    require(cpus == 4 and len(page) == 4096, 'invalid recovery CPU/evidence profile')
    h = struct.unpack('<512Q', page)
    epoch = before['boot_epoch']+1
    require(h[:3] == (MAGIC, 1, epoch) and page[24:40].hex() == before['uuid'], 'wrong recovered boot identity')
    require(h[5:8] == (before['committed_transactions'], before['replayed_blocks'], int(before['discarded_tail'])),
            'native recovery disagrees with independent prefix')
    require(h[8:11] == (before['last_commit_lsn']+4, before['generation']+1, before['log_epoch']+1),
            'recovered checkpoint/commit chain mismatch')
    require(h[11] >= 4096 and h[12] == before['replayed_blocks']+7 and h[13] == 4 and h[14] > 0
            and not any(h[15:]), 'incomplete recovery I/O evidence')
    lines = serial.splitlines()
    expected = [b'STORAGE_V13_BOOT_DURABLE', b'STORAGE_V13_READY', b'SMP_BOOT_OK a=4 b=15 c=0']
    expected += [f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode() for cpu in (1, 2, 3)]
    require(all(lines.count(line) == 1 for line in expected)
            and not any(s in serial for s in (b'FAIL', b'PANIC', b'SMP_ERROR')), 'incomplete/failed native recovery')
    return dict(epoch=epoch, uuid=before['uuid'], replayed_blocks=h[6], discarded_tail=bool(h[7]),
                commit_lsn=h[8], reads=h[11], writes=h[12], flushes=h[13], elapsed_guest_ms=h[14])


def boot(elf: Path, disk: Path, output: Path, timeout: float, *,
         backend_uri: str | None = None, cut_event=None) -> tuple[bytes, bytes, int]:
    output.mkdir()
    data = elf.read_bytes(); inspect_elf(data)
    require(boot_profile(data)['ram_mib'] == 1024, 'requires 1 GiB profile')
    location = symbol(data, 'STORAGE_V13_EVIDENCE')
    require(location['size'] == 4096 and location['pa'] % 4096 == 0, 'invalid evidence symbol')
    binary = shutil.which('qemu-system-aarch64', path=env()['PATH'])
    require(binary is not None, 'QEMU missing')
    version = subprocess.check_output([binary, '--version'], text=True, timeout=10)
    require(version.splitlines()[0] in ('QEMU emulator version 10.2.2', 'QEMU emulator version 10.2.2 (v10.2.2)'), 'unverified QEMU')
    raw = bytearray(); serial = bytearray(); decoder = FrameDecoder()
    proc = sock = qmp = None; cpus = []; memory = {}; args = []; page = b''; power_cut = False
    with tempfile.TemporaryDirectory(prefix='cyx-store-') as td, (output/'stderr.log').open('wb') as errors:
        try:
            path = str(Path(td)/'q.sock')
            args = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                    '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
                    '-S', '-display', 'none', '-monitor', 'none', '-nic', 'none',
                    '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                    '-qmp', f'unix:{path},server=on,wait=off', '-kernel', str(elf), '-no-reboot',
                    '-drive', f'if=none,id=store,file={backend_uri or disk},format=raw,cache=writeback',
                    '-global', 'virtio-mmio.force-legacy=false', '-device',
                    'virtio-blk-device,drive=store'+(',request-merging=off' if backend_uri is not None else '')]
            end = time.monotonic()+timeout
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors, env=env())
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None, 'QEMU exited before handshake')
                if time.monotonic() >= end: raise TimeoutError('QMP deadline')
                try: sock.connect(path); break
                except (FileNotFoundError, ConnectionRefusedError): time.sleep(.01)
            qmp = Qmp(sock); require('QMP' in qmp.receive(end), 'invalid QMP greeting')
            qmp.execute('qmp_capabilities'); cpus = qmp.execute('query-cpus-fast')
            memory = qmp.execute('query-memory-size-summary')
            require(memory['base-memory'] == 1024**3, 'wrong RAM size')
            qmp.execute('cont')
            while time.monotonic() < end:
                require(proc.poll() is None, 'QEMU exited')
                chunk = base64.b64decode(qmp.execute('ringbuf-read', {'device':'cyxlog','size':1048576,'format':'base64'}), validate=True)
                raw.extend(chunk); require(len(raw) <= 2*1024*1024, 'serial budget')
                for frame in decoder.feed(chunk): serial.extend(frame)
                if cut_event is not None and cut_event.is_set():
                    qmp.execute('stop')
                    qmp.execute('pmemsave', {'val':location['pa'],'size':4096,'filename':str(output/'page.bin')})
                    page = (output/'page.bin').read_bytes()
                    power_cut = True
                    proc.kill(); proc.wait(timeout=2)
                    return bytes(serial), page, len(cpus)
                require(not any(s in serial for s in (b'FAIL',b'PANIC',b'SMP_ERROR')), 'guest failure')
                if b'STORAGE_V13_READY\n' in serial:
                    if backend_uri is None:
                        qmp.execute('stop')
                    qmp.execute('pmemsave', {'val':location['pa'],'size':4096,'filename':str(output/'page.bin')})
                    page = (output/'page.bin').read_bytes()
                    require(decoder.loss == decoder.corrupt == 0 and not decoder.buffer, 'corrupt framed UART')
                    if backend_uri is not None:
                        # QMP stop and graceful close issue host-originated FLUSH.
                        # Preserve precisely the guest's captured durability.
                        proc.kill(); proc.wait(timeout=2)
                    return bytes(serial), page, len(cpus)
                time.sleep(.01)
            raise TimeoutError('native storage deadline')
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    if qmp: qmp.execute('quit')
                except (OSError, ValueError, RuntimeError): pass
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try: proc.wait(timeout=2)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)
            if sock: sock.close()
            (output/'serial.bin').write_bytes(raw); (output/'serial.txt').write_bytes(serial)
            if qmp: (output/'qmp.jsonl').write_text(''.join(json.dumps(m)+'\n' for m in qmp.transcript))
            (output/'launch.json').write_text(json.dumps(dict(argv=args,cpus=cpus,memory=memory,
                qemu_version=version,qemu_sha256=sha(Path(binary)),power_cut=power_cut,
                exit=proc.returncode if proc else None),indent=2)+'\n')

def run(elf: Path, output: Path, timeout: float = 120) -> dict:
    require(1 <= timeout <= 300, 'invalid timeout')
    elf = elf.resolve(strict=True); output = output.resolve()
    require(not output.exists(), 'refuse to overwrite evidence')
    output.mkdir(parents=True)
    before = manifest(); (output/'source-manifest.json').write_text(json.dumps(before,indent=2)+'\n')
    report = dict(status='FAIL', scope='native-journal-two-boots', native_storage_verified=False,
                  native_powercut_verified=False, native_cluster_verified=False,
                  production_isolation_verified=False, runtime_truth_attested=False,
                  elf_sha256=sha(elf), source_manifest_sha256=sha(output/'source-manifest.json'))
    try:
        disk = output/'disk.raw'; identity = uuid.uuid4().bytes
        command = ['cargo','run','--locked','--offline','-p','cyxia-prototype','--example','prototype-disk','--',str(disk),identity.hex()]
        provision = subprocess.run(command,cwd=ROOT,env=env(),capture_output=True,text=True,timeout=60)
        (output/'provision.log').write_text(provision.stdout+provision.stderr)
        require(provision.returncode == 0, 'formatter failed')
        require(disk.stat().st_size == 512*1024*1024, 'wrong disk size')
        report['disk_initial_sha256'] = sha(disk)
        report['boots'] = []
        for epoch in (1, 2):
            serial, page, cpus = boot(elf,disk,output/f'boot-{epoch}',timeout)
            observation=validate(serial,page,cpus,epoch,identity)
            durable=inspect_disk(disk)
            require(durable['boot_epoch']==epoch and durable['uuid']==identity.hex() and durable['last_commit_lsn']==observation['commit_lsn'], 'disk disagrees with native evidence')
            observation['independent_disk']=durable
            report['boots'].append(observation)
        require(sha(elf) == report['elf_sha256'] and before == manifest(), 'source/image changed')
        report['disk_final_sha256'] = sha(disk)
        report.update(status='PASS',native_storage_verified=True)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, struct.error) as error:
        report['error'] = type(error).__name__+': '+str(error)
    report['evidence_sha256'] = {str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*')) if p.is_file() and p.name!='disk.raw'}
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,required=True); parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--timeout',type=float,default=120); args=parser.parse_args()
    result=run(args.elf,args.output,args.timeout); print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['status']=='PASS' else 1)
