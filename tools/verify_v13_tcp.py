#!/usr/bin/env python3
"""Verify guest-resident ARP/IPv4/TCP over two native VirtIO NICs.

Each node first commits its BootEpoch on a distinct 512 MiB disk and obtains
VirtIO entropy. Application bytes here are diagnostic plaintext. This does not
certify TLS, authenticated membership, resource contracts, or remote tasks.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import json
import secrets
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from doctor import env, ROOT
from check_elf import boot_profile, inspect_elf, symbol
from check_v13_disk import inspect as inspect_disk
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import manifest, require, sha

MAGIC = 0x4359585443503133
BODY = 65536
TOTAL = 64 + BODY + 16


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('>' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def validate_capture(data: bytes) -> dict:
    require(24 <= len(data) <= 4 * 1024 * 1024, 'invalid capture size')
    order = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(bytes(data[:4]))
    require(order is not None, 'unsupported capture encoding')
    major, minor, _, _, snaplen, network = struct.unpack_from(order + 'HHIIII', data, 4)
    require((major, minor, network) == (2, 4, 1) and snaplen >= 1514, 'invalid capture header')
    packets, arp, syn, segments, acks = [0, 0], [0, 0], [None, None], [[], []], [[], []]
    handshake = False
    arp_requests, arp_reply, ordinal = set(), False, 0
    at = 24
    while at < len(data):
        require(at + 16 <= len(data), 'truncated capture record')
        _, _, length, original = struct.unpack_from(order + 'IIII', data, at)
        at += 16
        require(14 <= length <= 1514 and length == original and at + length <= len(data), 'invalid frame size')
        frame = data[at:at + length]; at += length
        ordinal += 1
        node = frame[11]
        require(node in (1, 2) and frame[6:12] == bytes([2,0,0,0,0,node]), 'invalid source MAC')
        peer, slot = 3 - node, node - 1
        require(frame[:6] in (bytes([2,0,0,0,0,peer]), b'\xff' * 6), 'invalid destination MAC')
        packets[slot] += 1
        if frame[12:14] == b'\x08\x06':
            require(len(frame) >= 42 and frame[14:20] == b'\x00\x01\x08\x00\x06\x04', 'invalid ARP')
            operation = int.from_bytes(frame[20:22], 'big')
            require(operation in (1,2) and frame[22:28] == frame[6:12]
                    and frame[28:32] == bytes([10,42,0,node])
                    and frame[38:42] == bytes([10,42,0,peer]), 'invalid ARP identity/operation')
            peer_mac = bytes([2,0,0,0,0,peer])
            if operation == 1:
                require(frame[32:38] in (bytes(6), b'\xff'*6, peer_mac), 'invalid ARP request target')
                arp_requests.add((node,peer))
            else:
                require(frame[:6] == frame[32:38] == peer_mac and (peer,node) in arp_requests,
                        'ARP response lacks matching request')
                arp_reply = True
            arp[slot] += 1
            continue
        require(frame[12:14] == b'\x08\x00', 'unexpected network protocol')
        ip = frame[14:]
        require(len(ip) >= 20 and ip[0] == 0x45 and ip[9] == 6, 'unexpected IPv4 header')
        size = int.from_bytes(ip[2:4], 'big')
        require(40 <= size <= len(ip) and checksum(ip[:20]) == 0, 'invalid IPv4 length/checksum')
        require(int.from_bytes(ip[6:8], 'big') & 0x3fff == 0, 'IPv4 fragments unsupported')
        require(ip[12:20] == bytes([10,42,0,node,10,42,0,peer]), 'unexpected IP identities')
        tcp = ip[20:size]
        pseudo = ip[12:20] + b'\0\x06' + len(tcp).to_bytes(2, 'big')
        require(checksum(pseudo + tcp) == 0, 'invalid TCP checksum')
        source, dest, sequence, ack = struct.unpack_from('>HHII', tcp)
        require((source,dest) == ((40001,8443) if node == 1 else (8443,40001)), 'unexpected TCP ports')
        hlen, flags = (tcp[12] >> 4) * 4, tcp[13]
        require(20 <= hlen <= len(tcp) and not flags & 5, 'invalid TCP header/reset/fin')
        if flags & 2:
            if node == 1:
                require(flags == 2 and ack == 0, 'invalid initiating SYN')
            else:
                require(flags == 18 and syn[0] is not None
                        and ack == (syn[0] + 1) & 0xffffffff, 'missing or invalid SYN-ACK')
            require(syn[slot] in (None, sequence), 'multiple TCP sessions in one proof')
            syn[slot] = sequence
        elif node == 1 and flags & 16 and all(value is not None for value in syn):
            handshake |= (ack == (syn[1] + 1) & 0xffffffff
                          and sequence == (syn[0] + 1) & 0xffffffff)
        if flags & 16:
            acks[slot].append((ack,ordinal))
        payload = tcp[hlen:]
        if payload:
            require(handshake and flags & 16, 'TCP data before three-way handshake')
            segments[slot].append((sequence, payload, ordinal))
    streams = []
    identities = []
    for slot in (0,1):
        require(handshake and arp_reply and syn[slot] is not None and arp[slot] >= 1, 'missing ARP/TCP handshake')
        stream, present = bytearray(TOTAL), bytearray(TOTAL)
        base = (syn[slot] + 1) & 0xffffffff
        coverage_at = 0
        for sequence, payload, ordinal in segments[slot]:
            offset = (sequence - base) & 0xffffffff
            require(offset + len(payload) <= TOTAL, 'TCP data outside bounded stream')
            for index, value in enumerate(payload, offset):
                require(not present[index] or stream[index] == value, 'conflicting TCP retransmission')
                if not present[index]:
                    coverage_at = max(coverage_at,ordinal)
                stream[index] = value; present[index] = 1
        require(all(present), 'missing bytes in TCP stream')
        node, peer = slot + 1, 2 - slot
        require(stream[:16] == b'CYXTCP13' + bytes([1,0,node,peer,0,0,0,0]), 'invalid diagnostic stream header')
        boot = int.from_bytes(stream[16:24], 'little')
        require(boot > 0 and any(stream[24:40]) and any(stream[40:56]), 'missing boot identity/challenge')
        require(stream[56:64] == BODY.to_bytes(4,'little') + b'\0' * 4, 'invalid diagnostic length')
        require(stream[64:64+BODY] == bytes(((i*17)&255)^node^((i>>8)&255) for i in range(BODY)), 'invalid native TCP payload')
        require(stream[-16:] == b'CYXACK13' + BODY.to_bytes(8,'little'), 'missing application acknowledgment')
        require(any(((ack - base) & 0xffffffff) == TOTAL and ordinal > coverage_at
                    for ack,ordinal in acks[1-slot]), 'peer never TCP-acknowledged after complete stream')
        identities.append({'boot': boot, 'filesystem': bytes(stream[24:40]).hex(), 'challenge': bytes(stream[40:56]).hex()})
        streams.append(TOTAL)
    require(identities[0]['filesystem'] != identities[1]['filesystem'], 'cloned disk identity')
    require(identities[0]['challenge'] != identities[1]['challenge'], 'repeated challenge')
    return {'frames_by_source': packets, 'arp_by_source': arp, 'stream_bytes': streams, 'identities': identities}


def bind_captures(captures: list[dict], observations: dict, disks: list[dict], provisioned: list[dict]) -> None:
    require(len(captures) == len(disks) == len(provisioned) == 2, 'two complete disk/capture proofs required')
    require(captures[0]['identities'] == captures[1]['identities'], 'captures describe different challenges/sessions')
    for capture in captures:
        require(capture['stream_bytes'] == observations['stream_bytes'], 'capture/evidence byte counts differ')
        for node, identity in enumerate(capture['identities']):
            require(identity['boot'] == observations['boot_epochs'][node]
                    and identity['filesystem'] == observations['filesystem_uuids'][node], 'capture/evidence boot identity mismatch')
            require(identity['filesystem'] == provisioned[node]['uuid'], 'guest identity differs from provisioned disk')
            require(disks[node]['uuid'] == identity['filesystem'] and disks[node]['boot_epoch'] == identity['boot'],
                    'native BootEpoch differs from committed disk record')


def validate(serial: list[bytes], pages: list[bytes], cpu_counts: list[int]) -> dict:
    require(len(serial) == len(pages) == len(cpu_counts) == 2, 'exactly two nodes required')
    require(cpu_counts == [4,4] and all(len(p) == 4096 for p in pages), 'wrong native evidence shape')
    rows = [struct.unpack('<512Q', p) for p in pages]
    require([r[3] for r in rows] == [1,2], 'wrong native node identities')
    for row, text in zip(rows, serial):
        require(row[:3] == (MAGIC,1,1) and row[4] == 3-row[3], 'invalid TCP evidence header')
        require(row[5] > 0 and row[8] > 0 and any(row[6:8]) and any(row[9:11]), 'missing durable boot identity')
        require(row[6:8] != row[9:11], 'cloned filesystem identity')
        require(row[11:15] == (TOTAL,TOTAL,BODY,1), 'incomplete transfer/ack/entropy')
        require(1000 <= row[15] < 20000 and all(v == 0 for v in row[16:]), 'guest failure/reserved evidence')
        lines = text.splitlines()
        require(b'FAIL' not in text and b'SMP_ERROR' not in text and b'PANIC' not in text, 'guest reported failure')
        require(lines.count(f'TCP_V13_READY node={row[3]} peer={row[4]} bytes={TOTAL}'.encode()) == 1, 'missing/duplicate completion')
        require(lines.count(f'TCP_V13_START node={row[3]} peer={row[4]} boot={row[5]} EL1_TCP_PLAINTEXT_ONLY'.encode()) == 1, 'missing scope marker')
        require(lines.count(b'STORAGE_V13_BOOT_DURABLE') == 1 and lines.count(b'ENTROPY_READY VIRTIO MECHANISM') == 1, 'missing boot persistence/entropy')
        require(lines.index(b'STORAGE_V13_BOOT_DURABLE') < next(i for i,line in enumerate(lines) if line.startswith(b'TCP_V13_START ')), 'network started before durable boot')
        require(all(lines.count(f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode()) == 1 for cpu in (1,2,3)) and lines.count(b'SMP_BOOT_OK a=4 b=15 c=0') == 1, 'missing native four-core startup')
    require(rows[0][5:8] == rows[1][8:11] and rows[1][5:8] == rows[0][8:11], 'cross-node boot observations differ')
    return {'nodes':2, 'cpus_per_node':4, 'native_tcp_verified':True, 'native_cluster_verified':False,
            'tls_verified':False, 'boot_epochs':[r[5] for r in rows], 'filesystem_uuids':[struct.pack('<2Q',*r[6:8]).hex() for r in rows], 'stream_bytes':[r[11] for r in rows]}


def profile(data: bytes) -> dict:
    inspect_elf(data)
    location = symbol(data, 'TCP_V13_EVIDENCE')
    require(location['pa'] % 4096 == 0 and location['size'] == 4096,
            'invalid network evidence page')
    require(boot_profile(data)['ram_mib'] == 1024, 'native TCP image must declare 1 GiB RAM')
    return location


def run(elf: Path, output: Path, timeout: float = 60, *, linked: bool = True, entropy: bool = True, formatter: Path | None = None) -> dict:
    require(1 <= timeout <= 60, 'invalid execution deadline')
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), 'refuse to reuse evidence output')
    output.mkdir(parents=True)
    before = manifest()
    (output / 'source-manifest.json').write_text(json.dumps(before, indent=2) + '\n')
    report = {'status': 'FAIL', 'scope': 'native-tcp-bringup', 'nodes': 2,
              'native_tcp_verified': False, 'native_cluster_verified': False,
              'tls_verified': False, 'production_isolation_verified': False,
              'runtime_truth_attested': False, 'linked': linked, 'entropy_device': entropy,
              'elf_sha256': sha(elf), 'source_manifest_sha256': sha(output / 'source-manifest.json')}
    guests = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='cyx-tcp-') as td, ExitStack() as stack:
        try:
            location = profile(elf.read_bytes())
            formatter = (formatter or ROOT / 'target/debug/examples/prototype-disk').resolve(strict=True)
            report['formatter_sha256'] = sha(formatter)
            binary = shutil.which('qemu-system-aarch64')
            require(binary is not None, 'qemu-system-aarch64 is missing')
            version = subprocess.check_output([binary, '--version'], timeout=10, text=True)
            require(version.splitlines()[0] in ('QEMU emulator version 10.2.2',
                    'QEMU emulator version 10.2.2 (v10.2.2)'), 'unverified QEMU version')
            report.update(qemu_version=version, qemu_sha256=sha(Path(binary)))
            # Reserving then releasing the loopback port can race with another
            # process. QEMU startup failure is fatal; it cannot yield PASS.
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            end = started + timeout
            for node in (1, 2):
                folder = output / f'node-{node}'
                folder.mkdir()
                disk = folder / 'disk.raw'
                uuid = secrets.token_hex(16)
                result = subprocess.run([str(formatter), str(disk), uuid], check=True, capture_output=True, timeout=30)
                (folder / 'format.log').write_bytes(result.stdout + result.stderr)
                require(disk.stat().st_size == 512 * 1024 * 1024, 'disk must be 512 MiB')
                (folder / 'disk-before.json').write_text(json.dumps({'uuid': uuid, 'sha256': sha(disk)}) + '\n')
                path = str(Path(td) / f'q{node}.sock')
                link = f'socket,id=net0,{"listen" if node == 1 else "connect"}=127.0.0.1:{port}'
                args = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                        '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
                        '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
                        '-drive', f'if=none,id=disk0,format=raw,file={disk},cache=writeback', '-device', 'virtio-blk-device,drive=disk0',
                        '-netdev', link, '-device', f'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:0{node}',
                        '-object', f'filter-dump,id=capture,netdev=net0,file={folder / "ethernet.pcap"}',
                        '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                        '-qmp', f'unix:{path},server=on,wait=off', '-kernel', str(elf), '-no-reboot']
                if entropy:
                    args.extend(['-object', 'rng-random,id=rng0,filename=/dev/urandom', '-device', 'virtio-rng-device,rng=rng0'])
                guest = {'folder': folder, 'argv': args, 'raw': bytearray(), 'serial': bytearray(),
                         'decoder': FrameDecoder(), 'proc': None, 'sock': None, 'qmp': None}
                guests.append(guest)
                err = stack.enter_context((folder / 'qemu-stderr.log').open('wb'))
                guest['proc'] = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                guest['sock'] = sock
                while True:
                    require(guest['proc'].poll() is None, f'node {node}: QEMU exited before handshake')
                    if time.monotonic() >= end:
                        raise TimeoutError('QMP handshake deadline')
                    try:
                        sock.connect(path)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        time.sleep(.01)
                qmp = Qmp(sock)
                guest['qmp'] = qmp
                require('QMP' in qmp.receive(end), 'invalid QMP greeting')
                qmp.execute('qmp_capabilities')
                guest['cpus'] = qmp.execute('query-cpus-fast')
                guest['memory'] = qmp.execute('query-memory-size-summary')
                require(guest['memory']['base-memory'] == 1024 * 1024 * 1024, 'wrong QEMU RAM size')
            for guest in guests:
                if not linked:
                    guest['qmp'].execute('set_link', {'name': 'eth0', 'up': False})
                guest['qmp'].execute('cont')
            while time.monotonic() < end:
                for guest in guests:
                    require(guest['proc'].poll() is None, 'QEMU exited before acceptance')
                    value = guest['qmp'].execute('ringbuf-read', {'device': 'cyxlog', 'size': 1048576, 'format': 'base64'})
                    data = base64.b64decode(value, validate=True)
                    guest['raw'].extend(data)
                    require(len(guest['raw']) <= 2 * 1024 * 1024, 'serial budget exceeded')
                    for frame in guest['decoder'].feed(data):
                        guest['serial'].extend(frame)
                    require(not any(word in guest['serial'] for word in (b'FAIL', b'SMP_ERROR', b'PANIC')),
                            'guest reported failure')
                if all(b'TCP_V13_READY ' in guest['serial'] for guest in guests):
                    pages = []
                    for guest in guests:
                        qmp = guest['qmp']
                        qmp.execute('stop')
                        page = guest['folder'] / 'native-page.bin'
                        qmp.execute('pmemsave', {'val': location['pa'], 'size': 4096, 'filename': str(page)})
                        pages.append(page.read_bytes())
                        decoder = guest['decoder']
                        require(decoder.loss == decoder.corrupt == 0 and not decoder.buffer,
                                'incomplete/corrupt framed UART transport')
                    observations = validate([bytes(g['serial']) for g in guests], pages,
                                            [len(g['cpus']) for g in guests])
                    require(sha(elf) == report['elf_sha256'], 'ELF changed during guest run')
                    require(before == manifest(), 'source changed during guest run')
                    report.update(status='PASS', native_tcp_verified=True, observations=observations)
                    break
                time.sleep(.01)
            else:
                raise TimeoutError('two-guest TCP execution deadline')
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            for guest in guests:
                proc, qmp = guest['proc'], guest['qmp']
                if proc is not None and proc.poll() is None:
                    try:
                        if qmp:
                            qmp.execute('quit')
                    except (OSError, ValueError, RuntimeError):
                        pass
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=2)
                if guest['sock']:
                    guest['sock'].close()
                folder = guest['folder']
                (folder / 'serial.bin').write_bytes(guest['raw'])
                (folder / 'serial.txt').write_bytes(guest['serial'])
                if qmp:
                    (folder / 'qmp.jsonl').write_text(''.join(json.dumps(m) + '\n' for m in qmp.transcript))
                decoder = guest['decoder']
                (folder / 'launch.json').write_text(json.dumps({'argv': guest['argv'],
                    'cpus': guest.get('cpus'), 'memory': guest.get('memory'),
                    'exit': proc.returncode if proc is not None else None,
                    'transport': {'frames': decoder.frames, 'lost': decoder.loss, 'corrupt': decoder.corrupt}}, indent=2) + '\n')
    if report['status'] == 'PASS':
        try:
            captures = [validate_capture((guest['folder'] / 'ethernet.pcap').read_bytes()) for guest in guests]
            disks = [inspect_disk(guest['folder'] / 'disk.raw') for guest in guests]
            provisioned = [json.loads((guest['folder'] / 'disk-before.json').read_text()) for guest in guests]
            bind_captures(captures, report['observations'], disks, provisioned)
            report['captures'] = captures
            report['durable_disks'] = disks
        except (OSError, ValueError) as error:
            report.update(status='FAIL', native_tcp_verified=False,
                          error=type(error).__name__ + ': ' + str(error))
            report['observations']['native_tcp_verified'] = False
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['evidence_sha256'] = {str(p.relative_to(output)): sha(p)
        for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('--disconnected', action='store_true', help='negative test; must fail')
    parser.add_argument('--without-entropy', action='store_true', help='negative test; must fail closed')
    parser.add_argument('--formatter', type=Path)
    args = parser.parse_args()
    try:
        report = run(args.elf, args.output, args.timeout, linked=not args.disconnected, entropy=not args.without_entropy, formatter=args.formatter)
    except (OSError, ValueError) as error:
        print(str(error), file=__import__('sys').stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
