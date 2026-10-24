#!/usr/bin/env python3
"""Verify two native guests exchanging Ethernet frames; never certify a cluster.

The host supplies QEMU's Ethernet link and captures evidence. Frame generation,
receive validation and peer acknowledgments execute inside each native guest.
There is deliberately no TCP, TLS, durable contract or remote task claim here.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from check_elf import boot_profile, inspect_elf, symbol
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import manifest, require, sha

MAGIC = 0x4359584E45543133


def validate_capture(data: bytes) -> dict:
    """Independently inspect QEMU's Ethernet PCAP, including full test payloads."""
    require(24 <= len(data) <= 4 * 1024 * 1024, 'invalid capture size')
    byte_order = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(bytes(data[:4]))
    require(byte_order is not None, 'unsupported capture encoding')
    major, minor, zone, precision, snaplen, network = struct.unpack_from(byte_order + 'HHIIII', data, 4)
    require((major, minor, network) == (2, 4, 1) and snaplen >= 64,
            'invalid Ethernet capture header')
    counts, sequences, complete_ack = [0, 0], [0, 0], [False, False]
    ordinals = [set(), set()]
    offset = 24
    while offset < len(data):
        require(offset + 16 <= len(data), 'truncated packet header')
        _, _, captured, original = struct.unpack_from(byte_order + 'IIII', data, offset)
        offset += 16
        require(captured == original == 64 and offset + captured <= len(data), 'truncated/invalid packet')
        packet = data[offset:offset + captured]
        offset += captured
        node, peer, sequence = packet[23:26]
        require(node in (1, 2) and peer == 3 - node and sequence < 16, 'invalid captured identities')
        require(packet[:6] == bytes([2, 0, 0, 0, 0, peer])
                and packet[6:12] == bytes([2, 0, 0, 0, 0, node])
                and packet[12:23] == b'\x88\xb5CYXNET13\x01', 'invalid captured protocol')
        ordinal = int.from_bytes(packet[28:36], 'little')
        require(ordinal % 16 == sequence, 'invalid captured sequence')
        for at in range(36, 64):
            expected = node ^ sequence ^ packet[26] ^ packet[27] ^ packet[28 + (at - 36) % 8] ^ at
            require(packet[at] == expected, 'corrupt captured payload')
        slot = node - 1
        require(ordinal not in ordinals[slot], 'duplicate captured sequence ordinal')
        ordinals[slot].add(ordinal)
        counts[slot] += 1
        sequences[slot] |= 1 << sequence
        complete_ack[slot] |= int.from_bytes(packet[26:28], 'little') == 65535
    require(all(n >= 64 for n in counts), 'insufficient captured traffic in both directions')
    require(sequences == [65535, 65535], 'incomplete captured sequence coverage')
    require(all(complete_ack), 'missing captured complete peer acknowledgment')
    return {'frames_by_source': counts, 'sequence_masks': sequences, 'complete_acknowledgments': complete_ack}


def validate(serial: list[bytes], pages: list[bytes], cpu_counts: list[int]) -> dict:
    require(len(serial) == len(pages) == len(cpu_counts) == 2, 'exactly two guests required')
    require(cpu_counts == [4, 4], 'both guests must have exactly four vCPUs')
    require(all(len(page) == 4096 for page in pages), 'incomplete evidence page')
    words = [struct.unpack('<512Q', page) for page in pages]
    require({row[3] for row in words} == {1, 2}, 'two distinct guest identities required')
    for row, text in zip(words, serial):
        require(row[:3] == (MAGIC, 1, 1), 'invalid or incomplete evidence header')
        require(row[4] == 3 - row[3], 'unexpected peer identity')
        require(row[5] == 65535 and row[8] >= 16, 'incomplete receive coverage')
        require(row[6] == 65535, 'missing complete peer acknowledgment')
        require(row[7] >= 64, 'insufficient transmit coverage')
        require(all(value == 0 for value in row[9:]), 'guest error or nonzero reserved field')
        require(b'FAIL' not in text and b'SMP_ERROR' not in text and b'NET_ERROR' not in text,
                'guest reported failure')
        marker = f'NET_PAIR_READY node={row[3]} peer={row[4]} received=65535'.encode()
        lines = text.splitlines()
        require(lines.count(marker) == 1, 'missing/duplicate serial completion')
        require(all(lines.count(f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode()) == 1
                    for cpu in (1, 2, 3))
                and lines.count(b'SMP_BOOT_OK a=4 b=15 c=0') == 1,
                'missing/duplicate native secondary boot handshakes')
        require(lines.count(f'NET_PAIR_START node={row[3]} peer={row[4]} EL1_ETHERNET_ONLY'.encode()) == 1,
                'missing bounded EL1 Ethernet scope declaration')
    return {'nodes': 2, 'cpus_per_node': 4, 'native_ethernet_verified': True,
            'native_cluster_verified': False, 'tls_verified': False,
            'transmitted': [row[7] for row in words], 'received': [row[8] for row in words]}


def profile(data: bytes) -> dict:
    inspect_elf(data)
    location = symbol(data, 'NET_EVIDENCE')
    require(location['pa'] % 4096 == 0 and location['size'] == 4096,
            'invalid network evidence page')
    require(boot_profile(data)['ram_mib'] == 1024, 'native net image must declare 1 GiB RAM')
    return location


def run(elf: Path, output: Path, timeout: float = 30, *, linked: bool = True) -> dict:
    require(1 <= timeout <= 60, 'invalid execution deadline')
    elf = elf.resolve(strict=True)
    output = output.resolve()
    require(not output.exists(), 'refuse to reuse evidence output')
    output.mkdir(parents=True)
    before = manifest()
    (output / 'source-manifest.json').write_text(json.dumps(before, indent=2) + '\n')
    report = {'status': 'FAIL', 'scope': 'native-ethernet-bringup', 'nodes': 2,
              'native_ethernet_verified': False, 'native_cluster_verified': False,
              'tls_verified': False, 'production_isolation_verified': False,
              'runtime_truth_attested': False, 'linked': linked,
              'elf_sha256': sha(elf), 'source_manifest_sha256': sha(output / 'source-manifest.json')}
    guests = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='cyx-net-') as td, ExitStack() as stack:
        try:
            location = profile(elf.read_bytes())
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
                path = str(Path(td) / f'q{node}.sock')
                link = f'socket,id=net0,{"listen" if node == 1 else "connect"}=127.0.0.1:{port}'
                args = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                        '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
                        '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
                        '-netdev', link, '-device', f'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:0{node}',
                        '-object', f'filter-dump,id=capture,netdev=net0,file={folder / "ethernet.pcap"}',
                        '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                        '-qmp', f'unix:{path},server=on,wait=off', '-kernel', str(elf), '-no-reboot']
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
                    require(not any(word in guest['serial'] for word in (b'FAIL', b'SMP_ERROR', b'NET_ERROR')),
                            'guest reported failure')
                if all(b'NET_PAIR_READY ' in guest['serial'] for guest in guests):
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
                    report.update(status='PASS', native_ethernet_verified=True, observations=observations)
                    break
                time.sleep(.01)
            else:
                raise TimeoutError('two-guest Ethernet execution deadline')
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
            for node, capture in enumerate(captures):
                counts = capture['frames_by_source']
                require(counts[node] == report['observations']['transmitted'][node],
                        'captured TX count differs from guest completion count')
                require(counts[1 - node] >= report['observations']['received'][node],
                        'guest RX count exceeds captured peer traffic')
            report['captures'] = captures
        except (OSError, ValueError) as error:
            report.update(status='FAIL', native_ethernet_verified=False,
                          error=type(error).__name__ + ': ' + str(error))
            report['observations']['native_ethernet_verified'] = False
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['evidence_sha256'] = {str(p.relative_to(output)): sha(p)
        for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--disconnected', action='store_true', help='negative test; must fail')
    args = parser.parse_args()
    try:
        report = run(args.elf, args.output, args.timeout, linked=not args.disconnected)
    except (OSError, ValueError) as error:
        print(str(error), file=__import__('sys').stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
