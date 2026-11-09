#!/usr/bin/env python3
"""Observe one released local learning pair on unchanged, caller-selected C4 inputs."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

from boot_reboot_contract import prepare_disk
from doctor import env
from run_qemu import Qmp
from run_v13_a02 import inject_config
from run_v13_boot_recovery import DEBUG_SYMBOLS
from check_elf import symbol
from transport import FrameDecoder
from verify_v13_boot_recovery import CONFIG_MAGIC, require
from verify_v13_model import loaded_bytes
from v16_learning_pair import (VERSION, BANKS, TOOL_ROOT, sha, write_json, trusted_context,
                               released_pair_candidate, fatal_evidence, launch_argv)


def observe_pair(qmp, save, symbols, proc, deadline, decoder, raw, text, *, max_stops=64):
    """Live reads are hints. Every authority read follows confirmed QMP pause."""
    require(type(max_stops) is int and 1 <= max_stops <= 64, 'invalid stop bound')
    stopped = 0; next_serial = 0
    qmp.execute('cont')
    while time.monotonic() < deadline:
        require(proc.poll() is None, 'native process exited before released pair')
        if time.monotonic() >= next_serial:
            chunk = base64.b64decode(qmp.execute('ringbuf-read',
                dict(device='cyxlog', size=1048576, format='base64')), validate=True)
            raw.extend(chunk)
            require(len(raw) <= 8 * 1024 * 1024, 'serial capture overflow')
            for payload in decoder.feed(chunk):
                text.extend(payload + b'\n')
            require(not any(word in text or word in raw for word in (b'PANIC', b'SMP_ERROR', b'UNIFIED_FAIL')),
                    'native guest fault')
            next_serial = time.monotonic() + 1
        live = save('pending-replay.bin', symbols['replay']['pa'], 512)
        control = save('pending-control.bin', symbols['control']['pa'], 4096)
        fatal_hint = False
        try:
            fatal_evidence(live, control)
        except ValueError:
            fatal_hint = True
        if fatal_hint or released_pair_candidate(live) is not None:
            require(stopped < max_stops, 'stopped candidate probe limit exceeded')
            qmp.execute('stop')
            require(qmp.execute('query-status')['status'] == 'paused', 'capture not stopped')
            stopped += 1
            probe = {}
            for key, (_, size) in BANKS.items():
                if key != 'config':
                    probe[key] = save(f'probe-{stopped:02d}-{key}.bin', symbols[key]['pa'], size)
            fatal_evidence(probe['replay'], probe['control'])
            if (released_pair_candidate(probe['replay']) is None
                    or struct.unpack('<64Q', probe['boot'])[2] % 2):
                qmp.execute('cont')
                time.sleep(.1)
                continue
            for key, value in probe.items():
                require(save(key + '.bin', symbols[key]['pa'], len(value)) == value,
                        'stopped bank changed: ' + key)
            return dict(stopped_attempts=stopped, **released_pair_candidate(probe['replay']))
        time.sleep(.1)
    raise TimeoutError('native learning pair did not release within host observation window')


def close_owned(proc, sock, qmp, *, started_ns):
    """Attempt every owned cleanup independently; return all ordinary failures."""
    errors = []; forced = False; quit_ok = False; eof = False; peer_pid = None
    def attempt(label, operation):
        try:
            return operation()
        except Exception as error:
            errors.append(label + ': ' + str(error))
    if qmp is not None:
        try:
            connection = qmp.sock.sock if isinstance(qmp.sock, WireSocket) else qmp.sock
            peer_pid = (connection.getsockopt(0, 2) if sys.platform == 'darwin' else
                        struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0])
            require(proc is not None and peer_pid == proc.pid, 'QMP peer is not owned process')
        except Exception as error:
            errors.append('peer identity: ' + str(error))
    if qmp is not None and proc is not None and attempt('process poll', proc.poll) is None:
        try:
            qmp.execute('quit'); quit_ok = True
            deadline = time.monotonic() + 5
            while True:
                try:
                    message = qmp.receive(deadline)
                    require('event' in message, 'unexpected response after quit')
                except RuntimeError as error:
                    require(str(error) == 'QMP disconnected', 'QMP failed before EOF')
                    eof = True; break
        except Exception as error:
            errors.append('normal quit/EOF: ' + str(error))
    if proc is not None:
        attempt('process wait', lambda: proc.wait(timeout=5))
        if attempt('process poll after wait', proc.poll) is None:
            forced = True
            attempt('process kill', proc.kill)
            attempt('process wait after kill', lambda: proc.wait(timeout=5))
    if sock is not None:
        closed = attempt('QMP socket close', sock.close)
        if isinstance(closed, list):
            errors.extend(closed)
    return dict(schema=1, pid=proc.pid if proc else None, started_ns=started_ns,
                exited_ns=time.monotonic_ns(), returncode=proc.returncode if proc else None,
                forced=forced, quit_ok=quit_ok, eof=eof, peer_pid=peer_pid, errors=errors)


class WireSocket:
    """Preserve raw QMP chunks and independently close every owned resource."""
    def __init__(self, sock, directory):
        self.sock = sock
        self.received = self.sent = None
        try:
            self.received = (directory / 'qmp-received.bin').open('xb')
            self.sent = (directory / 'qmp-sent.bin').open('xb')
        except BaseException:
            self.close()
            raise
    def recv(self, size):
        data = self.sock.recv(size)
        self.received.write(data); self.received.flush()
        return data
    def sendall(self, data):
        self.sent.write(data); self.sent.flush()
        return self.sock.sendall(data)
    def settimeout(self, timeout):
        self.sock.settimeout(timeout)
    def close(self):
        errors = []
        for label, resource in (('raw QMP socket', self.sock), ('QMP receive evidence', self.received),
                                ('QMP send evidence', self.sent)):
            if resource is not None:
                try:
                    resource.close()
                except Exception as error:
                    errors.append(label + ': ' + str(error))
        return errors


def run(build_manifest, output, *, source_root, formatter, qemu, qemu_source, timeout=600):
    require(type(timeout) in (int, float) and 5 <= timeout <= 600, 'invalid bounded host timeout')
    context = trusted_context(source_root=source_root, build_manifest=build_manifest,
                              formatter=formatter, qemu_binary=qemu, qemu_source=qemu_source)
    paths = {k: Path(v) for k, v in context['paths'].items()}
    output = Path(output).resolve()
    require(not output.exists(), 'refuse to reuse learning capture output')
    output.mkdir(mode=0o700, parents=True)
    result = dict(version=VERSION, status='FAIL', released_pair_observed=False, capture_complete=False,
                  reward_replay_verified=False, accepted_training_sample_verified=False,
                  model_trained=False, event_hash_recomputed=False, initial_image_reexecution_verified=False,
                  native_acceptance_status='NOT_RUN',
                  formal_acceptance={name: 'NOT_RUN' for name in ('A03', 'A08', 'A10', 'A16')})
    raw = bytearray(); text = bytearray(); decoder = FrameDecoder()
    proc = sock = qmp = None; started = None; config = None
    symbols = context['symbols']
    def finalization_error(label, error):
        message = label + ': ' + str(error)
        result.setdefault('cleanup_errors', []).append(message)
        result.setdefault('error', message)
        result.update(status='FAIL', released_pair_observed=False, capture_complete=False)
    def finalize(label, operation):
        try:
            return operation()
        except Exception as error:
            finalization_error(label, error)
    def save(name, address, size):
        destination = output / name
        qmp.execute('pmemsave', dict(val=address, size=size, filename=str(destination)))
        value = destination.read_bytes()
        require(len(value) == size, 'short QMP physical capture')
        return value
    try:
        write_json(output / 'native-context.json', context)
        shutil.copyfile(paths['build_manifest'], output / 'build-manifest.json')
        for name in context['artifacts']:
            shutil.copyfile(paths['build_manifest'].parent / name, output / name)
        for relative in context['tools']:
            target = output / 'producer-tools' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(TOOL_ROOT / relative, target)
        for relative in context['source_map']:
            target = output / 'source-inputs' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(paths['source_root'] / relative, target)
        write_json(output / 'source-manifest.json', context['source_map'])
        image = (output / 'node-a.elf').read_bytes(); location = symbol(image, 'A02_BOOT_MODEL')
        (output / 'model.bin').write_bytes(loaded_bytes(image, location['va'], location['size']))
        uuid = secrets.token_hex(16)
        write_json(output / 'formatter-command.json', dict(argv=[str(paths['formatter']), str(output / 'disk.raw'), uuid]))
        origin = prepare_disk(output, paths['formatter'], uuid)
        write_json(output / 'disk-before.json', dict(bytes=(output / 'disk.raw').stat().st_size,
                                                   sha256=sha(output / 'disk.raw')))
        inputs = dict(version=VERSION, mode=0, nonce=secrets.token_hex(16), disk_uuid=uuid,
                      timeout_seconds=timeout, poll_seconds=.1, serial_seconds=1, max_stopped_attempts=64,
                      disk_origin=origin, scope='released local pair observation; no native acceptance')
        write_json(output / 'input.json', inputs)
        config = (struct.pack('<4Q', CONFIG_MAGIC, 1, 0, 0) + bytes.fromhex(inputs['nonce'])
                  + bytes.fromhex(context['artifacts']['node-a.elf']) + bytes.fromhex(sha(output / 'input.json'))
                  + bytes.fromhex(sha(output / 'source-manifest.json')) + bytes(368))
        (output / 'config.bin').write_bytes(config)
        # Repeat all explicit validation after setup, immediately before spawn.
        require(trusted_context(**paths) == context, 'native provenance changed before start')
        with tempfile.TemporaryDirectory(prefix='cyx-lp-') as temporary, (output / 'qemu-stderr.log').open('wb') as errors:
            qpath = str(Path(temporary) / 'q.sock'); gpath = str(Path(temporary) / 'g.sock')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
            argv = launch_argv(paths['qemu_binary'], output, qpath, gpath, port)
            write_json(output / 'launch.json', dict(argv=argv, qmp=qpath, gdb=gpath, port=port, symbols=symbols))
            started = time.monotonic_ns()
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors, env=env())
            end = time.monotonic() + timeout
            connection = socket.socket(socket.AF_UNIX)
            sock = WireSocket(connection, output)
            while True:
                require(proc.poll() is None and time.monotonic() < end, 'QMP startup failed')
                try:
                    connection.connect(qpath); break
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(.01)
            qmp = Qmp(sock)
            require('QMP' in qmp.receive(end), 'missing QMP greeting')
            qmp.execute('qmp_capabilities')
            cpus = qmp.execute('query-cpus-fast'); memory = qmp.execute('query-memory-size-summary')
            require(len(cpus) == 4 and memory['base-memory'] == 1024**3, 'platform mismatch')
            write_json(output / 'platform.json', dict(cpus=cpus, memory=memory))
            header = save('dtb-header.bin', 0x40000000, 40)
            magic, size = struct.unpack_from('>2I', header)
            require(magic == 0xd00dfeed and 40 <= size <= 2 * 1024**2, 'invalid platform DTB')
            save('platform.dtb', 0x40000000, size)
            write_json(output / 'config-injection.json', inject_config(gpath, config, symbols['config']['pa']))
            require(save('config-observed.bin', symbols['config']['pa'], 512) == config, 'config not observed')
            result['boundary'] = observe_pair(qmp, save, symbols, proc, end, decoder, raw, text)
    except (OSError, ValueError, RuntimeError, TimeoutError, KeyError, struct.error, subprocess.SubprocessError) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        # The temporary socket directory may have been removed, but the connected
        # owned QMP fd remains usable until this cleanup finishes.
        if qmp is not None and proc.poll() is None:
            try:
                qmp.execute('stop')
                require(qmp.execute('query-status')['status'] == 'paused', 'diagnostic not stopped')
                diagnostic_names = dict(DEBUG_SYMBOLS)
                for key, (name, _) in BANKS.items():
                    diagnostic_names[key] = name
                failures = {}
                for key, name in diagnostic_names.items():
                    try:
                        location = symbol(image, name)
                        require(0 < location['size'] <= 512 * 1024, 'diagnostic bank bound')
                        save('diagnostic-' + key + '.bin', location['pa'], location['size'])
                    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
                        failures[key] = str(error)
                if failures:
                    result['diagnostic_errors'] = failures
                chunk = base64.b64decode(qmp.execute('ringbuf-read',
                    dict(device='cyxlog', size=1048576, format='base64')), validate=True)
                raw.extend(chunk)
                require(len(raw) <= 8 * 1024**2, 'serial capture overflow')
                for payload in decoder.feed(chunk):
                    text.extend(payload + b'\n')
            except (OSError, ValueError, RuntimeError, TimeoutError) as error:
                result.setdefault('error', 'failure capture: ' + str(error))
        process = close_owned(proc, sock, qmp, started_ns=started)
        for error in process['errors']:
            finalization_error('owned cleanup', error)
        if proc is not None and (process['forced'] or process['returncode'] != 0 or not process['quit_ok'] or not process['eof']):
            finalization_error('owned cleanup', 'process lacks normal quit/EOF/wait0')
        finalize('process-exit record', lambda: write_json(output / 'process-exit.json', process))
        if qmp:
            finalize('QMP transcript', lambda: write_json(output / 'qmp-transcript.json', qmp.transcript))
        finalize('raw serial', lambda: (output / 'serial.bin').write_bytes(raw))
        finalize('decoded serial', lambda: (output / 'serial.txt').write_bytes(text))
        def final_disk():
            if (output / 'disk.raw').exists():
                write_json(output / 'disk-after.json', dict(bytes=(output / 'disk.raw').stat().st_size,
                                                           sha256=sha(output / 'disk.raw')))
        finalize('final disk custody', final_disk)
    try:
        require('error' not in result, result.get('error', 'capture failed'))
        from v16_learning_archive import verify_pair_capture
        checked = verify_pair_capture(output, save_exports=True, **paths)
        result.update(status='OBSERVED', released_pair_observed=True, capture_complete=True,
                      accepted_training_sample_verified=False, model_trained=False,
                      event_hash_recomputed=False, initial_image_reexecution_verified=False,
                      formal_acceptance=checked['formal_acceptance'], verification=checked)
    except (OSError, ValueError, RuntimeError, KeyError, struct.error, subprocess.SubprocessError) as error:
        result.setdefault('error', type(error).__name__ + ': ' + str(error))
    result['artifacts'] = {}
    def inventory():
        for path in sorted(output.rglob('*')):
            if path.is_file():
                digest = finalize('artifact hash ' + str(path.relative_to(output)), lambda: sha(path))
                if digest is not None:
                    result['artifacts'][str(path.relative_to(output))] = digest
    finalize('artifact inventory', inventory)
    finalize('summary record', lambda: write_json(output / 'summary.json', result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'build-manifest', 'output', 'formatter', 'qemu', 'qemu-source'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=600)
    args = parser.parse_args(argv)
    result = run(args.build_manifest, args.output, source_root=args.source_root,
                 formatter=args.formatter, qemu=args.qemu, qemu_source=args.qemu_source, timeout=args.timeout)
    print(json.dumps({k: result[k] for k in ('status', 'released_pair_observed', 'capture_complete')}, indent=2))
    return int(result['status'] != 'OBSERVED')


if __name__ == '__main__':
    sys.exit(main())
