"""A10-only ordered host observations. These are custody, not attestation."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import threading
import time

from run_qemu import Qmp
from doctor import env
from verify_smp import require, sha


def formatter_environment():
    """Explicit build context; never archive inherited secrets or overrides."""
    local = env()
    selected = {key: local[key] for key in ('PATH', 'HOME', 'CARGO_HOME', 'RUSTUP_HOME',
        'CARGO_TARGET_DIR', 'TMPDIR', 'TMP', 'TEMP', 'SDKROOT', 'DEVELOPER_DIR') if key in local}
    selected.update(LC_ALL='C', LANG='C', TZ='UTC')
    require(all(len(value) <= 8192 for value in selected.values()), 'formatter environment bound')
    return selected


def formatter_identity(rustup=None):
    """Select tools solely from explicit caller/local context, never a receipt."""
    selected = rustup or shutil.which('rustup', path=env()['PATH'])
    require(selected is not None, 'trusted local rustup is missing')
    rustup = Path(selected).resolve(strict=True)
    def output(argv):
        return subprocess.check_output(argv, text=True, timeout=10, env=env())
    result = {'rustup': dict(path=str(rustup), sha256=sha(rustup),
                            version=output([str(rustup), '--version']))}
    for name in ('cargo', 'rustc'):
        raw = output([str(rustup), 'which', '--toolchain', 'stable', name])
        require(len(raw.splitlines()) == 1 and Path(raw.strip()).is_absolute(),
                'invalid trusted formatter tool lookup')
        path = Path(raw.strip()).resolve(strict=True)
        version = output([str(path), '--version'] + (['--verbose'] if name == 'rustc' else []))
        result[name] = dict(path=str(path), sha256=sha(path), lookup_output=raw, version=version)
        if name == 'rustc':
            hosts = [line[6:] for line in version.splitlines() if line.startswith('host: ')]
            require(len(hosts) == 1 and hosts[0] and all(c.isalnum() or c in '-_.' for c in hosts[0]),
                    'missing trusted formatter host target')
            result[name]['host'] = hosts[0]
    return result


def formatter_artifact(output):
    """Parse artifact metadata as data; the verifier never executes its path."""
    from check_prototype_evidence import _pairs
    from verify_v13_a10_native_receipt import finite_tree
    require(len(output.encode()) <= 4 * 1024**2, 'formatter build output bound')
    found = []
    for line in output.splitlines():
        try:
            row = finite_tree(json.loads(line, object_pairs_hook=_pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite formatter output'))))
        except RecursionError as error:
            raise ValueError('formatter output nesting bound') from error
        require(type(row) is dict, 'invalid formatter compiler output object')
        if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'prototype-disk':
            path = row.get('executable')
            require(row['target'].get('kind') == ['example'] and type(path) is str
                    and Path(path).is_absolute() and len(path) <= 1024,
                    'invalid formatter compiler artifact')
            found.append(path)
    require(len(found) == 1, 'missing/ambiguous formatter compiler artifact')
    return found[0]


class Witness:
    def __init__(self, path, *, byte_limit=16 * 1024**2, row_limit=1000000):
        self.path = path
        self.lock = threading.RLock()
        self.seq = 0
        self.bytes = 0
        self.byte_limit, self.row_limit = byte_limit, row_limit
        path.touch(exist_ok=False)

    def record(self, event, **fields):
        with self.lock:
            row = dict(seq=self.seq + 1, monotonic_ns=time.monotonic_ns(), event=event, **fields)
            data = (json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n').encode()
            require(len(data) <= 4 * 1024**2 and self.bytes + len(data) <= self.byte_limit
                    and self.seq < self.row_limit, 'native witness bound exceeded')
            with self.path.open('ab') as stream:
                stream.write(data)
            self.seq += 1
            self.bytes += len(data)


def close_capture(proc, sock, server, qmp, backend, witness, report):
    """Own-process SIGKILL precedes backend loss; never graceful device flush."""
    def attempt(label, action):
        try:
            action()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            prior = report.get('error')
            report['error'] = (prior + '; ' if prior else '') + label + ': ' + str(error)
    def record(event, **fields):
        attempt('native cleanup witness', lambda: witness.record(event, **fields))
    if proc is not None and proc.poll() is None:
        record('kill', pid=proc.pid, signal=9)
        attempt('QEMU kill', proc.kill)
        attempt('QEMU wait', lambda: proc.wait(timeout=5))
        record('wait', pid=proc.pid, returncode=proc.returncode)
    if sock:
        attempt('QMP socket close', sock.close)
    if server:
        attempt('NBD close', server.close)
        if server.error is not None:
            report['error'] = 'NBD worker: ' + str(server.error)
        record('backend-close', run_id=backend.meta['run_id'])
    if qmp:
        attempt('native QMP journal close', qmp.close_journal)


class TranscriptJournal:
    def __init__(self, path, *, byte_limit, command_limit, witness=None):
        self.stream = path.open('xb')
        self.byte_limit, self.command_limit = byte_limit, command_limit
        self.bytes = self.commands = 0
        self.lifecycle = []
        self.rows = 0
        self.witness = witness
        self.lock = witness.lock if witness is not None else threading.RLock()

    def append(self, row):
        # The base Qmp appends sends before sendall and received objects at parse
        # time. Preserve that point in time without replacing its protocol.
        with self.lock:
            data = (json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n').encode()
            sent = row['direction'] == 'send'
            message = row['message']
            lifecycle = sent and message['execute'] in ('cont', 'stop', 'quit')
            require(len(data) <= 4 * 1024**2 and self.bytes + len(data) <= self.byte_limit
                    and self.rows < 2 * self.command_limit + 3
                    and self.commands + int(sent) <= self.command_limit
                    and (not lifecycle or len(self.lifecycle) < 3),
                    'native QMP journal bound exceeded')
            self.stream.write(data)
            self.stream.flush()
            self.bytes += len(data)
            self.commands += int(sent)
            self.rows += 1
            if lifecycle:
                self.lifecycle.append(row)
            if self.witness is not None and (sent or 'id' in message):
                self.witness.record('qmp-request' if sent else 'qmp-response', id=message['id'])

    def extend(self, rows):
        for row in rows:
            self.append(row)

    def close(self):
        self.stream.close()


class NativeQmp(Qmp):
    def __init__(self, sock, witness, *, journal_path=None, byte_limit=0, command_limit=0):
        super().__init__(sock)
        self.witness = witness
        self.journal = None
        if journal_path is not None:
            self.journal = TranscriptJournal(journal_path, byte_limit=byte_limit,
                                             command_limit=command_limit, witness=witness)
            self.transcript = self.journal

    def close_journal(self):
        if self.journal is not None:
            self.journal.close()

    @property
    def capture_commands(self):
        if self.journal is not None:
            return self.journal.lifecycle
        return [row for row in self.transcript if row['direction'] == 'send'
                and row['message']['execute'] in ('cont', 'stop', 'quit')]

    def execute(self, command, args=None):
        if self.journal is not None:
            return super().execute(command, args)
        self.witness.record('qmp-request', id=self.seq + 1)
        result = super().execute(command, args)
        self.witness.record('qmp-response', id=self.seq)
        return result
