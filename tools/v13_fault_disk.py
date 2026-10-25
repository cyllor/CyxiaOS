"""Bounded volatile NBD device for native crash tests; never interprets a filesystem.

Wire contract: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
Only 512-byte aligned READ/WRITE, FLUSH and DISC are advertised/accepted. A write
reply acknowledges volatile visibility. A FLUSH reply follows backing-file fsync.
The after-ack boundary means a reply was sent, not that the guest consumed it.
"""
from __future__ import annotations
import hashlib
import gzip
import json
import os
from pathlib import Path
import select
import socket
import struct
import threading
import uuid
from verify_smp import require, sha

OPTION_MAGIC = 0x49484156454f5054
REPLY_MAGIC = 0x3e889045565a9
MAX_PAYLOAD = 1024 * 1024
MAX_PENDING = 32768  # 16 MiB: one journal's worth, in 512-byte sectors.


def receive(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size-len(data))
        if not chunk:
            raise EOFError('NBD peer disconnected')
        data.extend(chunk)
    return bytes(data)


class Backend:
    def __init__(self, path: Path, output: Path, *, cut: int = 0,
                 phase: str = 'before', unflushed: str = 'drop',
                 reverse_replies: bool = False, compress: bool = False):
        require(cut >= 0 and phase in ('before', 'after-ack'), 'invalid cut boundary')
        require(unflushed in ('drop', 'reverse-half'), 'invalid survivor rule')
        self.path, self.output = path, output
        self.size = path.stat().st_size
        require(self.size > 0 and self.size % 512 == 0, 'unaligned export size')
        output.mkdir()
        self.cut, self.phase, self.unflushed = cut, phase, unflushed
        self.reverse_replies = reverse_replies
        self.compress = compress
        self.cut_event = threading.Event()
        self.pending: dict[int, bytes] = {}
        self.requests = self.mutations = self.acks = self.flushes = 0
        self.events = self.wire = self.disk = None
        self.events_hash, self.wire_hash = hashlib.sha256(), hashlib.sha256()
        self.meta = dict(version=1, run_id=uuid.uuid4().hex,
                         disk_initial_sha256=sha(path), size=self.size,
                         cut=cut, phase=phase, unflushed=unflushed,
                         reverse_replies=reverse_replies,
                         trace_encoding='gzip' if compress else 'raw',
                         max_pending_sectors=MAX_PENDING)
        (output/'start.json').write_text(json.dumps(self.meta, indent=2)+'\n')

    def log(self, event, **fields):
        line = json.dumps(dict(event=event, **fields), separators=(',', ':'))+'\n'
        self.events_hash.update(line.encode('utf-8'))
        self.events.write(line)
        self.events.flush()

    def negotiate(self, sock):
        sock.sendall(struct.pack('>QQH', 0x4e42444d41474943, OPTION_MAGIC, 3))
        flags, = struct.unpack('>I', receive(sock, 4))
        require(flags & 1 and flags & ~3 == 0, 'unsupported NBD client flags')

        def reply(option, kind, body=b''):
            sock.sendall(struct.pack('>QIII', REPLY_MAGIC, option, kind, len(body))+body)

        for _ in range(32):
            magic, option, length = struct.unpack('>QII', receive(sock, 16))
            require(magic == OPTION_MAGIC and length <= 4096, 'invalid NBD option')
            body = receive(sock, length)
            self.log('option', option=option, body=body.hex())
            if option == 1:
                require(not body, 'only the default NBD export exists')
                sock.sendall(struct.pack('>QH', self.size, 5)+(b'' if flags & 2 else bytes(124)))
                return True
            if option == 2:
                reply(option, 1)
                return False
            if option in (6, 7):
                require(len(body) >= 6, 'short NBD INFO/GO')
                name_length, = struct.unpack_from('>I', body)
                require(name_length == 0, 'only the default NBD export exists')
                count, = struct.unpack_from('>H', body, 4)
                require(len(body) == 6+2*count, 'invalid NBD INFO/GO length')
                reply(option, 3, struct.pack('>HQH', 0, self.size, 5))
                reply(option, 3, struct.pack('>HIII', 3, 512, 4096, MAX_PAYLOAD))
                reply(option, 1)
                if option == 7:
                    return True
            else:
                reply(option, 0x80000001)
        raise ValueError('NBD option budget exhausted')

    def request(self, sock):
        header = receive(sock, 28)
        magic, flags, kind, handle, offset, length = struct.unpack('>IHHQQI', header)
        require(magic == 0x25609513 and flags == 0 and kind in (0, 1, 2, 3), 'unsupported NBD request')
        require(length <= MAX_PAYLOAD and offset+length <= self.size
                and offset % 512 == length % 512 == 0, 'NBD request outside export/budget')
        require((kind in (0, 1) and length > 0) or (kind in (2, 3) and offset == length == 0), 'invalid NBD request range')
        body = receive(sock, length) if kind == 1 else b''
        at = self.wire.tell()
        self.wire.write(header+body)
        self.wire_hash.update(header+body)
        self.wire.flush()
        self.requests += 1
        if kind in (1, 3):
            self.mutations += 1
        request = dict(id=self.requests, kind=kind, handle=handle, offset=offset,
                       length=length, mutation=self.mutations if kind in (1, 3) else 0)
        self.log('request', **request, wire_offset=at, data_sha256=hashlib.sha256(body).hexdigest())
        return request, body

    def apply(self, request, body):
        kind, offset, length = (request[key] for key in ('kind', 'offset', 'length'))
        if kind == 0:
            self.disk.seek(offset)
            result = bytearray(self.disk.read(length))
            require(len(result) == length, 'short backing-file read')
            for relative in range(0, length, 512):
                sector = self.pending.get(offset+relative)
                if sector is not None:
                    result[relative:relative+512] = sector
            return bytes(result)
        if kind == 1:
            new = sum(offset+i not in self.pending for i in range(0, length, 512))
            require(len(self.pending)+new <= MAX_PENDING, 'volatile cache budget exhausted')
            for relative in range(0, length, 512):
                self.pending[offset+relative] = body[relative:relative+512]
        elif kind == 3:
            self.persist(sorted(self.pending, reverse=True))
            self.pending.clear()
            self.flushes += 1
        self.log('complete', id=request['id'], pending_sectors=len(self.pending), flushes=self.flushes)
        return b''

    def persist(self, offsets):
        for offset in offsets:
            self.disk.seek(offset)
            self.disk.write(self.pending[offset])
        self.disk.flush()
        os.fsync(self.disk.fileno())

    def power_cut(self, request):
        offsets = sorted(self.pending, reverse=True)
        survivors = offsets[:(len(offsets)+1)//2] if self.unflushed == 'reverse-half' else []
        if survivors:
            self.persist(survivors)
        self.log('cut', id=request['id'], mutation=request['mutation'], phase=self.phase,
                 discarded_sectors=len(offsets)-len(survivors), surviving_offsets=survivors,
                 acks=self.acks, flushes=self.flushes)
        self.pending.clear()
        self.cut_event.set()

    def serve(self, sock):
        events = gzip.open(self.output/'events.jsonl.gz', 'wt', encoding='utf-8') if self.compress else (self.output/'events.jsonl').open('w')
        wire = gzip.open(self.output/'requests.bin.gz', 'wb') if self.compress else (self.output/'requests.bin').open('wb')
        with self.path.open('r+b') as self.disk, events as self.events, wire as self.wire:
            try:
                if not self.negotiate(sock):
                    return
                while True:
                    replies = []
                    cut_before = None
                    disconnect = False
                    for index in range(16 if self.reverse_replies else 1):
                        if index and not select.select([sock], [], [], .002)[0]:
                            break
                        request, body = self.request(sock)
                        if request['kind'] == 2:
                            disconnect = True
                            break
                        selected = self.cut != 0 and request['mutation'] == self.cut
                        if selected and self.phase == 'before':
                            cut_before = request
                            break
                        response = self.apply(request, body)
                        replies.append((request, response, selected))
                        # Never let a later WRITE ACK overtake a FLUSH whose
                        # durable snapshot did not include that later write.
                        if selected or request['kind'] == 3:
                            break
                    for request, response, selected in (reversed(replies) if self.reverse_replies else replies):
                        reply = struct.pack('>IIQ', 0x67446698, 0, request['handle'])
                        sock.sendall(reply+response)
                        self.acks += 1
                        self.log('ack', id=request['id'], reply=reply.hex(), data_sha256=hashlib.sha256(response).hexdigest())
                        if selected:
                            self.power_cut(request)
                            return
                    if cut_before is not None:
                        self.power_cut(cut_before)
                        return
                    if disconnect:
                        return
            except EOFError:
                self.log('disconnect', pending_sectors=len(self.pending))
            finally:
                self.pending.clear()
                (self.output/'capture.json').write_text(json.dumps(dict(version=1,
                    events_raw_sha256=self.events_hash.hexdigest(),
                    requests_raw_sha256=self.wire_hash.hexdigest()), indent=2)+'\n')


class Server:
    """One local connection. Closing the transport never flushes volatile writes."""
    def __init__(self, backend: Backend, path: Path):
        self.backend, self.path = backend, path
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path)); self.listener.listen(1)
        self.connection = None
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            self.connection, _ = self.listener.accept()
            with self.connection:
                self.backend.serve(self.connection)
        except (OSError, ValueError) as error:
            self.error = error

    def close(self):
        for sock in (self.connection, self.listener):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        self.thread.join(2)
        require(not self.thread.is_alive(), 'NBD worker did not terminate')
