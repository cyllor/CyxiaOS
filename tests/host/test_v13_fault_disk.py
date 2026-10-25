import importlib
import gzip
import inspect
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))


class VolatileNbd(unittest.TestCase):
    def start(self, go=False, **options):
        try:
            module = importlib.import_module('v13_fault_disk')
        except ModuleNotFoundError as error:
            if error.name != 'v13_fault_disk':
                raise
            self.fail('native volatile NBD fault backend is missing')
        if 'compress' in options:
            self.assertIn('compress',inspect.signature(module.Backend).parameters,'lossless compressed capture missing')
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'disk.raw'
        self.path.write_bytes(bytes(4096))
        self.initial = Path(temp.name) / 'initial.raw'
        self.initial.write_bytes(bytes(4096))
        self.backend = module.Backend(self.path, Path(temp.name) / 'trace', **options)
        self.client, server = socket.socketpair()
        self.client.settimeout(2)
        self.addCleanup(self.client.close)
        self.errors = []

        def serve():
            try:
                with server:
                    self.backend.serve(server)
            except Exception as error:
                self.errors.append(error)

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        self.assertEqual(self.receive(18), struct.pack('>QQH', 0x4e42444d41474943, 0x49484156454f5054, 3))
        self.client.sendall(struct.pack('>I', 3))
        if go:
            # QEMU first requests structured replies, then negotiates GO with
            # explicit block constraints. Unsupported options must not abort.
            self.client.sendall(struct.pack('>QII', 0x49484156454f5054, 8, 0))
            self.assertEqual(self.receive(20), struct.pack('>QIII', 0x3e889045565a9, 8, 0x80000001, 0))
            self.client.sendall(struct.pack('>QIIIHH', 0x49484156454f5054, 7, 8, 0, 1, 3))
            self.assertEqual(self.receive(32), struct.pack('>QIIIHQH', 0x3e889045565a9, 7, 3, 12, 0, 4096, 5))
            self.assertEqual(self.receive(34), struct.pack('>QIIIHIII', 0x3e889045565a9, 7, 3, 14, 3, 512, 4096, 1048576))
            self.assertEqual(self.receive(20), struct.pack('>QIII', 0x3e889045565a9, 7, 1, 0))
        else:
            self.client.sendall(struct.pack('>QII', 0x49484156454f5054, 1, 0))
            self.assertEqual(self.receive(10), struct.pack('>QH', 4096, 5))

    def receive(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.client.recv(size-len(data))
            self.assertTrue(part, 'unexpected NBD disconnect')
            data.extend(part)
        return bytes(data)

    def request(self, kind, handle, offset=0, data=b'', length=0):
        self.client.sendall(struct.pack('>IHHQQI', 0x25609513, 0, kind, handle, offset, len(data) if kind == 1 else length)+data)

    def reply(self, handle):
        self.assertEqual(self.receive(16), struct.pack('>IIQ', 0x67446698, 0, handle))

    def finish(self):
        self.client.close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.errors, [])

    def inspect(self):
        try:
            module = importlib.import_module('check_v13_fault_disk')
        except ModuleNotFoundError as error:
            if error.name != 'check_v13_fault_disk':
                raise
            self.fail('independent NBD transcript verifier is missing')
        return module.inspect(self.initial, self.path, self.backend.output)

    def test_write_read_flush_distinguishes_volatile_visibility_from_durability(self):
        self.start(go=True)
        self.request(1, 1, data=b'A'*512); self.reply(1)
        self.assertEqual(self.path.read_bytes(), bytes(4096))
        self.request(0, 2, length=512); self.reply(2)
        self.assertEqual(self.receive(512), b'A'*512)
        self.request(3, 3); self.reply(3)
        self.assertEqual(self.path.read_bytes(), b'A'*512+bytes(3584))
        self.finish()
        self.assertEqual(self.inspect()['acknowledged_flushes'], 1)

    def test_cut_before_flush_loses_acknowledged_unflushed_write(self):
        self.start(cut=2, phase='before')
        self.request(1, 1, data=b'A'*512); self.reply(1)
        self.request(3, 2)
        self.assertTrue(self.backend.cut_event.wait(2))
        self.assertEqual(self.path.read_bytes(), bytes(4096))
        self.finish()
        self.assertEqual(self.inspect()['cut']['phase'], 'before')

    def test_cut_after_flush_reply_preserves_acknowledged_write(self):
        self.start(cut=2, phase='after-ack')
        self.request(1, 1, data=b'A'*512); self.reply(1)
        self.request(3, 2); self.reply(2)
        self.assertTrue(self.backend.cut_event.wait(2))
        self.assertEqual(self.path.read_bytes(), b'A'*512+bytes(3584))
        self.finish()
        self.assertEqual(self.inspect()['cut']['phase'], 'after-ack')
        events = self.backend.output/'events.jsonl'
        original = events.read_text()
        events.write_text(''.join(line+'\n' for line in original.splitlines()
                                 if not (json.loads(line)['event'] == 'ack' and json.loads(line)['id'] == 2)))
        with self.assertRaisesRegex(ValueError, 'after-ack cut has no immediate ACK'):
            self.inspect()
        events.write_text(original)
        self.path.write_bytes(bytes(4096))
        with self.assertRaisesRegex(ValueError, 'durable disk differs'):
            self.inspect()

    def test_unflushed_sectors_can_survive_in_reverse_order_without_a_flush(self):
        self.start(cut=4, phase='before', unflushed='reverse-half')
        for handle in (1, 2, 3):
            self.request(1, handle, offset=(handle-1)*512, data=bytes([handle])*512)
            self.reply(handle)
        self.request(3, 4)
        self.assertTrue(self.backend.cut_event.wait(2))
        self.assertEqual(self.path.read_bytes(), bytes(512)+bytes([2])*512+bytes([3])*512+bytes(2560))
        self.finish()
        self.assertEqual(self.inspect()['cut']['surviving_offsets'], [1024, 512])

    def test_pipelined_requests_can_complete_in_reverse_order(self):
        self.start(reverse_replies=True)
        first=struct.pack('>IHHQQI',0x25609513,0,1,1,0,512)+b'A'*512
        second=struct.pack('>IHHQQI',0x25609513,0,1,2,512,512)+b'B'*512
        self.client.sendall(first+second)
        self.reply(2); self.reply(1)
        self.request(3, 3); self.reply(3)
        self.assertEqual(self.path.read_bytes(), b'A'*512+b'B'*512+bytes(3072))
        self.finish()
        self.assertTrue(self.inspect()['reordered_replies'])
        wire = self.backend.output/'requests.bin'
        data = bytearray(wire.read_bytes()); data[28] ^= 1; wire.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'request payload digest'):
            self.inspect()

    def test_disconnect_drains_earlier_pipelined_replies(self):
        self.start(reverse_replies=True)
        write=struct.pack('>IHHQQI',0x25609513,0,1,1,0,512)+b'A'*512
        second=struct.pack('>IHHQQI',0x25609513,0,1,2,512,512)+b'B'*512
        disc=struct.pack('>IHHQQI',0x25609513,0,2,3,0,0)
        self.client.sendall(write+second+disc)
        self.reply(2); self.reply(1)
        self.assertEqual(self.client.recv(1),b'')
        self.finish()
        self.assertEqual(self.inspect()['acknowledged_flushes'],0)

    def test_flush_reply_covers_every_write_acknowledged_before_it(self):
        self.start(reverse_replies=True)
        writes={1:(0,b'A'*512),3:(512,b'B'*512)}
        self.client.sendall(struct.pack('>IHHQQI',0x25609513,0,1,1,0,512)+b'A'*512
            +struct.pack('>IHHQQI',0x25609513,0,3,2,0,0)
            +struct.pack('>IHHQQI',0x25609513,0,1,3,512,512)+b'B'*512)
        acknowledged=set()
        for _ in range(3):
            magic,error,handle=struct.unpack('>IIQ',self.receive(16))
            self.assertEqual((magic,error),(0x67446698,0))
            if handle==2:
                stable=self.path.read_bytes()
                for earlier in acknowledged:
                    offset,body=writes[earlier]
                    self.assertEqual(stable[offset:offset+512],body,'FLUSH reply preceded durability of an already-ACKed write')
            else:
                acknowledged.add(handle)
        self.finish()
        self.inspect()

    def test_verifier_rejects_acked_write_overtaking_a_flush_that_did_not_persist_it(self):
        self.start()
        self.request(1,1,data=b'A'*512); self.reply(1)
        self.request(3,2); self.reply(2)
        self.request(1,3,offset=512,data=b'B'*512); self.reply(3)
        self.finish()
        events=self.backend.output/'events.jsonl'
        rows=[json.loads(line) for line in events.read_text().splitlines()]
        prefix=[row for row in rows if row['event']=='option']
        def event(kind,identity):
            return next(row for row in rows if row['event']==kind and row.get('id')==identity)
        reordered=prefix+[event(kind,identity) for kind,identity in [
            ('request',1),('complete',1),('ack',1),('request',2),('complete',2),
            ('request',3),('complete',3),('ack',3),('ack',2)]]+[rows[-1]]
        events.write_text(''.join(json.dumps(row)+'\n' for row in reordered))
        with self.assertRaisesRegex(ValueError,'FLUSH ACK omitted an already-ACKed write'):
            self.inspect()

    def test_native_boundary_schedule_excludes_host_flush_and_merged_writes(self):
        runner=importlib.import_module('verify_v13_storage_faults')
        self.assertTrue(callable(getattr(runner,'validate_schedule',None)), 'native boundary binding missing')
        rows=[dict(mutation=i+1,kind=1,offset=8192+i*512,length=512) for i in range(8)]
        rows.append(dict(mutation=9,kind=3,offset=0,length=0))
        runner.validate_schedule(rows,dict(writes=1,flushes=1))
        with self.assertRaisesRegex(ValueError,'host or missing FLUSH'):
            runner.validate_schedule(rows+[dict(mutation=10,kind=3,offset=0,length=0)],dict(writes=1,flushes=1))
        merged=[dict(row) for row in rows];merged[0]['length']=1024
        with self.assertRaisesRegex(ValueError,'merged or incomplete native sector schedule'):
            runner.validate_schedule(merged,dict(writes=1,flushes=1))

    def test_compressed_capture_retains_exact_raw_bytes_and_tamper_rejection(self):
        self.start(compress=True,cut=2,phase='after-ack')
        self.request(1,1,data=b'A'*512);self.reply(1)
        self.request(3,2);self.reply(2)
        self.assertTrue(self.backend.cut_event.wait(2))
        self.finish()
        self.assertEqual(self.inspect()['acknowledged_flushes'],1)
        wire=self.backend.output/'requests.bin.gz'
        raw=gzip.decompress(wire.read_bytes())
        expected=struct.pack('>IHHQQI',0x25609513,0,1,1,0,512)+b'A'*512
        expected+=struct.pack('>IHHQQI',0x25609513,0,3,2,0,0)
        self.assertEqual(raw,expected)
        self.assertLess(wire.stat().st_size,len(raw))
        changed=bytearray(raw);changed[28]^=1
        wire.write_bytes(gzip.compress(changed,mtime=0))
        with self.assertRaisesRegex(ValueError,'request payload digest'):
            self.inspect()


if __name__ == '__main__':
    unittest.main()
