"""The matrix must reach all real NBD mutation kinds, phases and loss policies."""
import copy
import gzip
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v16_a10_cut_v4 import validate_profile, validate_selector
import verify_v16_a10_cut_v4 as v4
from v16_a10_write_v2 import Qmp, Server, Witness, close_capture
from v13_fault_disk import Backend
from check_v13_fault_disk import inspect as inspect_nbd
from test_v16_a10_write_v2 import CHILD as ORIGINAL_CHILD


def exercise(root, kind, phase, loss, errors=True):
    """Real backend + Unix sockets + owned subprocess; no VM verdict."""
    for name in ('initial.raw', 'disk.raw'):
        (root/name).write_bytes(bytes(16384))
    witness = Witness(root/'native-provenance.jsonl')
    backend = Backend(root/'disk.raw', root/'nbd', cut=3, phase=phase,
                      unflushed=loss, reverse_replies=True, compress=True,
                      witness=witness.record, event_clock='host-monotonic-ns-v1',
                      arm_input_sha256='1'*64)
    server = Server(backend, root/'n.sock')
    selected = ("struct.pack('>IHHQQI',0x25609513,0,1,3,1536,512)+b'z'*512"
                if kind == 1 else "struct.pack('>IHHQQI',0x25609513,0,3,3,0,0)")
    old = ("n.sendall(struct.pack('>IHHQQI',0x25609513,0,1,1,512,512)+b'x'*512)\n"
           "  assert n.recv(16)==b'';n.close()")
    new = ("n.sendall(b''.join(struct.pack('>IHHQQI',0x25609513,0,1,i,i*512,512)"
           "+bytes([119+i])*512 for i in (1,2))+"+selected+")\n"
           "  while n.recv(1024):pass\n  n.close()")
    assert old in ORIGINAL_CHILD
    child = ORIGINAL_CHILD.replace(old, new)
    if not errors:
        child = child.replace('error(1);error(2);', '').replace('error(3);break', 'break')
    proc = subprocess.Popen([sys.executable, '-B', '-c', child,
                             str(server.path), str(root/'q.sock')],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    qmp = None
    try:
        until = time.monotonic()+5
        while True:
            try:
                sock.connect(str(root/'q.sock'))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= until:
                    raise
                time.sleep(.001)
        qmp = Qmp(sock, witness, journal_path=root/'qmp.jsonl',
                  byte_limit=65536, command_limit=32)
        assert 'QMP' in qmp.receive(until)
        while not backend.ready and time.monotonic() < until:
            time.sleep(.001)
        assert backend.ready
        backend.arm()
        qmp.execute('cont')
        assert server.completed.wait(3)
        qmp.execute('ringbuf-read', dict(device='cyxlog', size=1048576, format='base64'))
        qmp.execute('stop')
        qmp.execute('query-status')
        report = dict(cut_observed=True)
        close_capture(proc, sock, server, qmp, backend, witness, report)
        assert 'error' not in report, report
        assert proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        server.close()
        sock.close()
        proc.stderr.close()
    rows = [json.loads(line) for line in (root/'qmp.jsonl').read_bytes().splitlines()]
    wrows = [json.loads(line) for line in (root/'native-provenance.jsonl').read_bytes().splitlines()]
    lifecycle = v4.Lifecycle(iter(wrows))
    faults = []
    for command, _ in v4.transactions(rows, 32, [], fault_events=faults):
        assert lifecycle.take('qmp-request')['id'] == command['id']
        assert lifecycle.take('qmp-response')['id'] == command['id']
    lifecycle.take(None)
    context = dict(pid=proc.pid, backend_run_id=backend.meta['run_id'],
                   endpoints=dict(qmp=str(root/'q.sock'), nbd=str(server.path)))
    transport = v4.validate_observations(root, context, rows, lifecycle)
    trace = inspect_nbd(root/'initial.raw', root/'disk.raw', root/'nbd')
    selector = dict(cut=3, kind=kind, offset=1536 if kind == 1 else 0,
                    length=512 if kind == 1 else 0,
                    data_sha256=hashlib.sha256(b'z'*512 if kind == 1 else b'').hexdigest())
    inputs = dict(mode=2, cut=3, phase=phase, unflushed=loss, reverse_replies=True)
    protocol = dict(lifecycle=lifecycle.events, transport=transport, fault_io_events=faults)
    scope = dict(post_resume_points=[1, 2, 3], resume_monotonic_ns=next(
        r['monotonic_ns'] for r in wrows if r['event'] == 'qmp-request'))
    return context, inputs, protocol, dict(nbd_trace=trace), scope, selector


class MatrixCutProfile(unittest.TestCase):
    def test_each_matrix_phase_and_loss_reaches_capture(self):
        for mode in (2, 3):
            for phase in ('before', 'after-ack'):
                for loss in ('drop', 'reverse-half'):
                    inputs = dict(mode=mode, cut=3, phase=phase, unflushed=loss,
                                  reverse_replies=True, sample_ms=30000,
                                  capture_timeout_seconds=1920)
                    with self.subTest(mode=mode, phase=phase, loss=loss):
                        validate_profile(inputs, mode, capture=True)

    def test_actual_backend_all_eight_cut_shapes_and_survivors(self):
        for kind in (1, 3):
            for phase in ('before', 'after-ack'):
                for loss in ('drop', 'reverse-half'):
                    with self.subTest(kind=kind, phase=phase, loss=loss), tempfile.TemporaryDirectory(prefix='a10-v4-') as temp:
                        root = Path(temp)
                        facts = exercise(root, kind, phase, loss)
                        v4.verify_cut_causality(root, *facts)
                        disk = (root/'disk.raw').read_bytes()
                        if kind == 1 and phase == 'before':
                            self.assertEqual(disk[1536:2048], bytes(512))
                        if kind == 3 and phase == 'after-ack':
                            self.assertEqual(disk[512:1024], b'x'*512)
                            self.assertEqual(disk[1024:1536], b'y'*512)
                        bad = copy.deepcopy(facts)
                        bad[-1]['kind'] = 3 if kind == 1 else 1
                        with self.assertRaises(ValueError):
                            v4.verify_cut_causality(root, *bad)

    def test_no_error_event_is_not_a_missing_cut_or_eof(self):
        with tempfile.TemporaryDirectory(prefix='a10-v4-') as temp:
            root = Path(temp)
            facts = exercise(root, 3, 'after-ack', 'drop', errors=False)
            self.assertEqual(facts[2]['fault_io_events'], [])
            v4.verify_cut_causality(root, *facts)
            damaged = copy.deepcopy(facts)
            damaged[2]['lifecycle']['backend-cut']['run_id'] = '0'*32
            with self.assertRaises(ValueError):
                v4.verify_cut_causality(root, *damaged)

    def test_exact_selector_and_source_bounds(self):
        flush = dict(cut=1, kind=3, offset=0, length=0,
                     data_sha256=hashlib.sha256(b'').hexdigest())
        validate_selector(flush)
        for bad in (dict(flush, cut=True), dict(flush, kind=True),
                    dict(flush, length=512), dict(flush, data_sha256='0'*64),
                    dict(flush, extra=1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_selector(bad)
        base = dict(mode=2, cut=1, phase='before', unflushed='drop',
                    reverse_replies=True, sample_ms=30000, capture_timeout_seconds=1920)
        for key, value in (('cut', True), ('mode', True), ('reverse_replies', False),
                           ('phase', 'after'), ('unflushed', 'keep'),
                           ('sample_ms', 100), ('capture_timeout_seconds', 2000)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_profile(dict(base, **{key: value}), 2, capture=True)


if __name__ == '__main__':
    unittest.main()
