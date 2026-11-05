"""Host NBD/provenance regressions; not CyxiaOS native A10 acceptance.

Exercise the real backend with socket-level NBD requests and independently
replay every durability byte. Synthetic QMP witnesses test only the scope parser.
"""
from __future__ import annotations
import ast
from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest

from check_v13_fault_disk import inspect, read_events
from v13_a10_fault_scope import mutation_scope, require_post_resume_cut
from v13_fault_disk import Backend, receive

ROOT = Path(__file__).resolve().parents[1]


class Session:
    def __init__(self, root, *, cut=1, phase='before', loss='drop', reverse=False, legacy=False):
        self.root = root
        self.initial = root / 'initial.raw'
        self.disk = root / 'disk.raw'
        self.initial.write_bytes(bytes(4096))
        self.disk.write_bytes(self.initial.read_bytes())
        self.input = root / 'input.json'
        self.input.write_text(json.dumps(dict(cut=cut, cut_scope='post-arm-v1')) + '\n')
        digest = hashlib.sha256(self.input.read_bytes()).hexdigest()
        keywords = {} if legacy else dict(arm_input_sha256=digest)
        self.backend = Backend(self.disk, root / 'nbd', cut=cut, phase=phase,
            unflushed=loss, reverse_replies=reverse, event_clock='host-monotonic-ns-v1', **keywords)
        self.client, server = socket.socketpair()
        self.client.settimeout(3)
        self.errors = []
        self.handle = 0
        def serve():
            try:
                with server:
                    self.backend.serve(server)
            except (OSError, ValueError) as error:
                self.errors.append(error)
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        magic, options, flags = struct.unpack('>QQH', receive(self.client, 18))
        if (magic, options, flags) != (0x4e42444d41474943, 0x49484156454f5054, 3):
            self.close()
            raise AssertionError('backend no longer speaks the fixed NBD handshake')
        self.client.sendall(struct.pack('>I', 3))
        self.client.sendall(struct.pack('>QII', 0x49484156454f5054, 1, 0))
        size, export_flags = struct.unpack('>QH', receive(self.client, 10))
        if (size, export_flags) != (4096, 5):
            self.close()
            raise AssertionError('wrong NBD size/FLUSH feature')
        deadline = time.monotonic() + 3
        while not self.backend.ready and time.monotonic() < deadline:
            time.sleep(.001)
        if not self.backend.ready:
            self.close()
            raise AssertionError('backend negotiation did not finish')

    def send(self, kind, *, offset=0, body=None):
        self.handle += 1
        if kind == 1 and body is None:
            body = b'x' * 512
        body = body or b''
        length = len(body) if kind == 1 else 512 if kind == 0 else 0
        self.client.sendall(struct.pack('>IHHQQI', 0x25609513, 0, kind,
                                       self.handle, offset, length) + body)
        return self.handle

    def ack(self, handle, kind):
        reply = struct.unpack('>IIQ', receive(self.client, 16))
        if reply != (0x67446698, 0, handle):
            raise AssertionError('wrong NBD reply')
        return receive(self.client, 512) if kind == 0 else b''

    def setup_flush(self):
        self.ack(self.send(3), 3)

    def arm_and_record_resume(self):
        # Parser fixtures, not evidence of a real QEMU process or guest.
        injection_ns = time.monotonic_ns()
        readback_ns = time.monotonic_ns()
        self.backend.arm()
        self.resume_ns = time.monotonic_ns()
        rows = [dict(event='injection', seq=1, monotonic_ns=injection_ns),
                dict(event='save', seq=2, monotonic_ns=readback_ns, name='config-observed.bin'),
                dict(event='qmp-request', seq=3, monotonic_ns=self.resume_ns, id=1),
                dict(event='qmp-response', seq=4, monotonic_ns=time.monotonic_ns(), id=1)]
        (self.root / 'native-provenance.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
        (self.root / 'qmp.jsonl').write_text(json.dumps(dict(direction='send',
            message=dict(execute='cont', id=1))) + '\n')

    def finish_cut(self):
        if not self.backend.cut_event.wait(3):
            raise AssertionError('requested post-arm power cut did not occur')
        self.thread.join(3)
        if self.thread.is_alive() or self.errors:
            raise AssertionError('backend failed to finish: ' + repr(self.errors))
        return inspect(self.initial, self.disk, self.root / 'nbd')

    def close(self):
        try:
            self.client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.client.close()
        self.thread.join(6)
        if self.thread.is_alive():
            raise AssertionError('test backend thread did not terminate')


@contextmanager
def session(**kwargs):
    with tempfile.TemporaryDirectory(prefix='a10-arming-') as temporary:
        case = Session(Path(temporary), **kwargs)
        try:
            yield case
        finally:
            case.close()


class FaultArming(unittest.TestCase):
    def test_setup_flush_count_cannot_shift_first_write_or_flush(self):
        for count in (0, 1, 3):
            for phase in ('before', 'after-ack'):
                for kind in (1, 3):
                    for reverse in (False, True):
                        with self.subTest(count=count, phase=phase, kind=kind, reverse=reverse):
                            with session(phase=phase, reverse=reverse) as case:
                                for _ in range(count):
                                    case.setup_flush()
                                self.assertFalse(case.backend.cut_event.is_set())
                                self.assertEqual(case.backend.fault_mutations, 0)
                                case.arm_and_record_resume()
                                handle = case.send(kind)
                                if phase == 'after-ack':
                                    case.ack(handle, kind)
                                replay = case.finish_cut()
                                self.assertEqual(replay['cut']['mutation'], 1)
                                self.assertEqual(replay['cut']['raw_mutation'], count + 1)
                                self.assertEqual(replay['mutations'], 1)
                                self.assertEqual(replay['raw_mutations'], count + 1)
                                self.assertEqual(case.disk.read_bytes(), case.initial.read_bytes())
                                scope = require_post_resume_cut(case.root, 1)
                                self.assertEqual(scope['post_resume_points'], [1])
                                self.assertEqual(scope['pre_resume_raw_points'], list(range(1, count+1)))
                                self.assertEqual(scope['post_resume_raw_points'], [count+1])

    def test_write_before_flush_cut_keeps_original_loss_and_flush_semantics(self):
        for phase in ('before', 'after-ack'):
            for loss in ('drop', 'reverse-half'):
                with self.subTest(phase=phase, loss=loss), session(cut=3, phase=phase, loss=loss) as case:
                    case.setup_flush()
                    case.arm_and_record_resume()
                    case.ack(case.send(1, offset=0, body=b'a'*512), 1)
                    case.ack(case.send(1, offset=512, body=b'b'*512), 1)
                    handle = case.send(3)
                    if phase == 'after-ack':
                        case.ack(handle, 3)
                    replay = case.finish_cut()
                    self.assertEqual(replay['cut']['raw_mutation'], 4)
                    actual = case.disk.read_bytes()
                    if phase == 'after-ack':
                        self.assertEqual(actual[:1024], b'a'*512 + b'b'*512)
                    elif loss == 'drop':
                        self.assertEqual(actual, bytes(4096))
                    else:
                        self.assertEqual(actual[:1024], bytes(512) + b'b'*512)

    def test_clean_run_still_counts_and_replays_prepare_flush(self):
        with session(cut=0) as case:
            case.setup_flush()
            case.setup_flush()
            case.arm_and_record_resume()
            case.ack(case.send(1), 1)
            case.ack(case.send(3), 3)
            case.send(2)
            case.thread.join(3)
            self.assertFalse(case.thread.is_alive())
            self.assertEqual(case.errors, [])
            replay = inspect(case.initial, case.disk, case.root / 'nbd')
            self.assertEqual((replay['mutations'], replay['raw_mutations'], replay['flushes']), (2, 4, 3))
            self.assertEqual(case.disk.read_bytes()[:512], b'x'*512)

    def test_preparation_write_is_rejected_without_side_effects(self):
        with session() as case:
            case.send(1)
            case.thread.join(3)
            self.assertFalse(case.thread.is_alive())
            self.assertEqual(len(case.errors), 1)
            self.assertIn('WRITE before fault arming', str(case.errors[0]))
            self.assertFalse(case.backend.cut_event.is_set())
            self.assertEqual(case.disk.read_bytes(), bytes(4096))
            with self.assertRaises(ValueError):
                inspect(case.initial, case.disk, case.root / 'nbd')
            with self.assertRaises(ValueError):
                case.backend.arm()

    def test_queued_preparation_frame_prevents_arm(self):
        with session() as case:
            with case.backend.gate:
                handle = case.send(3)
                with self.assertRaisesRegex(ValueError, 'not drained'):
                    case.backend.arm()
                self.assertFalse(case.backend.armed)
            case.ack(handle, 3)
            case.arm_and_record_resume()
            case.send(1)
            self.assertEqual(case.finish_cut()['cut']['raw_mutation'], 2)

    def test_arm_is_one_shot(self):
        with session() as case:
            case.arm_and_record_resume()
            with self.assertRaisesRegex(ValueError, 'already consumed'):
                case.backend.arm()
            case.send(1)
            case.finish_cut()

    def test_arming_waits_for_preparation_completion_and_ack(self):
        with session() as case:
            entered, release, finished = threading.Event(), threading.Event(), threading.Event()
            original = case.backend.apply
            def delayed(request, body):
                entered.set()
                if not release.wait(2):
                    raise ValueError('test failed to release preparation FLUSH')
                return original(request, body)
            case.backend.apply = delayed
            handle = case.send(3)
            self.assertTrue(entered.wait(2))
            failures = []
            def armer():
                try:
                    case.backend.arm()
                except Exception as error:
                    failures.append(error)
                finally:
                    finished.set()
            worker = threading.Thread(target=armer)
            worker.start()
            try:
                self.assertFalse(finished.wait(.03))
                self.assertFalse(case.backend.armed)
            finally:
                release.set()
                worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            case.ack(handle, 3)
            case.backend.apply = original
            case.send(1)
            replay = case.finish_cut()
            self.assertEqual(replay['cut']['mutation'], 1)
            self.assertEqual(replay['cut']['raw_mutation'], 2)

    def test_legacy_absolute_mode_retains_its_original_behavior(self):
        # The old failure: with absolute numbering, the setup FLUSH is cut=1.
        # Existing offline callers keep that explicit legacy contract.
        with session(legacy=True) as case:
            case.send(3)
            replay = case.finish_cut()
            self.assertEqual(replay['version'], 1)
            self.assertEqual(replay['cut']['mutation'], 1)
            self.assertNotIn('raw_mutation', replay['cut'])


class ArmingEvidence(unittest.TestCase):
    def rewrite(self, case, rows):
        path = case.root / 'nbd' / 'events.jsonl'
        raw = ''.join(json.dumps(row, separators=(',', ':'))+'\n' for row in rows).encode()
        path.write_bytes(raw)
        capture = case.root / 'nbd' / 'capture.json'
        document = json.loads(capture.read_text())
        document['events_raw_sha256'] = hashlib.sha256(raw).hexdigest()
        capture.write_text(json.dumps(document))

    def test_rehashed_duplicate_and_nonfinite_fault_records_are_rejected(self):
        with session() as case:
            case.setup_flush()
            case.arm_and_record_resume()
            case.send(1)
            case.finish_cut()
            root = case.root / 'nbd'
            events = root / 'events.jsonl'
            capture = root / 'capture.json'
            original_events = events.read_bytes()
            original_capture = capture.read_bytes()
            first, remainder = original_events.split(b'\n', 1)
            self.assertIn(b'"event":', first)
            forged_rows = {
                'duplicate-event': first.replace(b'"event":',
                    b'"event":"arm","event":', 1) + b'\n' + remainder,
                'nonfinite-value': first[:-1] + b',"poison":NaN}\n' + remainder,
            }
            for name, forged in forged_rows.items():
                with self.subTest(name=name):
                    events.write_bytes(forged)
                    digest = hashlib.sha256(forged).hexdigest()
                    recorded = json.loads(original_capture)
                    recorded['events_raw_sha256'] = digest
                    capture.write_text(json.dumps(recorded) + '\n')
                    pattern = ('Duplicate JSON key' if name == 'duplicate-event'
                               else 'nonfinite fault event number')
                    with self.assertRaisesRegex(ValueError, pattern):
                        inspect(case.initial, case.disk, root)
            events.write_bytes(original_events)
            capture.write_bytes(original_capture)
            self.assertEqual(case.finish_cut()['cut']['mutation'], 1)

    def test_duplicate_start_and_capture_fields_cannot_select_an_ambiguous_record(self):
        with session() as case:
            case.setup_flush()
            case.arm_and_record_resume()
            case.send(1)
            case.finish_cut()
            root = case.root / 'nbd'
            for filename, token in (('start.json', '"version"'),
                                    ('capture.json', '"version"')):
                with self.subTest(filename=filename):
                    path = root / filename
                    original = path.read_text()
                    self.assertIn(token, original)
                    path.write_text(original.replace(token, token + ': 2, ' + token, 1))
                    with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
                        inspect(case.initial, case.disk, root)
                    path.write_text(original)
            self.assertEqual(case.finish_cut()['cut']['mutation'], 1)

    def test_rehashed_tampered_arming_and_raw_identity_are_rejected(self):
        with session() as case:
            case.setup_flush()
            case.arm_and_record_resume()
            case.send(1)
            case.finish_cut()
            original = read_events(case.root / 'nbd')
            for change in ('missing-arm', 'duplicate-arm', 'wrong-baseline', 'counted-prepare',
                           'renumbered-raw', 'wrong-cut-raw', 'wrong-input', 'unacked-arm'):
                with self.subTest(change=change):
                    rows = copy.deepcopy(original)
                    arm = next(row for row in rows if row['event'] == 'arm')
                    setup = next(row for row in rows if row['event'] == 'request')
                    active = next(row for row in rows if row.get('scope') == 'armed')
                    cut = next(row for row in rows if row['event'] == 'cut')
                    if change == 'missing-arm': rows.remove(arm)
                    elif change == 'duplicate-arm': rows.insert(rows.index(arm), dict(arm))
                    elif change == 'wrong-baseline': arm['raw_mutations'] += 1
                    elif change == 'counted-prepare': setup['mutation'] = 1
                    elif change == 'renumbered-raw': active['raw_mutation'] = 1
                    elif change == 'wrong-cut-raw': cut['raw_mutation'] += 1
                    elif change == 'wrong-input': arm['input_sha256'] = 'a'*64
                    else: arm['acks'] = 0
                    self.rewrite(case, rows)
                    with self.assertRaises(ValueError):
                        inspect(case.initial, case.disk, case.root / 'nbd')
            self.rewrite(case, original)
            self.assertEqual(case.finish_cut()['cut']['mutation'], 1)

    def test_scope_rejects_arming_after_resume_and_before_readback(self):
        with session() as case:
            case.setup_flush()
            case.arm_and_record_resume()
            case.send(1)
            case.finish_cut()
            path = case.root / 'native-provenance.jsonl'
            original = [json.loads(line) for line in path.read_text().splitlines()]
            arm = next(row for row in read_events(case.root / 'nbd') if row['event'] == 'arm')
            for change in ('early-resume', 'late-readback'):
                with self.subTest(change=change):
                    rows = copy.deepcopy(original)
                    if change == 'early-resume': rows[2]['monotonic_ns'] = arm['monotonic_ns'] - 1
                    else: rows[1]['monotonic_ns'] = arm['monotonic_ns'] + 1
                    path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
                    with self.assertRaises(ValueError): mutation_scope(case.root)
            path.write_text(''.join(json.dumps(row)+'\n' for row in original))
            self.assertEqual(mutation_scope(case.root)['post_resume_points'], [1])

    def test_scope_rejects_activity_between_arm_and_cont(self):
        with session() as case:
            case.setup_flush()
            case.arm_and_record_resume()
            case.send(1)
            case.finish_cut()
            rows = read_events(case.root / 'nbd')
            active = next(row for row in rows if row.get('scope') == 'armed')
            path = case.root / 'native-provenance.jsonl'
            witness = [json.loads(line) for line in path.read_text().splitlines()]
            witness[2]['monotonic_ns'] = active['monotonic_ns'] + 1
            witness[3]['monotonic_ns'] = active['monotonic_ns'] + 2
            path.write_text(''.join(json.dumps(row)+'\n' for row in witness))
            with self.assertRaisesRegex(ValueError, 'before actual guest resume'):
                mutation_scope(case.root)

    def test_runner_arms_after_readback_before_the_only_cont(self):
        tree = ast.parse((ROOT / 'tools/run_v13_a10.py').read_text())
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        calls = [node for node in ast.walk(run) if isinstance(node, ast.Call)]
        arms = [node for node in calls if isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'backend'
                and node.func.attr == 'arm']
        resumes = [node for node in calls if isinstance(node.func, ast.Attribute)
                   and node.func.attr == 'execute' and node.args
                   and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'cont']
        reads = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id == 'save'
                 and node.args and isinstance(node.args[0], ast.Constant)
                 and node.args[0].value == 'config-observed.bin']
        self.assertEqual((len(arms), len(resumes), len(reads)), (1, 1, 1))
        self.assertLess(reads[0].lineno, arms[0].lineno)
        self.assertLess(arms[0].lineno, resumes[0].lineno)
        backends = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id == 'Backend']
        self.assertEqual(len(backends), 1)
        self.assertIn('arm_input_sha256', {keyword.arg for keyword in backends[0].keywords})


if __name__ == '__main__':
    unittest.main()
