"""W4/A10: rehashed numeric ambiguity must not pass independent replay."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_prototype_evidence import read_json
from check_v13_fault_disk import decode_events, inspect, read_events
from test_a10_fault_arming import session


class FaultNumbers(unittest.TestCase):
    def test_overflowed_json_numbers_are_not_finite_evidence(self):
        for number in ('1e999', '-1e999', 'NaN', 'Infinity', '-Infinity'):
            with self.subTest(number=number), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'record.json'
                path.write_text('{"metric":' + number + '}\n')
                with self.assertRaises(ValueError):
                    read_json(path)
                with self.assertRaises(ValueError):
                    decode_events(path.read_bytes())

    def test_general_evidence_reader_retains_finite_fractional_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'record.json'
            path.write_text('{"reward":-0.125,"ratio":1e-3}\n')
            self.assertEqual(read_json(path), {'reward': -0.125, 'ratio': 0.001})

    def test_fault_integer_fields_reject_boolean_and_float_aliases(self):
        for field in ('id', 'option', 'mutation', 'raw_mutation', 'pending_sectors',
                      'flushes', 'acks', 'discarded_sectors'):
            for value in (False, True, 0.0, 1.0, -1):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    decode_events((json.dumps({'event': 'ack', field: value}) + '\n').encode())
        for offsets in ([False], [0.0], [-512], '0'):
            with self.subTest(offsets=offsets), self.assertRaises(ValueError):
                decode_events((json.dumps({'event': 'cut', 'surviving_offsets': offsets}) + '\n').encode())

    def test_rehashed_boolean_completion_ids_and_counts_are_rejected(self):
        with session() as case:
            case.setup_flush()
            case.arm_and_record_resume()
            case.send(1)
            case.finish_cut()
            root = case.root / 'nbd'
            original = read_events(root)
            original_events = (root / 'events.jsonl').read_bytes()
            original_capture = (root / 'capture.json').read_bytes()
            for event, field, value in (('complete', 'id', True),
                                        ('ack', 'id', True),
                                        ('complete', 'pending_sectors', False),
                                        ('complete', 'flushes', True),
                                        ('cut', 'mutation', True),
                                        ('cut', 'acks', True)):
                with self.subTest(event=event, field=field):
                    rows = copy.deepcopy(original)
                    row = next(row for row in rows if row['event'] == event)
                    self.assertEqual(row[field], value)  # exactly the old equality bypass
                    row[field] = value
                    raw = ''.join(json.dumps(row) + '\n' for row in rows).encode()
                    (root / 'events.jsonl').write_bytes(raw)
                    capture = json.loads(original_capture)
                    capture['events_raw_sha256'] = hashlib.sha256(raw).hexdigest()
                    (root / 'capture.json').write_text(json.dumps(capture) + '\n')
                    with self.assertRaises(ValueError):
                        inspect(case.initial, case.disk, root)
            (root / 'events.jsonl').write_bytes(original_events)
            (root / 'capture.json').write_bytes(original_capture)
            self.assertEqual(inspect(case.initial, case.disk, root)['cut']['mutation'], 1)

    def test_start_and_capture_integer_fields_are_exactly_typed(self):
        with session() as case:
            case.setup_flush()
            case.arm_and_record_resume()
            case.send(1)
            case.finish_cut()
            root = case.root / 'nbd'
            for filename, field, value in (('start.json', 'size', 4096.0),
                                           ('start.json', 'max_pending_sectors', 32768.0),
                                           ('capture.json', 'version', True)):
                with self.subTest(filename=filename, field=field):
                    path = root / filename
                    original = path.read_bytes()
                    record = json.loads(original)
                    record[field] = value
                    path.write_text(json.dumps(record) + '\n')
                    try:
                        with self.assertRaises(ValueError):
                            inspect(case.initial, case.disk, root)
                    finally:
                        path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
