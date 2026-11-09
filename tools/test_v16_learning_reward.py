"""Independent numeric vectors; optional R7 bytes remain outside the repository."""
import hashlib
import importlib
import json
import math
import random
import tempfile
from unittest.mock import patch
import importlib.util
import os
from pathlib import Path
import struct
import unittest


class NumericTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('v16_learning_reward'),
                             'independent numeric/canonical replay seam missing')
        self.r = importlib.import_module('v16_learning_reward')

    def test_cpu_union_priority_and_duplicate_intervals(self):
        node = bytes([1]) * 32
        rows = [(node, 0, 0, 10, 1), (node, 0, 5, 15, 0),
                (node, 0, 0, 10, 1), (node, 1, 0, 2, 2)]
        self.assertEqual(self.r.cpu_union(rows), dict(union_ns=17, policy_ns=10,
            executor_ns=7, optional_ns=0, raw_tagged_ns=[10, 22, 0]))

    def test_nearest_rank_penalties(self):
        rows = [(i + 1, i, 1, i + i + 1) for i in range(98)]
        rows += [(99, 98, 2, 0), (100, 99, 4, 0)]
        p = self.r.performance(rows, 0)
        self.assertEqual(p, dict(emitted=100, completed=98, rejected=1, timed_out=0,
            pending=1, penalty_p99_ns=10000000000, actual_completed_p99_ns=98))

    def test_integer_mlp_round_saturate_and_first_tie(self):
        model = bytearray(2772)
        struct.pack_into('<i', model, 2576 + 48 * 4, -32769)
        self.assertEqual(self.r.model_score(model, [0] * 64), -32768)
        model = bytes(2772)
        self.assertEqual(self.r.select_model(model, [[0] * 64, [256] * 64]), ([0, 0], 0))
        self.assertEqual(self.r.round_neuron(32), 1)
        self.assertEqual(self.r.round_neuron(-32), -1)

    def test_binary64_operation_rounding(self):
        f = self.r.Binary64
        self.assertEqual(f.integer(2**53 + 1).bits, 0x4340000000000000)
        self.assertEqual(f.integer(1).div(f.integer(10)).bits, 0x3fb999999999999a)
        self.assertEqual(f.integer(1).sub(f.integer(1)).bits, 0)

    def test_invalid_numerics(self):
        with self.assertRaises(ValueError):
            self.r.performance([], 0)
        with self.assertRaises(ValueError):
            self.r.model_score(bytes(3), [0] * 64)
        with self.assertRaises(ValueError):
            self.r.cpu_union([(bytes(32), 0, 10, 9, 0)])

    def test_software_binary64_fixed_native_goldens(self):
        # Independent literal encodings from learning_softfloat.rs golden
        # vectors, including a primitive-rounding example that must not fuse.
        f = self.r.Binary64
        one, half, sign = 0x3ff0000000000000, 0x3fe0000000000000, 1 << 63
        vectors = [
            ('add', 0, sign, 0), ('add', sign, sign, sign),
            ('sub', sign, 0, sign), ('sub', sign, sign, 0),
            ('mul', 0, sign | one, sign), ('div', sign, sign | one, 0),
            ('add', one, 0x3ca0000000000000, one),
            ('add', one + 1, 0x3ca0000000000000, one + 2),
            ('sub', one, 0x3ca0000000000000, one - 1),
            ('sub', 0x0010000000000000, 0x000fffffffffffff, 1),
            ('mul', 1, half, 0), ('mul', sign | 1, half, sign),
            ('mul', 3, half, 2), ('mul', 5, half, 2),
            ('mul', 1, half + 1, 1), ('mul', one + 1, one - 2, one),
            ('div', one, 0x4008000000000000, 0x3fd5555555555555),
            ('div', 3, 0x4000000000000000, 2),
            ('div', 0x0010000000000000, 0x4000000000000000, 0x0008000000000000),
        ]
        for op, a, b, expected in vectors:
            with self.subTest(op=op, a=hex(a), b=hex(b)):
                self.assertEqual(getattr(f(a), op)(f(b)).bits, expected)
        self.assertEqual(f(one + 1).mul(f(one - 2)).sub(f(one)).bits, 0)
        for op, a, b in [('add', 0x7fefffffffffffff, (1993 << 52)),
                         ('mul', 0x7fefffffffffffff, one + 1),
                         ('div', 0x7fefffffffffffff, half), ('div', one, 0)]:
            with self.subTest(op=op), self.assertRaises(ValueError):
                getattr(f(a), op)(f(b))
        for nonfinite in (0x7ff0000000000000, 0x7ff8000000000000, 0xfff0000000000000):
            with self.assertRaises(ValueError):
                f(nonfinite)

    def test_software_binary64_differential_finite_patterns(self):
        f = self.r.Binary64
        rng = random.Random(0x4359584c4541524e)
        operations = dict(add=lambda a,b:a+b, sub=lambda a,b:a-b,
                          mul=lambda a,b:a*b, div=lambda a,b:a/b)
        for _ in range(128):
            a, b = [rng.getrandbits(64) for _ in range(2)]
            if (a >> 52) & 2047 == 2047 or (b >> 52) & 2047 == 2047:
                continue
            x, y = [struct.unpack('<d', struct.pack('<Q', n))[0] for n in (a, b)]
            for op, reference in operations.items():
                if op == 'div' and y == 0:
                    continue
                expected = reference(x, y)
                if math.isfinite(expected):
                    bits = struct.unpack('<Q', struct.pack('<d', expected))[0]
                    self.assertEqual(getattr(f(a), op)(f(b)).bits, bits, (op, a, b))
                else:
                    with self.assertRaises(ValueError):
                        getattr(f(a), op)(f(b))

    def test_reward_cost_clipping_and_denominator_floors(self):
        cases = [(20, 10, 2000, 1000, 1_000_000_000),
                 (0, 0, 0, 0, 20_000_000_000),
                 (1, 0, 0, 1000, 0), (0, 10, 1, 0, 0)]
        for completed, baseline, latency, latency0, cpu in cases:
            cp = dict(completed=completed, penalty_p99_ns=latency)
            bp = dict(completed=baseline, penalty_p99_ns=latency0)
            x, x0 = completed / 10.0, baseline / 10.0
            dx = (x - x0) / max(x0, 1.0 / 10.0)
            l, l0 = latency / 1_000_000_000.0, latency0 / 1_000_000_000.0
            dl = (l - l0) / max(l0, 1.0 / 1_000_000.0)
            raw = cpu / 10_000_000_000.0
            cost = min(1.0, max(0.0, raw))
            value = (0.4 * min(1.0, max(-1.0, dx)) -
                     0.4 * min(1.0, max(-1.0, dl))) - 0.2 * cost
            expected = dict(raw_cost=raw, clipped_cost=cost, delta_throughput=dx,
                            delta_latency=dl, value=value)
            actual = self.r.reward_values(cp, bp, cpu)
            for key, reference in expected.items():
                self.assertEqual(actual[key].bits,
                                 struct.unpack('<Q', struct.pack('<d', reference))[0], (key, cp, bp))

    def test_feature_normalization_presence_and_clipping(self):
        row = bytearray(6144)
        struct.pack_into('<H', row, 522, 8)
        struct.pack_into('<12Q', row, 2048 + 24 * 8,
                         1000, 0, 65, 500, 0, 0, 100, 1, 64, 100001, 1000, 10000)
        struct.pack_into('<Q', row, 2048 + 40 * 8, 15)
        struct.pack_into('<4Q', row, 2048 + 67 * 8, 4001, 0, 50000, 1)
        struct.pack_into('<Q', row, 2048 + 71 * 8, 13)
        encoded = self.r.encode_weight_features(row, 0)
        self.assertEqual(encoded[16:28], [256, 0, 256, 128, 0, 0, 256, 256, 256, 256, 256, 256])
        self.assertEqual(encoded[40:43], [1, 256, 0])
        self.assertEqual(encoded[56:64], [256, 0, 128, 256, 256, 0, 256, 256])

    def test_full_integer_network_hidden_relu_bias_and_negative_weight(self):
        model = bytearray(2772)
        model[0] = 64
        model[2048] = 32
        model[2560] = 192  # signed -64
        inp = [0] * 64; inp[0] = 3
        # h1=3; h2=round(1.5)=2; linear output=-2 (not ReLU).
        self.assertEqual(self.r.model_score(model, inp), -2)
        inp[0] = -3
        self.assertEqual(self.r.model_score(model, inp), 0)
        struct.pack_into('<i', model, 2576, 4)
        self.assertEqual(self.r.model_score(model, inp), -1)

    def test_cpu_union_class_priority_nodes_and_zero_length(self):
        a, b = bytes([1]) * 32, bytes([2]) * 32
        rows = [(a, 0, 0, 20, 3), (a, 0, 5, 15, 1), (a, 0, 8, 12, 0),
                (a, 0, 12, 12, 0), (b, 0, 0, 4, 2)]
        self.assertEqual(self.r.cpu_union(rows), dict(union_ns=24, policy_ns=4,
            executor_ns=10, optional_ns=10, raw_tagged_ns=[4, 14, 20]))

    def test_performance_duplicate_window_and_end_boundaries(self):
        rows = [(i+1, i, 1, i+1) for i in range(100)]
        self.assertEqual(self.r.performance(rows, 0)['penalty_p99_ns'], 1)
        for bad in ((1, 1, 1, 2), (101, 10**10, 1, 10**10),
                    (101, 100, 1, 10**10 + 1), (101, 100, 2, 101)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.r.performance(rows[:99] + [bad], 0)

    def test_inventory_hash_original_summary_disk_and_membership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'capture'; root.mkdir()
            names = ('summary.json', 'disk.raw', 'native-context.json', 'model.bin')
            for name in names:
                (root / name).write_bytes(name.encode())
            inventory = Path(temporary) / 'inventory.json'
            inventory.write_text(json.dumps(dict(count=4, files={name:hashlib.sha256(
                (root/name).read_bytes()).hexdigest() for name in names})))
            trusted = hashlib.sha256(inventory.read_bytes()).hexdigest()
            self.assertEqual(self.r.verify_original_inventory(root, inventory, trusted)['files'], 4)
            with self.assertRaisesRegex(ValueError, 'anchor mismatch'):
                self.r.verify_original_inventory(root, inventory, '00'*32)
            for name in names:
                original = (root/name).read_bytes(); (root/name).write_bytes(original+b'changed')
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'inventory changed'):
                    self.r.verify_original_inventory(root, inventory, trusted)
                (root/name).write_bytes(original)
            (root/'extra').write_bytes(b'x')
            with self.assertRaisesRegex(ValueError, 'membership'):
                self.r.verify_original_inventory(root, inventory, trusted)
            (root/'extra').unlink()
            (root/'model.bin').unlink(); (root/'model.bin').symlink_to(root/'disk.raw')
            with self.assertRaises(ValueError):
                self.r.verify_original_inventory(root, inventory, trusted)

    def test_original_inventory_path_traversal_and_required_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'capture'; root.mkdir()
            inventory = Path(temporary) / 'inventory.json'
            for files in ({'../outside':'11'*32}, {},
                          {name:'11'*32 for name in ('summary.json','disk.raw','native-context.json','model.bin','../x')}):
                inventory.write_text(json.dumps(dict(count=len(files), files=files)))
                with self.assertRaises(ValueError):
                    self.r.verify_original_inventory(root, inventory,
                        hashlib.sha256(inventory.read_bytes()).hexdigest())

    def test_cli_requires_new_report_outside_capture(self):
        import verify_v16_learning_reward as cli
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); capture = root/'capture'; capture.mkdir()
            exports = root/'exports'; exports.mkdir()
            arguments = []
            for flag in ('capture', 'original-inventory', 'kernel-source-root', 'build-manifest',
                         'formatter', 'qemu', 'qemu-source', 'frozen-producer-root', 'exports-directory'):
                arguments += ['--'+flag, str(capture if flag=='capture' else exports if flag=='exports-directory' else root)]
            arguments += ['--original-inventory-sha256','11'*32]
            with patch.object(cli, 'verify_reward_capture', side_effect=AssertionError('must not reach replay')):
                with self.assertRaisesRegex(ValueError, 'new file outside'):
                    cli.main(arguments + ['--output', str(capture/'report.json')])
                with self.assertRaisesRegex(ValueError, 'new file outside'):
                    cli.main(arguments + ['--output', str(exports/'report.json')])


@unittest.skipUnless(os.environ.get('CYXIA_REWARD_R7_ROOT'), 'caller-selected R7 integration bytes')
class ActualR7Tests(unittest.TestCase):
    def test_canonical_matches_original_native416(self):
        import v16_learning_reward as r
        root = Path(os.environ['CYXIA_REWARD_R7_ROOT'])
        manifest = json.loads((root / 'learning-offline-extraction-01/manifest.json').read_text())
        pair = manifest['pairs'][0]
        raw = [(root / 'learning-offline-extraction-01' / pair[k]['raw_export']['file']).read_bytes()
               for k in ('candidate', 'baseline')]
        model = (root / 'learning-pair-01/model.bin').read_bytes()
        result = r.numeric_pair(raw[0], raw[1], model)
        self.assertEqual(result['candidate']['trial_canonical_sha256'],
                         '484ff15ea6041b3fb222440d3abc41dc258b2b1141abc9e678e260bdd8d0dfcc')
        self.assertEqual(result['baseline']['trial_canonical_sha256'],
                         '01171a785dbf2077632c33fd89beeba24bacacf73977172a631c15ee817adbf4')
        self.assertTrue(result['reward_numeric_verified'])
        self.assertEqual(result['candidate']['cpu']['union_ns'], 11647437)
        self.assertEqual(result['baseline']['cpu']['union_ns'], 10942521)
        self.assertEqual(result['candidate']['performance']['completed'], 14)
        # Separate host IEEE operation oracle; this expected hash never calls
        # the production software-numeric or canonical implementation.
        expected_bits = struct.pack('<d', -(0.2 * (11647437 / 10000000000)))
        self.assertEqual(result['reward']['value']['bits'], 'bf2e8876709c8da7')
        expected_hash = hashlib.sha256(b'CYXIA_PAIRED_LABEL_1.3\0' + bytes.fromhex(
            '484ff15ea6041b3fb222440d3abc41dc258b2b1141abc9e678e260bdd8d0dfcc') + bytes.fromhex(
            '01171a785dbf2077632c33fd89beeba24bacacf73977172a631c15ee817adbf4') + expected_bits).hexdigest()
        self.assertEqual(result['prospective_paired_label_sha256'], expected_hash)
        self.assertFalse(result['protected_sample_export_verified'])
        self.assertFalse(result['source_event_hash_recomputed'])
        cpu_at = 2048 + struct.unpack_from('<Q', raw[0], 128)[0] * 6144
        request_at = cpu_at + struct.unpack_from('<Q', raw[0], 136)[0] * 64
        for offset in (56, 416, 448, 760, 768, 1792, 2048 + 208, 2048 + 344,
                       cpu_at + 40, cpu_at + 56, request_at + 8, request_at + 48):
            with self.subTest(offset=offset):
                changed = bytearray(raw[0]); changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    r.numeric_pair(changed, raw[1], model)
        # Event chronology is not recoverable from this projection. Numeric
        # agreement cannot authenticate eventHash; outer inventory rejects it.
        changed = bytearray(raw[0]); changed[384] ^= 1
        projected = r.numeric_pair(changed, raw[1], model)
        self.assertEqual(projected['prospective_paired_label_sha256'],
                         result['prospective_paired_label_sha256'])
        self.assertFalse(projected['source_event_hash_recomputed'])
        self.assertFalse(projected['native_acceptance_inferred_from_trusted_producer'])
        changed = bytearray(model); changed[2560] ^= 1
        with self.assertRaises(ValueError):
            r.numeric_pair(raw[0], raw[1], changed)


if __name__ == '__main__':
    unittest.main()
