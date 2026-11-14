"""Mutation tests for the real raw join. These fixtures never establish native PASS."""
import struct
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from test_verify_v15_ownership import fixture, ROW_WORDS
from test_v16_a03_demand import scene
import verify_v17_a03_demand as verifier


def bound_fixture():
    owner = fixture()
    for index, base in enumerate((2_000_000_000, 17_000_000_000)):
        at = 128 + index*ROW_WORDS
        old = owner[at+9]
        for field in (9,10,32,48,64,80,192+8,192+9,192+28,192+36):
            owner[at+field] += base-old
    last = 128+ROW_WORDS
    demand = list(struct.unpack('<128Q',scene()))
    demand[40:44] = [owner[last+14],owner[last+12],owner[last+192+28],owner[last+9]]
    model = owner[last+192:last+832]
    return demand,model,owner


def encode(parts):
    return [struct.pack('<'+str(len(w))+'Q',*w) for w in parts]


class AppliedBinding(unittest.TestCase):
    def test_exact_applied_receipt_binds_to_ordinary_load_window(self):
        got = verifier.validate_binding(*encode(bound_fixture()))
        self.assertEqual(got['control_sets'],[2,6,2])
        self.assertEqual(got['native_acceptance_status'],'NOT_RUN')

    def test_pending_reply_other_plan_and_changed_receipt_cannot_finish(self):
        for part,field,value in [(1,14,1),(0,40,99),(0,41,99),(1,21,9),(2,128+ROW_WORDS+79,99)]:
            parts = bound_fixture();parts[part][field] = value
            with self.subTest(part=part,field=field),self.assertRaises(ValueError):
                verifier.validate_binding(*encode(parts))

    def test_existing_growth_before_workload_is_not_ordinary_expansion(self):
        parts = bound_fixture()
        parts[0][7] = 3_000_000_000
        parts[0][8] = 13_000_000_000
        parts[0][9] = 14_000_000_000
        with self.assertRaisesRegex(ValueError,'high-load window'):
            verifier.validate_binding(*encode(parts))

    def test_structure_without_native_custody_or_model_replay_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(verifier.demand,'verify_capture',return_value={'stimulus_verified':False}), \
                 patch.object(verifier,'replay_owners') as replay:
                with self.assertRaisesRegex(ValueError,'mandatory'):
                    verifier.verify(root,source_root=root)
                replay.assert_not_called()
