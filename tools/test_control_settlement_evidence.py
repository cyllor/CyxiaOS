import struct
import unittest
import verify_domains as verifier
import test_verify_domains as fixtures
from test_verify_domains import encode


class ControlSettlementEvidenceTests(unittest.TestCase):
    def bank(self):
        w = [0] * 64
        w[:2] = [0x4359435345540001, 1]
        w[2:17] = [2,1,42,7,0,10_000_000,13_000_000,2_500_000,3_000_000,
                   2_500_000,3_000_000,2_500_000,3_000_000,1,6]
        return w

    def test_control_failure_survives_task_quarantine_and_final_export(self):
        guest = {}
        snapshot = fixtures.EvidenceParserTests().snapshot(overrun=True)
        snapshot['CONTROL_SETTLEMENT_EVIDENCE'] = encode(self.bank())
        snapshot['GOVERNANCE_V13_EVIDENCE'] = encode([0]*16)
        snapshot['GOVERNANCE_RUNTIME_V13_EVIDENCE'] = encode([0]*64)
        with self.assertRaisesRegex(ValueError, 'overrun/quarantine'):
            verifier.refresh_snapshot(guest,snapshot)
        self.assertEqual(guest.get('control_settlement_evidence'),self.bank())
        self.assertEqual(guest['control_settlements'][0]['actual_ns'],3_000_000)
        retained = verifier.retained_observation(guest)
        self.assertEqual(retained['control_settlement_evidence'],self.bank())
        self.assertEqual(retained['governance_runtime_evidence'],[0]*64)
        self.assertEqual(retained['governance_evidence'],[0]*16)
        verifier.refresh_snapshot(guest,fixtures.EvidenceParserTests().snapshot())
        self.assertIsNone(guest['control_settlement_evidence'])
        self.assertIsNone(guest['control_settlements'])

    def test_sticky_failure_rejects_an_older_healthy_task_snapshot(self):
        snapshot = fixtures.EvidenceParserTests().snapshot()
        snapshot['CONTROL_SETTLEMENT_EVIDENCE'] = encode(self.bank())
        with self.assertRaisesRegex(ValueError,'physical control settlement'):
            verifier.refresh_snapshot({},snapshot)

    def test_empty_is_not_a_failure_and_partial_is_not_a_complete_receipt(self):
        self.assertEqual(verifier.parse_control_settlements(encode([0]*64)),[])
        w=self.bank();w[2]=1
        rows=verifier.parse_control_settlements(encode(w))
        self.assertEqual(rows,[{'cpu':1,'complete':False}])
        w[0]=0
        with self.assertRaises(ValueError):
            verifier.parse_control_settlements(encode(w))

    def test_completed_row_is_bound_to_its_slot_credit_and_arithmetic(self):
        parsed=verifier.parse_control_settlements(encode(self.bank()))[0]
        self.assertEqual((parsed['cpu'],parsed['sequence'],parsed['reserved_ns']),(1,42,2_500_000))
        self.assertTrue(parsed['complete'])
        for index,value in [(0,1),(1,0),(3,2),(4,0),(5,0),(6,1),(8,1),
                            (9,0),(11,1),(12,1),(13,1),(14,1),(15,0),(16,5),(63,1)]:
            with self.subTest(index=index):
                w=self.bank();w[index]=value
                with self.assertRaises(ValueError):
                    verifier.parse_control_settlements(encode(w))

    def test_governance_failure_keeps_raw_snapshot_deadline_and_bill(self):
        snapshot=fixtures.EvidenceParserTests().snapshot()
        w=[0]*64;w[48]=0x701;w[54:56]=[60_000_000,10_000_000]
        snapshot['GOVERNANCE_RUNTIME_V13_EVIDENCE']=encode(w)
        guest={}
        with self.assertRaisesRegex(ValueError,'governance runtime fault'):
            verifier.refresh_snapshot(guest,snapshot)
        kept=verifier.retained_observation(guest)
        self.assertIsNone(kept['governance_runtime'])
        self.assertEqual(kept['governance_runtime_evidence'],w)

if __name__=='__main__':unittest.main()
