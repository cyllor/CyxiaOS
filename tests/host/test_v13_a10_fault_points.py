"""Select observed device boundaries, never infer native fault acceptance."""
import importlib
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))

class FaultPoints(unittest.TestCase):
    def fixtures(self):
        from verify_v13_a10 import payload
        import hashlib
        writer=(100,9)
        capture=dict(mode=2,writer=writer,records=[
            dict(owner=writer,operation=4,result=0,data_length=4096,offset=0,
                 data_sha256=hashlib.sha256(payload(3)).hexdigest(),writes=1,flushes=1,sequence=7),
            dict(owner=writer,operation=5,result=0,durable_seq=3,writes=7,flushes=3,sequence=8),
        ])
        rows=[]
        for group in range(7):
            for sector in range(8):
                rows.append(dict(mutation=len(rows)+1,kind=1,offset=(2+group)*4096+sector*512,length=512))
            if group in (0,5,6):rows.append(dict(mutation=len(rows)+1,kind=3,offset=0,length=0))
        return capture,rows

    def checker(self):
        try:return importlib.import_module('verify_v13_a10_faults')
        except ModuleNotFoundError:self.fail('ordinary native mutation selector missing')

    def test_selects_every_real_sector_and_flush_between_write_and_fsync_reply(self):
        capture,rows=self.fixtures()
        result=self.checker().overwrite_window(capture,rows)
        self.assertEqual(result['points'],list(range(10,60)))
        self.assertEqual(result['flush_points'],[50,59])
        self.assertFalse(result['A10_complete'])

    def test_missing_merged_or_misaligned_boundary_cannot_be_used_for_matrix(self):
        import copy
        capture,rows=self.fixtures()
        cases=[]
        wrong=copy.deepcopy(rows);wrong[10]['length']=4096;cases.append(wrong)
        wrong=copy.deepcopy(rows);wrong[10]['mutation']=10;cases.append(wrong)
        wrong=copy.deepcopy(rows);wrong[8]['kind']=1;wrong[8]['length']=512;cases.append(wrong)
        cases.append(rows[:-1])
        for wrong in cases:
            with self.subTest(wrong=wrong[8]),self.assertRaises(ValueError):self.checker().overwrite_window(capture,wrong)
        capture['records'][0]['writes']=2
        with self.assertRaises(ValueError):self.checker().overwrite_window(capture,rows)

    def test_no_device_reply_is_labeled_el0_consumption(self):
        capture,rows=self.fixtures()
        result=self.checker().overwrite_window(capture,rows)
        self.assertEqual(result['boundary_semantics'],{'before':'request not executed','after-ack':'device reply sent'})
        capture['records'][1]['durable_seq']=2
        with self.assertRaises(ValueError):self.checker().overwrite_window(capture,rows)
