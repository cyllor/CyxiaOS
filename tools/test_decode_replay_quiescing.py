"""Integrity contracts for read-only native Quiescing observations."""
import struct
import unittest
import decode_replay_quiescing as decoder
import test_verify_domains as fixtures
from verify_domains import refresh_snapshot

class QuiescingDecoder(unittest.TestCase):
    def raw(self, payload=None):
        w=[0]*64;w[:8]=[2,decoder.MAGIC,1,64,1,0,0,0]
        p=[0]*56;p[:15]=[7,2,2,1,1,12,1,0,2,100,0,8,0,4,1]
        p[15:24]=[7,2,51,0,12,3,41,80,120]
        p[24]=3;p[27]=1;p[29:35]=[1,1,51,90,95,85]
        if payload:payload(p)
        w[8:]=p
        return w
    def packed(self,w):return struct.pack('<64Q',*w)
    def test_exact_unknown_identity_is_diagnostic_only(self):
        r=decoder.decode(self.packed(self.raw()))
        self.assertEqual(r['gate'],'execution')
        self.assertEqual(r['apply'],[7,2,51,0,12,3])
        self.assertEqual(r['execution_state'],'Unknown')
        self.assertFalse(r['native_acceptance_verified'])
    def test_all_original_gates_have_distinct_legal_records(self):
        for stage in (1, 3, 4, 5, 6, 7):
            with self.subTest(stage=stage):
                w=self.raw();p=w[8:];p[8]=stage
                if stage==3:
                    p[14]=4;p[24]=1;p[26]=1
                else:
                    p[13:35]=[0]*22
                    if stage==1:
                        p[11]=0;p[12]=p[10];p[35:41]=[1,23,4,2,91,0]
                    elif stage==4:p[12]=p[11]
                    elif stage in (5,6):
                        p[10:13]=[504,512,512 if stage==5 else 0]
                        p[41:43]=[1,int(stage==6)]
                    else:
                        p[9]=p[11]=0;p[43]=11
                w[8:]=p
                self.assertEqual(decoder.decode(self.packed(w))['gate'],decoder.GATES[stage])
    def test_zero_odd_and_corruption_are_distinct(self):
        self.assertEqual(decoder.decode(bytes(512))['status'],'not_published')
        w=self.raw();w[0]=3
        self.assertEqual(decoder.decode(self.packed(w))['status'],'in_progress')
        for index,value in ((1,4),(4,2),(8,0),(16,3),(22,4),(32,2),(63,1)):
            with self.subTest(index=index):
                w=self.raw();w[index]=value
                with self.assertRaises(ValueError):decoder.decode(self.packed(w))
        with self.assertRaises(ValueError):decoder.decode(bytes(511))
    def test_optional_capture_binds_boot_and_preserves_torn_raw(self):
        bundle=fixtures.EvidenceParserTests().snapshot()
        w=self.raw();bundle['REPLAY_QUIESCING_EVIDENCE']=self.packed(w)
        guest={};refresh_snapshot(guest,bundle)
        self.assertEqual(guest['replay_quiescing']['gate'],'execution')
        w[0]=3;bundle['REPLAY_QUIESCING_EVIDENCE']=self.packed(w)
        refresh_snapshot(guest,bundle)
        self.assertEqual(guest['replay_quiescing_evidence'],w)
        self.assertEqual(guest['replay_quiescing']['status'],'in_progress')
        w=self.raw();w[8]=w[23]=2;bundle['REPLAY_QUIESCING_EVIDENCE']=self.packed(w)
        with self.assertRaisesRegex(ValueError,'BootEpoch'):refresh_snapshot(guest,bundle)

if __name__=='__main__':unittest.main()
