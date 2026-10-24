"""Verifier parser negatives; these constructed pages are not native evidence."""
import importlib
from pathlib import Path
import struct
import sys
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))

class RuntimeVerifier(unittest.TestCase):
    def setUp(self):
        self.tool = importlib.import_module('verify_v13_runtime')
        self.serial = (b'SMP_CPU_ON a=1 b=1 c=0\nSMP_CPU_ON a=2 b=2 c=0\n'
                       b'SMP_CPU_ON a=3 b=3 c=0\nSMP_BOOT_OK a=4 b=15 c=0\nSTORAGE_V13_BOOT_DURABLE\n'
                       b'RUNTIME_V13_STARTED mode=continuous ownership=fixed model=untrained\n')

    def page(self, n=12):
        words = [0] * 1024
        words[:35] = [self.tool.MAGIC, 1, 2*n, 100000+n*10000, 100000, n,
            2, 13, 0, 0, 1, n*100, 1, n, n, 0, 0, 0, 0, n*8, n*8,
            n*400, n*800, 800, 800, 2, 1, n, 4, 0, 100000, n, 1, 11, 22]
        words[35:42]=[100,n*100,100*n,0,100,100,100]
        words[42]=n
        for i in range(n):
            sequence=i+1
            record=[sequence, 1, 100000+i*10000, 100100+i*10000, i*4, i*8,
                4, 8, 0, 4, 0, 2, 1, 8, (0x15 << 26) | 0x541, 0, 1, 1,
                10+i, 1, 1, 1, 0, 0]
            words[64+i*24:64+(i+1)*24]=record
        for i in range(n):
            at=832+(i%12)*16
            words[at:at+16]=[i+1,100000+i*10000,110000+i*10000,
                i,2 if i else 1,1,800 if i else 400,400,800 if i else 400,400,8 if i else 4,4,0,0,0,0]
        return struct.pack('<1024Q',*words)

    def test_two_samples_prove_liveness_but_do_not_claim_complete_isolation(self):
        result=self.tool.validate(self.serial,[self.page(12),self.page(22)],4,1)
        self.assertTrue(result['continuous_runtime_verified'])
        for key in ('production_isolation_verified','core_transition_verified',
                    'trained_model_verified','native_cluster_verified','guaranteed_minimum_service_verified'):
            self.assertFalse(result[key])

    def test_reject_marker_short_page_and_single_sample(self):
        for pages in ([],[self.page()],[self.page(),b'']):
            with self.assertRaises(ValueError): self.tool.validate(self.serial,pages,4,1)
        with self.assertRaises(ValueError): self.tool.validate(b'RUNTIME_V13_STARTED', [self.page(12),self.page(22)],4,1)

    def test_reject_inconsistent_model_scores_core_budget_and_epoch(self):
        for word in (0,1,2,6,7,8,12,15,18,23,28,32,64+8,64+9,64+14,64+16,64+22,832+3,832+6,832+10):
            words=list(struct.unpack('<1024Q',self.page()))
            words[word] ^= 1
            if word==23: words[word]=901
            with self.subTest(word=word), self.assertRaises(ValueError):
                self.tool.validate(self.serial,[struct.pack('<1024Q',*words),self.page(22)],4,1)

    def fault_page(self,n):
        words=list(struct.unpack('<1024Q',self.page(n)))
        words[12]=2;words[14]=n-1;words[15]=1;words[16]=7;words[29]=1;words[35]=700
        for i in range(n):
            at=64+i*24
            if i==4:
                words[at+3]=words[at+2]+10000
                words[at+13]=9;words[at+15]=7;words[at+16]=2;words[at+19]=100
                words[at+20:at+22]=[4,8]
            if i>4: words[at+1]=2
        # The fifth decision failed; the fifth completed window retains policy 4.
        if n<=17: words[832+5*16+3]=4
        return struct.pack('<1024Q',*words)

    def test_fault_recovery_preserves_business_and_rejects_no_progress(self):
        pages=[self.fault_page(12),self.fault_page(22)]
        result=self.tool.validate(self.serial,pages,4,1)
        self.assertEqual(result['controller_faults'],1)
        self.assertEqual(result['service_generation'],2)
        words=list(struct.unpack('<1024Q',pages[0]));words[64+4*24+20]=0
        with self.assertRaises(ValueError):
            self.tool.validate(self.serial,[struct.pack('<1024Q',*words),pages[1]],4,1)

    def test_durable_marker_cannot_be_missing_duplicate_or_late(self):
        marker=b'STORAGE_V13_BOOT_DURABLE\n'
        for serial in (self.serial.replace(marker,b''),self.serial+marker,
                       self.serial.replace(marker,b'')+marker):
            with self.assertRaises(ValueError): self.tool.validate(serial,[self.page(12),self.page(22)],4,1)

    def test_reject_frozen_second_sample_and_wrong_cpu_count(self):
        for pages,cpus in (([self.page(),self.page()],4),([self.page(),self.page(22)],3)):
            with self.assertRaises(ValueError): self.tool.validate(self.serial,pages,cpus,1)

if __name__=='__main__': unittest.main()
