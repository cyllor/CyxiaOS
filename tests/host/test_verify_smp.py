"""Synthetic records exercise the judge, never count as native runtime evidence."""
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_smp as v


def fixture():
    words=[0]*512
    words[:16]=[v.MAGIC,1,1,15,14,2,6,2,2,0,13,0,0,0,0,0]
    words[24:32]=[1,0,16,16,5,0,0,1000]
    words[32:40]=[2,18,5,23,10,0,1800,500]
    words[40:48]=[3,24,0,24,5,0,2400,0]
    lines=['SMP_CPU_ON a=1 b=1 c=0','SMP_CPU_ON a=2 b=2 c=0','SMP_CPU_ON a=3 b=3 c=0',
        'SMP_BOOT_OK a=4 b=15 c=0','SMP_SCALE_FIXTURE a=6 b=9 c=3','SMP_SCALE_FIXTURE a=2 b=13 c=5',
        'SMP_CONTROL_STALL a=16 b=15 c=23',
        'SMP_CPU_EVIDENCE a=1 b=16 c=5','SMP_ROLE_PROGRESS a=1 b=0 c=16',
        'SMP_CPU_EVIDENCE a=2 b=23 c=10','SMP_ROLE_PROGRESS a=2 b=18 c=5',
        'SMP_CPU_EVIDENCE a=3 b=24 c=5','SMP_ROLE_PROGRESS a=3 b=24 c=0',
        'SMP_SCOPE model=fixture production_isolation=false physical_isolation=false',
        'SMP_SELFTEST_PASS cpus=4']
    return ('\n'.join(lines)+'\n').encode(), words


class SmpJudgeTests(unittest.TestCase):
    def test_complete_synthetic_fixture(self):
        text,words=fixture();self.assertEqual(v.validate(text,struct.pack('<512Q',*words),4)['permission_fault_probes'],20)
    def test_pass_string_without_live_evidence_is_not_success(self):
        with self.assertRaises(ValueError):v.validate(b'SMP_SELFTEST_PASS cpus=4\n',bytes(4096),4)
    def test_every_header_field_is_enforced(self):
        text,words=fixture()
        for i in range(16):
            bad=words.copy();bad[i]^=1
            with self.subTest(i=i),self.assertRaises(ValueError):v.validate(text,struct.pack('<512Q',*bad),4)
    def test_live_page_must_agree_with_serial(self):
        text,words=fixture();words[25]=1
        with self.assertRaises(ValueError):v.validate(text,struct.pack('<512Q',*words),4)
    def test_qmp_cpu_count_is_not_inferred_from_log(self):
        text,words=fixture()
        for count in [0,1,2,3,5]:
            with self.subTest(count=count),self.assertRaises(ValueError):v.validate(text,struct.pack('<512Q',*words),count)
    def test_incomplete_and_trailing_page_bytes(self):
        text,words=fixture();page=struct.pack('<512Q',*words)
        for length in [0,1,4095,4097]:
            with self.subTest(length=length),self.assertRaises(ValueError):v.validate(text,(page+b'\0')[:length],4)
    def test_duplicate_completion_or_fault_line_rejected(self):
        text,words=fixture();page=struct.pack('<512Q',*words)
        for suffix in [b'FAIL panic\n',b'SMP_ERROR a=1 b=4 c=0\n',b'SMP_SELFTEST_PASS cpus=4\n']:
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):v.validate(text+suffix,page,4)
    def test_missing_transition_and_no_business_progress_rejected(self):
        text,words=fixture();page=struct.pack('<512Q',*words)
        for bad in [text.replace(b'SMP_SCALE_FIXTURE a=6 b=9 c=3\n',b''),text.replace(b'a=16 b=15 c=23',b'a=16 b=15 c=15')]:
            with self.assertRaises(ValueError):v.validate(bad,page,4)
    def test_native_mechanism_cannot_claim_model_or_physical_isolation(self):
        text,words=fixture()
        for bad in [text.replace(b'model=fixture',b'model=real'),text.replace(b'physical_isolation=false',b'physical_isolation=true')]:
            with self.assertRaises(ValueError):v.validate(bad,struct.pack('<512Q',*words),4)
    def test_zero_private_memory_progress_rejected(self):
        text,words=fixture();words[46]=0
        with self.assertRaises(ValueError):v.validate(text,struct.pack('<512Q',*words),4)
    def test_nonzero_reserved_field_rejected(self):
        text,words=fixture();words[100]=1
        with self.assertRaises(ValueError):v.validate(text,struct.pack('<512Q',*words),4)
    def test_failed_cpu_start_is_not_success(self):
        text,words=fixture();text=text.replace(b'SMP_CPU_ON a=1 b=1 c=0',b'SMP_CPU_ON a=1 b=1 c=4')
        with self.assertRaises(ValueError):v.validate(text,struct.pack('<512Q',*words),4)


if __name__=='__main__':unittest.main()
