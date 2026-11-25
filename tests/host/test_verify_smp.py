"""Synthetic records exercise the judge, never count as native runtime evidence.

The default judge contract is the V0.20 fixed CPU0 topology (C={CPU0},
B={CPU1-3}); the retired dynamic CoreSet contract stays tested through
validate_legacy for the opt-in legacy-coreset feature build.
"""
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_smp as v


def fixture():
    words=[0]*512
    words[:16]=[v.MAGIC,1,1,15,14,1,14,0,1,0,14,0,0,0,0,0]
    words[24:32]=[1,16,0,16,5,0,1000,0]
    words[32:40]=[2,18,0,23,5,0,1800,0]
    words[40:48]=[3,24,0,24,5,0,2400,0]
    lines=['SMP_CPU_ON a=1 b=1 c=0','SMP_CPU_ON a=2 b=2 c=0','SMP_CPU_ON a=3 b=3 c=0',
        'SMP_BOOT_OK a=4 b=15 c=0',
        'SMP_FIXED_CPU0 a=1 b=14 c=1',
        'SMP_CONTROL_STALL a=1 b=0 c=14',
        'SMP_CPU_EVIDENCE a=1 b=16 c=16',
        'SMP_CPU_EVIDENCE a=2 b=23 c=18',
        'SMP_CPU_EVIDENCE a=3 b=24 c=24',
        'SMP_SCOPE model=fixed_cpu0 production_isolation=false physical_isolation=false',
        'SMP_SELFTEST_PASS cpus=4']
    return ('\n'.join(lines)+'\n').encode(), words


def legacy_fixture():
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


def page(words):
    return struct.pack('<512Q',*words)


class FixedCpu0JudgeTests(unittest.TestCase):
    def test_complete_synthetic_fixture(self):
        text,words=fixture()
        obs=v.validate(text,page(words),4)
        self.assertEqual(obs['permission_fault_probes'],15)
        self.assertEqual(obs['quarantined'],1)
        self.assertEqual((obs['final_control'],obs['final_business']),(0,14))
        self.assertEqual(obs['business_progress'],[16,18,24])
        self.assertEqual(obs['control_progress'],[0,0,0])
    def test_pass_string_without_live_evidence_is_not_success(self):
        with self.assertRaises(ValueError):v.validate(b'SMP_SELFTEST_PASS cpus=4\n',bytes(4096),4)
    def test_every_header_field_is_enforced(self):
        text,words=fixture()
        for i in range(16):
            bad=words.copy();bad[i]^=1
            with self.subTest(i=i),self.assertRaises(ValueError):v.validate(text,page(bad),4)
    def test_live_page_must_agree_with_serial(self):
        text,words=fixture()
        for index in [25,27,33,43]:
            bad=words.copy();bad[index]+=1
            with self.subTest(index=index),self.assertRaises(ValueError):v.validate(text,page(bad),4)
    def test_qmp_cpu_count_is_not_inferred_from_log(self):
        text,words=fixture()
        for count in [0,1,2,3,5]:
            with self.subTest(count=count),self.assertRaises(ValueError):v.validate(text,page(words),count)
    def test_incomplete_and_trailing_page_bytes(self):
        text,words=fixture();raw=page(words)
        for length in [0,1,4095,4097]:
            with self.subTest(length=length),self.assertRaises(ValueError):v.validate(text,(raw+b'\0')[:length],4)
    def test_duplicate_completion_or_fault_line_rejected(self):
        text,words=fixture();raw=page(words)
        for suffix in [b'FAIL panic\n',b'SMP_ERROR a=1 b=4 c=0\n',b'SMP_SELFTEST_PASS cpus=4\n']:
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):v.validate(text+suffix,raw,4)
    def test_missing_topology_or_quarantine_markers_rejected(self):
        text,words=fixture();raw=page(words)
        for bad in [text.replace(b'SMP_FIXED_CPU0 a=1 b=14 c=1\n',b''),
                    text.replace(b'SMP_CONTROL_STALL a=1 b=0 c=14\n',b''),
                    text.replace(b'SMP_CONTROL_STALL a=1 b=0 c=14',b'SMP_CONTROL_STALL a=1 b=0 c=12'),
                    text.replace(b'SMP_FIXED_CPU0 a=1 b=14 c=1',b'SMP_FIXED_CPU0 a=3 b=12 c=1'),
                    text.replace(b'SMP_CONTROL_STALL a=1 b=0 c=14',b'SMP_CONTROL_STALL a=3 b=0 c=14')]:
            with self.assertRaises(ValueError):v.validate(bad,raw,4)
    def test_duplicate_topology_or_quarantine_markers_rejected(self):
        text,words=fixture();raw=page(words)
        for marker in [b'SMP_FIXED_CPU0 a=1 b=14 c=1\n',b'SMP_CONTROL_STALL a=1 b=0 c=14\n']:
            with self.subTest(marker=marker),self.assertRaises(ValueError):v.validate(text+marker,raw,4)
    def test_native_mechanism_cannot_claim_model_or_physical_isolation(self):
        text,words=fixture()
        for bad in [text.replace(b'model=fixed_cpu0',b'model=real'),
                    text.replace(b'model=fixed_cpu0',b'model=fixture'),
                    text.replace(b'physical_isolation=false',b'physical_isolation=true'),
                    text.replace(b'production_isolation=false',b'production_isolation=true'),
                    text+ b'SMP_SCOPE model=fixed_cpu0 production_isolation=false physical_isolation=false\n']:
            with self.assertRaises(ValueError):v.validate(bad,page(words),4)
    def test_business_or_irq_on_cpu0_rejected(self):
        text,words=fixture()
        for index in [16,17,18,19,20,21,22,23]:
            bad=words.copy();bad[index]=1
            with self.subTest(index=index),self.assertRaises(ValueError):v.validate(text,page(bad),4)
    def test_control_on_business_cpu_rejected(self):
        text,words=fixture()
        for index in [25,31,33,39,41,47]:
            bad=words.copy();bad[index]=1
            with self.subTest(index=index),self.assertRaises(ValueError):v.validate(text,page(bad),4)
    def test_weak_business_evidence_rejected(self):
        text,words=fixture()
        cases=[(25,3,b'SMP_CPU_EVIDENCE a=1 b=16 c=16',b'SMP_CPU_EVIDENCE a=1 b=16 c=3'),
               (27,0,b'SMP_CPU_EVIDENCE a=1 b=16 c=16',b'SMP_CPU_EVIDENCE a=1 b=0 c=16'),
               (28,4,None,None),(28,6,None,None),(29,1,None,None),(30,0,None,None)]
        for index,value,old_line,new_line in cases:
            bad=words.copy();bad[index]=value
            bad_text=text if old_line is None else text.replace(old_line,new_line)
            with self.subTest(index=index,value=value),self.assertRaises(ValueError):v.validate(bad_text,page(bad),4)
    def test_nonzero_reserved_field_rejected(self):
        text,words=fixture()
        for index in [48,100,511]:
            bad=words.copy();bad[index]=1
            with self.subTest(index=index),self.assertRaises(ValueError):v.validate(text,page(bad),4)
    def test_failed_cpu_start_is_not_success(self):
        text,words=fixture();text=text.replace(b'SMP_CPU_ON a=1 b=1 c=0',b'SMP_CPU_ON a=1 b=1 c=4')
        with self.assertRaises(ValueError):v.validate(text,page(words),4)
    def test_retired_dynamic_markers_rejected(self):
        text,words=fixture();raw=page(words)
        for extra in [b'SMP_SCALE_FIXTURE a=6 b=9 c=3\n',b'SMP_SCALE_MODEL a=6 b=9 c=3\n',
                      b'SMP_ROLE_PROGRESS a=1 b=0 c=16\n']:
            with self.subTest(extra=extra),self.assertRaises(ValueError):v.validate(text+extra,raw,4)
    def test_out_of_order_evidence_rejected(self):
        text,words=fixture()
        swapped=text.replace(b'SMP_FIXED_CPU0 a=1 b=14 c=1\nSMP_CONTROL_STALL a=1 b=0 c=14\n',
                             b'SMP_CONTROL_STALL a=1 b=0 c=14\nSMP_FIXED_CPU0 a=1 b=14 c=1\n')
        self.assertNotEqual(swapped,text)
        with self.assertRaises(ValueError):v.validate(swapped,page(words),4)
    def test_fixed_validator_rejects_legacy_evidence(self):
        text,words=legacy_fixture()
        with self.assertRaises(ValueError):v.validate(text,page(words),4)


class LegacyCoreSetJudgeTests(unittest.TestCase):
    def test_complete_synthetic_fixture(self):
        text,words=legacy_fixture()
        self.assertEqual(v.validate_legacy(text,page(words),4)['permission_fault_probes'],20)
    def test_pass_string_without_live_evidence_is_not_success(self):
        with self.assertRaises(ValueError):v.validate_legacy(b'SMP_SELFTEST_PASS cpus=4\n',bytes(4096),4)
    def test_every_header_field_is_enforced(self):
        text,words=legacy_fixture()
        for i in range(16):
            bad=words.copy();bad[i]^=1
            with self.subTest(i=i),self.assertRaises(ValueError):v.validate_legacy(text,page(bad),4)
    def test_live_page_must_agree_with_serial(self):
        text,words=legacy_fixture();words[25]=1
        with self.assertRaises(ValueError):v.validate_legacy(text,page(words),4)
    def test_qmp_cpu_count_is_not_inferred_from_log(self):
        text,words=legacy_fixture()
        for count in [0,1,2,3,5]:
            with self.subTest(count=count),self.assertRaises(ValueError):v.validate_legacy(text,page(words),count)
    def test_incomplete_and_trailing_page_bytes(self):
        text,words=legacy_fixture();raw=page(words)
        for length in [0,1,4095,4097]:
            with self.subTest(length=length),self.assertRaises(ValueError):v.validate_legacy(text,(raw+b'\0')[:length],4)
    def test_duplicate_completion_or_fault_line_rejected(self):
        text,words=legacy_fixture();raw=page(words)
        for suffix in [b'FAIL panic\n',b'SMP_ERROR a=1 b=4 c=0\n',b'SMP_SELFTEST_PASS cpus=4\n']:
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):v.validate_legacy(text+suffix,raw,4)
    def test_missing_transition_and_no_business_progress_rejected(self):
        text,words=legacy_fixture();raw=page(words)
        for bad in [text.replace(b'SMP_SCALE_FIXTURE a=6 b=9 c=3\n',b''),text.replace(b'a=16 b=15 c=23',b'a=16 b=15 c=15')]:
            with self.assertRaises(ValueError):v.validate_legacy(bad,raw,4)
    def test_native_mechanism_cannot_claim_model_or_physical_isolation(self):
        text,words=legacy_fixture()
        for bad in [text.replace(b'model=fixture',b'model=real'),text.replace(b'physical_isolation=false',b'physical_isolation=true')]:
            with self.assertRaises(ValueError):v.validate_legacy(bad,page(words),4)
    def test_zero_private_memory_progress_rejected(self):
        text,words=legacy_fixture();words[46]=0
        with self.assertRaises(ValueError):v.validate_legacy(text,page(words),4)
    def test_nonzero_reserved_field_rejected(self):
        text,words=legacy_fixture();words[100]=1
        with self.assertRaises(ValueError):v.validate_legacy(text,page(words),4)
    def test_failed_cpu_start_is_not_success(self):
        text,words=legacy_fixture();text=text.replace(b'SMP_CPU_ON a=1 b=1 c=0',b'SMP_CPU_ON a=1 b=1 c=4')
        with self.assertRaises(ValueError):v.validate_legacy(text,page(words),4)
    def test_legacy_validator_rejects_fixed_evidence(self):
        text,words=fixture()
        with self.assertRaises(ValueError):v.validate_legacy(text,page(words),4)


if __name__=='__main__':unittest.main()
