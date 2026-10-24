"""Synthetic evidence tests for the checker, not native-execution claims."""
import sys,struct,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_ai_control as gate

def fixture():
    w=[0]*512;w[:16]=[0x4359584149303031,1,1,0,15,14,2,2,1,1,8,7,2,13,0,6]
    for start,file in [(16,'core-head.bin'),(20,'schema.txt')]:
        w[start:start+4]=struct.unpack('<4Q',bytes.fromhex(gate.runner.sha(ROOT/'ports/control-service'/file)))
    cpus=[[0]*16,[7,8,1000,0,0,8,1,5,(0x15<<26)|0x431,0,0,0,0,0,0,0],
          [1,1,100,0,15,1,16,10,(0x15<<26)|0x431,0,0,0,0,0,0,0],
          [0,0,0,0,26,0,26,5,0,0,0,0,0,0,0,0]]
    for i,c in enumerate(cpus):w[32+i*16:48+i*16]=c
    lines=['SMP_CPU_ON a=1 b=1 c=0','SMP_CPU_ON a=2 b=2 c=0','SMP_CPU_ON a=3 b=3 c=0','SMP_BOOT_OK a=4 b=15 c=0',
        'SMP_SCALE_MODEL a=6 b=9 c=3','SMP_SCALE_MODEL a=2 b=13 c=5',
        'AI_HELPER_DENIED_PUBLICATION a=2 b=3 c=0','AI_BUSINESS_SURVIVED a=8 b=8 c=2','AI_CONTROLLER_RECOVERED a=2 b=8 c=7']
    for i in range(6):
        high=i<2;desired=6 if high else 2;after=6 if 1<=i<5 else 2
        r=[i+1,1,1 if high else 3,2 if high else 6,desired,after,1 if high else 2,
            30000 if high else 1000,30000 if high else 1000,
            *gate.expected_logits(30000 if high else 1000,30000 if high else 1000,28000 if high else 1000,2000),
            int(i in (1,5)),i+1,i*100,(i+1)*100]
        w[96+i*16:112+i*16]=r
        lines.append(f'AI_DECISION a={i+1} b={desired} c={after}')
    for i,c in enumerate(cpus):lines.append(f'AI_CPU_EVIDENCE a={i} b={c[0]} c={c[6]}')
    lines += [gate.SCOPE,'AI_CONTROL_PASS cpus=4']
    return ('\n'.join(lines)+'\n').encode(),w

def page(w):return struct.pack('<512Q',*w)
class GateTests(unittest.TestCase):
    def setUp(self):self.gate=gate.Acceptance();self.serial,self.words=fixture()
    def test_accepts_complete_dual_evidence(self):
        r=self.gate.validate(self.serial,page(self.words),4);self.assertEqual(r['model_inferences'],8)
    def test_no_pass_without_physical_page(self):
        with self.assertRaises(ValueError):self.gate.validate(self.serial,b'',4)
    def test_wrong_cpu_count_rejected(self):
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),1)
    def test_serial_pass_alone_not_evidence(self):
        with self.assertRaises(ValueError):self.gate.validate(b'AI_CONTROL_PASS cpus=4\n',page(self.words),4)
    def test_duplicate_pass_rejected(self):
        with self.assertRaises(ValueError):self.gate.validate(self.serial+b'AI_CONTROL_PASS cpus=4\n',page(self.words),4)
    def test_different_model_hash_rejected(self):
        self.words[16]^=1
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),4)
    def test_changed_logits_rejected(self):
        self.words[96+9]^=1
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),4)
    def test_forged_scale_receipt_rejected(self):
        self.words[96+5]=6
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),4)
    def test_overlapping_windows_rejected(self):
        self.words[112+14]=0
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),4)
    def test_business_cannot_claim_inference(self):
        self.words[32+3*16]=1
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),4)
    def test_missing_real_svc_rejected(self):
        self.words[32+16+8]=0
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),4)
    def test_reserved_fields_not_ignored(self):
        self.words[511]=1
        with self.assertRaises(ValueError):self.gate.validate(self.serial,page(self.words),4)
    def test_scope_cannot_be_promoted(self):
        s=self.serial.replace(b'telemetry=synthetic',b'telemetry=production')
        with self.assertRaises(ValueError):self.gate.validate(s,page(self.words),4)
    def test_fault_binary_cannot_certify_model_success(self):
        self.assertFalse(gate.Acceptance('hang').success()['model_driven'])
        with self.assertRaises(ValueError):gate.Acceptance('hang').validate(self.serial,page(self.words),4)
    def test_training_receipt_names_synthetic_data(self):
        import json,hashlib
        r=json.loads((ROOT/'ports/control-service/training.json').read_text())
        self.assertFalse(r['performance_benefit_verified']);self.assertFalse(r['full_16_domain_model'])
        self.assertEqual(r['model_sha256'],hashlib.sha256((ROOT/'ports/control-service/core-head.bin').read_bytes()).hexdigest())
if __name__=='__main__':unittest.main()
