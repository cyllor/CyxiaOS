"""Independent engineering-vector tests, never native execution evidence."""
import importlib
from pathlib import Path
import struct
import sys
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


class V13Model(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'tools/verify_v13_model.py').exists(), 'verifier missing')
        self.tool = importlib.import_module('verify_v13_model')
        self.serial = (b'SMP_CPU_ON a=1 b=1 c=0\nSMP_CPU_ON a=2 b=2 c=0\n'
                       b'SMP_CPU_ON a=3 b=3 c=0\nSMP_BOOT_OK a=4 b=15 c=0\n'
                       b'MODEL_V13_READY cases=8 cpu=1\n')

    def test_sparse_golden_layers(self):
        models, requests, _ = self.tool.fixtures()
        inp = list(struct.unpack_from('<64h', requests, 64))
        h1, h2, out = self.tool.reference(models[:2772], inp)
        self.assertEqual((h1[0], h1[1], h1[31]), (164, 0, 126))
        self.assertEqual((h2[0], h2[1], h2[15], out), (50, 0, 87, -6))

    def test_negative_half_saturation_and_tie_golden(self):
        models, _, _ = self.tool.fixtures()
        def score(model, x):
            return self.tool.reference(models[2772*model:2772*(model+1)], [x]+[0]*63)
        self.assertEqual(score(1,32)[2], -1)
        self.assertEqual(score(1,96)[2], -2)
        self.assertEqual(score(2,32767)[0][0],32767)
        self.assertEqual(score(2,32767)[2],512)
        self.assertEqual(score(3,32767)[1][0],32767)
        self.assertEqual(score(3,32767)[2],512)
        self.assertEqual([score(4,x)[2] for x in (300,100,100)],[-300,-100,-100])

    def test_invalid_model_and_input_rejected(self):
        for b,x in [(b'',[0]*64),(bytes(2772),[0]*63),(bytes(2772),[32768]*64)]:
            with self.assertRaises(ValueError): self.tool.reference(b,x)

    def test_stored_vectors_are_exact_reproducible_synthetic_packages(self):
        models, requests, metadata = self.tool.fixtures()
        self.assertEqual((ROOT/'ports/prototype/models.bin').read_bytes(),models)
        self.assertEqual((ROOT/'ports/prototype/requests.bin').read_bytes(),requests)
        self.assertTrue(metadata['synthetic'])

    def test_validator_rejects_marker_only_and_short_evidence(self):
        with self.assertRaises(ValueError): self.tool.validate(b'MODEL_V13_READY\n',b'',4)

    def test_native_result_mutations_rejected(self):
        models, requests, _ = self.tool.fixtures()
        page = bytearray(16384)
        struct.pack_into('<16Q',page,0,self.tool.MAGIC,1,1,1,8,1,4,20,21,1000000,1000,6,0,4096,8192,0)
        for i,(address,fsc) in enumerate([(0xa0000,0x4f),(0x90000,0x4f),(0xb0000,0x47),(0x30000,0x07)]):
            struct.pack_into('<4Q',page,256+i*32,i+1,8,(0x24<<26)|fsc,address)
        for i in range(8):
            off=4096+i*1536;request=requests[i*576:(i+1)*576]
            page[off:off+576]=request
            page[off+576:off+1088]=self.tool.expected_output(request,models)
            struct.pack_into('<8Q',page,off+1088,1,2,0,1,8,(0x15<<26)|0x531,0,0)
        result = self.tool.validate(self.serial,page,4)
        self.assertTrue(result['native_integer_fixture_verified'])
        self.assertFalse(result['production_isolation_verified'])
        self.assertFalse(result['trained_model_verified'])
        for offset in (0, 16, 40, 48, 4096+576+64, 4096+576+24):
            corrupt = bytearray(page);corrupt[offset] ^= 1
            with self.assertRaises(ValueError):
                self.tool.validate(self.serial,corrupt,4)
        with self.assertRaises(ValueError): self.tool.validate(self.serial,page,1)
        with self.assertRaisesRegex(ValueError, 'secondary'):
            self.tool.validate(b'MODEL_V13_READY cases=8 cpu=1\n',page,4)

if __name__ == '__main__': unittest.main()
