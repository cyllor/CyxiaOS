"""Independent stopped-bank decoder: literal hand-checked stage fixture."""
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[2]
MODULE=ROOT/'tools/publication_cost.py'
if MODULE.exists():
    spec=importlib.util.spec_from_file_location('publication_cost_decoder',MODULE)
    decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
    decode=decoder.decode_publication_cost
else:
    decode=lambda *_args,**_kwargs: None


def fixture():
    w=[0]*64
    w[:16]=[0x4359505542430001,1,1,11,9,402,7,3,1,8,1,20,100,1000,90,5]
    w[16:33]=[140,1200,160,1300,3,309,0,170,1500,180,1600,620,6,309,0,0,1]
    w[33:47]=[110,1050,120,1100,130,1150,135,1175,150,1250,11,9,402,1]
    w[63]=402
    return w


def raw(w):
    return struct.pack('<128Q',*(w+[0]*64))


class PublicationCostDecoder(unittest.TestCase):
    def test_successful_new_publication_requires_precommit_but_cached_receipt_does_not(self):
        w=fixture();w[16]=w[17]=w[46]=0
        with self.assertRaisesRegex(ValueError,'precommit'):
            decode(raw(w))
        # An exact cached receipt returns before Registry clock/callback work.
        w[15]=0;w[33:43]=[0]*10
        row=decode(raw(w))[0]
        self.assertEqual(row['registry_version'],309)
        self.assertEqual(row['registry_samples'],[])
        self.assertIsNone(row['precommit'])
        refused=w.copy();refused[20:23]=[2,0,10];refused[29:31]=[0,10]
        self.assertEqual(decode(raw(refused))[0]['registry_error'],10)
        for count in (1,2,3,4):
            bad=w.copy();bad[15]=count;bad[33:33+count*2]=fixture()[33:33+count*2]
            with self.assertRaises(ValueError):decode(raw(bad))

    def test_original_identity_and_cost_are_decoded(self):
        got=decode(raw(fixture()),expected={1:{'job':402,'target':7,'generation':3,'version':309}})
        self.assertIsNotNone(got,'raw stage evidence has no independent decoder')
        self.assertEqual(got[0]['cumulative_ns'],620)
        self.assertEqual(got[0]['registry_version'],309)
        self.assertEqual(got[0]['precommit'],{'wall_ns':140,'cpu_ns':1200})
        self.assertEqual(got[0]['registry_return'],{'wall_ns':160,'cpu_ns':1300})
        self.assertEqual(got[0]['release'],{'wall_ns':170,'cpu_ns':1500})

    def test_foreign_or_malformed_snapshots_are_rejected(self):
        bad=[]
        for i,value in [(0,1),(1,3),(1,5),(1,9),(2,2),(9,17),(10,3),(15,6),(24,1299),(27,621),(28,21),(43,12),(45,403),(46,0),(47,1),(63,401),(21,0),(29,310),(19,1199)]:
            w=fixture();w[i]=value;bad.append(raw(w))
        for b in bad+[raw(fixture())[:-1],raw(fixture())+b'\0']:
            with self.subTest(data=b[:16]):
                with self.assertRaises(ValueError):decode(b)
        for key,value in [('job',401),('target',8),('generation',4),('version',310),('cpu',2)]:
            with self.subTest(identity=key):
                with self.assertRaises(ValueError):decode(raw(fixture()),expected={1:{key:value}})


if __name__=='__main__':unittest.main()
