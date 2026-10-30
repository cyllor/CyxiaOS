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
    w[:16]=[0x4359505542430002,1,1,11,9,402,7,3,1,8,1,20,100,1000,90,5]
    w[16:33]=[140,1200,160,1300,3,309,0,170,1500,180,1600,620,6,309,0,0,1]
    w[33:47]=[110,1050,120,1100,130,1150,135,1175,150,1250,11,9,402,1]
    w[63]=402
    return w


def raw(w):
    return struct.pack('<128Q',*(w+[0]*64))


class PublicationCostDecoder(unittest.TestCase):
    def test_checkpoint_stop_requires_frozen_but_paid_later_freeze_is_allowed(self):
        w=fixture();w[1]=0
        with self.assertRaisesRegex(ValueError,'frozen'):
            decode(raw(w))
        # A later attempt may freeze a serializer-only stop's earlier
        # checkpoint, whose own Registry/local stop facts were both false.
        w=fixture();w[28]=0;w[31]=w[32]=0
        row=decode(raw(w))[0]
        self.assertTrue(row['frozen'])
        context=[2,100,11,9,402,7,3,309,0,0,90,610,700,0,0,1,1,402,1,1000]
        self.assertTrue(decoder.bind_publication_stop(row,context)['charged_stop_bound'])

    def test_bound_registry_stop_bit_must_match_checkpoint_in_both_directions(self):
        context=[1,100,11,9,402,7,3,309,0,0,90,610,700,0,0,1,1,402,1,1000]
        with self.assertRaisesRegex(ValueError,'Registry.stop'):
            decoder.bind_publication_stop(decode(raw(fixture()))[0],context)
        w=fixture();w[31]=1;context[0]=2
        with self.assertRaisesRegex(ValueError,'Registry.stop'):
            decoder.bind_publication_stop(decode(raw(w))[0],context)

    def test_bound_local_stop_cannot_be_readonly(self):
        context=[2,100,11,9,402,7,3,309,0,1,90,610,700,0,0,1,1,402,1,1000]
        with self.assertRaisesRegex(ValueError,'readonly'):
            decoder.bind_publication_stop(decode(raw(fixture()))[0],context)

    def test_bound_checkpoint_local_stop_cannot_disappear(self):
        w=fixture();w[31]=1
        context=[1,100,11,9,402,7,3,309,0,0,90,610,700,0,0,1,1,402,1,1000]
        with self.assertRaisesRegex(ValueError,'checkpoint.local.stop'):
            decoder.bind_publication_stop(decode(raw(w))[0],context)

    def test_readonly_cannot_have_entered_registry_even_without_local_stop(self):
        w=fixture();w[31]=1;w[32]=0
        context=[1,100,11,9,402,7,3,309,0,1,90,610,700,0,0,1,1,402,1,1000]
        with self.assertRaisesRegex(ValueError,'readonly'):
            decoder.bind_publication_stop(decode(raw(w))[0],context)

    def test_readonly_cannot_create_original_registry_only_stop_without_a_receipt(self):
        w=fixture();w[15]=0;w[16:23]=[0]*7;w[33:47]=[0]*14
        w[28]=0;w[29:33]=[0,8,1,0]
        context=[1,100,11,9,402,7,3,0,8,1,90,610,700,0,0,1,1,402,1,1000]
        # Even this matching Registry-only/no-receipt counterfactual cannot
        # be an original readonly stop transition under the held control gate.
        with self.assertRaisesRegex(ValueError,'readonly'):
            decoder.bind_publication_stop(decode(raw(w))[0],context)

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
        self.assertEqual(got[0]['checkpoint_cumulative_ns'],620)
        self.assertEqual(got[0]['registry_version'],309)
        self.assertEqual(got[0]['precommit'],{'wall_ns':140,'cpu_ns':1200})
        self.assertEqual(got[0]['registry_return'],{'wall_ns':160,'cpu_ns':1300})
        self.assertEqual(got[0]['release'],{'wall_ns':170,'cpu_ns':1500})
        self.assertFalse(got[0]['charged_stop_bound'])
        self.assertNotIn('cumulative_ns',got[0])
        self.assertNotIn('final',got[0])

    def test_final_cost_requires_complete_independently_matching_original_stop(self):
        row=decode(raw(fixture()))[0]
        context=[2,100,11,9,402,7,3,309,0,0,90,610,700,0,0,1,1,402,1,1000]
        joined=decoder.bind_publication_stop(row,context)
        self.assertEqual(joined['charged_cumulative_ns'],700)
        self.assertEqual(joined['charged_publication_ns'],610)
        self.assertEqual(joined['final_result_version'],309)
        self.assertNotIn('final',joined)
        for i,value in [(0,0),(1,101),(2,12),(3,8),(4,401),(5,8),(6,4),(7,310),(8,6),(10,91),(11,611),(12,701),(13,1),(14,1),(15,0),(16,2),(18,2),(19,1001)]:
            bad=context.copy();bad[i]=value
            with self.subTest(word=i):
                with self.assertRaises(ValueError):decoder.bind_publication_stop(row,bad)
        with self.assertRaises(ValueError):decoder.bind_publication_stop(row,context[:-1])

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
