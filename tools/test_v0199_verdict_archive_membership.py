"""Synthetic structural regression only; never a G4 or G5 proof producer."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import verify_v0199_verdicts as v


def archive(root, keys):
    _, _, _, inv = v.inventory()
    (root/'verdicts').mkdir()
    (root/'evidence').mkdir()
    payload=b'synthetic structural regression, not runtime/static/model evidence'
    (root/'evidence'/'fixture.bin').write_bytes(payload)
    members=json.dumps({'files':[{'path':'evidence/fixture.bin','bytes':len(payload),'sha256':v.digest(payload)}]}).encode()
    proofs=[]
    for test,proof in sorted(keys):
        checker=(test>>16<<16)|1
        item=dict(test_id=test,proof_class=v.NAMES[proof],checker_id=checker,checker_version=1,
                  boot_epoch=1,controller_epoch=1,security_epoch=0,object_or_stream_generation=1,seed=0,fault_point_id=0)
        item.update({k:'11'*32 for k in v.FIELDS if k.endswith('_hash')})
        item.update(evidence_count=1,evidence_digest=v.digest(members))
        proofs.append(item)
        stem=f'{test:08x}-{proof}'
        (root/'evidence'/f'{stem}.json').write_bytes(members)
        record=bytearray(320)
        struct.pack_into('<IHHQIHHIIII',record,0,0x43595632,4,320,1,test,1,proof,checker,1,0,1)
        struct.pack_into('<7Q',record,40,1,1,0,1,0,0,0)
        record[96:256]=bytes.fromhex('11'*32*5)
        record[256:288]=bytes.fromhex(v.digest(members))
        record[288:]=bytes.fromhex(v.digest(b'CYX/VERDICT/v4'+record[:288]))
        (root/'verdicts'/f'{stem}.bin').write_bytes(record)
    return json.dumps(dict(schema='cyxia-frozen-verdict-run/v1',run_id=1,inventory_sha256=inv,proofs=proofs)).encode()

class ArchiveMembership(unittest.TestCase):
    def test_count_preserving_proof_reassignment_rejected(self):
        # Preserve both aggregate counts and per-class counts, but move a
        # mandatory proof off its normative case onto an unrelated case.
        original = v.INVENTORY.read_bytes()
        for proof, source, destination in (
            ('STATIC_EL1', 'P09', 'P01'),
            ('MODEL_CHECK', 'P02', 'P01'),
            ('ARCH_A53', 'P10', 'P01'),
        ):
            with self.subTest(proof=proof), tempfile.TemporaryDirectory() as d:
                data = json.loads(original)
                cases = {case['id']: case for case in data['cases']}
                key = 'g5_additional' if proof == 'ARCH_A53' else 'g4_required'
                cases[source][key].remove(proof)
                cases[destination][key].append(proof)
                path = Path(d) / 'inventory.json'
                path.write_text(json.dumps(data), encoding='utf-8')
                with patch.object(v, 'INVENTORY', path):
                    with self.assertRaisesRegex(ValueError, 'inventory proof assignment mismatch: ' + proof):
                        v.inventory()
    def test_complete_canonical_archive_still_aggregates(self):
        g4,g5,_,_=v.inventory()
        # Synthetic namespace fixtures cannot supply a trusted board lock.
        # Preserve the target's stronger physical evidence boundary.
        for keys, physical_status in ((g4,'NOT_RUN'),(g5,'INVALID_EVIDENCE')):
            with self.subTest(physical_status=physical_status), tempfile.TemporaryDirectory() as d:
                r=Path(d); m=archive(r,keys)
                result=v.aggregate(m,v.digest(m),r)
                self.assertEqual(result['G4_QEMU']['counts']['PASS'],262)
                self.assertEqual(result['G4_QEMU']['complete_ids'],127)
                self.assertEqual(result['G5_ARCH']['counts']['PASS'],262)
                self.assertEqual(result['ARCH_A53']['counts'][physical_status],26)
                self.assertNotEqual(result['G5_ARCH']['status'],'PASS')
    def test_complete_archive_with_unknown_or_duplicate_record_rejected(self):
        for filename in ('0008000c-1.bin','00010001-2.bin','duplicate.bin'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as d:
                r=Path(d); _,keys,_,_=v.inventory(); m=archive(r,keys)
                (r/'verdicts'/filename).write_bytes((r/'verdicts'/'00010001-1.bin').read_bytes())
                with self.assertRaisesRegex(ValueError,'unexpected verdict'):
                    v.aggregate(m,v.digest(m),r)
    def test_unfrozen_required_record_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); m=archive(r,{(0x10001,1)})
            (r/'verdicts'/'00010002-1.bin').write_bytes(b'unfrozen')
            with self.assertRaisesRegex(ValueError,'unexpected verdict'):
                v.aggregate(m,v.digest(m),r)
    def test_missing_expected_remains_not_run(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); m=archive(r,{(0x10001,1)})
            (r/'verdicts'/'00010001-1.bin').unlink()
            self.assertEqual(v.aggregate(m,v.digest(m),r)['G4_QEMU']['counts']['NOT_RUN'],262)
    def test_namespace_symlink_rejected_even_for_empty_run(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); m=archive(r,set())
            (r/'verdicts').rmdir(); (r/'verdicts').symlink_to(r/'missing')
            with self.assertRaisesRegex(ValueError,'invalid verdict directory'):
                v.aggregate(m,v.digest(m),r)

if __name__=='__main__': unittest.main()
