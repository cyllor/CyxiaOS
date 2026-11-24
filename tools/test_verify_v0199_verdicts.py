"""Synthetic structural regressions only; no formal case verdicts are issued."""
import hashlib,json,struct,tempfile,unittest
from pathlib import Path
import verify_v0199_verdicts as v
class VerdictTests(unittest.TestCase):
    def setup_run(self,root,status=1,reason=0):
        g4,g5,ids,inv=v.inventory()
        test,proof=min(g4)
        fields=dict(checker_id=(test>>16<<16)|1,checker_version=1,boot_epoch=1,controller_epoch=1,
                    security_epoch=0,object_or_stream_generation=1,seed=0,fault_point_id=0)
        fields.update({k:"11"*32 for k in v.FIELDS if k.endswith("_hash")})
        item=dict(test_id=test,proof_class=v.NAMES[proof],**fields)
        manifest=json.dumps(dict(schema="cyxia-frozen-verdict-run/v1",run_id=1,inventory_sha256=inv,proofs=[item])).encode()
        stem=f"{test:08x}-{proof}"
        (root/"verdicts").mkdir();(root/"evidence").mkdir()
        e=b"synthetic test fixture, not runtime proof"
        (root/"evidence"/"object.bin").write_bytes(e)
        m=json.dumps({"files":[{"path":"evidence/object.bin","bytes":len(e),"sha256":v.digest(e)}]}).encode()
        (root/"evidence"/f"{stem}.json").write_bytes(m)
        record=bytearray(320)
        struct.pack_into("<IHHQIHHIIII",record,0,0x43595632,4,320,1,test,status,proof,fields["checker_id"],1,reason,1)
        struct.pack_into("<7Q",record,40,1,1,0,1,0,0,0)
        record[96:256]=bytes.fromhex("11"*32*5);record[256:288]=hashlib.sha256(m).digest()
        record[288:]=hashlib.sha256(b"CYX/VERDICT/v4"+record[:288]).digest()
        p=root/"verdicts"/f"{stem}.bin";p.write_bytes(record)
        return manifest,p
    def test_missing_proofs_never_pass_and_failure_dominates(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);m,p=self.setup_run(r)
            a=v.aggregate(m,v.digest(m),r)
            self.assertEqual(a["G4_QEMU"]["status"],"NOT_RUN")
            self.assertEqual(a["G4_QEMU"]["counts"]["PASS"],1)
            self.assertEqual(a["G4_QEMU"]["counts"]["NOT_RUN"],261)
            self.assertEqual(a["G5_ARCH"]["counts"]["NOT_RUN"],287)
            rec=bytearray(p.read_bytes());struct.pack_into("<H",rec,20,2);struct.pack_into("<I",rec,32,4)
            rec[288:]=hashlib.sha256(b"CYX/VERDICT/v4"+rec[:288]).digest();p.write_bytes(rec)
            self.assertEqual(v.aggregate(m,v.digest(m),r)["G4_QEMU"]["status"],"FAIL")
    def test_invalid_record_evidence_or_manifest_cannot_count_as_pass(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);m,p=self.setup_run(r)
            with self.assertRaises(ValueError):v.aggregate(m,"00"*32,r)
            (r/"evidence/object.bin").write_bytes(b"changed")
            a=v.aggregate(m,v.digest(m),r)
            self.assertEqual(a["G4_QEMU"]["counts"]["PASS"],0)
            self.assertEqual(a["G4_QEMU"]["status"],"BLOCKED_INVALID_EVIDENCE")
            rec=bytearray(p.read_bytes());rec[32]=4
            rec[288:]=hashlib.sha256(b"CYX/VERDICT/v4"+rec[:288]).digest()
            with self.assertRaises(ValueError):v.parse(rec)
if __name__=="__main__":unittest.main()
