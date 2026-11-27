"""Synthetic structural regressions only; no formal case verdicts are issued."""
import hashlib,json,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import verify_v0199_verdicts as v
class VerdictTests(unittest.TestCase):
    def frozen_evidence(self, manifest, count, evidence):
        locked = json.loads(manifest)
        locked["proofs"][0].update(evidence_count=count, evidence_digest=v.digest(evidence))
        return json.dumps(locked).encode()

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
        manifest=self.frozen_evidence(manifest,1,m)
        (root/"evidence"/f"{stem}.json").write_bytes(m)
        record=bytearray(320)
        struct.pack_into("<IHHQIHHIIII",record,0,0x43595632,4,320,1,test,status,proof,fields["checker_id"],1,reason,1)
        struct.pack_into("<7Q",record,40,1,1,0,1,0,0,0)
        record[96:256]=bytes.fromhex("11"*32*5);record[256:288]=hashlib.sha256(m).digest()
        record[288:]=hashlib.sha256(b"CYX/VERDICT/v4"+record[:288]).digest()
        p=root/"verdicts"/f"{stem}.bin";p.write_bytes(record)
        return manifest,p
    def test_manifest_member_order_and_count_are_independent_of_rehashed_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen_manifest, verdict = self.setup_run(root)
            evidence = root / "evidence" / f"{verdict.stem}.json"
            members = json.loads(evidence.read_bytes())["files"]
            contents = b"second complete evidence object"
            second = "evidence/other.bin"
            (root / second).write_bytes(contents)
            members.append({"path": second, "bytes": len(contents), "sha256": v.digest(contents)})

            def write_evidence(entries):
                raw = json.dumps({"files": entries}).encode()
                evidence.write_bytes(raw)
                record = bytearray(verdict.read_bytes())
                struct.pack_into("<I", record, 36, len(entries))
                record[256:288] = hashlib.sha256(raw).digest()
                record[288:] = hashlib.sha256(b"CYX/VERDICT/v4" + record[:288]).digest()
                verdict.write_bytes(record)
                return raw

            def check(raw):
                return v.aggregate(raw, v.digest(raw), root)["G4_QEMU"]

            members_raw = write_evidence(members)
            self.assertEqual(check(frozen_manifest)["status"], "BLOCKED_INVALID_EVIDENCE")
            expected_two = self.frozen_evidence(frozen_manifest, 2, members_raw)
            self.assertEqual(check(expected_two)["counts"]["PASS"], 1)
            reversed_raw = write_evidence(list(reversed(members)))
            frozen_reversed = self.frozen_evidence(frozen_manifest, 2, reversed_raw)
            self.assertEqual(check(frozen_reversed)["status"], "BLOCKED_INVALID_EVIDENCE")

    def test_stable_ids_and_required_runtime_proofs_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, verdict = self.setup_run(root)
            record = bytearray(verdict.read_bytes())
            deleted_case = (8 << 16) | 12
            struct.pack_into("<I", record, 16, deleted_case)
            struct.pack_into("<I", record, 24, (8 << 16) | 1)
            record[288:] = hashlib.sha256(b"CYX/VERDICT/v4" + record[:288]).digest()
            with self.assertRaisesRegex(ValueError, "unknown stable test ID"):
                v.parse(record)

            changed = json.loads(v.INVENTORY.read_bytes())
            changed["cases"][0]["g4_required"] = ["STATIC_EL1"]
            inventory = root / "changed-inventory.json"
            inventory.write_text(json.dumps(changed), encoding="utf-8")
            with patch.object(v, "INVENTORY", inventory):
                with self.assertRaisesRegex(ValueError, "mandatory runtime proof"):
                    v.inventory()

    def test_every_proof_pair_matches_baseline_matrix(self):
        # 安§7.4, pp. 171–172. Check membership as well as totals.
        matrix = {
            "P": ("9 10 11 12 13", "10 11 12", "2 4 5 6 13"),
            "F": ("2 9", "", "2 3 5 6 7 9 10 11 12 13"),
            "M": ("2 4 5 8 10 11 12 13 14 15", "2 4 8 10 11 12 13 15", "4 5 6 9 11 13 14"),
            "N": ("1 7 12 15", "", "3 4 9 10 11 13 15 16"),
            "D": ("2 3 9 10 12 13 14", "4 6 9 10 14", "3 4 5 6 9 14"),
            "S": ("1 2 9 11 12 13", "9 13", "2 3 4 5 6 7 8 11 12 13"),
            "J": ("1 2 7 13", "1 2 7", "1 2 3 4 5 6 7 8 9 10 11 12 13"),
            "A": ("1 4 6 7 10 16", "1 4 6", "4 5 6 7 10 11 15 16"),
            "E": ("3 5 8 15", "3 8", "1 2 3 4 5 6 7 8 13 14 15"),
            "H": ("1 5 6", "", "1 2 3 4 5 6"),
        }
        g4, g5, ids, _ = v.inventory()
        expected = {
            (f"{family}{int(number):02d}", proof)
            for family, columns in matrix.items()
            for proof, column in zip(("STATIC_EL1", "ARCH_A53", "MODEL_CHECK"), columns)
            for number in column.split()
        }
        expected.update((name, "RUNTIME_QEMU") for name in ids.values())
        self.assertEqual({(ids[test], v.NAMES[proof]) for test, proof in g5}, expected)
        self.assertEqual({(ids[test], v.NAMES[proof]) for test, proof in g4},
                         {pair for pair in expected if pair[1] != "ARCH_A53"})

    def test_legacy_manifest_without_frozen_evidence_binding_cannot_certify(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, verdict = self.setup_run(root)
            for field in ("evidence_count", "evidence_digest"):
                manifest = json.loads(raw)
                del manifest["proofs"][0][field]
                legacy = json.dumps(manifest).encode()
                report = v.aggregate(legacy, v.digest(legacy), root)
                self.assertEqual(report["G4_QEMU"]["status"], "BLOCKED_INVALID_EVIDENCE")
                self.assertEqual(report["G4_QEMU"]["counts"]["PASS"], 0)

            # A legacy archive can still record the absence of a verdict.
            verdict.unlink()
            report = v.aggregate(legacy, v.digest(legacy), root)
            self.assertEqual(report["G4_QEMU"]["status"], "NOT_RUN")
    def test_physical_and_spelling_aliases_do_not_inflate_evidence_count(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);m,p=self.setup_run(r)
            f=r/"evidence"/(p.stem+".json")
            members=json.loads(f.read_bytes())["files"]
            old=r/members[0]["path"]
            alias=r/"evidence"/"alias.bin"
            os.link(old,alias)
            for spelling in ("evidence/./object.bin","evidence//object.bin","evidence/alias.bin"):
                entries = [members[0], {**members[0], "path": spelling}]
                entries.sort(key=lambda entry: entry["path"].encode("utf-8"))
                ambiguous=json.dumps({"files":entries}).encode()
                f.write_bytes(ambiguous)
                rec=bytearray(p.read_bytes());struct.pack_into("<I",rec,36,2)
                rec[256:288]=hashlib.sha256(ambiguous).digest()
                rec[288:]=hashlib.sha256(b"CYX/VERDICT/v4"+rec[:288]).digest()
                p.write_bytes(rec)
                locked=self.frozen_evidence(m,2,ambiguous)
                self.assertEqual(v.aggregate(locked,v.digest(locked),r)["G4_QEMU"]["status"],"BLOCKED_INVALID_EVIDENCE")
    def test_duplicate_keys_and_noncanonical_constants_fail_closed(self):
        for raw in (b'{"run_id":1,"run_id":2}', b'{"nested":{"x":1,"x":2}}', b'{"n":NaN}', b'{"n":Infinity}'):
            with self.assertRaises(ValueError):v.strict_json(raw)
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);m,p=self.setup_run(r)
            duplicate=m.replace(b'"run_id": 1',b'"run_id": 1,"run_id": 1')
            self.assertNotEqual(duplicate,m)
            with self.assertRaises(ValueError):v.aggregate(duplicate,v.digest(duplicate),r)
            stem=p.stem
            f=r/"evidence"/(stem+".json")
            ambiguous=b'{"files":[],"files":'+json.dumps(json.loads(f.read_bytes())["files"]).encode()+b'}'
            f.write_bytes(ambiguous)
            rec=bytearray(p.read_bytes())
            rec[256:288]=hashlib.sha256(ambiguous).digest()
            rec[288:]=hashlib.sha256(b"CYX/VERDICT/v4"+rec[:288]).digest()
            p.write_bytes(rec)
            locked=self.frozen_evidence(m,1,ambiguous)
            self.assertEqual(v.aggregate(locked,v.digest(locked),r)["G4_QEMU"]["status"],"BLOCKED_INVALID_EVIDENCE")
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

    def test_evidence_digest_must_match_the_frozen_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, _ = self.setup_run(root)
            frozen = json.loads(raw)
            frozen["proofs"][0]["evidence_digest"] = v.digest(b"different frozen evidence manifest")
            raw = json.dumps(frozen).encode()
            report = v.aggregate(raw, v.digest(raw), root)
            self.assertEqual(report["G4_QEMU"]["counts"]["PASS"], 0)
            self.assertEqual(report["G4_QEMU"]["status"], "BLOCKED_INVALID_EVIDENCE")

if __name__=="__main__":unittest.main()
