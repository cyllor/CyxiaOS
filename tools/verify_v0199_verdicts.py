#!/usr/bin/env python3
"""Independent structural/custody verification and G4/G5 aggregation.

This is NOT a case checker: it never manufactures PASS or FAIL Verdict v4
records, interprets a diagnostic log as a formal proof, or certifies the
trusted origin of a run manifest. The operator supplies the *previously
frozen authenticated* manifest and exact expected digest. Native/static/
model/architecture checkers produce the individual canonical records.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

CLASSES={"RUNTIME_QEMU":1,"STATIC_EL1":2,"ARCH_A53":3,"MODEL_CHECK":4}
NAMES={v:k for k,v in CLASSES.items()}
STATUS={0:"NOT_RUN",1:"PASS",2:"FAIL"}
REASONS={0:{1,2,7,8,9},1:{0},2:{3,4,5,6}}
INVENTORY=Path(__file__).resolve().parent/"v0199-required-proof-inventory.json"

# Verdict v4 identity allocation and the ranges in baseline 安§7.4.
_CASE_RANGES = (
    range(1, 14), range(1, 14), range(1, 16), range(1, 17),
    range(1, 15), range(1, 14), range(1, 14),
    (*range(1, 12), 15, 16), (*range(1, 9), 13, 14, 15), range(1, 7),
)
STABLE_CASES = {
    (domain << 16) | number: f"{family}{number:02d}"
    for domain, (family, numbers) in enumerate(zip("PFMNDSJAEH", _CASE_RANGES), 1)
    for number in numbers
}

def require(ok,msg):
    if not ok: raise ValueError(msg)
def digest(data):return hashlib.sha256(data).hexdigest()
def strict_json(raw):
    # Hashing ambiguous JSON bytes does not ensure all independent readers
    # agree on their semantic contents. Reject repeated object keys and
    # nonstandard non-finite numeric constants at every nesting level.
    def unique(pairs):
        out={}
        for key,value in pairs:
            require(key not in out,"duplicate JSON key: "+key)
            out[key]=value
        return out
    def bad_constant(value):
        raise ValueError("noncanonical JSON constant: "+value)
    return json.loads(raw,object_pairs_hook=unique,parse_constant=bad_constant)
def sha_path(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()
def hash_value(v):
    require(isinstance(v,str) and len(v)==64 and v==v.lower(),"invalid canonical SHA256")
    try: bytes.fromhex(v)
    except ValueError: raise ValueError("invalid canonical SHA256")
    require(len(bytes.fromhex(v))==32,"invalid canonical SHA256")
    return v
def safe_file(root,relative):
    require(isinstance(relative,str) and relative!="","missing relative evidence path")
    p=Path(relative)
    require(not p.is_absolute() and ".." not in p.parts,"evidence escapes root")
    require(p.as_posix()==relative and "\\" not in relative and relative!=".",
            "noncanonical evidence path")
    cur=root
    for part in p.parts:
        cur=cur/part
        require(not cur.is_symlink(),"symlink evidence rejected")
    require(cur.is_file(),"missing evidence file")
    require(cur.resolve().is_relative_to(root.resolve()),"evidence escapes root")
    return cur
def inventory():
    raw=INVENTORY.read_bytes()
    j=strict_json(raw)
    cases=j["cases"]
    require(j["required_ids"] == len(cases) == len(STABLE_CASES) == 127, "inventory invalid")
    ids = {}
    g4, physical = set(), set()
    for case in cases:
        test = case["test_id"]
        name = case["id"]
        require(type(test) is int and isinstance(name, str)
                and STABLE_CASES.get(test) == name and test not in ids,
                "unknown or duplicate stable test ID")
        required, additional = case["g4_required"], case["g5_additional"]
        require(isinstance(required, list) and required.count("RUNTIME_QEMU") == 1,
                "missing mandatory runtime proof")
        require(all(
            proof in ("RUNTIME_QEMU", "STATIC_EL1", "MODEL_CHECK") for proof in required
        ) and len(required) == len(set(required)), "invalid required proof classes")
        require(additional in ([], ["ARCH_A53"]), "invalid mandatory physical proof")
        ids[test] = name
        g4.update((test, CLASSES[proof]) for proof in required)
        physical.update((test, CLASSES[proof]) for proof in additional)
    g5 = g4 | physical
    require(len(g4)==262 and len(g5-g4)==26,"inventory proof count mismatch")
    return g4,g5,ids,digest(raw)
def parse(raw):
    require(len(raw)==320,"wrong Verdict v4 size")
    magic,ver,size,run,test,status,proof,checker,checker_version,reason,count=struct.unpack_from("<IHHQIHHIIII",raw)
    require((magic,ver,size)==(0x43595632,4,320),"wrong Verdict v4 header")
    require(test in STABLE_CASES, "unknown stable test ID")
    require(status in STATUS and proof in NAMES and reason in REASONS[status],"invalid status/reason/class")
    require(run>0 and checker_version>0 and checker>>16==test>>16 and checker&0xffff,"invalid checker identity")
    epochs=struct.unpack_from("<7Q",raw,40)
    require(epochs[-1]==0,"nonzero reserved field")
    hashes=[raw[i:i+32].hex() for i in range(96,288,32)]
    require(digest(b"CYX/VERDICT/v4"+raw[:288])==raw[288:].hex(),"record digest mismatch")
    empty=hashes[-1]=="0"*64
    require((count==0)==empty and (status==0 or count>0),"PASS/FAIL without evidence")
    return dict(run_id=run,test_id=test,proof_class=proof,status=STATUS[status],checker_id=checker,
                checker_version=checker_version,reason=reason,evidence_count=count,
                boot_epoch=epochs[0],controller_epoch=epochs[1],security_epoch=epochs[2],
                object_or_stream_generation=epochs[3],seed=epochs[4],fault_point_id=epochs[5],
                **dict(zip(("design_hash","binary_hash","security_profile_hash","input_hash","rule_hash","evidence_digest"),hashes)))

FIELDS=("checker_id","checker_version","boot_epoch","controller_epoch","security_epoch",
        "object_or_stream_generation","seed","fault_point_id","design_hash","binary_hash",
        "security_profile_hash","input_hash","rule_hash")
def aggregate(manifest_raw,locked_digest,root):
    require(digest(manifest_raw)==hash_value(locked_digest),"run manifest not the locked input")
    j=strict_json(manifest_raw)
    g4,g5,ids,inv_hash=inventory()
    require(j["schema"]=="cyxia-frozen-verdict-run/v1" and j["inventory_sha256"]==inv_hash,"wrong inventory binding")
    run=j["run_id"]
    require(type(run) is int and 0<run<2**64,"invalid run id")
    expected={}
    for item in j["proofs"]:
        require(type(item["test_id"]) is int and 0<item["test_id"]<2**32,"invalid expected test ID")
        key=(item["test_id"],CLASSES[item["proof_class"]])
        require(key in g5 and key not in expected,"duplicate/unknown expected proof")
        require(all(k in item for k in FIELDS),"incomplete frozen expected input")
        if "evidence_count" in item:
            count = item["evidence_count"]
            require(type(count) is int and 0 <= count < 2**32, "invalid frozen evidence count")
        if "evidence_digest" in item:
            hash_value(item["evidence_digest"])
        for k in FIELDS:
            if k.endswith("_hash"):
                require(hash_value(item[k])!="0"*64,"zero expected hash")
            else:require(type(item[k]) is int and 0<=item[k]<2**64,"invalid expected integer")
        require(0<item["checker_id"]<2**32 and item["checker_id"]>>16==key[0]>>16
                and item["checker_id"]&0xffff and 0<item["checker_version"]<2**32,
                "invalid expected checker")
        expected[key]=item
    rows={}
    for key in sorted(g5):
        base=dict(test_id=key[0],id=ids[key[0]],proof_class=NAMES[key[1]])
        item=expected.get(key)
        if item is None:
            rows[key]={**base,"status":"NOT_RUN","reason":"missing frozen expected input"};continue
        # Fixed file naming is an internal archive convention, not a new
        # guest ABI. The manifest commits the checker, inputs and exact
        # evidence manifest supplied to that checker.
        stem=f'{key[0]:08x}-{key[1]}'
        rel=f'verdicts/{stem}.bin'
        path=root/rel
        if not path.exists() and not path.is_symlink():
            rows[key]={**base,"status":"NOT_RUN","reason":"missing verdict"};continue
        try:
            raw=safe_file(root,rel).read_bytes()
            v=parse(raw)
            require((v["run_id"],v["test_id"],v["proof_class"])==(run,*key),"wrong run/proof key")
            require(all(v[k]==item[k] for k in FIELDS),"frozen input mismatch")
            if v["evidence_count"]:
                require(v["evidence_count"] == item.get("evidence_count"),
                        "evidence count differs from frozen input")
                require(v["evidence_digest"] == item.get("evidence_digest"),
                        "evidence digest differs from frozen input")
                # Digest of the exact external manifest bytes; each member's
                # SHA256/size is then independently read from the archive.
                m=safe_file(root,f'evidence/{stem}.json').read_bytes()
                require(digest(m)==v["evidence_digest"],"evidence manifest digest mismatch")
                members=strict_json(m)["files"]
                require(isinstance(members,list) and len(members)==v["evidence_count"],"evidence count mismatch")
                identities=set()
                previous_path = b""
                for e in members:
                    p=safe_file(root,e["path"])
                    utf8_path = e["path"].encode("utf-8")
                    require(previous_path < utf8_path, "evidence paths must be unique and UTF-8 sorted")
                    previous_path = utf8_path
                    st=p.stat()
                    identity=(st.st_dev,st.st_ino)
                    require(identity not in identities,"aliased physical evidence member")
                    identities.add(identity)
                    require(type(e["bytes"]) is int and 0<=e["bytes"]<2**64
                            and st.st_size==e["bytes"] and sha_path(p)==hash_value(e["sha256"]),
                            "evidence object mismatch")
            rows[key]={**base,"status":v["status"],"reason_code":v["reason"],"evidence_count":v["evidence_count"],
                       "record_sha256":digest(raw)}
        except (OSError,ValueError,KeyError,TypeError,struct.error) as exc:
            # A malformed archive is an integration blocker. Do not invent
            # a checker Verdict v4 FAIL, or override reliable prior verdicts.
            rows[key]={**base,"status":"INVALID_EVIDENCE","reason":str(exc)}
    def summary(keys):
        counts={s:sum(rows[k]["status"]==s for k in keys) for s in ("PASS","FAIL","NOT_RUN","INVALID_EVIDENCE")}
        status="FAIL" if counts["FAIL"] else "BLOCKED_INVALID_EVIDENCE" if counts["INVALID_EVIDENCE"] else "NOT_RUN" if counts["NOT_RUN"] else "PASS"
        return dict(status=status,required=len(keys),counts=counts,
                    complete_ids=sum(all(rows[k]["status"]=="PASS" for k in keys if k[0]==i) for i in ids))
    return dict(schema="cyxia-verdict-aggregation/v1",run_id=run,manifest_sha256=locked_digest,
                scope="archive integrity and proof coverage only; checker semantics and trusted origin external",
                G4_QEMU=summary(g4),G5_ARCH=summary(g5),proofs=list(rows.values()))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--manifest-sha256",required=True)
    p.add_argument("--evidence-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    result=aggregate(a.manifest.read_bytes(),a.manifest_sha256,a.evidence_root.resolve(strict=True))
    with a.output.open("x",encoding="utf-8") as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write("\n")
    print(json.dumps({k:result[k] for k in ("run_id","G4_QEMU","G5_ARCH")},indent=2))
    return 0 if result["G4_QEMU"]["status"]==result["G5_ARCH"]["status"]=="PASS" else 1
if __name__=="__main__":
    raise SystemExit(main())
