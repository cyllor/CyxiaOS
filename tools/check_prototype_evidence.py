#!/usr/bin/env python3
"""Check prototype evidence completeness/integrity, not attest runtime truth.

A passing host test or a well-formed catalogue is never a native prototype PASS.
External sign-off must independently audit the guest verifier and raw traces.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "docs/implementation/prototype-requirements.json"
STATUSES = frozenset({"DESIGN_DEFINED", "IMPLEMENTED", "PASS", "FAIL", "NOT_RUN", "NOT_SUPPORTED", "BLOCKED"})
EXTRA_IDS = (
    "T-MODEL-01", "T-ACTION-01", "T-ACTION-02", "T-CORE-01", "T-CORE-02",
    "T-XDOMAIN-01", "T-FS-01", "T-IPC-01", "T-IRQ-01", "T-POWER-01",
    "T-CLUSTER-01", "T-CLUSTER-02", "T-DOMAIN-ALL",
    "V-ABI-01", "V-CORE-02", "V-LOCK-03", "V-TX-04", "V-FS-05", "V-CL-06", "V-AI-07", "V-REC-08",
    "SYS-X01", "SYS-X02", "SYS-X03", "CLU-X01", "CLU-X02", "CLU-X03", "SEC-X01", "AI-X01",
)
REQUIRED = frozenset(
    [f"A{i:02}" for i in range(1, 17)]
    + [f"T{i:02}" for i in range(1, 21)]
    + [f"D{i:02}" for i in range(1, 17)] + list(EXTRA_IDS)
)
# Do not let an edited manifest relabel a two-node gate as a one-node test.
CLUSTER = frozenset(
    [f"T{i:02}" for i in range(1, 21)]
    + ["A12", "A13", "A14", "D16", "T-CLUSTER-01", "T-CLUSTER-02", "V-CL-06", "V-REC-08",
       "CLU-X01", "CLU-X02", "CLU-X03", "SEC-X01"]
)
SPECS = {
    "system": "2df965ba7604a444acf08d519e430c65429aebdf757fe3de29969dc7b9e2a35a",
    "cluster": "198a63231025dc58872d1c27edc21cd0613e2321d30f1fd34b999f878b324db3",
}


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, f"Duplicate JSON key: {key}")
        out[key] = value
    return out


def read_json(path: Path):
    require(path.stat().st_size <= 4 * 1024 * 1024, "JSON exceeds bounded size")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(EvidenceError(f"Invalid number {value}")))


def exact_keys(obj, required: set[str], optional: set[str] = frozenset()) -> None:
    require(type(obj) is dict and required <= obj.keys() and obj.keys() <= required | optional,
            "Missing or unknown schema field")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_path(root: Path, name: str) -> Path:
    require(isinstance(name, str) and bool(name) and "\\" not in name, "Invalid evidence path")
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and ".." not in relative.parts
            and relative.as_posix() == name and bool(relative.parts), "Unsafe/noncanonical evidence path")
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), "Evidence path contains a symlink")
    require(current.is_file() and current.resolve().is_relative_to(root.resolve()), "Evidence file missing/escaping root")
    return current


def artifact(root: Path, record) -> Path:
    exact_keys(record, {"path", "sha256"})
    require(isinstance(record["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None,
            "Invalid evidence digest")
    path = safe_path(root, record["path"])
    require(0 < path.stat().st_size <= 1024 * 1024 * 1024, "Empty/oversized evidence file")
    require(sha256(path) == record["sha256"], "Evidence hash mismatch: " + record["path"])
    return path


def runtime_evidence(root: Path, item: dict, tree: str) -> None:
    # This validates bindings and integrity only. A self-authored verifier
    # receipt does not prove an image actually booted or an AI action occurred.
    receipt_path = artifact(root, item["evidence"])
    r = read_json(receipt_path)
    exact_keys(r, {"schema_version", "test_id", "verdict", "source_tree", "execution", "nodes", "build_id",
                   "qemu_version", "seed", "fault_injection_point", "expected_invariant", "observed_result",
                   "model", "action_schema", "machine_config", "events", "reproducer", "verifier"})
    require(type(r["schema_version"]) is int and r["schema_version"] == 1, "Unsupported receipt schema")
    require(r["test_id"] == item["id"] and r["verdict"] == item["status"] and r["source_tree"] == tree,
            "Receipt is for a different requirement, outcome or source tree")
    require(r["execution"] == "native-cyxia-guest", "Host tests cannot close native requirements")
    for field in ("build_id", "qemu_version", "fault_injection_point", "expected_invariant", "observed_result"):
        require(isinstance(r[field], str) and bool(r[field].strip()), "Missing runtime context: " + field)
    require(type(r["seed"]) is int and 0 <= r["seed"] < 2**64, "Invalid fault seed")
    nodes = r["nodes"]
    require(type(nodes) is list and len(nodes) == (2 if item["id"] in CLUSTER else 1), "Wrong native node count")
    ids = set()
    for n in nodes:
        exact_keys(n, {"node_id", "boot_epoch", "os", "vcpus", "image"})
        require(isinstance(n["node_id"], str) and re.fullmatch(r"[0-9a-f]{64}", n["node_id"]) is not None
                and n["node_id"] != "0" * 64 and n["node_id"] not in ids, "Invalid/duplicate native identity")
        require(type(n["boot_epoch"]) is int and 0 < n["boot_epoch"] < 2**64, "Invalid native boot epoch")
        require(n["os"] == "CyxiaOS" and type(n["vcpus"]) is int and n["vcpus"] == 4,
                "Expected the specification's four-vCPU native guest test configuration")
        artifact(root, n["image"])
        ids.add(n["node_id"])
    for field in ("model", "action_schema", "machine_config", "events", "reproducer", "verifier"):
        artifact(root, r[field])


def validate(document, root: Path, source_tree: str) -> dict:
    exact_keys(document, {"schema_version", "baseline_commit", "baseline_tree", "specs", "requirements"})
    require(type(document["schema_version"]) is int and document["schema_version"] == 1, "Unsupported catalogue schema")
    for name in ("baseline_commit", "baseline_tree"):
        require(isinstance(document[name], str) and re.fullmatch(r"[0-9a-f]{40}", document[name]) is not None,
                "Invalid baseline identity")
    require(isinstance(source_tree, str) and re.fullmatch(r"[0-9a-f]{40}", source_tree) is not None, "Invalid source tree")
    require(type(document["specs"]) is dict and document["specs"] == SPECS, "Specification identity changed")
    rows = document["requirements"]
    require(type(rows) is list and len(rows) == len(REQUIRED), "Incomplete/extra requirement set")
    seen = set()
    counts = {s: 0 for s in sorted(STATUSES)}
    for item in rows:
        exact_keys(item, {"id", "requirement", "clause", "status", "gap", "code", "evidence"})
        ident = item["id"]
        require(isinstance(ident, str) and ident in REQUIRED and ident not in seen, "Unknown/duplicate requirement ID")
        seen.add(ident)
        status = item["status"]
        require(isinstance(status, str) and status in STATUSES, "Invalid evidence state")
        for field in ("requirement", "clause", "gap"):
            require(isinstance(item[field], str) and bool(item[field].strip()), "Missing scope: " + field)
        require(type(item["code"]) is list and bool(item["code"]), "Missing code trace")
        for name in item["code"]:
            safe_path(root, name)
        if status in {"PASS", "FAIL"}:
            runtime_evidence(root, item, source_tree)
        else:
            require(item["evidence"] is None, "Non-runtime states must not carry a runtime receipt")
        counts[status] += 1
    require(seen == REQUIRED, "Missing mandatory requirements")
    return {"schema_version": 1, "catalogue_valid": True, "source_tree": source_tree,
            "requirements": len(rows), "states": counts,
            "release_evidence_complete": counts["PASS"] == len(REQUIRED),
            "runtime_truth_attested": False,
            "scope": "Completeness, identity and file-integrity gate only; independent verifier/trace review is required."}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, default=DEFAULT)
    p.add_argument("--root", type=Path, default=ROOT)
    p.add_argument("--source-tree", help="Exact Git tree whose evidence is under review")
    p.add_argument("--release", action="store_true", help="Fail unless every mandatory gate has bound native evidence")
    a = p.parse_args(argv)
    try:
        tree = a.source_tree or subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=a.root, text=True, timeout=10).strip()
        result = validate(read_json(a.manifest), a.root.resolve(), tree)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if a.release and not result["release_evidence_complete"] else 0
    except (EvidenceError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("prototype-evidence: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
