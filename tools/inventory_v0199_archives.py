"""Inventory G4/G5 archive candidates without issuing or aggregating verdicts."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

if __package__:
    from . import acceptance_coverage as coverage
    from . import verify_v0199_verdicts as verdicts
else:
    import acceptance_coverage as coverage
    import verify_v0199_verdicts as verdicts


MANIFEST_SCHEMA = "cyxia-frozen-verdict-run/v1"
VERDICT_HEADER = bytes.fromhex("3256594304004001")
PROOF_NAME = re.compile(r"[0-9a-f]{8}-[1-4]\.(bin|json)")
MAX_JSON_BYTES = 16 * 1024 * 1024
CONTAINER_SUFFIXES = {".zip", ".tar", ".tgz", ".gz", ".zst", ".xz", ".7z"}


def requirements():
    g4, g5, names, digest = verdicts.inventory()
    if errors := coverage.validate(coverage.ROWS):
        raise ValueError("invalid coverage table: " + ", ".join(errors))
    covered = {row[0].removeprefix("SEC-"): row[2] for row in coverage.ROWS}
    if set(covered) != set(names.values()):
        raise ValueError("coverage IDs differ from the required proof inventory")

    def classes(keys):
        return dict(sorted(Counter(verdicts.NAMES[class_id] for _, class_id in keys).items()))

    return {
        "stable_ids": len(names),
        "proof_inventory_sha256": digest,
        "g4_required_pairs": len(g4),
        "g5_required_pairs": len(g5),
        "g4_required": classes(g4),
        "g5_additional": classes(g5 - g4),
        "coverage": coverage.counts(coverage.ROWS),
        "missing_coverage_source_paths": coverage.check_paths(coverage.ROWS),
        "required_by_id": [
            {
                "id": name,
                "test_id": test,
                "coverage": covered[name],
                "g4": [verdicts.NAMES[k] for key, k in sorted(g4) if key == test],
                "g5_additional": [verdicts.NAMES[k] for key, k in sorted(g5 - g4) if key == test],
            }
            for test, name in sorted(names.items())
        ],
    }


class ArchiveScan:
    def __init__(self, inventory_digest):
        self.inventory_digest = inventory_digest
        self.counts = Counter()
        self.run_manifests = []
        self.verdict_records = []
        self.evidence_manifests = []
        self.inspection_errors = []

    def inspect_file(self, location, name, size, open_file):
        self.counts["files"] += 1
        path = PurePosixPath(name)
        if path.suffix.lower() in CONTAINER_SUFFIXES:
            self.counts["nested_or_unsupported_containers_skipped"] += 1
            return
        if path.suffix.lower() in {".jsonl", ".ndjson"}:
            self.counts["stream_logs_skipped"] += 1
            return
        canonical = PROOF_NAME.fullmatch(path.name)
        record_path = canonical and path.parent.name == "verdicts" and path.suffix == ".bin"
        evidence_path = canonical and path.parent.name == "evidence" and path.suffix == ".json"
        if evidence_path:
            self.evidence_manifests.append(location)

        if record_path or size == 320:
            candidate = {"location": location}
            with open_file() as stream:
                raw = stream.read(321)
            if record_path or raw.startswith(VERDICT_HEADER):
                try:
                    record = verdicts.parse(raw)
                    candidate.update(run_id=record["run_id"], test_id=record["test_id"],
                                     proof_class=verdicts.NAMES[record["proof_class"]])
                    candidate["sha256"] = sha256(raw).hexdigest()
                except ValueError as error:
                    candidate["parse_error"] = str(error)
                self.verdict_records.append(candidate)
                return

        has_json_name = path.suffix.lower() == ".json" or "manifest" in path.name.lower()
        if size > MAX_JSON_BYTES:
            if has_json_name:
                self.counts["large_json_or_manifest_skipped"] += 1
            return
        with open_file() as stream:
            head = stream.read(64)
            if not has_json_name and not head.lstrip().startswith(b"{"):
                return
            raw = head + stream.read(MAX_JSON_BYTES + 1 - len(head))
        if len(raw) > MAX_JSON_BYTES:
            self.counts["large_json_or_manifest_skipped"] += 1
            return
        self.counts["json_inspected"] += 1
        try:
            doc = verdicts.strict_json(raw)
        except (ValueError, RecursionError) as error:
            self.counts["invalid_json"] += 1
            if MANIFEST_SCHEMA.encode("ascii") in raw:
                self.run_manifests.append({"location": location, "parse_error": str(error)})
            return
        if not isinstance(doc, dict) or doc.get("schema") != MANIFEST_SCHEMA:
            return
        self.run_manifests.append({
            "location": location,
            "sha256": sha256(raw).hexdigest(),
            "run_id": doc["run_id"] if type(doc.get("run_id")) is int else None,
            "inventory_hash_matches": doc.get("inventory_sha256") == self.inventory_digest,
            "declared_entries": len(doc["proofs"]) if isinstance(doc.get("proofs"), list) else None,
        })

    def inspect_path(self, path):
        try:
            if path.is_symlink():
                self.counts["symlinks_skipped"] += 1
            elif path.is_dir():
                for member in sorted(path.iterdir()):
                    self.inspect_path(member)
            elif path.is_file():
                if path.suffix.lower() == ".zip":
                    self.counts["zip_archives"] += 1
                    with zipfile.ZipFile(path) as archive:
                        for item in archive.infolist():
                            if item.is_dir():
                                continue
                            if stat.S_ISLNK(item.external_attr >> 16):
                                self.counts["symlinks_skipped"] += 1
                                continue
                            self.inspect_file(f"{path}!/{item.filename}", item.filename,
                                              item.file_size, lambda: archive.open(item))
                else:
                    self.inspect_file(str(path), path.as_posix(),
                                      path.stat().st_size, lambda: path.open("rb"))
        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
            self.inspection_errors.append({"location": str(path), "error": str(error)})

    def result(self, path):
        return {
            "input": str(path),
            "counts": dict(sorted(self.counts.items())),
            "run_manifest_candidates": self.run_manifests,
            "verdict_record_candidates": self.verdict_records,
            "evidence_manifest_paths": self.evidence_manifests,
            "inspection_errors": self.inspection_errors,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="directories, files or ZIP artifacts")
    args = parser.parse_args()
    for path in args.inputs:
        if not path.exists():
            parser.error(f"missing archive input {path}")
    expected = requirements()
    results = []
    for path in args.inputs:
        scan = ArchiveScan(expected["proof_inventory_sha256"])
        scan.inspect_path(path.absolute())
        results.append(scan.result(path.absolute()))
    json.dump({
        "schema": "cyxia-v0199-archive-inventory/v1",
        "scope": "observed files and structural candidates; no trust or verdict determination",
        "requirements": expected,
        "inputs": results,
    }, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
