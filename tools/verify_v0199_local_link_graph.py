#!/usr/bin/env python3
"""Verify the resolved *active* CyxiaOS single-device Cargo dependency graph.

This is narrower than G0/G4 native acceptance. Historical crates can still
exist in the repository/lockfile; the release graph must not load them.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

PACKAGE_RE = re.compile(r"^([A-Za-z0-9_-]+) v[0-9]+(?:\.[0-9]+){2}(?:[+-][^ ]+)?(?: |$)", re.M)

PROHIBITED = frozenset(
    {"cyxia-cluster-transport", "cyxia-peer-billing"}
)
REQUIRED = frozenset(
    {"cyxia-kernel", "cyxia-kernel-core", "cyxia-prototype"}
)


def inspect_tree(text: str) -> dict[str, object]:
    packages = frozenset(PACKAGE_RE.findall(text))
    missing = sorted(REQUIRED - packages)
    forbidden = sorted(packages & PROHIBITED)
    return {
        "status": "PASS" if not missing and not forbidden else "FAIL",
        "package_count": len(packages),
        "required_missing": missing,
        "prohibited_active": forbidden,
        "native_network_independent": "cyxia-cluster-transport" not in packages,
        "rule": "Active default native Cargo closure only; not source deletion or hardware validation",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cargo_tree", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = inspect_tree(args.cargo_tree.read_text(encoding="utf-8"))
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
    print(body, end="")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
