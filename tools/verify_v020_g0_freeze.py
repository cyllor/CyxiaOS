#!/usr/bin/env python3
"""Verify the V0.20 G0 design baseline and its shared security-track digest."""
from __future__ import annotations

from collections import Counter
from hashlib import sha1
import json
from pathlib import Path
import re
import sys

if __package__:
    from .verify_v0199_verdicts import NAMES, digest, inventory, require, strict_json
else:
    from verify_v0199_verdicts import NAMES, digest, inventory, require, strict_json


ROOT = Path(__file__).resolve().parents[1]
LOCK = "docs/design/v0.20-g0-baseline-lock.json"
BASELINE = "docs/design/baselines/v0.19.9-implementation-spec.txt"
MEDIA = "docs/design/v0.20-g1-media-freeze.md"
NATIVE = "docs/design/v0.20-native-local-system.md"
SCOPE = "docs/implementation/v020-sim-acceptance-scope.md"
SCOPE_MAP = "docs/implementation/v020-sim-proof-scope.json"
INVENTORY = "tools/v0199-required-proof-inventory.json"
TRACKS = ("SEC-P", "SEC-F", "SEC-M", "SEC-N", "SEC-D", "SEC-S")


def section(raw, start, end):
    if start:
        before, marker, after = raw.partition(start.encode())
        require(marker and start.encode() not in after, f"missing or ambiguous start {start!r}")
        raw = marker + after
    if end:
        before, marker, after = raw.partition(end.encode())
        require(marker and end.encode() not in after, f"missing or ambiguous end {end!r}")
        raw = before
    return raw


def source_hashes(root):
    native = (root / NATIVE).read_bytes()
    sources = {
        BASELINE: (root / BASELINE).read_bytes(),
        f"{NATIVE}#design": section(native, None, "\n## 6. 实施现状"),
        f"{NATIVE}#acceptance": section(native, "\n## 7. 验收与发布", "\n| 门槛 |"),
        f"{MEDIA}#approval": section(
            (root / MEDIA).read_bytes(), "\n> 本文件是", "\n> - 标注【基线字节】",
        ),
        f"{SCOPE}#approved-scope": section((root / SCOPE).read_bytes(), None, "\n## PR #101"),
        SCOPE_MAP: (root / SCOPE_MAP).read_bytes(),
        INVENTORY: (root / INVENTORY).read_bytes(),
        "tools/qemu/README.md": (root / "tools/qemu/README.md").read_bytes(),
    }
    return {name: digest(data) for name, data in sources.items()}


def freeze_digest(sources):
    canonical = json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
    return digest(b"CYX/G0/V0.20/v1\0" + canonical)


def registry_owners(baseline):
    """Read owner/key pairs from the archived 安§0.10 table for review."""
    table = section(
        baseline, "\n安 0.10 参数分治与交叉引用注册表", "\n待登记使用点：",
    ).decode()
    table = re.sub(
        r"(?m)^\s*(?:CyxiaOS V0\.19\.9 · 第 \d+|<PARSED TEXT FOR PAGE[^\n]+>|"
        r"CYXIAOS /[^\n]+|唯一拥有者 / 键[^\n]*)[ \t]*$", "", table,
    )
    owners = list(re.finditer(r"(?m)^[ \t]*([A-Z][A-Za-z0-9]+\.v\d+) /[ \t]*", table))
    keys = {}
    for index, owner in enumerate(owners):
        end = owners[index + 1].start() if index + 1 < len(owners) else len(table)
        row = table[owner.end():end]
        fields = list(re.finditer(r"(?m)^[ \t]*([a-z][a-z_]*\.[A-Za-z_][A-Za-z0-9_.]*)", row))
        require(len(fields) == 1, f"ambiguous parameter row for {owner[1]}")
        field = fields[0]
        key = field[1]
        # PDF line breaks can bisect a key. A value after the key marks a
        # continuation of the value column, such as the layout unit "index".
        rest, _, tail = row[field.end():].partition("\n")
        suffix = re.match(r"\s*([a-z_]+)[ \t]*$", tail, re.M)
        if not rest.strip() and suffix:
            key += suffix[1]
        require(key not in keys, f"duplicate parameter owner or key: {key}")
        keys[key] = owner[1]
    require(len(keys) == 135, "baseline must enumerate all 135 registered parameter keys")
    return keys


def verify_topology_and_abi(root, baseline):
    control = root / "crates/kernel-core/src/control_plane"
    topology = (control / "cpu0_v0199.rs").read_text()
    for declaration in (
        "CONTROL_CPU: usize = 0", "CONTROL_MASK: u64 = 0b0001", "BUSINESS_MASK: u64 = 0b1110",
    ):
        require(re.search(rf"^pub const {re.escape(declaration)};$", topology, re.M),
                f"topology changed: {declaration}")
    roles = (control / "role_manifest_v0199.rs").read_text()
    roster = re.search(r"pub const ROLES: \[Role; ROLE_COUNT\] = \[\n(.*?)\n\];", roles, re.S)
    require(roster is not None and "pub const ROLE_COUNT: usize = 8;" in roles
            and len(re.findall(r"(?m)^    Role::\w+,$", roster[1])) == 8,
            "the eight-role control roster changed")
    for role, role_id, right in (("Operations", 6, "SEND_ADVICE"), ("Security", 7, "SEND_FINDING")):
        require(roster[1].count(f"Role::{role},") == 1, f"missing or duplicate {role} role")
        require(f"Self::{role} => {role_id}," in roles, f"wrong {role} role id")
        require(f"Self::{role} => SNAPSHOT | {right}," in roles, f"wrong {role} authority")
    security = root / "crates/kernel-core/src/security"
    require("pub const ABI_VERSION: u16 = 3;" in (security / "syscall_v3.rs").read_text(),
            "wrong native syscall ABI")
    syscall_table = section(baseline, "\n01 task_exit", "\n50 service_call").decode()
    expected = {int(n, 16) for n in re.findall(r"(?m)^([0-9a-f]{2})[ \t]+", syscall_table)} | {0x50}
    decode = section((security / "syscall.rs").read_bytes(),
                     "Ok(match no {", "_ => return Err(Error::Invalid)").decode()
    abi_numbers = [int(n, 16) for n in re.findall(r"(?m)^\s*0x([0-9a-f]+) =>", decode)]
    require(len(abi_numbers) == len(expected) == 19 and set(abi_numbers) == expected,
            "ABI3 call numbers differ from the 19 in the baseline")
    return [f"0x{number:02x}" for number in sorted(abi_numbers)]


def verify_scope(root):
    g4, g5, names, _ = inventory()
    overlay = strict_json((root / SCOPE_MAP).read_bytes())
    require(overlay["schema"] == "cyxia-v020-sim-scope/v1" and overlay["profile"] == "V0.20-SIM",
            "wrong SIM overlay profile")
    source = overlay["source_inventory"]
    raw = (root / INVENTORY).read_bytes()
    blob = sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    require(source["path"] == INVENTORY and source["blob"] == blob,
            "SIM overlay inventory source changed")
    cases = overlay["cases"]
    require(len(cases) == len(names) and {case["test_id"]: case["id"] for case in cases} == names,
            "SIM overlay changed stable case identities")
    required = [(case["test_id"], p["proof_class"]) for case in cases for p in case["g4_required"]]
    physical = [(case["test_id"], p) for case in cases for p in case["g5_additional"]]
    require(len(required) == len(g4) and set(required) == {(test, NAMES[kind]) for test, kind in g4},
            "SIM overlay changed G4 proof assignments")
    require(all(p["scope"] == ("SIMULATOR" if p["proof_class"] == "RUNTIME_QEMU"
                             else "SUPPLEMENTARY_REQUIRED")
                for case in cases for p in case["g4_required"]), "SIM overlay changed a proof scope")
    require(len(physical) == 26 and {(test, p["proof_class"]) for test, p in physical}
            == {(test, NAMES[kind]) for test, kind in g5 - g4}, "SIM overlay changed G5 obligations")
    require(all(p["status"] == "DEFERRED_PHYSICAL_NON_BLOCKING"
                and p["evidence_scope"] == "SIMULATOR" and p["simulator_software_obligation"]
                for _, p in physical), "SIM obligation lost its software evidence requirement")
    snapshots = overlay["snapshot_assertion_groups"]
    require(len(snapshots) == len({group["name"] for group in snapshots}) == 7
            and all(group["scope"] == "SIMULATOR" for group in snapshots),
            "SIM overlay changed the seven snapshot assertion groups")
    return {
        "stable_test_ids": len(names),
        "g4_proofs": dict(sorted(Counter(NAMES[kind] for _, kind in g4).items())),
        "g5_physical_proofs": len(physical),
        "separate_simulator_software_obligations": len(physical),
        "snapshot_assertion_groups": len(snapshots),
    }


def verify(root=ROOT):
    lock = strict_json((root / LOCK).read_bytes())
    require(lock["schema"] == "cyxia-v020-g0-baseline-lock/v1", "wrong G0 lock schema")
    source_commit = lock["source_commit"]
    require(isinstance(source_commit, str) and re.fullmatch(r"[0-9a-f]{40}", source_commit),
            "invalid G0 source commit")
    sources = source_hashes(root)
    require(lock["sources"] == sources, "normative source digest mismatch")
    sha = freeze_digest(sources)
    require(lock["baseline_sha256"] == sha and lock["security_tracks"] == dict.fromkeys(TRACKS, sha),
            "the six security tracks do not reference the same baseline")
    baseline = (root / BASELINE).read_bytes()
    keys = registry_owners(baseline)
    return {
        "gate": "G0",
        "status": "PASS",
        "source_commit": source_commit,
        "baseline_sha256": sha,
        "control_cpu": 0,
        "business_cpus": [1, 2, 3],
        "security_tracks": list(TRACKS),
        "registered_parameters": len(keys),
        "parameter_owners": len(set(keys.values())),
        "abi3_syscalls": verify_topology_and_abi(root, baseline),
        **verify_scope(root),
    }


def main():
    try:
        print(json.dumps(verify(), indent=2))
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"G0 baseline check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
