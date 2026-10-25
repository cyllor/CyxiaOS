#!/usr/bin/env python3
"""Report the separate 1.3 catalogue without promoting legacy/host evidence.

No complete 1.3 native case verifier is registered yet. PASS/FAIL receipts are
therefore rejected, not accepted merely because a JSON file says a VM ran.
Component and bring-up results remain outside this full-case catalogue.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

from check_prototype_evidence import artifact, exact_keys, read_json, require, safe_path, sha256

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'docs/implementation/v13-requirements.json'
SPEC_SHA256 = '01f8c315018d8117c0b43671add6527fe76d0b83caabe865b5d714a99fa135a0'
# Rust revision changes §1.2 and build inventory; normalized remaining requirements unchanged.
# Independently compared with all 51 scenario/outcome rows in the pinned DOCX.
DEFINITIONS_SHA256 = '7a10fb882654b9ad89a9b4735e038cd16259d1b2401c74e5abccba628b14151e'
CASE_IDS = frozenset([f'A{i:02}' for i in range(1, 17)]
                     + [f'T{i:02}' for i in range(1, 21)]
                     + [f'E{i:02}' for i in range(1, 16)])
FAMILIES = frozenset(['D01_WEIGHT', 'D01_CORESET'] + [f'D{i:02}' for i in range(2, 16)]
                     + ['D16_QUOTE', 'D16_PLACE'])
STATUSES = frozenset({'PASS', 'FAIL', 'NOT_RUN'})


def check_rows(rows, expected, label, root, *, descriptions):
    require(type(rows) is list and len(rows) == len(expected), f'Incomplete {label}')
    ids = [r.get('id') if type(r) is dict else None for r in rows]
    require(all(type(i) is str for i in ids) and len(set(ids)) == len(ids)
            and set(ids) == expected, f'Invalid {label}')
    counts = {status: 0 for status in ('PASS', 'FAIL', 'NOT_RUN')}
    keys = {'id', 'status', 'evidence'}
    if descriptions:
        keys |= {'scenario', 'required_outcome'}
    for row in rows:
        exact_keys(row, keys)
        require(type(row['status']) is str and row['status'] in STATUSES, 'Invalid test status')
        if descriptions:
            for field in ('scenario', 'required_outcome'):
                require(type(row[field]) is str and bool(row[field].strip()), 'Missing case meaning')
        if row['status'] == 'NOT_RUN':
            require(row['evidence'] is None, 'NOT_RUN cannot carry a runtime receipt')
        else:
            require(type(row['evidence']) is dict, 'Native result requires a receipt')
            # A digest can bind bytes, but cannot prove that the complete case
            # happened. Add an independently reviewed per-case raw-event
            # verifier before admitting results here. Never use eval/subprocess
            # on a manifest-supplied checker or a trusted boolean in its JSON.
            artifact(root, row['evidence'])
            raise ValueError(f"No complete 1.3 native receipt verifier registered for {row['id']}")
        counts[row['status']] += 1
    return counts


def validate(document, root=ROOT):
    root = Path(root).resolve()
    exact_keys(document, {'schema_version', 'spec', 'deviations', 'cases',
                          'action_families', 'filesystem_fault_matrix'})
    require(type(document['schema_version']) is int and document['schema_version'] == 1,
            'Unsupported catalogue schema')
    spec = document['spec']
    exact_keys(spec, {'path', 'version', 'sha256'})
    require(spec['version'] == '1.3' and spec['sha256'] == SPEC_SHA256,
            'Wrong specification identity')
    require(sha256(safe_path(root, spec['path'])) == SPEC_SHA256,
            'Changed specification bytes')
    deviations = document['deviations']
    require(type(deviations) is list and len(deviations) == 1, 'Missing/changed approved Rust deviation')
    d = deviations[0]
    exact_keys(d, {'id', 'clause', 'authorized', 'decision'})
    require(d['id'] == 'LANG-RUST' and d['clause'] == '1.2' and d['authorized'] is True
            and type(d['decision']) is str and bool(d['decision'].strip()), 'Invalid Rust deviation')
    cases = check_rows(document['cases'], CASE_IDS, 'case set', root, descriptions=True)
    definitions = [{key: row[key] for key in ('id', 'scenario', 'required_outcome')}
                   for row in document['cases']]
    encoded = json.dumps(sorted(definitions, key=lambda row: row['id']), ensure_ascii=False,
                         sort_keys=True, separators=(',', ':')).encode('utf-8')
    require(hashlib.sha256(encoded).hexdigest() == DEFINITIONS_SHA256,
            'Changed 1.3 case definitions')
    actions = check_rows(document['action_families'], FAMILIES, 'action family set', root,
                         descriptions=False)
    fs = document['filesystem_fault_matrix']
    exact_keys(fs, {'frozen', 'evidence', 'reason'})
    require(type(fs['frozen']) is bool and type(fs['reason']) is str and bool(fs['reason'].strip()),
            'Invalid filesystem matrix status')
    require(fs['frozen'] is False and fs['evidence'] is None,
            'No reviewed native filesystem fault matrix verifier is registered')
    return {'schema_version': 1, 'spec_version': '1.3', 'catalogue_valid': True,
            'mandatory_cases': len(CASE_IDS), 'action_families': len(FAMILIES),
            'states': {s: cases[s] + actions[s] for s in cases},
            'filesystem_fault_matrix_complete': False,
            'functional_acceptance_complete': False, 'strict_spec_conformance': False,
            'approved_deviations': deviations, 'runtime_truth_attested': False,
            'scope': 'Catalogue integrity only; native full-case verifiers and filesystem fault matrix remain required.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--release', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = validate(read_json(args.manifest), args.root)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if args.release and not result['functional_acceptance_complete'] else 0
    except (OSError, ValueError, TypeError) as error:
        print(f'v13-evidence: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
