#!/usr/bin/env python3
"""Report the separate 1.3 catalogue without promoting legacy/host evidence.

A02 has a fixed native receipt adapter following a real native run and separate
receipt replay. It validates raw events, execution provenance and the caller's
source root; producer PASS booleans and host fixtures cannot establish a result.
A10 additionally has fixed offline matrix reconstruction, but its native
launch/capture admission remains closed. Other cases, native FAIL classification
and filesystem catalogue completion remain unenrolled. Coverage registration
does not change unrun catalogue entries.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

from check_prototype_evidence import artifact, exact_keys, read_json, require, safe_path, sha256
from verify_v13_a02 import verify_native_receipt
from verify_v13_a10_receipt import (NATIVE_ADMISSION_BLOCKERS as A10_BLOCKERS,
                                   VERSION as A10_OFFLINE_VERSION,
                                   verify_matrix_receipt as verify_a10_matrix_receipt)

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


def check_rows(rows, expected, label, root, *, descriptions, qemu_source=None):
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
            receipt = artifact(root, row['evidence'])
            if row['id'] == 'A10' and descriptions:
                require(row['status'] == 'PASS', 'A10 native FAIL classification is not registered')
                require(receipt.name == 'summary.json', 'A10 receipt must name summary.json')
                verify_a10_matrix_receipt(receipt.parent, source_root=root)
                # Rebuilding file/durability bytes cannot replace independent
                # native process, launch, injection and capture provenance.
                raise ValueError('A10 native receipt admission remains closed: ' + '; '.join(A10_BLOCKERS))
            if row['id'] != 'A02' or not descriptions:
                raise ValueError(f"No complete 1.3 native receipt verifier registered for {row['id']}")
            require(row['status'] == 'PASS', 'A02 native FAIL classification is not registered')
            require(receipt.name == 'summary.json', 'A02 receipt must name summary.json')
            # Fixed reviewed code only. Neither the manifest nor the receipt
            # can select a checker, source checkout or executable archive.
            options = {'source_root': root}
            if qemu_source is not None:
                options['qemu_source'] = qemu_source
            observed = verify_native_receipt(receipt.parent, **options)
            require(observed.get('test_id') == 'A02'
                    and observed.get('native_acceptance_status') == row['status']
                    and observed.get('native_execution_verified') is True
                    and observed.get('runtime_truth_attested') is False,
                    'A02 receipt does not establish the declared native result')
        counts[row['status']] += 1
    return counts


def validate(document, root=ROOT, *, qemu_source=None):
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
    cases = check_rows(document['cases'], CASE_IDS, 'case set', root, descriptions=True,
                       qemu_source=qemu_source)
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
    # Only count after every row, definition and receipt has passed validation.
    # The legacy states field includes 18 action families; it is not an A/T/E
    # denominator. A-only completion never changes global release acceptance.
    groups = {group: {status: 0 for status in ('PASS', 'FAIL', 'NOT_RUN')}
              for group in ('A', 'T', 'E')}
    for row in document['cases']:
        groups[row['id'][0]][row['status']] += 1
    return {'schema_version': 1, 'spec_version': '1.3', 'catalogue_valid': True,
            'mandatory_cases': len(CASE_IDS), 'action_families': len(FAMILIES),
            'states': {s: cases[s] + actions[s] for s in cases},
            'case_states': cases, 'action_states': actions, 'case_groups': groups,
            'a_acceptance_complete': groups['A']['PASS'] == 16,
            'filesystem_fault_matrix_complete': False,
            'functional_acceptance_complete': False, 'strict_spec_conformance': False,
            'approved_deviations': deviations, 'runtime_truth_attested': False,
            'verifier_coverage': {
                'native_receipt_cases': ['A02'],
                'raw_contracts': {
                    'A02': {'verifier': 'tools/verify_v13_a02.py', 'wire_version': 2,
                            'native_receipt_admitted': True,
                            'native_verifier_version': 'a02-native-v4'},
                    'A10': {'verifier': 'tools/verify_v13_a10_receipt.py',
                            'native_receipt_admitted': False,
                            'offline_verifier_version': A10_OFFLINE_VERSION,
                            'native_admission_blockers': list(A10_BLOCKERS)}}},
            'scope': 'Catalogue integrity, fixed A02 native verification and A10 offline reconstruction; other native cases and filesystem acceptance remain required.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--qemu-source', type=Path,
                        help='explicit trusted patched-QEMU checkout for A02 replay')
    parser.add_argument('--release', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = validate(read_json(args.manifest), args.root, qemu_source=args.qemu_source)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if args.release and not result['functional_acceptance_complete'] else 0
    except (OSError, ValueError, TypeError) as error:
        print(f'v13-evidence: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
