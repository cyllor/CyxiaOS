#!/usr/bin/env python3
"""Report the separate 1.3 catalogue without promoting legacy/host evidence.

A01/A02/A03 have fixed native receipt adapters validating protected raw events,
execution provenance and the caller's source root. A01 additionally requires
actual architecture/authority observations and same-disk boot continuity;
producer PASS booleans and host fixtures cannot establish a result.
A09 requires full stopped-memory/native custody replay with an explicit trusted
build directory and QEMU source; raw page structure alone cannot establish PASS.
A10 additionally has fixed offline matrix reconstruction and native custody
replay requiring explicit caller-selected build, formatter and QEMU inputs.
A12 verifies native boot/discovery/authentication/configuration and legal Local
admission with explicit source, build, formatter and QEMU inputs; A13/A14 remain
separate obligations.
Other cases, native FAIL classification
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
from verify_v15_a01 import (VERSION as A01_NATIVE_VERSION,
                            verify_acceptance as verify_a01_native_receipt)
from verify_v15_ownership import verify_native as verify_a03_native_receipt
from memory_v15_custody import verify_native as verify_a09_native_receipt
from verify_v13_a10_receipt import (VERSION as A10_OFFLINE_VERSION,
                                   verify_matrix_receipt as verify_a10_matrix_receipt)
from verify_v13_a10_native_receipt import (
    VERSION as A10_NATIVE_VERSION,
    verify_native_matrix_receipt as verify_a10_native_matrix_receipt,
)
from verify_v16_a12 import (VERSION as A12_NATIVE_VERSION,
                            verify_native as verify_a12_native_receipt)

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


def check_rows(rows, expected, label, root, *, descriptions, qemu_source=None,
               a09_build=None, a10_build_manifest=None, a10_formatter=None,
               a12_build_manifest=None, a12_formatter=None):
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
            if row['id'] == 'A01' and descriptions:
                require(row['status'] == 'PASS', 'A01 native FAIL classification is not registered')
                require(receipt.name == 'summary.json', 'A01 receipt must name summary.json')
                require(qemu_source is not None, 'A01 requires explicit trusted QEMU source')
                observed = verify_a01_native_receipt(receipt.parent, source_root=root,
                                                     qemu_source=qemu_source)
                require(observed.get('test_id') == 'A01'
                        and observed.get('native_acceptance_status') == 'PASS'
                        and observed.get('native_execution_verified') is True
                        and observed.get('runtime_truth_attested') is False
                        and observed.get('reboot_chain_verified') is True,
                        'A01 native receipt does not establish complete A01')
                counts[row['status']] += 1
                continue
            if row['id'] == 'A03' and descriptions:
                require(row['status'] == 'PASS', 'A03 native FAIL classification is not registered')
                require(receipt.name == 'summary.json', 'A03 receipt must name summary.json')
                require(qemu_source is not None, 'A03 requires explicit trusted QEMU source')
                observed = verify_a03_native_receipt(receipt.parent, source_root=root,
                                                     qemu_source=qemu_source)
                model = observed.get('model_replay')
                require(observed.get('test_id') == 'A03'
                        and observed.get('native_acceptance_status') == 'PASS'
                        and observed.get('native_execution_verified') is True
                        and observed.get('runtime_truth_attested') is False
                        and observed.get('control_sets') == [2, 6, 2]
                        and type(model) is list and len(model) == 2
                        and all(type(item) is dict
                                and item.get('status') == 'MODEL_REPLAY_VALID'
                                and item.get('full_integer_mlp') is True for item in model),
                        'A03 native receipt does not establish complete A03')
                counts[row['status']] += 1
                continue
            if row['id'] == 'A09' and descriptions:
                require(row['status'] == 'PASS', 'A09 native FAIL classification is not registered')
                require(receipt.name == 'summary.json', 'A09 receipt must name summary.json')
                require(a09_build is not None and qemu_source is not None,
                        'A09 requires explicit trusted build directory and QEMU source')
                # Only the caller supplies the trusted build/source context.
                # Raw page checks and an archived producer verdict grant nothing.
                observed = verify_a09_native_receipt(receipt.parent, build=a09_build,
                    source_root=root, qemu_source=qemu_source)
                require(type(observed) is dict
                        and observed.get('status') == 'PASS'
                        and observed.get('test_id') == 'A09'
                        and observed.get('native_acceptance_status') == 'PASS'
                        and observed.get('native_execution_verified') is True
                        and observed.get('full_a09_verified') is True
                        and observed.get('actual_cache_pressure_verified') is True
                        and observed.get('runtime_truth_attested') is False,
                        'A09 native receipt does not establish complete A09')
                counts[row['status']] += 1
                continue
            if row['id'] == 'A10' and descriptions:
                require(row['status'] == 'PASS', 'A10 native FAIL classification is not registered')
                require(receipt.name == 'summary.json', 'A10 receipt must name summary.json')
                verify_a10_matrix_receipt(receipt.parent, source_root=root)
                # The receipt cannot choose a build, source, executable or
                # verifier. Raw replay alone never opens native admission.
                require(all(value is not None for value in
                            (qemu_source, a10_build_manifest, a10_formatter)),
                        'A10 native receipt admission remains closed without explicit '
                        'caller-selected A10 build, formatter and QEMU inputs')
                observed = verify_a10_native_matrix_receipt(receipt.parent, source_root=root,
                    build_manifest=a10_build_manifest,
                    qemu_binary=Path(qemu_source) / 'build/qemu-system-aarch64',
                    qemu_source=qemu_source, formatter_binary=a10_formatter)
                require(observed.get('test_id') == 'A10'
                        and observed.get('native_acceptance_status') == 'PASS'
                        and observed.get('native_execution_verified') is True
                        and observed.get('raw_matrix_verified') is True
                        and observed.get('native_filesystem_fault_matrix_complete') is True,
                        'A10 native receipt does not establish the complete A10 matrix')
                counts[row['status']] += 1
                continue
            if row['id'] == 'A12' and descriptions:
                require(row['status'] == 'PASS', 'A12 native FAIL classification is not registered')
                require(receipt.name == 'summary.json', 'A12 receipt must name summary.json')
                require(all(value is not None for value in
                            (qemu_source, a12_build_manifest, a12_formatter)),
                        'A12 requires explicit trusted source, build, formatter and QEMU inputs')
                observed = verify_a12_native_receipt(receipt.parent, source_root=root,
                    build_manifest=a12_build_manifest, formatter=a12_formatter,
                    qemu_source=qemu_source)
                require(type(observed) is dict
                        and observed.get('test_id') == 'A12'
                        and observed.get('native_acceptance_status') == 'PASS'
                        and observed.get('full_a12_verified') is True
                        and observed.get('native_execution_verified') is True
                        and observed.get('runtime_truth_attested') is False,
                        'A12 native receipt does not establish complete A12')
                counts[row['status']] += 1
                continue
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


def validate(document, root=None, *, qemu_source=None, a09_build=None, a10_build_manifest=None,
             a10_formatter=None, a12_build_manifest=None, a12_formatter=None):
    explicit_source = root is not None
    root = Path(ROOT if root is None else root).resolve()
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
    if not explicit_source and type(document['cases']) is list:
        require(not any(type(row) is dict and row.get('id') == 'A12'
                        and row.get('status') == 'PASS' for row in document['cases']),
                'A12 requires an explicit trusted source root')
    cases = check_rows(document['cases'], CASE_IDS, 'case set', root, descriptions=True,
                       qemu_source=qemu_source, a09_build=a09_build,
                       a10_build_manifest=a10_build_manifest,
                       a10_formatter=a10_formatter, a12_build_manifest=a12_build_manifest,
                       a12_formatter=a12_formatter)
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
    a09_context = a09_build is not None and qemu_source is not None
    a10_context = all(value is not None for value in
                      (qemu_source, a10_build_manifest, a10_formatter))
    a12_context = explicit_source and all(value is not None for value in
                      (qemu_source, a12_build_manifest, a12_formatter))
    native_receipt_cases = ['A01', 'A02', 'A03']
    if a09_context:
        native_receipt_cases.append('A09')
    if a10_context:
        native_receipt_cases.append('A10')
    if a12_context:
        native_receipt_cases.append('A12')
    return {'schema_version': 1, 'spec_version': '1.3', 'catalogue_valid': True,
            'mandatory_cases': len(CASE_IDS), 'action_families': len(FAMILIES),
            'states': {s: cases[s] + actions[s] for s in cases},
            'case_states': cases, 'action_states': actions, 'case_groups': groups,
            'a_acceptance_complete': groups['A']['PASS'] == 16,
            'filesystem_fault_matrix_complete': False,
            'functional_acceptance_complete': False, 'strict_spec_conformance': False,
            'approved_deviations': deviations, 'runtime_truth_attested': False,
            'verifier_coverage': {
                'native_receipt_cases': native_receipt_cases,
                'raw_contracts': {
                    'A01': {'verifier': 'tools/verify_v15_a01.py',
                            'native_receipt_admitted': True,
                            'native_verifier_version': A01_NATIVE_VERSION,
                            'requires_explicit_qemu_source': True},
                    'A02': {'verifier': 'tools/verify_v13_a02.py', 'wire_version': 2,
                            'native_receipt_admitted': True,
                            'native_verifier_version': 'a02-native-v4'},
                    'A03': {'verifier': 'tools/verify_v15_ownership.py',
                            'native_receipt_admitted': True,
                            'native_verifier_version': 'v15-model-owner-v1',
                            'requires_explicit_qemu_source': True},
                    'A09': {'verifier': 'tools/memory_v15_custody.py',
                            'native_receipt_admitted': a09_context,
                            'native_verifier_version': 'v15-a09-memory-v1',
                            'requires_explicit_build': True,
                            'requires_explicit_qemu_source': True},
                    'A10': {'verifier': 'tools/verify_v13_a10_receipt.py',
                            'native_receipt_admitted': a10_context,
                            'offline_verifier_version': A10_OFFLINE_VERSION,
                            'native_verifier_version': A10_NATIVE_VERSION,
                            'native_admission_blockers': [] if a10_context else [
                                'explicit caller-selected A10 build, formatter and QEMU inputs required']},
                    'A12': {'verifier': 'tools/verify_v16_a12.py',
                            'native_receipt_admitted': a12_context,
                            'native_verifier_version': A12_NATIVE_VERSION,
                            'requires_explicit_source_root': True,
                            'requires_explicit_build_manifest': True,
                            'requires_explicit_formatter': True,
                            'requires_explicit_qemu_source': True}}},
            'scope': 'Catalogue integrity, A01/A02/A03 native verification, explicit-context A09 native memory custody, A10 native matrix replay and A12 native boot/discovery/auth/config/Local admission; other native cases and filesystem acceptance remain required.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT)
    parser.add_argument('--root', type=Path,
                        help='trusted source root; explicit for A12, otherwise defaults to this checkout')
    parser.add_argument('--qemu-source', type=Path,
                        help='explicit trusted patched-QEMU checkout for native receipt replay')
    parser.add_argument('--a09-build', type=Path,
                        help='explicit trusted A09 build directory for complete native memory replay')
    parser.add_argument('--a10-build-manifest', type=Path,
                        help='explicit trusted build record for complete A10 native replay')
    parser.add_argument('--a10-formatter', type=Path,
                        help='explicit trusted formatter binary for A10 native replay')
    parser.add_argument('--a12-build-manifest', type=Path,
                        help='explicit trusted build record for A12 native replay')
    parser.add_argument('--a12-formatter', type=Path,
                        help='explicit trusted formatter binary for A12 native replay')
    parser.add_argument('--release', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = validate(read_json(args.manifest), args.root, qemu_source=args.qemu_source,
                          a09_build=args.a09_build,
                          a10_build_manifest=args.a10_build_manifest,
                          a10_formatter=args.a10_formatter,
                          a12_build_manifest=args.a12_build_manifest,
                          a12_formatter=args.a12_formatter)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if args.release and not result['functional_acceptance_complete'] else 0
    except (OSError, ValueError, TypeError) as error:
        print(f'v13-evidence: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
