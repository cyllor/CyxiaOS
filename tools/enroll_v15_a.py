#!/usr/bin/env python3
"""Enrol one independently verified A receipt in a new run catalogue.

The checked-in specification catalogue is never modified. All existing rows
are revalidated against the explicit source, so old-source PASS cannot survive
a source change merely because another case has just passed.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

from check_prototype_evidence import read_json, require, sha256
from check_v13_evidence import DEFAULT, ROOT, validate

SUPPORTED = ('A01', 'A02', 'A03', 'A09', 'A10', 'A12')


def enroll(document, case, receipt, source_root=None, **context):
    require(case in SUPPORTED, 'no fixed native adapter registered for requested A case')
    explicit_source = source_root is not None
    source_root = Path(ROOT if source_root is None else source_root).resolve(strict=True)
    receipt = Path(receipt).resolve(strict=True)
    require(receipt.name == 'summary.json', 'native receipt must name summary.json')
    try:
        relative = receipt.relative_to(source_root)
    except ValueError as error:
        raise ValueError('receipt must be inside the explicit source root') from error
    result = copy.deepcopy(document)
    rows = [row for row in result.get('cases', []) if row.get('id') == case]
    require(len(rows) == 1, 'requested case must occur exactly once')
    rows[0].update(status='PASS', evidence={'path': relative.as_posix(), 'sha256': sha256(receipt)})
    # Fixed local adapters, including all other retained PASS rows, own verdicts.
    report = validate(result, source_root if explicit_source else None, **context)
    return result, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT)
    parser.add_argument('--case', choices=SUPPORTED, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--source-root', type=Path,
                        help='trusted source root; explicit for A12, otherwise defaults to this checkout')
    parser.add_argument('--qemu-source', type=Path, required=True)
    parser.add_argument('--a09-build', type=Path,
                        help='explicit trusted A09 build directory')
    parser.add_argument('--a10-build-manifest', type=Path)
    parser.add_argument('--a10-formatter', type=Path)
    parser.add_argument('--a12-build-manifest', type=Path)
    parser.add_argument('--a12-formatter', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        context = {'qemu_source': args.qemu_source}
        for name in ('a09_build', 'a10_build_manifest', 'a10_formatter',
                     'a12_build_manifest', 'a12_formatter'):
            if getattr(args, name) is not None:
                context[name] = getattr(args, name)
        document, report = enroll(read_json(args.manifest), args.case, args.receipt,
                                  args.source_root, **context)
        require(args.output.resolve() != DEFAULT.resolve(), 'refuse to replace the specification catalogue')
        with args.output.open('x') as destination:
            json.dump(document, destination, ensure_ascii=False, indent=2)
            destination.write('\n')
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print('enroll-v15-a: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
