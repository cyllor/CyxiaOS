#!/usr/bin/env python3
"""Create a run-specific A02 catalogue only after fixed native receipt replay.

The input catalogue is never edited. Exit zero means enrolment succeeded, not
that all A/T/E cases passed. Receipts must remain under the explicit source root;
archive metadata cannot select the source checkout or an executable verifier.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from check_prototype_evidence import read_json, require, safe_path, sha256
from check_v13_evidence import DEFAULT, ROOT, validate


def enroll(manifest: Path, receipt: Path, output: Path, *, source_root: Path,
           qemu_source: Path | None = None) -> dict:
    root = Path(source_root).resolve(strict=True)
    # Keep the lexical path until safe_path checks every ancestor for symlinks.
    receipt = Path(receipt).absolute()
    relative = receipt.relative_to(root).as_posix()
    receipt = safe_path(root, relative)
    require(receipt.name == 'summary.json', 'A02 receipt must name summary.json')
    document = read_json(manifest)
    validate(document, root, qemu_source=qemu_source)
    row = next(row for row in document['cases'] if row['id'] == 'A02')
    require(row['status'] == 'NOT_RUN', 'refuse to replace an existing A02 result')
    row.update(status='PASS', evidence={'path': relative, 'sha256': sha256(receipt)})
    # This invokes the fixed A02 native adapter, checks source/image/QEMU and
    # raw capture provenance, and revalidates every other catalogue row.
    report = validate(document, root, qemu_source=qemu_source)
    with Path(output).open('x', encoding='utf-8') as destination:
        destination.write(json.dumps(document, ensure_ascii=False, indent=2) + '\n')
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--qemu-source', type=Path)
    args = parser.parse_args(argv)
    try:
        report = enroll(args.manifest, args.receipt, args.output,
                        source_root=args.source_root, qemu_source=args.qemu_source)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(f'a02-enrolment: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
