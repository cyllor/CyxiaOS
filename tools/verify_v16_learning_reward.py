#!/usr/bin/env python3
"""Verify one original R7 D01 numeric/canonical pair without importing a label."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from v16_learning_reward import verify_reward_capture
from verify_v13_boot_recovery import require


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('capture', 'original-inventory', 'kernel-source-root', 'build-manifest',
                 'formatter', 'qemu', 'qemu-source', 'frozen-producer-root', 'exports-directory', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--original-inventory-sha256', required=True,
                        help='Caller-trusted SHA256 of the immutable original capture inventory')
    args = parser.parse_args(argv)
    output = args.output.resolve(strict=False)
    capture = args.capture.resolve(strict=True)
    exports = args.exports_directory.resolve(strict=True)
    require(not args.output.is_symlink() and not output.exists()
            and output != capture and capture not in output.parents
            and output != exports and exports not in output.parents,
            'report must be a new file outside original capture/derived exports')
    result = verify_reward_capture(args.capture, original_inventory=args.original_inventory,
        original_inventory_sha256=args.original_inventory_sha256, source_root=args.kernel_source_root,
        build_manifest=args.build_manifest, formatter=args.formatter, qemu_binary=args.qemu,
        qemu_source=args.qemu_source, producer_tools_root=args.frozen_producer_root,
        exports_directory=args.exports_directory)
    result['numeric_checker_identity'] = {
        name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
        for name in ('v16_learning_reward.py', 'verify_v16_learning_reward.py')}
    with output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    print(json.dumps(dict(report=str(output), pairs=len(result['pairs']),
                         reward_numeric_verified=result['reward_numeric_verified'],
                         trial_canonical_matches_native=result['trial_canonical_matches_native'],
                         protected_sample_export_verified=False), sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
