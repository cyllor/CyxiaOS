#!/usr/bin/env python3
"""Independently consume the retained full compositor pair on canonical paths.

Resolve the host temporary directory before the frozen producer's read-only
validator runs: macOS commonly exposes it through the /var symlink.
"""
import argparse
import json
from pathlib import Path
import tempfile

import cosmic_native_tiles_v1 as tiles
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve(strict=True))
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result = tiles.assemble(args)
        result['consumer_producers'] = tiles.os_x86.producer_sources(__file__)
        result['canonical_temporary_directory'] = tempfile.tempdir
        (args.output / 'cosmic-native-tiles-origin.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], output=str(args.output)), indent=2))


if __name__ == '__main__':
    main()
