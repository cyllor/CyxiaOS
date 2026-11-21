#!/usr/bin/env python3
"""Build genuine workspace/tiling applets with the locked complete GUI graph."""
import argparse
import json
from pathlib import Path

import build_cosmic_time_applet_v2 as driver
import cosmic_workspace_applets_v1 as contract
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache-from', type=Path)
    parser.add_argument('--sysroot', type=Path, default=contract.base.ROOT / 'artifacts/sysroot/x86_64-musl')
    parser.add_argument('--cargo-cache', type=Path, default=contract.base.ROOT / 'artifacts/cosmic-comp-cache')
    args = parser.parse_args()
    root = contract.base.ROOT
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        report = driver.build(args.output, args.sysroot, root / 'artifacts/cosmic-sources',
            root / 'artifacts/cosmic-native-sources', args.cargo_cache,
            Path('/Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin'), Path('/usr/bin/clang'),
            args.cache_from, contract_module=contract, programs=contract.PROGRAMS, producer_entry=__file__)
    print(json.dumps({k: report[k] for k in ('status', 'elapsed_seconds', 'binaries')}, indent=2))


if __name__ == '__main__':
    main()
