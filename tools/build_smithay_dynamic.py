#!/usr/bin/env python3
"""Build pinned Smithay named client admission and disconnect cleanup on native display."""
import argparse
import json
from dataclasses import replace
from pathlib import Path

from build_smithay_wayland import BuildProfile, MODULES, build
from build_sysroot import ROOT

PROFILE = BuildProfile(
    manifest=ROOT / "ports/cosmic/smithay-dynamic-source.json",
    source=ROOT / "ports/cosmic/smithay-dynamic/main.rs",
    binary_stem="smithay-dynamic",
    entrypoint=Path(__file__).resolve(),
    lto="fat",
    modules=(*MODULES, ROOT / "ports/cosmic/smithay-multi/scene.rs",
             ROOT / "ports/cosmic/smithay-dynamic/clients.rs"),
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--arch", choices=("aarch64", "x86_64"), default="aarch64")
    parser.add_argument("--sysroot", type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--mesa-report", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument('--size-profile', choices=('existing', 'compact'), default='existing',
                        help='Explicit compact build uses Rust z and safe identical-code folding')
    args = parser.parse_args()
    profile = replace(PROFILE, opt_level='z', icf='safe') if args.size_profile == 'compact' else PROFILE
    print(json.dumps(build(args.output.resolve(), args.cache.resolve(),
                           args.mesa_report.resolve(), args.fetch, profile=profile, architecture=args.arch, sysroot=args.sysroot), indent=2))
