#!/usr/bin/env python3
"""Build the pinned Smithay two-client composition and focus integration."""
import argparse
import json
from pathlib import Path

from build_smithay_wayland import BuildProfile, MODULES, build
from build_sysroot import ROOT

PROFILE = BuildProfile(
    manifest=ROOT / "ports/cosmic/smithay-multi-source.json",
    source=ROOT / "ports/cosmic/smithay-multi/main.rs",
    binary_stem="smithay-multi",
    entrypoint=Path(__file__).resolve(),
    lto="fat",
    modules=(*MODULES, ROOT / "ports/cosmic/smithay-multi/scene.rs"),
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--mesa-report", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.output.resolve(), args.cache.resolve(),
                           args.mesa_report.resolve(), args.fetch, profile=PROFILE), indent=2))
