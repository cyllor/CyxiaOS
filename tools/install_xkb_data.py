#!/usr/bin/env python3
"""Stage pinned COSMIC evdev/pc105/us assets offline into a new output directory."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

if __package__:
    from . import build_sysroot, desktop_ports
else:
    import build_sysroot
    import desktop_ports

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ports/xkb/manifest.json"
BuildError = build_sysroot.BuildError
digest = build_sysroot.digest
XKB_ROOT = "/usr/share/X11/xkb"
RULE_TARGET = XKB_ROOT + "/rules/evdev"
INCLUDES = (
    "keycodes/evdev", "keycodes/aliases",
    "types/complete", "types/basic", "types/pc", "types/iso9995", "types/extra",
    "types/level5", "types/numpad", "types/mousekeys",
    "compat/complete", "compat/basic", "compat/iso9995", "compat/mousekeys",
    "compat/accessx", "compat/misc", "compat/xfree86", "compat/level5", "compat/caps",
    "compat/ledcaps", "compat/lednum", "compat/ledscroll",
    "symbols/pc", "symbols/us", "symbols/inet", "symbols/srvr_ctrl", "symbols/keypad",
    "geometry/pc",
)
ASSETS = tuple((name, XKB_ROOT + "/" + name) for name in INCLUDES) + (
    ("COPYING", "/usr/share/doc/xkeyboard-config/COPYING"),
)
# Exact xkeyboard-config 2.42 rules/meson.build recipe, compat-rules=true.
# The merge script sorts by basename; no file contents are reconstructed here.
RULE_PARTS = (
    "0000-hdr.part", "0001-lists.part", "0002-evdev.lists.part",
    "0004-evdev.model_keycodes.part", "0005-layout1_keycodes.part",
    "0006-layout_keycodes.part", "0007-options_keycodes.part",
    "0008-modellayout_geometry.part", "0009-model_geometry.part",
    "0011-modellayoutvariant_symbols.part", "0013-modellayout_symbols.part",
    "0015-modellayout1_symbols.part", "0018-modellayout2_symbols.part",
    "0020-modellayout3_symbols.part", "0022-modellayout4_symbols.part",
    "0026-evdev.model_symbols.part", "0027-evdev.modellayout_symbols1.part",
    "0033-modellayout_compat.part", "0034-modellayout1_compat.part",
    "0035-model_types.part", "0036-layoutoption_symbols.part",
    "0037-layout1option_symbols.part", "0038-layout2option_symbols.part",
    "0039-layout3option_symbols.part", "0040-layout4option_symbols.part",
    "compat/0028-layoutvariant_compat.part", "compat/0029-layout1variant1_compat.part",
    "compat/0030-layout2variant2_compat.part", "compat/0031-layout3variant3_compat.part",
    "compat/0032-layout4variant4_compat.part", "compat/0041-option_symbols.part",
)
OPTION_PARTS = (
    ("0042-option_symbols.part", "symbols"),
    ("0043-option_compat.part", "compatibility"),
    ("0044-option_types.part", "types"),
)
LAYOUT_PARTS = ("0012-ml_s.part", "0014-ml1_s.part", "0017-ml2_s.part",
                "0019-ml3_s.part", "0021-ml4_s.part")
VARIANT_PARTS = ("0010-mlv_s.part", "0016-ml1v1_s.part", "0023-ml2v2_s.part",
                 "0024-ml3v3_s.part", "0025-ml4v4_s.part")
GENERATORS = ("rules/generate-options-symbols.py", "rules/compat/map-variants.py",
              "rules/merge.py")


def load_package(manifest: Path = MANIFEST) -> dict:
    package = desktop_ports.package_named(desktop_ports.load_manifest(manifest), "xkeyboard-config")
    identity = desktop_ports.identity(package)
    if (identity["kind"] != "sha256-archive" or package["version"] != "2.42"
            or package.get("archive_root") != "xkeyboard-config-2.42"
            or package.get("license_file") != "COPYING"):
        raise BuildError("The asset recipe requires SHA-pinned xkeyboard-config 2.42")
    return package


def regular_source(source: Path, relative: str) -> Path:
    name = PurePosixPath(relative)
    if name.is_absolute() or not name.parts or ".." in name.parts:
        raise BuildError("Source path must remain inside the verified archive")
    path = source
    for part in name.parts:
        path = path / part
        if path.is_symlink():
            raise BuildError("Selected source assets cannot follow symlinks")
    if not path.is_file():
        raise BuildError(f"Missing regular source file: {relative}")
    return path


def file_record(path: Path) -> dict:
    return {"bytes": path.stat().st_size, "sha256": digest(path)}


def copy_asset(source: Path, relative: str, destination: Path, guest_path: str) -> dict:
    original = regular_source(source, relative)
    data = original.read_bytes()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    if destination.read_bytes() != data:
        raise BuildError(f"Asset copy changed bytes: {guest_path}")
    return {"path": guest_path, "source": relative, **file_record(destination)}


def catalog_bounds(paths: list[str]) -> dict:
    directories = set()
    for path in paths:
        name = PurePosixPath(path)
        if (not name.is_absolute() or ".." in name.parts or str(name) != path
                or name == PurePosixPath("/") or len(path.encode("utf-8")) >= 96):
            raise BuildError("Rootfs asset path exceeds catalog contract")
        directories.update(str(parent) for parent in name.parents)
    if len(set(paths)) != len(paths) or len(paths) + 8 > 128 or len(directories) > 64:
        raise BuildError("Rootfs asset count or directory count exceeds catalog contract")
    return {"asset_files": len(paths), "executable_slots_reserved": 8,
            "catalog_file_limit": 128, "directory_nodes": len(directories),
            "directory_node_limit": 64,
            "max_path_bytes": max((len(p.encode("utf-8")) for p in paths), default=0),
            "path_byte_limit_exclusive": 96}


def generate_evdev(source: Path, output: Path) -> dict:
    """Run only the upstream generators, twice, with no ambient Python modules."""
    if sys.version_info < (3, 12):
        raise BuildError("Python 3.12+ is required for safe extraction and upstream generators")
    interpreter = Path(sys.executable).resolve()
    commands = []
    scripts = [{"path": name, **file_record(regular_source(source, name))}
               for name in GENERATORS]
    rules = source / "rules"
    static = [regular_source(source, "rules/" + name) for name in RULE_PARTS]

    def run(script: str, arguments: list[str], target: Path) -> None:
        command = [str(interpreter), "-I", str(regular_source(source, script)), *arguments]
        commands.append({"argv": command, "stdout": str(target)})
        with target.open("xb") as stdout, target.with_suffix(target.suffix + ".log").open("xb") as stderr:
            result = subprocess.run(command, cwd=source, stdout=stdout, stderr=stderr,
                                    env={"PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC"},
                                    timeout=120, check=False)
        if result.returncode or not target.stat().st_size:
            raise BuildError(f"Upstream XKB generator failed: {target}")

    passes = []
    for index in (1, 2):
        generated = output / f"generation-{index}"
        generated.mkdir()
        parts = []
        for filename, section in OPTION_PARTS:
            target = generated / filename
            run(GENERATORS[0], ["--rules-section=" + section, "--xkb-config-root", str(source),
                               str(rules / "base.xml"), str(rules / "base.extras.xml")], target)
            parts.append(target)
        for level, (layout_part, variant_part) in enumerate(zip(LAYOUT_PARTS, VARIANT_PARTS)):
            for want, filename, inputs in (
                ("mls", layout_part, ("layoutsMapping.lst", "variantsMapping.lst")),
                ("mlvs", variant_part, ("variantsMapping.lst",)),
            ):
                target = generated / filename
                run(GENERATORS[1], ["--want=" + want, "--number=" + str(level), "-",
                                   *(str(rules / "compat" / name) for name in inputs)], target)
                parts.append(target)
        run(GENERATORS[2], [str(path) for path in static + parts], generated / "evdev")
        passes.append(generated)
    names = [name for name, _ in OPTION_PARTS] + list(LAYOUT_PARTS) + list(VARIANT_PARTS) + ["evdev"]
    for name in names:
        if (passes[0] / name).read_bytes() != (passes[1] / name).read_bytes():
            raise BuildError(f"Repeated upstream generation differs: {name}")
    return {"recipe": "xkeyboard-config 2.42 rules/meson.build; compat-rules=true",
            "scripts": scripts, "commands": commands, "repeat_identical": True,
            "python": {"path": str(interpreter), "version": sys.version, **file_record(interpreter)},
            "outputs": [{"path": name, **file_record(passes[0] / name)} for name in names]}


def source_inventory(source: Path) -> list[dict]:
    records = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source).as_posix()
        if path.is_symlink():
            # Official alias links are inputs to the option generator, never installed.
            records.append({"path": relative, "kind": "archive-internal-symlink",
                            "target": os.readlink(path)})
        elif path.is_file():
            records.append({"path": relative, "kind": "file", **file_record(path)})
    return records


def install(output: Path, cache: Path, manifest: Path = MANIFEST) -> dict:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise BuildError("Output must be a new directory; existing data is never overwritten")
    package = load_package(manifest)
    bounds = catalog_bounds([target for _, target in ASSETS] + [RULE_TARGET])
    record = desktop_ports.verify(package, cache, 8 * 1024 * 1024)
    output.mkdir(parents=True, exist_ok=False)
    sources = output / "source"
    sources.mkdir()
    source = build_sysroot.unpack(package, record, sources)
    generation = generate_evdev(source, output)
    inventory = source_inventory(source)
    # A failed generator leaves its diagnostics but cannot publish a rootfs.
    staged = output / "rootfs.pending"
    staged.mkdir()
    installed = [copy_asset(source, name, staged / target.lstrip("/"), target)
                 for name, target in ASSETS]
    installed.append(copy_asset(output / "generation-1", "evdev",
                                staged / RULE_TARGET.lstrip("/"), RULE_TARGET))
    installed[-1]["source"] = "generation-1/evdev"
    report = {
        "schema_version": 1, "status": "PASS", "scope": "Initial evdev/pc105/us asset staging only",
        "supported_rmlvo": {"rules": "evdev", "model": "pc105", "layout": "us", "variant": "", "options": ""},
        "all_upstream_layouts_supported": False, "guest_keyboard_verified": False,
        "cosmic_session_verified": False, "source": record,
        "manifest": {"path": str(manifest), **file_record(manifest)},
        "installer": {"path": str(Path(__file__).resolve()), **file_record(Path(__file__))},
        "generation": generation, "source_files": inventory,
        "assets": sorted(installed, key=lambda entry: entry["path"]),
        "asset_bytes": sum(entry["bytes"] for entry in installed), "bounds": bounds,
        "rootfs": str(output / "rootfs"),
    }
    with (output / "report.pending.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    staged.rename(output / "rootfs")
    (output / "report.pending.json").rename(output / "report.json")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New staging directory; contains rootfs and report.json")
    parser.add_argument("--cache", type=Path, default=desktop_ports.DEFAULT_CACHE)
    args = parser.parse_args()
    try:
        report = install(args.output, args.cache)
        print(json.dumps({name: report[name] for name in ("status", "rootfs", "asset_bytes", "bounds")}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"XKB asset installation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
