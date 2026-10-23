#!/usr/bin/env python3
"""Build pinned upstream Smithay with an explicit static EGL loader, offline."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import time
import tomllib

from build_cosmic import clean_environment, new_output, run_bounded, tree_identity
from build_rust_egl_probe import extract, source_input
from build_sysroot import ROOT, DEFAULT_OUTPUT, digest, inspect_elf, toolchain

MANIFEST = ROOT / "ports/cosmic/smithay-wayland-source.json"
PROBE = ROOT / "ports/cosmic/smithay-wayland/main.rs"
LOCK = ROOT / "ports/cosmic/smithay-wayland.Cargo.lock"
MODULES = [ROOT / "ports/cosmic/smithay-wayland/native.rs", ROOT / "ports/cosmic/smithay-wayland/us.xkb"]
COSMIC_LOCK = ROOT / "artifacts/cosmic-sources/cosmic-comp-epoch/Cargo.lock"


@dataclass(frozen=True)
class BuildProfile:
    manifest: Path = MANIFEST
    source: Path = PROBE
    binary_stem: str = "smithay-wayland"
    entrypoint: Path | None = None
    lto: str = "thin"
    modules: tuple[Path, ...] = tuple(MODULES)

    def __post_init__(self):
        if not self.binary_stem or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in self.binary_stem):
            raise ValueError("Invalid binary output name")
        if self.lto not in ("thin", "fat"):
            raise ValueError("Unsupported LTO profile")
        names = [p.name.casefold() for p in self.modules]
        if "main.rs" in names or len(names) != len(set(names)):
            raise ValueError("Module filenames would overwrite a source input")


def image_page_count(headers):
    """Count every touched LOAD page, matching the kernel's validated ELF plan.

    A segment can start inside a page. Rounding only its size undercounts the
    final page when that offset pushes its end over a page boundary.
    """
    pages = set()
    for header in headers:
        if header["type"] == 1 and header["memsz"]:
            start = header["vaddr"] // 4096
            end = (header["vaddr"] + header["memsz"] + 4095) // 4096
            pages.update(range(start, end))
    return len(pages)


def toml_value(value):
    if isinstance(value, dict):
        return "{" + ", ".join(json.dumps(k) + " = " + toml_value(v)
                               for k, v in value.items()) + "}"
    return json.dumps(value)


def project_manifest(source, manifest, cosmic_packages):
    """Keep all mandatory upstream dependencies; omit inactive workspace backends.

    This changes dependency selection only. The full upstream Rust source and
    original build.rs remain present, with just the explicit EGL loader patch.
    """
    original = tomllib.loads(source.read_text())
    smithay = next(p for p in cosmic_packages if p["name"] == "smithay")
    selected = set(manifest["projected_dependencies"])
    lines = ["[package]"]
    lines += [json.dumps(k) + " = " + toml_value(v)
              for k, v in original["package"].items() if k != "metadata"]
    removed = []
    for section in ("dependencies", "build-dependencies"):
        lines += ["", "[" + section + "]"]
        for name, value in original[section].items():
            optional = isinstance(value, dict) and value.get("optional", False)
            if name not in selected:
                if not optional:
                    raise ValueError("Cannot remove mandatory upstream dependency: " + name)
                removed.append(name)
                continue
            spec = next(d for d in smithay["dependencies"] if d.split()[0] == name)
            words = spec.split()
            versions = [p for p in cosmic_packages if p["name"] == name
                        and (len(words) == 1 or p["version"] == words[1])]
            if len(versions) != 1:
                raise ValueError("Ambiguous pinned dependency: " + spec)
            data = dict(value) if isinstance(value, dict) else {}
            data["version"] = "=" + versions[0]["version"]
            lines.append(json.dumps(name) + " = " + toml_value(data))
    lines += ["", "[features]", "default = []"]
    for name in manifest["projected_features"]:
        lines.append(name + " = " + toml_value(original["features"][name]))
    # Preserve cfg validation for omitted upstream backends without enabling
    # their features or pulling their dependency closures into this build.
    known_features = ", ".join(json.dumps(name) for name in original["features"])
    lines += ["", "[lints.rust]", "unexpected_cfgs = { level = \"warn\", check-cfg = ["
              + json.dumps("cfg(feature, values(" + known_features + "))") + "] }"]
    source.write_text("\n".join(lines) + "\n")
    return dict(omitted_optional_dependencies=removed, removed_workspace=True,
                removed_dev_dependencies=True, retained_mandatory_dependencies=True)


def build(output, cache, mesa_report, fetch=False, *, profile=BuildProfile()):
    manifest_path, probe = profile.manifest, profile.source
    manifest = json.loads(manifest_path.read_text())
    budget = manifest["budgets"]
    all_inputs = [manifest["smithay_archive"], *manifest["crates"]]
    if sum(p["bytes"] for p in all_inputs) > budget["max_download_bytes"]:
        raise ValueError("Download closure exceeds limit")
    if digest(COSMIC_LOCK) != manifest["cosmic_lock_sha256"] or digest(LOCK) != manifest["cargo_lock_sha256"]:
        raise ValueError("Pinned lock changed")
    packages = tomllib.loads(COSMIC_LOCK.read_text())["package"]
    if not any(p["name"] == "smithay" and p.get("source", "").endswith("#" + manifest["smithay_commit"])
               for p in packages):
        raise ValueError("Smithay revision differs from COSMIC")
    for crate in manifest["crates"]:
        if not any(p["name"] == crate["name"] and p["version"] == crate["version"]
                   and p.get("checksum") == crate["sha256"] for p in packages):
            raise ValueError("Registry dependency differs from COSMIC lock: " + crate["name"])
    mesa = json.loads(mesa_report.read_text())
    if mesa.get("status") != "libraries-compiled":
        raise ValueError("Mesa SDK is not compiled")
    output = new_output(output)
    for name in ("logs", "source", "source/src", "source/.cargo", "vendor", "cargo-home", "native", "provenance"):
        (output / name).mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    rustc = str(Path.home() / ".cargo/bin/rustc")
    cargo = str(Path.home() / ".cargo/bin/cargo")
    env = clean_environment(str(Path.home() / ".cargo/bin") + ":/usr/bin:/bin:/opt/homebrew/bin")
    env.update(CARGO_HOME=str(output / "cargo-home"), CARGO_TARGET_DIR=str(output / "target"))
    source = output / "source"
    report = dict(status="FAIL", guest_execution="not performed", scope=manifest["scope"],
                  smithay_commit=manifest["smithay_commit"], features=manifest["features"],
                  source_sha256=digest(probe), manifest_sha256=digest(manifest_path),
                  build_profile=dict(manifest=str(manifest_path), source=str(probe),
                                     binary_stem=profile.binary_stem, lto=profile.lto),
                  builder_sha256=digest(Path(__file__)), cargo_lock_sha256=digest(LOCK),
                  cosmic_lock_sha256=digest(COSMIC_LOCK), mesa_report_sha256=digest(mesa_report),
                  helper_sha256={str(ROOT / "tools" / p): digest(ROOT / "tools" / p)
                                 for p in ("build_rust_egl_probe.py", "build_cosmic.py", "build_sysroot.py")},
                  patches_sha256={p: digest(ROOT / p) for p in manifest["patches"]},
                  modules_sha256={str(p): digest(p) for p in profile.modules},
                  commands=[], budgets=budget)
    if profile.entrypoint is not None:
        report["helper_sha256"][str(profile.entrypoint)] = digest(profile.entrypoint)
    input_files = {
        manifest_path: report["manifest_sha256"], probe: report["source_sha256"],
        LOCK: report["cargo_lock_sha256"], COSMIC_LOCK: report["cosmic_lock_sha256"],
        Path(__file__).resolve(): report["builder_sha256"],
        **{Path(p): value for p, value in report["helper_sha256"].items()},
        **{ROOT / p: value for p, value in report["patches_sha256"].items()},
        **{Path(p): value for p, value in report["modules_sha256"].items()},
    }
    for path in input_files:
        shutil.copyfile(path, output / "provenance" / path.name)
    model_paths = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml")]
    for name in ("ai-runtime", "kernel-core", "contracts"):
        directory = ROOT / "crates" / name
        model_paths += [directory / "Cargo.toml", *sorted(directory.rglob("*.rs"))]
    report["model_inputs_sha256"] = {str(path): digest(path) for path in model_paths}
    input_files.update({Path(path): value for path, value in report["model_inputs_sha256"].items()})
    for path in model_paths:
        destination = output / "provenance/model" / path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    deadline = time.monotonic() + budget["timeout_seconds"]

    def run(arguments, label, cwd=source, extra=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Whole build timeout")
        record = dict(command=list(map(str, arguments)), cwd=str(cwd), environment=extra or {})
        report["commands"].append(record)
        run_bounded(record["command"], cwd, {**env, **(extra or {})},
                    output / "logs" / (label + ".log"), remaining,
                    budget["min_free_bytes"], budget["max_build_bytes"], budget_root=output)

    try:
        report["rustc"] = subprocess.check_output([rustc, "-vV"], env=env, text=True)
        report["cargo"] = subprocess.check_output([cargo, "-V"], env=env, text=True)
        archive = source_input(cache, manifest["smithay_archive"],
                               manifest["smithay_commit"] + ".tar.gz", fetch)
        upstream, expanded = extract(archive, source, manifest["smithay_archive"]["root"],
                                     budget["max_expanded_bytes"])
        smithay = source / "smithay"
        upstream.rename(smithay)
        report["upstream_source_tree_sha256"] = tree_identity(smithay)["sha256"]
        for index, patch in enumerate(manifest["patches"]):
            run(["/usr/bin/patch", "--batch", "--forward", "-p1", "-i", ROOT / patch],
                f"patch-{index}", smithay)
        report["manifest_projection"] = project_manifest(smithay / "Cargo.toml", manifest, packages)
        report["patched_source_tree_sha256"] = tree_identity(smithay)["sha256"]
        for crate in manifest["crates"]:
            name = crate["name"] + "-" + crate["version"]
            archive = source_input(cache, crate, name + ".crate", fetch)
            directory, count = extract(archive, output / "vendor", name,
                                       budget["max_expanded_bytes"] - expanded)
            expanded += count
            files = {str(p.relative_to(directory)): digest(p)
                     for p in directory.rglob("*") if p.is_file()}
            (directory / ".cargo-checksum.json").write_text(
                json.dumps(dict(files=files, package=crate["sha256"])) + "\n")
        report["expanded_source_bytes"] = expanded
        report["vendor_tree_sha256"] = tree_identity(output / "vendor")["sha256"]
        shutil.copyfile(probe, source / "src/main.rs")
        for module in profile.modules:
            shutil.copyfile(module, source / "src" / module.name)
        shutil.copyfile(LOCK, source / "Cargo.lock")
        (source / "Cargo.toml").write_text(
            '[package]\nname="cyxia-smithay-wayland"\nversion="0.1.0"\nedition="2024"\n'
            '[workspace]\nmembers=["smithay"]\n[dependencies]\n'
            'smithay={path="smithay",default-features=false,features='
            + json.dumps(manifest["features"]) + '}\nlibc="=0.2.182"\n'
            '[profile.release]\nopt-level="s"\ndebug=1\ncodegen-units=1\nlto='
            + json.dumps(profile.lto) + '\npanic="abort"\n')
        (source / ".cargo/config.toml").write_text(
            '[source.crates-io]\nreplace-with="checked-vendor"\n'
            '[source.checked-vendor]\ndirectory=' + json.dumps(str(output / "vendor")) + "\n")
        report["cargo_inputs_sha256"] = {
            str(p.relative_to(output)): digest(p)
            for p in (source / "Cargo.toml", source / ".cargo/config.toml")
        }
        libraries = dict(mesa["target"]["link_dependencies_sha256"])
        # xkbcommon is mandatory upstream Smithay input, including in this
        # renderer-only feature set. Use the verified existing static target SDK.
        xkb_path = DEFAULT_OUTPUT / "xkbcommon-build-report.json"
        report["xkbcommon_report_sha256"] = digest(xkb_path)
        xkb = json.loads(xkb_path.read_text())
        if xkb["status"] != "cross-built":
            raise ValueError("xkbcommon SDK is not compiled")
        libraries[str(DEFAULT_OUTPUT / "sysroot/usr/lib/libxkbcommon.a")] = xkb["target"]["archive"]["sha256"]
        for path, value in libraries.items():
            if digest(Path(path)) != value:
                raise ValueError("Static link input changed: " + path)
        report["static_inputs_sha256"] = libraries
        shutil.copyfile(mesa_report, output / "mesa-build-report.json")
        shutil.copyfile(xkb_path, output / "xkbcommon-build-report.json")
        target = manifest["target"]
        target_lib = Path(subprocess.check_output(
            [rustc, "--print", "target-libdir", "--target", target], env=env, text=True).strip())
        unwind = target_lib / "self-contained/libunwind.a"
        shutil.copyfile(unwind, output / "native/libunwind.a")
        report["rust_unwind_sha256"] = digest(unwind)
        report["rust_target_rlibs_sha256"] = {p.name: digest(p) for p in sorted(target_lib.glob("*.rlib"))}
        cc = DEFAULT_OUTPUT / "bin/aarch64-linux-musl-cc"
        report["target_driver_sha256"] = digest(cc)
        input_files.update({cc: report["target_driver_sha256"], unwind: report["rust_unwind_sha256"],
                            mesa_report: report["mesa_report_sha256"],
                            xkb_path: report["xkbcommon_report_sha256"]})
        input_files.update({target_lib / p: value for p, value in report["rust_target_rlibs_sha256"].items()})
        flags = ["-C", "linker=" + str(cc), "-C", "link-self-contained=no",
                 "-C", "relocation-model=static", "-C", "target-feature=+crt-static",
                 "-L", "native=" + str(output / "native"),
                 "-C", "link-arg=-Wl,--start-group"]
        for path in libraries:
            if path.endswith(".a") and Path(path).name not in ("libc.a", "libclang_rt.builtins-aarch64.a"):
                flags += ["-C", "link-arg=" + path]
        flags += ["-C", "link-arg=-Wl,--end-group"]
        run([cargo, "metadata", "--locked", "--offline", "--format-version=1",
             "--filter-platform", target], "metadata")
        metadata = json.loads((output / "logs/metadata.log").read_text())
        report["resolved_packages"] = [{key: p[key] for key in ("name", "version", "source", "id")}
                                      for p in metadata["packages"]]
        report["resolved_features"] = {p["id"]: p["features"] for p in metadata["resolve"]["nodes"]}
        run([cargo, "build", "--locked", "--offline", "--release", "--target", target,
             "-p", "cyxia-smithay-wayland", "-j", "2", "--message-format=json-render-diagnostics"],
            "cargo-build", extra={"CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags)})
        report["compiled_artifacts_sha256"] = {}
        for line in (output / "logs/cargo-build.log").read_text().splitlines():
            if line.startswith("{"):
                message = json.loads(line)
                if message.get("reason") == "compiler-artifact":
                    for name in message["filenames"]:
                        path = Path(name)
                        report["compiled_artifacts_sha256"][str(path.relative_to(output))] = digest(path)
        binary = output / "target" / target / "release/cyxia-smithay-wayland"
        symbols = output / (profile.binary_stem + ".symbols.elf")
        shutil.copyfile(binary, symbols)
        report["symbols"] = inspect_elf(symbols)
        binary = output / (profile.binary_stem + ".elf")
        shutil.copyfile(symbols, binary)
        run([toolchain()["llvm-strip"], "--strip-all", binary], "strip")
        report["probe"] = inspect_elf(binary)
        report["image_pages"] = image_page_count(report["probe"]["program_headers"])
        report["generated_bindings"] = {str(p.relative_to(output)): digest(p)
                                       for p in (output / "target").rglob("*_bindings.rs")
                                       if p.name in ("egl_bindings.rs", "gl_bindings.rs")}
        if len(report["generated_bindings"]) != 2:
            raise ValueError("Expected original Smithay EGL/GLES generated bindings")
        for name, value in report["generated_bindings"].items():
            if value != manifest["generated_bindings"][Path(name).name]:
                raise ValueError("Generated API changed: " + name)
        report["stack_pages"] = 64
        report["admission_pages"] = report["image_pages"] + report["stack_pages"]
        if report["admission_pages"] > 4096:
            raise ValueError("ELF plus mandatory 64 stack pages exceeds 4096-page admission budget")
        run([cargo, "run", "--quiet", "--locked", "--offline", "--manifest-path", ROOT / "Cargo.toml",
             "-p", "cyxia-ai-runtime", "--example", "check_exec_admission", "--",
             "4096", str(report["admission_pages"])], "model-preflight", ROOT)
        report["model_preflight"] = json.loads((output / "logs/model-preflight.log").read_text())
        preflight = output / "target/debug/examples/check_exec_admission"
        report["model_preflight_executable_sha256"] = {str(preflight.relative_to(output)): digest(preflight)}
        if report["model_preflight"] != dict(free=4096, requested=report["admission_pages"],
                                             allowed=True, model=8195):
            raise ValueError("Existing guest AI model rejects executable image; optimize before guest execution")
        for path, value in libraries.items():
            if digest(Path(path)) != value:
                raise ValueError("Static link input changed during build: " + path)
        input_files.update({source / "src/main.rs": report["source_sha256"],
                            source / "Cargo.lock": report["cargo_lock_sha256"]})
        input_files.update({source / "src" / Path(p).name: value
                            for p, value in report["modules_sha256"].items()})
        input_files.update({output / p: value for p, value in report["cargo_inputs_sha256"].items()})
        for path, value in input_files.items():
            if digest(path) != value:
                raise ValueError("Build input changed during compilation: " + str(path))
        for directory, expected in ((smithay, report["patched_source_tree_sha256"]),
                                    (output / "vendor", report["vendor_tree_sha256"])):
            if tree_identity(directory)["sha256"] != expected:
                raise ValueError("Source tree changed during compilation: " + str(directory))
        report["status"] = "cross-built"
    except Exception as error:
        report["error"] = repr(error)
        raise
    finally:
        report["logs"] = {p.name: digest(p) for p in sorted((output / "logs").glob("*.log"))}
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--mesa-report", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.output.resolve(), args.cache.resolve(),
                           args.mesa_report.resolve(), args.fetch), indent=2))
