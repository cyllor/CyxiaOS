#!/usr/bin/env python3
"""Cross-link official Rust std with the pinned target musl and fixed ELF layout.

Does not build the kernel, run the guest, or substitute a no_std implementation.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from build_sysroot import DEFAULT_OUTPUT, ROOT, digest, inspect_elf, toolchain
from target_profile import profile_for


def build(output=None, architecture="aarch64"):
    selected = profile_for(architecture)
    output = Path(output or selected.default_output(ROOT)).resolve()
    selected.require_report(json.loads((output / "build-report.json").read_text()))
    selected.inspect_archive(output / "sysroot/usr/lib/libc.a")
    rustc = Path.home() / ".cargo/bin/rustc"
    cc = selected.cc(output)
    source = ROOT / "user/ported/rust_std_probe.rs"
    target = selected.rust_target
    env = dict(os.environ)
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_BOOTSTRAP", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "LIBRARY_PATH", "CPATH"):
        env.pop(key, None)
    version = subprocess.check_output([str(rustc), "-vV"], env=env, text=True)
    target_lib = Path(subprocess.check_output([str(rustc), "--print", "target-libdir", "--target", target], env=env, text=True).strip())
    if not list(target_lib.glob("libstd-*.rlib")):
        raise RuntimeError("Install official target first: rustup target add " + target)
    tools = toolchain()
    producers = {str(path): digest(path) for path in (
        source, ROOT / 'user/ported/linux_nr.rs',
        ROOT / 'user/ported/x86_fault_probe.rs',
        ROOT / 'ports/cosmic/smithay-wayland/linux_syscall.rs',
        Path(__file__).resolve(), ROOT / 'tools/target_profile.py', ROOT / 'tools/build_sysroot.py')}
    temporary = output / "rust-std-probe.elf.tmp"
    command = [str(rustc), str(source), "--edition=2024", "--target", target,
               "-C", "linker=" + str(cc), "-C", "link-self-contained=no",
               "-C", "relocation-model=static", "-C", "target-feature=+crt-static",
               "-C", "panic=abort", "-C", "opt-level=2", "-C", "debuginfo=1",
               "-o", str(temporary)]
    with (output / ".build.lock").open("a") as lock, tempfile.TemporaryDirectory(prefix="rust-native-", dir=output) as native:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Rust's distributed libstd references its LLVM unwind archive even
        # with panic=abort. Expose that archive alone: adding the whole
        # self-contained directory could silently select a different libc/CRT.
        unwind = target_lib / "self-contained/libunwind.a"
        shutil.copyfile(unwind, Path(native) / "libunwind.a")
        command += ["-L", "native=" + native]
        log = output / "rust-std-probe-link.log"
        with log.open("w") as stream:
            subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        symbols = output / "rust-std-probe.symbols.elf"
        shutil.copyfile(temporary, symbols)
        subprocess.run([tools["llvm-strip"], "--strip-all", str(temporary)], check=True)
        result = inspect_elf(temporary, selected)
        final = output / "rust-std-probe.elf"
        temporary.replace(final)
        result['file'] = str(final)
        report = dict(status="cross-built", guest_execution="not performed", target=target,
                      rustc=version, command=command, executable=result,
                      producer_inputs_sha256=producers,
                      rust_target_rlibs_sha256={p.name: digest(p) for p in sorted(target_lib.glob("*.rlib"))},
                      source_sha256=digest(source), libc_sha256=digest(output / "sysroot/usr/lib/libc.a"),
                      linker_sha256=digest(cc), std=[dict(file=p.name, sha256=digest(p)) for p in sorted(target_lib.glob("libstd-*.rlib"))],
                      unwind_sha256=digest(unwind), symbols_sha256=digest(symbols), panic="abort", self_contained=False)
        if any(digest(Path(path)) != expected for path, expected in producers.items()):
            raise RuntimeError("Rust std producer input changed while compiling")
        report_path = output / "rust-std-probe-build-report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(report_path)
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--arch", choices=("aarch64", "x86_64"), default="aarch64")
    args = parser.parse_args()
    build(args.output, args.arch)
