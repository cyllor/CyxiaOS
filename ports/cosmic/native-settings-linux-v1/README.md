# Genuine settings daemon on the explicit Linux build host

This independent entry point builds `cosmic-settings-daemon` 1.10.0 at
`9e4ae69fc175191f15789d35423806ea0f093c9d`. It copies the existing
`native-settings/cosmic-settings-native.patch` without changing any byte. The
original builders, patch generator, source checkouts and historical receipts
remain separate inputs.

The real configuration and state D-Bus interfaces, filesystem watcher, theme
logic and Wayland client remain selected. The original `cyxia-native` feature
boundary is unchanged: volume and brightness mutations return
`org.freedesktop.DBus.Error.NotSupported`, unavailable brightness remains `-1`,
and no audio Varlink service is created. Upstream accessibility, locale, logind
and UPower failures retain their original behavior. This port does not emulate
system services or provide a replacement daemon. See the original
[`native-settings` description](../native-settings/README.md) for that boundary.

## Source and input contract

The new source policy binds the original patch manifest and its support files,
all 75 files of the settings Git tree, all 283 files of the pinned compositor
tree that supplies `cosmic-comp-config`, and the original checksum-bound
`wayland-sys` 0.31.11 archive. Canonical Git object traversal disables replacement
objects and verifies the actual checkout bytes. The exported source is derived
from the original complete file inventory and every reviewed patch preimage and
postimage. Its ordinary patch also retains the previously resolved lockfile;
this entry point never updates that lockfile.

Actual Cargo metadata must select the root native feature, the exact local
config and static Wayland packages, and the geonames data package without its
generator. Every selected registry dependency is checked from the effective
lock checksum through the original `.crate` and all extracted files and
directories. Git dependencies retain canonical commit/tree/blob checks.
Package identities, features and dependency edges are recorded together.

The Linux recipe binds the current runtime SDK assembly receipt and the actual
eight libc/CRT/builtins/Wayland/FFI/XKB input hashes. The three static client
archives are copied into the same `native/` directory as the official Rust
unwind archive and verified before and after Cargo. This directory is the
explicit rustc native search path, so static rlib bundling can discover the
real archives before final linking. Generated wrappers, all official target
`.rlib`/`.a` files, selected Rust 1.95.0 and Clang 19 executable identities, the
full SDK tree, source exports and dependency evidence are rechecked.

The resource limits remain the original settings bounds: two jobs, one shared
1200 second deadline, 1.5 GiB aggregate growth and 1 GiB free-space reserve. The
fixed FullOsV3 parser admits at most 64 MiB of private image backing including
the 2 MiB stack. These are build and admission limits; they are not runtime
qualification.

## Metadata and native build

The **caller must hold the shared native lease** at
`artifacts/v017-cosmic-completion-20261116/native-session.lock` before invoking
either operation. The tool also locks the selected private Cargo cache and SDK.
It does not acquire sources or provide a second native lease internally.

With that outer lease held, a metadata-only operation is:

```sh
python3 -B tools/build_cosmic_settings_linux_v1.py metadata \
  --recipe ports/cosmic/native-settings-linux-v1/native-recipe.json \
  --resource-profile ports/cosmic/native-settings-linux-v1/resource-profile.json \
  --source-cache artifacts/cosmic-sources \
  --cache artifacts/cosmic-runtime-cargo-cache \
  --sysroot artifacts/v017-cosmic-runtime-20261116/runtime-sdk-x86_64 \
  --rust-root /workspace/scratch/99a018f40879/toolchains/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu \
  --host-cc /workspace/scratch/99a018f40879/cosmic-work/tooling/prefix/usr/lib/llvm-19/bin/clang \
  --jobs 2 \
  --output artifacts/v017-cosmic-runtime-20261116/settings-native-metadata-v1
```

For the actual native build, select `build` and a different fresh output such
as `settings-native-build-v1`. Both operations pass `--locked --offline` to
Cargo. If a required source is absent, preparation needs a separate explicit
acquisition step; an offline failure is retained as a failure.

Metadata success is `SETTINGS_METADATA_VERIFIED_NOT_BUILT`. It is never accepted
by the installer. A native build publishes its complete, byte-verified ELF via
atomic rename only after source and input checks pass. Input changes, missing
logs, partial copies, report I/O errors, interruptions and temporary-directory
cleanup failures revoke the publication and clear `target_linked`. The raw
target directory, available logs and preserved source remain evidence.

## Installation and validation

`tools/cosmic_settings_inputs_v1.py::validate_build(output)` performs the full
read-only validation again, including the actual linked and published ELF
bytes. It relocates local Cargo manifest and target paths only from the recorded
temporary source root into the complete retained `output/source` tree; external
dependencies continue to refer to their original private cache.

After a genuine successful native build, install into a new curated prefix:

```sh
python3 -B tools/install_cosmic_settings_linux_v1.py \
  --build artifacts/v017-cosmic-runtime-20261116/settings-native-build-v1 \
  --output artifacts/v017-cosmic-runtime-20261116/settings-native-install-v1
```

The installer stages the real `cosmic-settings-daemon.elf` and all three
upstream licenses, validates the staged installation and original inputs, then
renames the directory atomically. Its receipt is
`cosmic-settings-linux-v1-origin.json`, with status `INSTALLED_NOT_RUN`.
`validate_inputs(prefix)` replays the same source, producer and artifact checks.
ELF files use mode `0755`, and license files use `0644`.

The tools keep `settings_verified`, `cosmic_session_ready` and
`cosmic_session_verified` false. Source export, metadata, linking, installation
and host fixtures do not prove D-Bus ownership, persistent WatchConfig/WatchState
events, real Wayland transport, supported control behavior or resource cleanup
in the guest. Those require separate execution evidence.

The focused host regression command is:

```sh
python3 -B -m unittest \
  tools.test_cosmic_settings_linux_v1 \
  tools.test_install_cosmic_settings_linux_v1 -v
```

Those tests use explicit Git/archive/file fixtures and never invoke Cargo,
native compilers, a settings service or a guest.
