# Native notification build and installation

The current recipe selects the genuine pinned `cosmic-notifications` package,
its original Cargo lock and explicit `--cfg tokio_unstable` flags. Its only
source transformation removes the exact reviewed root `.cargo/config.toml`;
the original checkout and `.cargo/config.default` remain intact. Additional
source ports need a separately reviewed input/output contract before this
installer can accept them.

The dependency validator reads canonical Git objects with
`--no-replace-objects`. Local replacement refs cannot substitute another tree
while retaining the expected winit commit/tree identifiers. This restriction
is local to the notification path; frozen generic build producers are unchanged.

## Explicit host tools and SDK

The notification entry points accept an installed Rust toolchain directly. Use
`--rust-root` with the directory containing `bin/rustc`, `bin/cargo` and
`bin/rustdoc`; the build also accepts `--host-cc` with the real host Clang path.
Its sibling `clang++` must be the corresponding host C++ driver. The selected
Rust installation must contain the official x86_64 musl target and LLVM tools.
These options leave the frozen generic producers unchanged and avoid requiring
the previous machine's rustup proxy or `/usr/bin/clang` layout.

`native-linux-x86_64-recipe.json` binds the SDK rebuilt on 2026-11-16 with
Clang 19.1.7 and the Rust 1.95.0 LLVM tools. It rechecks all eight native
inputs and changes six hashes from `native-recipe.json`; source, lock, features, resource bounds
and source-export policy are identical. The original recipe remains available
for its original SDK. An SDK hash mismatch is an input mismatch, and must not
be bypassed by substituting host libraries.

Run source acquisition and target compilation serially under the shared native
lease. For an existing lease owner, the explicit commands are:

```sh
python3 -B tools/prepare_cosmic_notifications.py \
  --recipe ports/cosmic/native-notifications/native-linux-x86_64-recipe.json \
  --rust-root <installed-rust-root> \
  --output artifacts/notification-sources

python3 -B tools/build_cosmic_notifications.py \
  --recipe ports/cosmic/native-notifications/native-linux-x86_64-recipe.json \
  --resource-profile ports/cosmic/recipes/cosmic-notifications-x86_64-resource.json \
  --rust-root <installed-rust-root> \
  --host-cc <actual-clang-executable> \
  --sysroot <matching-sdk-prefix> \
  --jobs 2 --output artifacts/notification-build
```

The explicit source-acquisition path permits standard proxy transport variables
and uses the recorded Git executable. Its receipt records variable names, not
proxy values. Arbitrary Cargo/compiler environment overrides remain excluded.
The target build still runs locked and offline with the original resource caps;
the acquisition transport settings do not enter its environment. A successful
source preparation is not a target build or a service execution.

### Extended Linux build budget

The first Linux target attempt reached the original 1200-second deadline without
a linked ELF. Its recipe, resource profile and failed output remain preserved.
The explicit follow-up pair is `native-linux-x86_64-extended-recipe.json` and
`native-linux-x86_64-resource-v2.json`, selecting
`notifications-static-x86_64-full-os-v2`. It extends only the per-command deadline
to 3600 seconds and records the reason in the profile. Metadata and Cargo build
each receive this deadline; it is not a total elapsed-time limit.

The source, lock, features, export policy and SDK identities remain identical to
the first Linux recipe. Bounds remain two jobs, 3 GiB of combined output, scratch
and private-cache growth, a 1 GiB free-space reserve, and a 64 MiB ELF/image limit
with a 2 MiB stack. The frozen 16 MiB LOAD inspector still applies. These are
experimental limits; the timeout does not establish a completed build or a
successful peak resource measurement. Runtime validation remains false.

Run the follow-up under the shared native lease with a fresh output directory:

```sh
python3 -B tools/build_cosmic_notifications.py \
  --recipe ports/cosmic/native-notifications/native-linux-x86_64-extended-recipe.json \
  --resource-profile ports/cosmic/native-notifications/native-linux-x86_64-resource-v2.json \
  --rust-root <installed-rust-root> \
  --host-cc <actual-clang-executable> \
  --sysroot <matching-sdk-prefix> \
  --jobs 2 --output artifacts/notification-build-linux-v2
```

The verified source/Cargo download cache may be reused. The interrupted target
directory has no sealed artifact identity or completed post-build verification;
this follow-up does not reuse it. Installation of this follow-up output must use
the same extended recipe and v2 resource profile pair.

## Install a completed target build

`tools/install_cosmic_notifications.py` is an offline installation and provenance
checker. It invokes read-only Git commands but never Cargo, a compiler, a version
probe, a service or a guest. By default, the build must already have completed
under the shared native lease and have a real `cross-built` report with both
link flags. The default path rejects failed or merely prepared inputs.

```sh
python3 -B tools/install_cosmic_notifications.py \
  --build artifacts/notification-build \
  --recipe ports/cosmic/native-notifications/native-linux-x86_64-recipe.json \
  --resource-profile ports/cosmic/recipes/cosmic-notifications-x86_64-resource.json \
  --sysroot <matching-sdk-prefix> \
  --source-cache artifacts/cosmic-sources \
  --cache artifacts/cosmic-cargo-cache \
  --output artifacts/notification-install
```

### Explicit Full OS post-link admission

The frozen builder checks a 16 MiB LOAD address window even when the selected
resource profile permits a 64 MiB Full OS image. A completed link rejected
at that boundary may be inspected and installed with `--full-os-linked-elf`.
This opt-in path preserves the original failed build report and every file in
the build directory. It reads the exact recorded link output under
`target/x86_64-unknown-linux-musl/release/cosmic-notifications`; the builder must
not have published `cosmic-notifications.elf`, an executable inspection or a
page count.

Admission requires the exact legacy LOAD error, `link_completed=true`,
`target_linked=false`, and successful preservation of source and all transitive
build producers. The complete source, export policy, recipe, metadata,
dependencies, SDK, toolchain and log checks still apply. A separate bounded
parser checks the linked ELF against the reviewed `full-os-v3` loader contract,
including its fixed 64 MiB address window and private image pool with a 2 MiB
stack. It preserves the original ELF guards and checks the loader's header,
segment, TLS and permission rules. The ELF must actually exceed the legacy
window while satisfying all of these checks. The admission contract rejects
changed loader sources or enlarged resource limits.

For the extended Linux build, use the explicit paired inputs:

```sh
python3 -B tools/install_cosmic_notifications.py \
  --full-os-linked-elf \
  --build artifacts/notification-build-linux-v2 \
  --recipe ports/cosmic/native-notifications/native-linux-x86_64-extended-recipe.json \
  --resource-profile ports/cosmic/native-notifications/native-linux-x86_64-resource-v2.json \
  --sysroot <matching-sdk-prefix> \
  --source-cache artifacts/cosmic-sources \
  --cache artifacts/cosmic-cargo-cache \
  --output artifacts/notification-install-full-os
```

The receipt records admission schema 1, mode `full-os-linked-elf-v1`, the original
`failed` status and report hash, the actual Full OS inspection and the fixed
loader-source identities. The installed ELF is byte-for-byte identical to the
recorded link output. The original build remains failed; installation has status
`INSTALLED_NOT_RUN`. Static admission does not execute the loader, obtain a
runtime memory grant or establish service/session readiness.

### Atomic publication and revalidation

The output must be a fresh directory outside the selected inputs. The installer
stages the following files in a sibling temporary directory, rechecks all inputs
and staged bytes, then publishes the directory with one rename:

- `cosmic-notifications.elf`, the unchanged target ELF, executable mode `0755`.
- `cosmic-notifications-origin.json`, with status `INSTALLED_NOT_RUN`.
- `rootfs/usr/share/doc/cosmic-notifications/LICENSE`, copied from the pinned
  upstream `LICENSE.md`.

The ELF is an input to the normal kernel program catalog at
`/bin/cosmic-notifications`. There is no replacement launcher and no duplicate
`rootfs/bin` entry. The real session manager retains its argv/environment and
inherited panel-socket descriptor contract. Curating this package alongside
other services is separate from installation; the existing source build,
SDK, private cache, recipe and resource files must remain available for recheck.

`validate_inputs(prefix)` verifies the installed package again. It accepts a
curated prefix containing other packages, but fixes the notification ELF,
license and receipt paths. It rejects input/output aliases, path escapes,
modified source or dependencies, stale producer/recipe/SDK identities, wrong
targets and modified or unbounded ELFs. The build's temporary Cargo source
directory has already been deleted: only local manifest paths beneath that
recorded directory are relocated to the verified complete `build/source` export.
External dependency paths must still lie in the selected private Cargo cache.
An installation admitted with `--full-os-linked-elf` retains that explicit mode
and repeats the same Full OS parser and original failed-build checks during
revalidation; it cannot silently switch to the default cross-build path.

The receipt binds the full Rust library inventory at installation time. The
original build report binds the build-time identities it recorded, including
std and unwind; installation does not add retrospective proof for other tools
or libraries. Every runtime flag remains false. Successful host tests or
installation do not establish D-Bus delivery, a visible Wayland notification,
closure/expiry semantics, panel integration, or a complete COSMIC session.
