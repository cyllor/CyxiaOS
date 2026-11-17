# Versioned notification static bindings

This port builds the pinned upstream `cosmic-notifications` 1.10.0 program at
commit `1e4c1f11fdcae273d6954fd0bfc54749a6145267` with real static Wayland and
XKB client bindings. It has separate source export, build and installation
entry points. The earlier notification builders, source checkout, registry
extractions, failed build reports and installation receipts remain unchanged.

## Exact source changes

The source policy binds the complete upstream Git tree, every file in two
checksum-verified registry archives, all three patches and the complete final
export. Git identity checks disable replacement objects. The exporter copies
whole packages, including their licenses, to `native-deps`; it never modifies
the source cache or registry extraction.

| Input | Reviewed change |
| --- | --- |
| Notification root | Remove the exact root Cargo configuration; supply its `tokio_unstable` flags explicitly; enable `cyxia-static` and two local crate overrides. |
| `wayland-sys` 0.31.11 | Add `cyxia-static-client` and the existing native-settings function-table mechanism, whose entries reference actual statically linked `wayland-client` symbols. Its build script probes the real static library. |
| `xkbcommon-dl` 0.4.2 | Add the existing compositor `static-link` mechanism, whose core, compose and X11 tables reference actual `xkbcommon` and `xkbcommon-x11` symbols. |

The root Cargo lock changes exactly three package records: the notification
package gains two direct dependency names, and the two overridden registry
packages lose only their registry `source` and `checksum` fields. Package names,
versions and all other lock records stay fixed. The effective lock hash is
`2b1590c107e77d72c3f29b45733f9a2ed470f39462e0b247e95dbfeac185dd78`.

The normalized target resolution binds every package, source, selected feature,
workspace membership and dependency edge. Upstream GUI, accessibility, Wayland
and X11 features remain selected; only the three static feature additions and
two direct root edges are permitted. The existing X11 loader dependencies are
still present. This port establishes a static Wayland client path and retains
the XKB X11 bindings; it does not establish a complete static X11 session.

The genuine `--locked --offline` metadata run on 2026-11-16 completed in
37.927 seconds with status `METADATA_VERIFIED_NOT_BUILT`. It verified 493 target
packages, three workspace packages and five local packages against graph hash
`49a3bee6a78e71ce6f86d8e684776ba5ed1c74a806d8c11585803b85f2520255`.
Its evidence is preserved under
`artifacts/v017-cosmic-runtime-20261116/notifications-static-metadata/`.
That operation did not compile or link the notification program, and all link
and runtime flags in its report remain false.

## Source export and native build

The source-only exporter invokes read-only Git commands and applies the three
exact patches in a new directory. It does not invoke Cargo, download sources,
probe a compiler or run a guest. The source-only receipt always records
`cargo_resolution_verified=false`; the later genuine Cargo operation records
its own resolution result.

```sh
python3 -B tools/prepare_cosmic_notifications_static_v1.py \
  --source-cache artifacts/cosmic-sources \
  --cache artifacts/cosmic-runtime-cargo-cache \
  --output artifacts/notifications-static-source
```

The recipe binds the separate `runtime-sdk-x86_64` assembly receipt and twelve
actual native inputs: libc, compiler builtins, three CRT objects, Wayland client,
libffi, XKB common, XKB common X11, XCB XKB, XCB and Xau. It cannot consume the
previous SDK by silently adding missing libraries or substituting host inputs.
The actual SDK assembly and its original inputs remain available for recheck.

**The caller must hold the shared native lease before invoking the build entry
point.** This versioned entry point has no `--native-lock` option; its internal
SDK lock does not replace the shared caller-owned lease. Use the existing
`native-session.lock` coordination for Cargo, compiler and guest operations.
For an existing lease owner, the metadata command is:

```sh
python3 -B tools/build_cosmic_notifications_static_v1.py \
  --recipe ports/cosmic/native-notifications-static-v1/native-recipe.json \
  --resource-profile ports/cosmic/native-notifications-static-v1/resource-profile.json \
  --source-cache artifacts/cosmic-sources \
  --cache artifacts/cosmic-runtime-cargo-cache \
  --sysroot artifacts/v017-cosmic-runtime-20261116/runtime-sdk-x86_64 \
  --rust-root <installed-rust-root> \
  --host-cc <actual-clang-executable> \
  --jobs 2 --metadata-only \
  --output artifacts/notifications-static-metadata
```

For a real target build, omit `--metadata-only` and choose another fresh output
directory. The builder never reuses a previous target directory. Cargo remains
locked and offline, with explicit compiler flags and the preserved original
feature selection. The profile keeps two jobs, a 3600-second deadline for each
command, 3 GiB of combined output/scratch/cache growth, a 1 GiB free-space
reserve, a 64 MiB ELF/image limit and a 2 MiB stack. Metadata and compilation
receive separate command deadlines. Cargo's offline setting is recorded;
build-script network sandboxing is not claimed.

After compilation, source exports, dependencies, metadata bytes, SDK, tool
identities, recipe, resource profile and transitive producers are rechecked.
The genuine linked bytes undergo the separate fixed FullOsV3 ELF parser, which
also verifies the reviewed Rust loader-source identities. Only then can this
new builder publish `cosmic-notifications.elf` and set `status=cross-built`.
Failed attempts retain their own reports and evidence. This new producer does
not rewrite or reclassify any previous builder's failed report.

### Native archives during Rust rlib compilation

The first static-binding target attempt failed after 539.968 seconds while
compiling the `xkbcommon-dl` rlib. Rust reported that it could not find the
native static `xkbcommon` library; the final notification executable was never
linked. The existing final-link arguments named the SDK archives, but rustc
also needs the archives in its native search path when it bundles native
objects into an rlib. At that point the frozen environment's `output/native`
directory contained only `libunwind.a`.

The dedicated static-v1 producer now copies the seven already hash-bound SDK
archives into that existing search directory. It preserves the frozen
`-L native=<output>/native` selection and all final-link arguments. The complete
directory must contain exactly those seven archives and the existing unwind
archive. Every source and copy is checked for its target archive format,
content identity and canonical path. The build records the source paths,
bytes, hashes, search flag and exact file set, rechecks them before compilation
and publication, and records their final preservation result on failed builds
as well. The installer independently derives the same set from the pinned
recipe and toolchain; hashes supplied only by a report cannot admit a changed
archive or an extra search input.

The original failed report, all logs, preserved source and target directory
remain under `artifacts/v017-cosmic-runtime-20261116/notifications-static-build-v1/`.
Its `retained-producers/` directory preserves all thirteen reported producers,
the source policy, three patches, recipe, profile and an exact report copy.
The original report SHA-256 is
`7b8d3f511d41d7bbdc6fae0317e414b30e1c1c94d9a714432f6a81622c05bded`.
This repair changes neither upstream features nor SDK/source originals and
requires another fresh build output. A compiler-only rlib discovery test is
separate from a completed notification link or guest acceptance.

## Installation and read-only consumer APIs

The separate installer accepts only a complete preserved static-v1 cross-build.
Metadata-only output, previous-version reports, missing links, failed checks or
runtime claims are rejected. The original report supplies six explicit origin
paths; every selected path and all supporting identities are verified again.
Neither installation nor verification invokes Cargo, a compiler or a guest.

```sh
python3 -B tools/install_cosmic_notifications_static_v1.py \
  --build artifacts/notifications-static-build \
  --output artifacts/notifications-static-install
```

The installer stages and fsyncs the target ELF, upstream notification license,
both vendored crate licenses and `cosmic-notifications-static-v1-origin.json`.
It repeats full input validation and staged-file inspection before one atomic
directory rename. Source changes during copying, aliases, modified logs or
ELFs, altered modes and overlapping outputs prevent publication. Its status
is `INSTALLED_NOT_RUN`; every notification/session runtime flag remains false.

The original temporary Cargo source tree no longer exists at installation
time. Local metadata manifests must have belonged to that exact temporary
root; they are relocated only into the fully verified preserved `build/source`
tree. The two vendored manifest locations are exact. External dependencies
must remain under the report's selected private Cargo cache.

Read-only consumers can import
`tools.install_cosmic_notifications_static_v1` and call:

- `validate_build_directory(output)`: returns `origin` and fully verified
  `inputs`, including the ELF, source, metadata, complete resolution, SDK,
  producer and log identities.
- `validate_inputs(prefix)`: replays the same build validation, validates the
  installation receipt and all installed files, and returns
  `status=VALIDATED_NOT_RUN` with the complete `receipt`.

A curated prefix may contain other genuine services. This package fixes
`cosmic-notifications.elf` for `/bin/cosmic-notifications`, its three license
paths and its versioned receipt. Capture tools must revalidate these inputs
before and after guest execution. Installation and host contract tests do not
establish D-Bus ownership/delivery, a presented notification surface,
expiry/closure semantics, panel integration or full COSMIC session readiness.

Run the narrow host regression suites with:

```sh
python3 -B -m unittest tools.test_cosmic_notifications_static_v1 \
  tools.test_install_cosmic_notifications_static_v1 -v
```

These tests use explicit parser/source/identity fixtures. Their successful
results are not native build or guest acceptance evidence.
