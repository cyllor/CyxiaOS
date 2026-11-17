# Genuine cosmic-session: explicit Linux host build v1

This independent producer builds the existing native port of genuine
`cosmic-session`. It preserves the historical producer, recipe, patch manifest,
source caches and failed evidence. The new recipe changes only the explicit
Linux resource profile and the five SDK input hashes verified in the current
x86 SDK. The source patch is an exact copy of the historical patch.

| Input | Fixed identity |
| --- | --- |
| cosmic-session | `8093b59bb1262b0612d814e6540ba936303f735a`, version `1.10.0` |
| launch-pad | `5b516ee6a012b5ad4a5acc0cf51b4472fc6733af`, version `1.0.1` |
| NativeChild/source patch | `45f9afc4f664bde364d87ca12bedb014fa189f85e8b95feb23135f9286a6ce3d` |
| Source Cargo.lock | `8cda0355e1b1b55abe8d71f7446a040e5e872cd9c5a1c03147e9c25a94157afd` |
| Patched Cargo.lock | `69a3d3c9796c3816d4dfedefded59b860e9ec4608ca881b3f15232404e7e30dd` |
| Session features | `--no-default-features --features cyxia-native` |
| launch-pad features | Exactly `cyxia-native`, selected as the root package's dependency |
| Target | `x86_64-unknown-linux-musl` |

`source-policy.json` binds the original historical patch manifest and its
support files. Both complete original Git trees must match that manifest,
including upstream origin, immutable commit/tree/blob identities, file modes
and file closure. The launch-pad source is supplied at the newly acquired
canonical `launch-pad-5b516ee` cache directory. This relocation leaves the old
manifest and its old path untouched.

The producer exports only verified canonical Git blobs, applies the unchanged
patch, checks every retained file against the fixed before/after map, and keeps
the entire result in `output/source`. No checked-out source is patched in place.

## Commands

The CLI requires the shared native lease even for metadata because Cargo and
compiler version probes are native host processes. Source acquisition is a
separate bounded operation. Both commands below are locked and offline; a
missing dependency produces a preserved failure rather than a network fetch.
Every output must be fresh. Do not reuse a failed output or modify an input SDK.

From the repository root, after the coordinator grants the native window:

```sh
python3 -B tools/build_cosmic_session_linux_v1.py metadata \
  --recipe ports/cosmic/native-session-linux-v1/native-recipe.json \
  --resource-profile ports/cosmic/native-session-linux-v1/resource-profile.json \
  --source-cache artifacts/cosmic-sources \
  --cache artifacts/cosmic-runtime-cargo-cache \
  --sysroot artifacts/v017-cosmic-runtime-20261116/runtime-sdk-x86_64 \
  --rust-root /workspace/scratch/99a018f40879/toolchains/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu \
  --host-cc /workspace/scratch/99a018f40879/cosmic-work/tooling/prefix/usr/lib/llvm-19/bin/clang \
  --native-lock artifacts/v017-cosmic-completion-20261116/native-session.lock \
  --output artifacts/v017-cosmic-runtime-20261116/session-linux-v1-metadata
```

For compilation, use the same explicit inputs, change the operation to `build`
and select a different fresh output, for example
`artifacts/v017-cosmic-runtime-20261116/session-linux-v1-build`. Build uses the
exact local package ID returned by metadata and `--bin cosmic-session`.

The selected Linux Rust toolchain must be at least 1.93 and contain genuine
official x86 musl standard libraries and unwind. The receipt records the
selected Rust/Clang paths, binary identities, version observations, SDK tree,
all target `.rlib`/`.a` files, native inputs and generated linker wrappers. The
five recipe hashes are for the current core SDK bytes; the driver is validated
at its actual relocated path rather than compared to an obsolete driver path.

## Bounds and failure behavior

The explicit profile permits one job, one shared 900 s deadline, at least 1 GiB
free space and at most 512 MiB of output, temporary export and Cargo-cache
growth. These are experimental build bounds. Exceeding a bound preserves a
failed report and partial logs; it does not justify expanding a runtime pool.

Successful ELF admission uses the fixed current `FullOsV3` contract: a maximum
64 MiB file and private image backing, with a 2 MiB stack included in that
backing. The inspector checks the real linked executable, load segments, page
budget, TLS, W^X, entry point and the other production parser constraints. This
proves parsing/admission, not execution or an AI resource grant.

Producer and input checks run on failure as well as success. Missing mandatory
logs, changed source/dependencies/toolchain, invalid ELF, expired bounds,
publication failure, receipt write failure and interruption cannot leave an
installable success. The raw target link and failed evidence are retained;
the published `cosmic-session.elf` is revoked. A metadata-only receipt always
has `target_linked=false` and no published ELF.

## Read-only consumer

```python
from tools.cosmic_session_inputs_v1 import validate_build

identity = validate_build(
    "/workspace/scratch/99a018f40879/CyxiaOS-cosmic/artifacts/"
    "v017-cosmic-runtime-20261116/session-linux-v1-build"
)
```

The consumer runs no Cargo, compiler, version probe or target program. It
accepts only a complete `cross-built` receipt from the current transitive
producer closure. It rechecks the two original sources, patch/support files,
retained source, exact Cargo command/feature selection, real Git dependencies,
SDK, tools, generated inputs, all target Rust archives, mandatory logs, raw
link and published FullOs inspection. Registry packages must match the exact
Cargo.lock checksum, the `.crate` in their actual cache namespace, and every
extracted file and directory. A mutable checksum sidecar cannot replace that
archive check.

Cargo's original metadata remains unmodified. After the temporary export has
been deleted, only local manifest paths below its recorded root are relocated
to `output/source`; external dependencies stay in their verified cache paths.
The original local package ID remains bound to the recorded build command.

The returned status is `SESSION_BUILD_REVALIDATED_NOT_RUN`, with stable input
identity, `receipt_sha256`, executable path/SHA/size, load/required page counts
and full inspection. Both `guest_execution` and `cosmic_session_ready` remain
false. A separate runtime capture must prove actual embedding, process
startup, compositor/environment handoff, DBus and the required genuine
session services before making a runtime claim.

## Host verification

```sh
python3 -B -m unittest tools.test_cosmic_session_linux_v1 tools.test_cosmic_registry_inputs_v1 -v
```

The tests use real temporary Git repositories, real patch application, exact
archive extraction comparisons and production ELF parsing. Cargo/compiler
calls are fixture boundaries, and tool/ELF samples are explicitly labeled.
These tests are not native compilation or COSMIC runtime evidence.
