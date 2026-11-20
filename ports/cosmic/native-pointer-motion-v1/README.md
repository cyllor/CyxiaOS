# Conservative background motion batching

This GPL-3.0-only layer follows `native-pointer-damage-v1`. It changes only
`dispatch_actions`, an allocation-free motion reducer, and the delivered-input
ledger's idle query. Raw kernel evdev records and the native input ABI remain
unchanged.

The reducer runs only when every pointer is unfocused and ungrabbed, no key or
button is held, and the complete decoded batch contains only relative motion.
It combines only adjacent collinear deltas moving in the same direction.
Turns, reversals, checked-add overflow and every mixed key/button batch retain
their original action order. A new decoded batch starts a new reduction; input
is never delayed to wait for more reports. Application-focused, grabbed, drag
and lock-suspended input retains the existing dispatch path.

This reduces redundant COSMIC processing when many hardware reports arrive
within one event-loop dispatch. Total relative displacement and the monotonic
clipping path are preserved; intermediate unfocused background motion events
are coalesced. Normal COSMIC processing still selects the final focus and
updates the pointer before any later button event.

`base/`, `motion.patch` and `source-policy.json` bind exact preimages and
postimages. The parent damage, tile and phase layers, compiler, full locked
468-package graph, SDK and native fences are preserved. Host regression:

```sh
CYXIA_MOTION_BASELINE=1 python3 tests/host/test_cosmic_pointer_motion.py # expected FAIL
python3 tests/host/test_cosmic_pointer_motion.py
```

The harness executes the actual `dispatch_actions` and native reducer with the
actual decoder and delivered-input ledger. The surrounding COSMIC state and
clock boundary are substituted. The complete native compositor must also be
measured with `tools/os_cosmic_pointer_probe.py`.

```sh
python3 tools/cosmic_native_pointer_motion_v1.py build \
  --output artifacts/v017-native-pointer-motion-build-v1 \
  --sysroot artifacts/sysroot/x86_64-musl \
  --rust-root /Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin \
  --reuse-build artifacts/v017-native-pointer-damage-build-v1
```

`--reuse-build` validates the previous full build, clones its Cargo target into
this new output using APFS copy-on-write, and keeps its identical admitted
unwind directory as a read-only linker input so Cargo can reuse dependencies.
Compilation outputs never modify the previous target. The new report binds
that input and validates it again at assembly. Omit this option for a fresh
build. Reusing dependencies does not mean every package was recompiled.

```sh
python3 tools/cosmic_native_pointer_motion_v1.py assemble \
  --build artifacts/v017-native-pointer-motion-build-v1 \
  --base-build artifacts/v017-os-pointer-batch-v1 \
  --output artifacts/v017-native-pointer-motion-catalog-v1
```

The assembler preserves the other 128 normal catalog inputs. All Cargo, rustc
and QEMU commands share the native-session lease. Compiling or reducing the
number of dispatched actions alone does not prove native pointer latency.
