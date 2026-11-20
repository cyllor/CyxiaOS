# Native pointer damage v1

This GPL-3.0-only port extends the pinned COSMIC native backend after the
existing 64 KiB tile-capacity patch. It preserves the complete compositor,
Smithay damage tracking, renderer, framebuffer readback and presentation fences.
Only the region submitted to the native display is reduced.

The old `render_output` checked `damage.is_some()` and then submitted the whole
1024 × 768 output. A small pointer move therefore needed 48 successful native
tile submissions. `damage.patch` encloses all reported damage in one clipped
rectangle, including the old and new cursor positions. Pixels inside that
rectangle come from the unchanged complete readback; the mapping's vertical
flip is applied using the complete framebuffer height. Empty damage retains
the conservative full-frame behavior. Session-lock blanking still uses the
full-frame constructor. Allocation, tile budget, retry rules, stall deadline,
error poisoning and frame/presentation completion gates remain unchanged.

The backend fixes the native mode and `Flipped180` transform. Smithay reports
physical output damage, so its coordinates and the post-readback native image
use the same pixel space, independently of the logical output scale. A bounding rectangle can include unchanged pixels between
independent damage regions; this trades some unnecessary work for bounded
state and keeps the submission contract simple.

`base/` retains the exact preimages. `source-policy.json` binds both preimages,
the patch, both postimages and the existing tile ABI. Historical port recipes,
builders, SDKs, dependency archives and captured evidence are not rewritten.

Run the real cursor regression (injecting only the native submission boundary):

```sh
CYXIA_DAMAGE_BASELINE=1 python3 tests/host/test_cosmic_pointer_damage.py # expected FAIL: 48 versus 1
python3 tests/host/test_cosmic_pointer_damage.py
```

Build both complete compositors with the existing offline 468-package graph:

```sh
python3 tools/cosmic_native_pointer_damage_v1.py build \
  --output artifacts/v017-native-pointer-damage-build-v1 \
  --sysroot artifacts/sysroot/x86_64-musl \
  --rust-root /Users/robin/.rustup/toolchains/stable-aarch64-apple-darwin
python3 tools/cosmic_native_pointer_damage_v1.py assemble \
  --build artifacts/v017-native-pointer-damage-build-v1 \
  --base-build artifacts/v017-os-pointer-input-ring-v1 \
  --output artifacts/v017-native-pointer-damage-catalog-v1
```

The assembler admits the full build report and changes only `cosmic-comp.elf`
in the normal 129-input catalog. `--baseline` selects the matched full-frame
compositor for a control capture. Compilation and host tests alone do not
establish native pointer latency or a complete desktop session; use
`tools/os_cosmic_pointer_probe.py` against a built OS image for that measurement.
All native compiler and QEMU operations must share `tools/native_session.py`'s
exclusive lease. Use an available stable Rust toolchain for host regressions.
