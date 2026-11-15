# COSMIC native backend separation

This directory tracks patches to the actual `cosmic-comp` commit
`41497b42d9744d9963c4c6d17e8add49489b45ee`. It does not contain a replacement
compositor, and the patch series is not yet a native backend or a built
COSMIC session.

`series.json` orders the existing nested-backend separation patch and the
new offscreen-rendering separation. Every patch has matching before/after
file hashes. The source Cargo.lock and upstream commit are also bound. Apply
the series to a fresh export; leave the pinned Git checkout unchanged.
The series pins each manifest SHA256, and the build recipe pins the series.

The actual patched compositor now passes an x86_64 musl cross-typecheck with
`backend-winit`; see [the implementation record](../../../docs/implementation/v17-cosmic-comp-20261115.md).
This checks common compositor code, not the cfg-disabled KMS module, a link,
or a Cyxia native backend. `cross-check-recipe.json` and
`cross-check-profile.json` reproduce this bounded compiler check.

## Implemented boundary

The common compositor now requests a renderer using
`BackendData::offscreen_renderer(OffscreenTarget<'_>)`. `OffscreenTarget`
contains Wayland/output objects and no KMS, DRM-node, GBM, or libseat types.
The request has the same shape with or without the KMS feature.

| Request | Preserved KMS device choice |
| --- | --- |
| `Primary` | Primary device; otherwise the existing software renderer |
| `Output` | Output device, then primary |
| `Surface` | Committed surface buffer device, then primary |
| `OutputBuffer` | Render on output/primary; copy to destination buffer's device when present |
| `SurfaceBuffer` | Destination buffer device, then committed surface device, then primary |
| `Screenshot` | Device advertised to the client, then primary |

The KMS backend owns resolution of these objects, destination pixel format,
and renderer construction. If no device resolves, the pre-existing software
renderer path is used; its existing missing-renderer error behavior is
preserved. A destination buffer by itself does not invent an output renderer.

The patch leaves the actual `State`, `Common`, `Shell`, workspace/window
layout, `render_session`, `render_workspace`, frame completion, and pixel
rendering implementations in use. The Winit and X11 branches still return
their real Glow renderer. This is a prerequisite for a Cyxia Glow branch,
not an implementation of that branch.

## Verification

Run from the repository root:

```sh
python3 ports/cosmic/native-comp/tests/test_offscreen_patch.py
```

The check applies both patches to a temporary copy, verifies every new patch
preimage/postimage and patch hash, then compiles the actual patched
`kms/offscreen_policy.rs` with seven dependency-free Rust tests. It acquires
the existing native-session lease before rustc and checks that the host is
idle. No Cargo dependency resolution, renderer, GPU, or guest is involved.

2026-11-15: missing-patch regression observed first; patch application and all
seven Rust tests passed. Rustfmt parsed the nine changed/new Rust modules.
Full compositor typechecking, actual GL rendering, Wayland buffer resolution,
and guest execution remain unverified by this test. The root integration
workflow owns those checks and final review/commit.

## Source-backed remaining work

References below refer to the immutable upstream checkout; the first patch
already gates much of the KMS/X11/Winit plumbing described here.

- `src/backend/mod.rs` and `src/state.rs:334`: the only actual backend
  variants are KMS, Winit, and X11. The nested patch's `src/lib.rs` correctly
  rejects a build with none enabled. A native backend still needs output
  creation, rendering/presentation, render scheduling, input/event delivery,
  configuration and shutdown connected to `State`/`Common`.
- `src/backend/winit.rs:51` shows the real single-renderer integration:
  `render::render_output`, buffer submission, `Common::send_frames`, primary
  output updates and presentation feedback. A native port should reuse this
  common rendering path with the existing Cyxia display/input ABI, rather
  than inserting an independent scene fixture.
- `src/backend/render/mod.rs:99` originally ties `RendererRef`,
  `GlMultiRenderer`, and `GlMultiError` to GBM multi-GPU types. The nested
  patch gates this and uses a real GLES error type without KMS. This patch
  additionally removes all common capture callbacks taking `&mut KmsState`.
- `src/state.rs:160`, `src/shell/element/surface.rs:23`, and
  `src/wayland/handlers/drm.rs` retain actual `DrmNode`/DMA-buffer protocol
  types. The nested Cargo patch deliberately retains Smithay `backend_drm`.
  Removing that feature alone cannot compile this code; its protocol and
  buffer semantics need an explicit portability decision.
- `src/state.rs:257`, `src/input/mod.rs:103`, `src/libei.rs`, and
  `src/lib.rs:180` retain libei state, backend identities, and initialization.
  Smithay `backend_libei` is still unconditional after the nested patch.
  It must be provided or separated consistently across all of these uses.
- `src/xwayland.rs`, `src/shell/element/surface.rs`, and the Xwayland handlers
  retain real X11 window types and protocol integration. `--no-xwayland`
  disables launch at runtime; it does not remove Smithay `xwayland` or its
  compilation dependencies.
- `src/state.rs:766` initializes `DBusState`; `src/config/mod.rs`,
  `src/theme.rs`, `src/session.rs`, and `src/utils/iced` retain the actual
  COSMIC configuration/session/theme/UI integration. Systemd's optional
  feature does not remove D-Bus or replace these services.
- Upstream Cargo.lock has 698 packages; the full locked source inventory is
  now available. The patched Winit feature selection resolves 487 packages
  and passes cross-typechecking. A successful Smithay fixture build covers
  a different closure. Linking, KMS compilation, and a Cyxia native-guest
  receipt remain outstanding.
