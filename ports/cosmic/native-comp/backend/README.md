# Cyxia backend patch source

These files generate `cosmic-comp-native-backend.patch` against the pinned
cosmic-comp export after the nested and offscreen patches. They become
`src/backend/cyxia/*` in the actual compositor. The pinned Git checkout is
never edited. `build_patch.py` requires a new output directory and writes
the patch and its before/after SHA256 manifest.

```sh
python3 ports/cosmic/native-comp/backend/build_patch.py \
  --base artifacts/v017-cosmic-native-20261115-r1/patched-source-02/source \
  --work artifacts/new-native-source
python3 ports/cosmic/native-comp/backend/tests/test_patch.py
```

`--no-default-features --features backend-cyxia` selects the native-only
build. `COSMIC_BACKEND=cyxia` selects it explicitly in a mixed build. Existing
default features and KMS/nested selection priority are retained.

The backend queries Cyxia ABI v1 before EGL initialization, uses the linked
Mesa `eglGetProcAddress` to initialize Smithay's real dispatch table once,
and creates `EGLSurfacelessDisplay`, `EGLContext`, `GlowRenderer`, and a
persistent `GlesRenderbuffer`. It calls the existing COSMIC
`render::render_output` with its real `Common`, `Shell`, workspaces, windows,
screen filter and cursor. CPU readback waits for the rendering fence, then
retains Smithay's real `GlesMapping` while a resumable cursor submits at most
16 native XRGB tiles per timer dispatch. EAGAIN and EINTR return immediately
to the event loop. No display-busy sleep blocks input or Wayland dispatch.
Failed partial presentation does not send frame callbacks or presented
feedback. Presentation requests are captured before the first yield, so a
newer commit is never reported as the older submitted frame.

The input ABI has no pollable descriptor. A calloop timer reads at most 128
records per dispatch, preserves SYN framing, reconciles held keys after
SYN_DROPPED, and forwards keyboard/button/relative-pointer actions through
the real COSMIC `State::process_input_event`. A separate ledger records
delivered input so a later read failure cannot hide pressed keys/buttons
when shutdown releases them. Rendering is dirty-driven and paced separately;
commits received during pending tile submission survive completion. The
60 Hz mode is a scheduling policy: ABI v1 does not
provide physical refresh measurements. Presentation feedback uses unknown
refresh and no vsync or hardware-timestamp flags.

The output has a fixed framebuffer size and orientation. ABI v1 has no
hotplug, rotation, DMA-BUF render node, power control or VRR interface. No
DMA-BUF global is advertised; clients use the existing wl_shm path. Native
input currently supports keyboard, relative pointer and three buttons;
unsupported packets are dropped and reconciled at the next SYN_REPORT.
Shutdown removes the timer, releases held input and device membership,
removes the output, destroys the GL resources and checks EGL thread release.

Session locking installs an internal shell/focus barrier immediately and
cancels an outstanding unlocked frame. The native backend retains the real
`SessionLocker` while a separate resumable cursor overwrites the entire
output with opaque black. It sends the protocol's `locked` event only after
the final successful tile; surfaces configured during blanking are retained.
Busy or partial submission cannot acknowledge the lock. Failure or a dead
owner leaves isolation in place, and replacement starts a fresh full blank.
Lock-resource liveness is checked separately from client connectivity, so a
client can destroy its pending lock and request a replacement without disconnecting.
New native input is decoded while blanking but never added to the delivered
input ledger or forwarded into the unlocked scene. Releases from other input
backends can reconcile pre-lock holds while the shell focus barrier remains
active; new presses, motion and gestures remain blocked.
Native focus writes and popup-grab installation also check the current shell
lock. Ordinary layers and popups cannot reclaim focus within the same dispatch;
lock surfaces must be alive, owned by the current locker and registered to an
output. Existing show-on-lock layer and popup-root rules remain available.

The existing `native.rs` is preserved as an exact prefix, with one documented
child-module declaration for resumable presentation appended. `linux_syscall.rs`
is an exact copy. The Python test checks these identities, all patch
preimages/postimages, the base patch hash and every new source file. Its
optional `--rust-tests` flag acquires the shared native
session lease and checks the host is idle before compiling the actual
patched ABI, cursor, delivered-input ledger, frame schedule, lock ownership
barrier and backend selector. This runs 24 native policy tests and four selector tests in each
of four feature combinations. Additional tests use the real Smithay input
traits, primary-output policy and COSMIC output configuration types; these
require the compositor's dependency closure. No stub traits are used.

These source/ABI tests do not link cosmic-comp, run Mesa rendering, exercise
the full compositor input pipeline or prove a Cyxia COSMIC guest session.
The integration workflow owns native-feature cross-typechecking, native
library linking, runtime services, image capacity and guest receipts.
