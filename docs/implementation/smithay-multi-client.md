# Independent concurrent xdg-shell clients

[`smithay_multi_client.c`](../../user/ported/smithay_multi_client.c) is a real
AArch64 libwayland client used by the native Smithay multiwindow gate. The
compositor starts two separate processes with argument `1` or `2` and an
independent connected Unix stream inherited as descriptor 3. Both clients
remain alive while their windows overlap. Each uses upstream Wayland 1.24.0,
generated xdg-shell version 1 bindings and a real xkbcommon keymap.

This bounded test exercises two fixed 64×48 windows, activation, stacking,
pointer hit testing, keyboard focus and close fallback. It does not establish
arbitrary application compatibility, resize/move gestures, popup grabs,
decorations, clipboard support or a complete COSMIC session. The previous
[single-window xdg-shell client](smithay-xdg-client.md), including its malformed
protocol test and resize coverage, remains separate.

## Protocol source and build

[`smithay-multi-client-source.json`](../../ports/cosmic/smithay-multi-client-source.json)
pins the same `wayland-protocols` 0.32.13 archive as Smithay. The builder verifies
both the archive and exact upstream `stable/xdg-shell/xdg-shell.xml` member,
then invokes the SDK's identity-checked native `wayland-scanner` 1.24.0 to
generate the client header and private protocol C source. The XML SHA256 is
`7ba7f9c8473deee674cb1f154a18abd0bb0cc072604fc055b0c15e459fc4c7df`.

```sh
python3 tools/build_smithay_multi_client.py \
  --output artifacts/smithay-multi-client-new
python3 -m unittest discover -s tests/host \
  -p test_smithay_multi_client.py -v
```

The builder requires fresh output, takes a shared read lock on the SDK,
performs no download or target execution, and never installs into the SDK.
Compiler dependency records restrict headers to the target sysroot and exact
generated header. All 64 source, generated, SDK and toolchain identities are
recorded and checked again after linking. Six host tests reject altered
archives, mismatched XML pins, changed scanners, unexpected generated-directory
headers and accidental overwrite of existing evidence.

The current build is
[`smithay-multi-client-r3`](../../artifacts/smithay-multi-client-r3/build-report.json).
Its 411,960-byte ELF has SHA256
`a857fd73238be49ebc32b194bda261861a53bdd10002ea9391faf8dba8209a6a`.
The earlier builds are retained: r1 corrected the manifest's copied component
name, while r2 introduced bounded telemetry and r3 fixed a receipt that still
exceeded its byte limit. Cross-compilation alone is not runtime evidence.

CyxiaOS's console accepts at most 64 bytes per syscall. Concurrent processes
can interleave continuations of longer writes, so every client receipt is a
complete line bounded to 64 bytes and emitted with one successful write.
Short writes fail instead of emitting a spliceable continuation. A zero-write
`EINTR` retries the complete record. Four additional host tests compile the
actual C emitter and exercise the 64/65-byte boundary, longest receipts, short
writes and interrupted writes. The full client host suite contains ten tests.

## Independent protocol and input checks

Each process binds `wl_compositor` version 4, `wl_shm` ARGB8888,
`xdg_wm_base` version 1 and `wl_seat` version 7. It creates an xdg toplevel and
makes an initial empty commit. Every received configure must have the exact
64×48 size and the activation sequence below; the exact configure serial is
acknowledged before buffer submission.

| Client | Placement in 128×96 canvas | Configure activation sequence | Frame pixel seeds |
| --- | --- | --- | --- |
| A / 1 | `(8, 8)` | inactive, active, inactive, active | 0, 272, 48, 273, 32 |
| B / 2 | `(40, 24)` | active, inactive, active | 0, 30, 272, 46 |

The initial pointer is at canvas `(48, 32)`, inside B at local `(8, 8)`.
Physical input drives all subsequent frames: A key updates B; left click in
A's exclusive region activates and raises A; B key updates A; right click in
the overlap must still target A; left click in B's exclusive region raises B;
C key updates B. Q closes B and keyboard focus returns to A even though the
pointer is outside A. D updates A and the final Q closes A.

Each process accepts only its own exact physical codes and press/release
order. Keyboard events require both keyboard focus and activated state.
Pointer buttons require local pointer coordinates, keyboard focus and
activation. A expects keys B, D, Q and buttons left, right; B expects keys
A, C, Q and one left click. Unexpected, duplicate, unfocused or out-of-order
events fail immediately. The next frame is never generated merely because a
frame callback arrived: it additionally requires the expected physical release.

The real sealed keymap descriptor is mapped read-only with `MAP_PRIVATE` and
parsed by xkbcommon. Each key's physical code must translate to the expected
lowercase keysym. Both clients require exactly two keyboard enters and one
keyboard leave before close. A requires one pointer enter, one motion and one
leave; B requires two pointer enters and one leave. Optional final leave
events during the client's own teardown are bounded and recorded separately
as `closing=1`; they do not substitute for normal focus transitions.

## Buffer lifetime and exit

Every frame creates a fresh memfd and shared writable mapping. The client
creates its real `wl_shm_pool` and `wl_buffer`, destroys the pool object,
closes the local descriptor and completes a server roundtrip before writing
any pixels. The independently computed scanout oracle therefore requires
actual shared pages rather than an import-time pixel copy. The established
RGB formula includes the client identity, local frame number and the physical
input code received by that process.

Frame callbacks must arrive once and in frame order after actual composition.
Buffer release is independently counted; its relative timing is not assumed.
The client keeps all mapped buffers valid until their real release events.
After the final Q release it requires exactly one `xdg_toplevel.close`, then
attaches null, commits, synchronizes, destroys every released buffer, unmaps
its pages and destroys the roles in protocol order before disconnecting.

Successful final client receipts require A's five frames, five callbacks, five
releases and ten physical events, and B's four frames, four callbacks, four
releases and eight physical events. Guest receipts alone are insufficient:
the runtime verifier also checks both concurrent process identities, server
configure acknowledgements, focus and stack state, all physical scanout
pixels, QMP input ordering, process exits and resource reclamation.

The compact final records split frame/input totals, focus totals and shell
completion without dropping any of those requirements:

```text
MULTI_CLIENT COUNTS id=1 f=5 cb=5 rel=5 ev=10
MULTI_CLIENT FOCUS id=1 ke=2 kl=1 pe=1 pl=1
MULTI_CLIENT RESULT PASS id=1 configures=4 acks=4 close=1
```
