# Independent anchored-resize clients

[`smithay_resize_client.c`](../../user/ported/smithay_resize_client.c) is a
separate AArch64 libwayland fixture for top-left and left-edge resizing,
ordinary repaint after an anchored resize, and cancellation when the owner
unmaps while its pointer button remains physically held. Two real processes
use independent Wayland connections on descriptor 3. No peer descriptor,
synthetic pointer event or client-initiated frame progression is used.

The earlier interactive client and its forged, foreign-owner and stale-serial
tests remain unchanged. This fixture adds two actual resize directions and
owner-unmap cancellation; it does not demonstrate all eight resize directions,
Escape cancellation, dynamic application connections or a complete COSMIC
session.

## Source and build

[`smithay-resize-client-source.json`](../../ports/cosmic/smithay-resize-client-source.json)
pins the existing `wayland-protocols` 0.32.13 archive and exact upstream
`stable/xdg-shell/xdg-shell.xml` member. Its XML SHA256 is
`7ba7f9c8473deee674cb1f154a18abd0bb0cc072604fc055b0c15e459fc4c7df`.
The identity-checked native Wayland 1.24.0 scanner generates the client bindings.
The client binds compositor v4, seat v7, SHM ARGB8888 and xdg-shell v1, and
parses Smithay's real sealed keyboard map using xkbcommon.

```sh
python3 tools/build_smithay_resize_client.py \
  --output artifacts/smithay-resize-client-new
python3 -m unittest discover -s tests/host \
  -p test_smithay_resize_client.py -v
```

Build output must be new. The builder uses the SDK under a shared read lock,
does not download or install dependencies, and hashes all actual compiler,
source, generated protocol and SDK inputs before and after linking. Six host
tests reject altered archives, incorrect XML identities, stale scanners,
unexpected generated headers and overwriting old evidence.

Every `RS_CLIENT` receipt fits one 64-byte console write. Short writes fail;
an interrupted write retries the same complete record. Four more host tests
compile the actual C emitter and check maximal serial values, the 64/65-byte
boundary, interrupted writes and short writes. Cross-compilation and those ten
host tests alone do not establish guest behavior.

The initial cross-build is
[`smithay-resize-client-r0`](../../artifacts/smithay-resize-client-r0/build-report.json).
Its 411,960-byte ELF SHA256 is
`2e3cf9a7125c07af819b5f3e4d8e98ab56367f83bdce23508ee6e59d81331a63`.
The report binds 64 actual build inputs.

## Real input and configure contract

A initially occupies `(24,16,64,48)` in a 128×96 canvas. B occupies
`(40,24,64,48)` and starts above A with keyboard focus. The pointer begins at
canvas `(32,24)`, A-local `(8,8)`.

| Scene | Required behavior |
| --- | --- |
| 0 | Both initial buffers visible; B active |
| 1 | Actual left press activates A and requests top-left edge 5 using that press serial |
| 2 | Motion `(-8,-4)` yields A `(16,12,72,52)` |
| 3 | Motion `(+12,+8)` yields A `(28,20,60,44)` |
| 4 | Left release ends resizing with a final 60×44 non-resizing configure |
| 5 | D press/release paints an ordinary 60×44 frame, preserving `(28,20)` |
| 6 | Actual right press requests left edge 4 with its own fresh serial |
| 7 | Motion `(-16,0)` yields A `(12,20,76,44)` |
| 8 | Q press/release closes and unmaps A while right remains held; B survives |
| 9 | Actual background right release produces no event for B |
| 10 | D press/release paints B's health frame |
| 11 | Q closes B; canvas is black |

Both resize gestures preserve the original opposite edge: the first holds
bottom-right `(88,64)`, while the second holds right edge x=88. Position and
size must become visible together when the corresponding ACKed buffer commits.
An ordinary repaint must not reapply an already-consumed position change.

A's configure sequence is `(width,height,activated,resizing)`:
`(64,48,0,0)`, `(64,48,1,0)`, `(64,48,1,1)`, `(72,52,1,1)`,
`(60,44,1,1)`, `(60,44,1,0)`, `(60,44,1,1)`, `(76,44,1,1)`.
B receives 64×48 throughout, with activation states `1,0,1` and no resizing.
Each exact configure serial is acknowledged before the responding commit.

A's eight frame seeds are `0,272,272,272,272,32,273,273`; B's two are `0,32`.
Nonzero seeds come from that client's actual received physical input. A frame
requires an actual configure or D release; callback arrival alone does not
trigger another repaint. Frame callback timestamps identify presented scenes:
A `0..7`, B `0,10`.

## Focus, cancellation and lifetime

A receives exactly two real pointer presses, two enters at local `(8,8)` and
two leaves as the compositor takes its resize grabs. Neither client may receive
grab motion or button release. After A's unmap, neither a stale A enter nor a
closing pointer leave is valid; B receives no pointer event at any stage.
A receives D and Q key pairs, with Q accepted only while its final resize is
active. B receives D and Q only after A has closed. Keys require keyboard focus,
activation and the exact xkb translation. Optional keyboard leaves during each
owner's teardown are bounded separately from normal focus changes.

Each frame uses a fresh sealed memfd and a writable shared mapping. The client
creates the real SHM pool and buffer, closes its local descriptor, completes a
server roundtrip and only then writes pixels. Independent scanout validation
therefore requires live shared pages. Each actual callback and buffer release
is counted once; mappings and buffers are destroyed only after release.

The client requires one actual `xdg_toplevel.close` after the final Q release,
commits a null buffer, synchronizes and destroys every released buffer and role
before disconnecting. Final receipts require A's eight frames/callbacks/releases,
eight configure/ACK pairs, four key events, two presses and two resize requests.
B requires two frames/callbacks/releases, three configure/ACK pairs, four key
events and no resize requests. The host verifier must additionally prove real
QMP input order, all physical scanout pixels, cancellation before the held
button release, surviving-client health and complete resource reclamation.

## Native runtime evidence

[`smithay-resize-runtime-r0`](../../artifacts/smithay-resize-runtime-r0/summary.json)
passed three independent single-core ARM QEMU boots. The summary SHA256 is
`2dbdb388548d8adabd1067ee8ca327c99ca873b5d7715bd359cb30e5ec6bfcdc`.
Across the three boots, the gate verified 36 physical scenes, 442,368 pixels,
45 actual QMP input commands, 33 configure/ACK pairs and 30 real buffer
commits, callbacks and releases. Every screenshot passed on its first attempt.
All three runs demonstrated owner unmap while the right button remained held,
then its physical release with no stale owner focus or unmatched survivor
event, followed by a successful B health repaint and clean exit.

The independent
[`raw evidence audit`](../../artifacts/smithay-resize-audit-r0/review.json)
passed with no findings. Per boot, it decoded 533 CRC-checked UART frames,
verified 214 complete atomic protocol records, independently repainted all
physical screenshots and checked 23 distinct configuration/button/key serial
allocations. Raw UART prefixes captured before host injection proved every
client frame/focus barrier and the transition from one held button in a
focusless cancellation grab to no held buttons and no grab.

The audit rechecked 490 provenance bindings and 118 kernel source identities,
both live client process identities, QMP completion order and final resource
reclamation. The three boots completed 108 local-AI display admissions with
zero CPU guard selections and zero display guard admissions. This verifies the
two exercised resize directions and owner-unmap cancellation; the broader
desktop boundaries above remain unchanged.
