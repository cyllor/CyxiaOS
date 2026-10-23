# Independent xdg-shell client

Verified on 2026-10-22 by three ARM/QEMU boots in
[`smithay-xdg-runtime-r2`](../../artifacts/smithay-xdg-runtime-r2/summary.json).
The separate AArch64 client uses real Wayland 1.24.0, generated upstream
xdg-shell bindings and xkbcommon. It exercises initial configuration,
acknowledgement, resize, close, shared buffers and physical seat input against
the [native Smithay integration](smithay-xdg-native.md).

This is a bounded xdg-shell version 1 integration. The healthy clients run
sequentially, with one toplevel visible at a time. It does not establish
concurrent window management, focus switching between windows, popup/grab
behavior, decorations, a COSMIC session or general Linux application support.

## Pinned protocol and isolated build

[`smithay-xdg-client-source.json`](../../ports/cosmic/smithay-xdg-client-source.json)
pins the same `wayland-protocols` 0.32.13 crate used by Smithay. Its archive
SHA256 is `23d0c813de3daa2ed6520af85a3bd49b0e722a3078506899aa9686fea58dc4b6`.
The builder checks the archive against the Smithay dependency manifest, reads
only the exact regular `protocols/stable/xdg-shell/xdg-shell.xml` member, and
checks that XML independently:
`7ba7f9c8473deee674cb1f154a18abd0bb0cc072604fc055b0c15e459fc4c7df`.

The existing SDK's verified native `wayland-scanner` 1.24.0 generates the
client header and private protocol C source. The compiled protocol is not a
handwritten opcode table or a copied file from an unchecked vendor tree.
Generated header SHA256:
`22d1e093faefd5ca07811c453a8246df65980f9978ad3de1b61f0033899704ce`;
generated protocol C SHA256:
`7788ec2e1e8774e4f069d361c450048ccb7e907a204d4ca2d74a64fab7bf7be5`.

```sh
python3 tools/build_smithay_xdg_client.py \
  --output artifacts/smithay-xdg-client-new
python3 -m unittest discover -s tests/host \
  -p test_smithay_xdg_client.py -v
```

The builder performs no download or guest execution. It holds a shared SDK
read lock, checks Wayland/xkbcommon archives and manifests, constrains compiler
header dependencies to the target sysroot and exact generated header, and
records all 64 actual inputs. Every build requires a new output directory;
recorded inputs are checked again after linking. Six host tests cover modified
archives, a mismatched XML pin, a changed scanner, unintended generated-directory
headers and preservation of existing output evidence. The earlier plain
`wl_surface` client and its frozen artifacts remain separate.

## Connection and initial handshake

The server starts `/bin/smithay-xdg-client` with a connected Unix stream
inherited as descriptor 3. `wl_display_connect_to_fd(3)` takes ownership.
Argument `0` selects the malformed connection described below; `1` and `2`
select independent healthy clients. The client binds `wl_compositor` version
4, `wl_shm` ARGB8888 and `xdg_wm_base` version 1. Healthy clients additionally
bind `wl_seat` version 7 with keyboard and pointer capabilities.

The healthy client creates a `wl_surface`, its `xdg_surface` and an
`xdg_toplevel`, then sets the title and application ID. It performs an initial
commit with no buffer attached. It requires a 64×48 toplevel configure with
the activated state followed by an `xdg_surface.configure`. The client
acknowledges that exact serial before its first buffer attachment. The server
independently validates the acknowledged serial and configured state.

Each event wait follows libwayland's prepare/read/cancel discipline, including
pending dispatch and output backpressure, with a 30-second monotonic timeout.

## Frames, resize, physical input and close

The surface dimensions and received-input pixel seeds remain identical to the
[plain Wayland client oracle](smithay-wayland-client.md#pixel-and-physical-input-contract).
The server draws each surface into a black 128×96 canvas presented at screen
coordinate `(32, 48)`. The host captures and checks all 12,288 pixels before
injecting the corresponding physical input sequence.

| Frame | Surface | Pixel seed | Physical input after capture |
| --- | --- | --- | --- |
| 0 | 64×48 | 0 | A key, code 30, press and release |
| 1 | 64×48 | Received key code 30 | Relative motion `(4, 3)`, then left button 272 press and release |
| 2 | 96×64 | Received button code 272 | Q key, code 16, press and release |

The actual sealed keymap descriptor is mapped with read-only `MAP_PRIVATE`
and parsed by xkbcommon. Each successful run received 23,019 keymap bytes per
healthy client. Key codes must translate to `a` and `q`; pointer movement must
match the prior enter coordinate and stay inside the surface. Duplicate,
out-of-order or unfocused input fails the client.

After forwarding frame 1's pointer release, the server sends a real activated
96×64 configure before completing that frame callback. The client checks the
dimensions and acknowledges the new serial before attaching frame 2. After
frame 2's Q release, the server sends `xdg_toplevel.close` before that frame
callback. The client requires exactly one close event in that position. The
callback barrier is a test synchronization policy: frame callbacks and physical
input remain distinct Wayland events.

Every frame uses a fresh memfd with shrink/grow/seal seals and a writable
shared mapping. After creating the real pool and buffer, the client destroys
the pool object, closes its descriptor and synchronizes with the server. It
then writes pixels, so correct rendered output proves shared pages survive
descriptor transfer and is not a snapshot taken during pool import.

The client replaces buffers without null attachments between frames. An xdg
null attachment unmaps the toplevel and would require a new initial configure
cycle. Only after close does this client attach null and commit once. All
three buffer objects and their mapped pages remain valid until each real
`wl_buffer.release` has been received exactly once, then are destroyed/unmapped.
Release is independent of frame callback ordering; the `FRAME PASS` marker
claims callback/input completion, while separate `RELEASE` markers and the
final result establish buffer lifetime completion. Role destruction is ordered
as toplevel, xdg surface, then wl surface.

## Malformed connection and recovery

Round 0 deliberately attaches a 64×48 buffer and commits before any initial
empty commit, configure or acknowledgement. It does not bind the seat or
request a keymap. Success requires libwayland to decode `EPROTO` with interface
`xdg_surface`, error `unconfigured_buffer` (3), and the exact ID of this
client's xdg surface. EOF, EPIPE, a timeout, another object or another error
cannot produce a passing result. The client then destroys local proxies and
disconnects.

Smithay's real protocol error and disconnect are independently checked by the
server. The rejected connection is first, followed by both successful clients,
so the run demonstrates that rejecting malformed protocol does not prevent
later healthy connections. In all three boots the rejected object was 7 and
the healthy configure serials were 1, 2, 3 and 4.

Representative actual client receipts are:

```text
XDG_CLIENT NEGATIVE PASS round=0 error=3 object=7 interface=xdg_surface disconnected=1
XDG_CLIENT CONFIGURE round=1 index=0 serial=1 width=64 height=48 activated=1
XDG_CLIENT ACK round=1 index=0 serial=1
XDG_CLIENT CONFIGURE round=1 index=1 serial=2 width=96 height=64 activated=1
XDG_CLIENT ACK round=1 index=1 serial=2
XDG_CLIENT CLOSE round=1 count=1
XDG_CLIENT RESULT PASS round=1 frames=3 callbacks=3 releases=3 input=1 configures=2 acks=2 close=1
```

These markers alone are insufficient evidence. The runtime verifier checks
cross-process ordering, server receipts, physical scanout captures, QMP input
commands, protocol identities, exit records and before/after resource state.

## Verified artifacts and results

The verified combination is server `smithay-xdg-build-r1`, kernel
`smithay-xdg-kernel-r1`, client `smithay-xdg-client-r0`, and runtime
`smithay-xdg-runtime-r2`. The client ELF is 411,960 bytes, SHA256
`264adfcf319ccd9366846cefe2c1e5b511a5e94032efc1f5ce523d0c47688994`.
Its [build report](../../artifacts/smithay-xdg-client-r0/build-report.json)
SHA256 is `d7dc10ba1a0e50a4573ddb613e0230a9ca3ae2e70921d50c87136ed840afa103`.
The [runtime report](../../artifacts/smithay-xdg-runtime-r2/summary.json)
SHA256 is `e996b83212e9cb32dec8ef288a9cde6e73ad7eedd424cac4f26a79b775f424c6`.

Across three boots, 18 native scanouts and 221,184 pixels pass the exact oracle,
with 12 configure/ACK pairs, six close events, three actual protocol rejections
and 42 physical input commands. Each boot records normal exit code 0 for the
negative client, both healthy clients and the compositor. Shared objects,
pages, mappings and references return to zero, with all 4,096 shared pages
free and no reserved/used shared grants remaining. Each boot completes 18
AI-admitted display submissions with no guard admission or display failure.

The client does not change resource limits or AI model decisions. The server's
fat-LTO build fits the existing executable policy at 3,976 pages including its
64-page stack; model 8195 admits it. Window protocol handling and ordered input
validation remain deterministic mechanisms inside the resource allocations
admitted by the existing AI policies.
