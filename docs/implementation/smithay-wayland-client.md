# Independent Wayland client for Smithay integration

This fixture is a separate AArch64 userspace process linked to the real
Wayland 1.24.0 client library and xkbcommon. It supplies the client half of
the Smithay protocol/render/input integration gate. Cross-compilation alone
does not establish that the compositor, display or input path works.

## Connection and protocol

The compositor creates a connected Unix stream pair, imports one end into
its real Wayland display and starts `/bin/smithay-wayland-client` with the
other end inherited as descriptor 3. The single argument is `1` or `2`,
identifying two sequential independent client processes. The client calls
`wl_display_connect_to_fd(3)`, which takes ownership of that descriptor.

The required globals are `wl_compositor` version 4, `wl_shm` with ARGB8888,
and `wl_seat` version 7 with keyboard and pointer capabilities. Version 7
allows Smithay's upstream sealed keymap memfd path. The actual keymap
descriptor is mapped read-only with `MAP_PRIVATE`, parsed with real xkbcommon
and closed. Private mapping is required by the version 7 protocol contract.
The client
uses a plain `wl_surface`; this gate does not establish xdg-shell behavior.

Each client submits three frames: 64×48, 64×48 with changed content, then
96×64. Each buffer has a separate bounded memfd with shrink/grow seals and
a shared writable mapping. The client destroys its pool and closes its
descriptor, synchronizes with the server, then writes the pixels. This
ordering tests genuinely shared pages after descriptor transfer rather
than a snapshot copied during import. No `wl_shm_pool.resize` is used.

After each actual frame callback and its required physical input sequence,
the client attaches a null buffer, commits, synchronizes, and waits for
`wl_buffer.release` before destroying the buffer and unmapping the pages.
Release is permitted before the frame callback; they are distinct protocol
events. Every callback and release must occur exactly once. Event waits
follow libwayland's prepare/read/cancel discipline and have a 30-second
monotonic timeout, including output backpressure and pending-event dispatch.

## Pixel and physical input contract

The server renders a black 128×96 canvas with the surface at canvas origin.
The native display region begins at screen coordinate `(32, 48)`. The
external verifier must capture and check the entire canvas after the
server's `SMITHAY_WAYLAND FRAME_READY` marker and before injecting input.
The server withholds the frame callback until it has forwarded the complete
physical input sequence.

| Frame | Dimensions | Input after screenshot | Seed for this frame |
| --- | --- | --- | --- |
| 0 | 64×48 | A key, evdev 30, press and release | 0 |
| 1 | 64×48 | Relative motion `(4, 3)`, then left button 272 press and release | Previously received key code 30 |
| 2 | 96×64 | Q key, evdev 16, press and release | Previously received button code 272 |

For client round `r` (1 or 2), frame `f` (0–2), received seed `s` and
zero-based coordinates `(x, y)`, the opaque ARGB8888 pixel is:

```text
R = (3*x + y + 29*r + 47*f + s) mod 256
G = (x + 5*y + 11*r + 31*f + 3*s) mod 256
B = (7*(x XOR y) + 13*r + 19*f + 5*s) mod 256
A = 255
```

The nonuniform axes and colors expose channel swaps, stride mistakes and
vertical inversion. The client takes `s` from its received event fields,
and validates press/release ordering and focus. Keyboard codes are also
translated through the delivered keymap and modifiers to `a` and `q`.
Pointer motion is checked against the prior enter coordinate and the
surface bounds. A callback without the expected input cannot advance the
client. The server and host verifier must independently verify the actual
rendered pixels and native input source; client markers alone cannot prove
display correctness.

The successful final marker is:

```text
SMITHAY_CLIENT RESULT PASS round=N frames=3 callbacks=3 releases=3 input=1
```

The compositor then accepts the next independent client. The integration
verifier must check both process identities, actual disconnect/reconnect,
normal exits and complete resource/grant reclamation.

## Isolated build

```sh
python3 tools/build_smithay_wayland_client.py \
  --output artifacts/smithay-wayland-client-new
python3 -m unittest discover -s tests/host \
  -p test_smithay_wayland_client.py -v
```

The builder performs no download or target execution. It holds a shared SDK
read lock, verifies the existing Wayland/xkbcommon manifests and archive
identities, and records the actual compiler dependency headers, source,
libraries, CRT, compiler/linker/strip tools and final static ELF layout.
Every output directory must be new, and all recorded inputs are checked
again after linking. The build has explicit time, disk and output limits.
No common sysroot, kernel source, Cargo configuration or previous evidence
is modified.

The current protocol-correct build is
`artifacts/smithay-wayland-client-r0/smithay-wayland-client.elf`, 403,560
bytes, SHA256
`68175dfff1184dc3008799ca4e0d24d553878d20aa2cb6cdb2b7709991001cea`.
Its build report SHA256 is
`607effdd69c0a3033dab531e2555dd270134ddb8a9730ed6c42f95737d82bef0`;
all 56 recorded inputs match the maintained source and SDK. Compile/link
logs contain no warnings. Three host provenance checks pass in
`artifacts/smithay-wayland-client-host-tests-r0.txt`.

The preserved r1 candidate used a read-only shared keymap mapping to avoid
the missing private file-mapping ABI. Checking the upstream protocol showed
this would violate the version 7 keymap contract, so that candidate was
rejected before any guest execution. Its rejection record remains in
`artifacts/smithay-wayland-client-r1/rejected-candidate.json`, and the
maintained source is restored to the exact r0 private-mapping implementation.
The kernel now supplies a real anonymous snapshot of fully write/shrink/grow
sealed memfd pages, with separate private contents and real PTE permissions;
the [memfd foundation](shared-memory.md) documents its bounded scope.

## Actual guest result

On 2026-10-22, the unchanged r0 client passed the combined
[Smithay Wayland runtime gate](../../artifacts/smithay-wayland-runtime-r3/summary.json)
in three independent ARM64 boots. Each boot ran one genuine Smithay server
and two sequential client processes, transferred and privately mapped the
23,019-byte sealed keymap, and completed all six frames with exactly one
callback and buffer release per frame. Both clients and the server exited
normally. All observed heap/image pages, OFDs, shared mappings and ancillary
references were reclaimed, with resource grants and releases conserved.

The server performed real GLES readback checks and native display submission.
The host independently checked all 128×96 canvas pixels before sending the
input for each frame: 18 frames and 221,184 scanout pixels across the three
boots. The 42 QMP input commands reached the clients through native input
and Smithay's keyboard/pointer protocol. The later frames used the received
key and button codes as their pixel seeds. These are observed guest results,
not deductions from the client PASS marker alone.

The frozen kernel is `artifacts/smithay-wayland-kernel-r3/cyxia-kernel.elf`,
SHA256 `93e9e4f7577912400d4b1cea990a8762be503c32b4d0d2f84284b1098981bcf1`.
The runtime report SHA256 is
`16220e0012b417dabccf7fc0108551bfbfff03662c8e53fa84d50f36bfd765c1`.
The server build and preserved failed candidates are described in the
[Smithay integration record](smithay-wayland-native.md).

This remains a bounded plain-surface integration fixture. It does not prove
xdg-shell, concurrent windows, pool resize or a complete COSMIC session;
the runtime report keeps `full_cosmic_port` and `cosmic_runtime_verified`
explicitly false.
