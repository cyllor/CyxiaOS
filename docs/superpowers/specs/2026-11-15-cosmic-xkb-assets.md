# COSMIC XKB rules and immutable asset mappings

Continues the approved complete CyxiaOS/COSMIC plan at `6b3461d`.
The actual unchanged compositor exits 134 at evdev/pc105/us keymap creation.
The SDK libxkbcommon uses fstat + read-only shared mmap, currently unavailable
for embedded boot files. Both data and runtime behavior must be delivered.

## Contract

- Install official SHA-pinned xkeyboard-config 2.42 generated evdev rules and
  the complete default pc105/us include closure, retaining original file bytes.
  No host keyboard database, embedded test keymap or compositor rebuild.
- Record archive, generator, copied file and license identities. Keep the
  initial supported layout explicit; do not claim every upstream layout.
- Stay inside the existing 128-file catalog, 96-byte paths and 64-node directory
  budget. Build/capture manifests bind every installed byte.
- Add bounded nonfixed MAP_SHARED read-only and MAP_PRIVATE copies of immutable
  boot assets. Validate offsets, EOF, flags and protections before allocation;
  zero the final partial page, reject whole pages beyond EOF, preserve OFD
  offset, retain mappings after close. Shared writes and later mprotect write
  upgrades fail; private copies may become writable without changing originals.
- Reuse actual AI heap grants, stopped-process copying, PTE permissions and
  existing whole-allocation unmap/exit reclamation. No fake syscall success.

## Verification

1. Preserve fresh real COSMIC RED (`baseline-01`, Exited134 BadKeymap).
2. Real musl/libxkbcommon probe RED against the unsupported mapping path,
   GREEN with support. A controlled regression replay must be labeled explicitly,
   rather than presented as a chronologically earlier capture. Check
   installed by-names compilation, actual US symbols including 6/^, Shift,
   Caps, Ctrl, serialization, invalid rules, and mapping permissions/lifetime.
3. Host VM policy tests prove atomic write-upgrade refusal and fresh reuse.
4. Same compositor SHA replay must pass the original keyboard boundary;
   classify any next failure honestly and retain complete raw evidence.
5. Relevant native/heap/thread/file regressions, independent Standards and Spec
   review. Complete desktop/session flags remain false without actual proof.

All native jobs use the shared lease, serially. Historical artifacts and .qwen/
are preserved. Routine implementation is already authorized.

## Measured follow-up: allocation records

Actual COSMIC `cosmic-observe-01` consumes all 512 heap mapping records during
XKB initialization. A one-page allocation fails with 590 pages still free,
followed by a NULL write fault. Completing this keyboard step therefore also
requires bounded full-os metadata capacity: 1,024 records, retaining legacy 512,
the 32 MiB heap, existing 2,048-page per-request cap and model 8198 reserve.
The existing real heap probe must first fail beyond 512 then prove record
exhaustion, payload preservation, zeroed alternating reuse and complete reclaim
at the new bound. This adds no physical heap capacity or altered AI policy.
