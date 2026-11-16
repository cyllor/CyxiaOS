# COSMIC notification service and multi-service pipe capacity

Continue the approved full CyxiaOS/COSMIC plan after `cfc22fb`, using the real
manifest-pinned notification daemon at `1e4c1f11fdcae273d6954fd0bfc54749a6145267`.
A03 remains cancelled. Full OS and complete desktop acceptance remain false.

## Measured prerequisite

The previous genuine session starts the compositor and settings daemon, then
the first notification-child pipe fails with EAGAIN. Its receipt records six
successful pipe grants and one model denial, with no mechanical-capacity denial.
The eight-pair pool and unchanged model retain two free pairs at this boundary.

- Increase only the full-os pipe backing to 32 pairs. Preserve the eight-pair
  legacy profile, 4096-byte per-pair bound, handle generation and model 8193.
  Preserve admission decisions and accounting; do not bypass the reserve.
- Verify the actual public pipe2/dup/read/write/poll/fstat/fcntl API: admission
  of 30 pairs in full-os and six in legacy, EAGAIN without output corruption,
  independent contents/identities, EOF/EPIPE on final close, stale-descriptor
  rejection, repeated reuse, and EMFILE rollback with only one FD slot free.
- First retain an actual failing full-os guest capture against the eight-pair
  pool, then the successful expanded-profile capture. Verify process, image,
  heap and open-description reclamation. Exercise the legacy guest separately.

## Genuine component work

- Record the unmodified build or preparation result before any source port.
  Use exact upstream source/lock hashes and genuine dependencies. Do not replace
  rendering, D-Bus or application behavior with a probe or invented service.
- Any source-local Cargo configuration must be explicitly reviewed and bound
  into the isolated build inputs. Keep old receipt-bound producers unchanged.
  New source patches must preserve their precise input and output identities.
- Advance through actual source preparation, bounded static target compilation
  and measured runtime prerequisites. Preserve all failed attempts and report
  the next real boundary when the service cannot yet run; compilation alone is
  not notification, desktop or session acceptance.
- The eventual service acceptance requires genuine D-Bus notification delivery,
  its Wayland layer surface and visible content, closure/expiry semantics and
  cleanup. Session integration must preserve the upstream manager and inherited
  panel socket protocol, and expose the next actual missing component/resource.

## Execution and review

The public test seams above continue the previously authorized design. All
native acquisition/build/guest work is serialized under the shared lease;
independent source-only tasks may run in parallel. Preserve previous evidence
and cached libraries that its receipts require. Run relevant host/guest checks,
independent Standards and Spec reviews, and commit the coherent verified slice.
