# COSMIC notifications and multi-service pipe capacity

This slice continues `cfc22fb` on `CyxiaOS-V0.17`. A03 remains cancelled.
Complete OS, desktop, and notification-service acceptance remain false.

## Pipe capacity

The previous genuine session could allocate six pipe pairs, then model 8193
refused the seventh with EAGAIN. The pool had eight pairs; this was an admission
decision retaining two free slots, not mechanical exhaustion.

Only `full-os` now has 32 pairs. Other profiles retain eight pairs. Each pair
still holds 4096 bytes, and model weights, decisions, endpoint generation,
ownership and descriptor limits remain unchanged. A compile-time bound protects
the handle's seven slot-index bits. `ai system` reports actual pool capacity,
unavailable slots and free slots separately from cumulative admission receipts.

The real x86 public-syscall probe retained the failing six-pair baseline, then
passed three complete capacity/reuse cycles at 30 admitted pairs in full-os and
six in legacy `large-memory`. It checks independent contents and identities,
flags, access direction, EAGAIN refusal without output corruption, duplicated
endpoints, EOF/EPIPE, closed descriptors, unread-data cleanup, and repeated
EMFILE rollback when only one descriptor slot is available. Both successful
guests reclaim every pipe slot, open description, thread, image and heap page.

The first legacy harness attempt omitted `large-memory`. Its exact embedded-ELF
check failed before starting a guest: the existing shared-memory initializer
returns ENODEV in that configuration, so optimization removes the later catalog.
The successful legacy guest uses the existing supported `large-memory` profile;
it retains eight pipes and sixteen process descriptors. The failed attempt is
preserved and is not counted as a guest result.

## Genuine notification sources

The source is upstream cosmic-notifications 1.10.0 at
`1e4c1f11fdcae273d6954fd0bfc54749a6145267`, with its unchanged Cargo.lock.
The explicit no-default-features build omits only optional journald logging;
the upstream libcosmic GUI, Wayland, accessibility and D-Bus features remain.
No daemon, renderer, service or native-library substitute is introduced.

Both original preparation and build reject the upstream root Cargo config.
A dedicated exporter now checks its exact bytes and removes only
`.cargo/config.toml`, preserving the original checkout and packaging copy.
Both reviewed `--cfg tokio_unstable` flags are supplied explicitly to Cargo.
Unknown configurations, flags, links, output overlaps and path escapes fail
closed. The first acquisition resolved 493 target packages, adding 203,399,767
bytes to the private source cache; this is source availability, not a link result.

The next build exposed tracked workspace links such as winit's `dpi/LICENSE`.
The frozen generic validator correctly refuses links outside an individual
package. The dedicated validator admits only the exact pinned winit commit and
Git tree, verifies every tracked blob and link in its complete 304-file checkout,
and binds resolved targets inside that checkout. It rejects changed contents,
external/absolute/broken/cyclic links and extra files. Other package validation
retains the existing rules. Original cache and prior producers remain unchanged.

Both new entry points bind and recheck the complete transitive local Python
producer inventory, including ELF and dependency validators, on success and
failure. Their native operations use the shared lease, fixed SDK inputs, offline
Cargo, two compiler jobs, a 1 GiB free-space reserve and a 3 GiB build-growth cap.
Preserved failed builds remain separate from later corrected attempts.

## Evidence and next boundary

Evidence root: `artifacts/v017-cosmic-notifications-20261115-r1`.
The full and legacy pipe guests share compiled-source identity
`3d68025e1a7c246f06f69136c72b7112c7e9888b091c50dafd39c9507f982bda`
(1,224 source files). Their captures are `pipe-full` and `pipe-legacy-02`;
the earlier eight-pair RED capture is `pipe-red`.

The real session trace passes the compositor environment handshake, spawns the
settings daemon and approves all nine pipe requests. Its next actual failure is
ENOENT for the uninstalled notification executable. The first copied observer
still expected the old 7/6/1 ledger after guest exit; this harness failure and
raw successful advancement are retained separately from corrected validation.

Notification build, final regression and review results are recorded separately;
neither the pipe probe nor a target build qualifies a rendered notification.
Real D-Bus delivery, visible Wayland layer surfaces, closure/expiry, panel socket
integration and full-session operation remain acceptance requirements.
