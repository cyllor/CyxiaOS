# Genuine COSMIC settings daemon feature boundary

The selected source is cosmic-settings-daemon 1.10.0 at
`9e4ae69fc175191f15789d35423806ea0f093c9d`. The generated ordinary patch keeps
the real D-Bus configuration/state interfaces, filesystem watcher, name lifecycle,
theme logic and Wayland client. It does not provide a replacement daemon.

Ordinary defaults select `audio` and `backlight`, retaining upstream PipeWire,
Varlink, udev and DDC integrations. The explicit `cyxia-native` recipe disables
both integrations. Disabled volume and brightness mutations return D-Bus
`org.freedesktop.DBus.Error.NotSupported`; brightness getters retain upstream's
unavailable sentinel `-1`. No audio Varlink socket is bound in that profile.
Keyboard brightness placeholders are left unchanged in ordinary defaults;
without `backlight` their mutators also return NotSupported.

The full genuine cosmic-comp-config package is exported from pinned compositor
`41497b42d9744d9963c4c6d17e8add49489b45ee`, with its license. Its libinput enum
separation matches the established compositor patch: RON configuration values
remain real values; no device API is emulated. The daemon selects that package
without libinput when `backlight` is disabled. Geonames retains its generator
as a default feature for ordinary package builds; the daemon only requires its
bitcode data types and already embedded timezone data.

The native feature also selects `wayland-sys` 0.31.11's explicit, default-off
`cyxia-static-client` feature. The complete registry package is exported locally
with its MIT license and patched through `[patch.crates-io]`. Its client function
table contains real `libwayland-client` symbol addresses, including the upstream
C variadic functions and conditional 1.23 entries. `WaylandClient::linked()`
constructs that table; the build script requires the real static client library.
Missing symbols are link errors. No loader, symbol, Wayland connection or device
response is fabricated. Existing dependency `dlopen` feature unification retains
the function-table API, while this explicitly selected client table uses static
addresses. Without `cyxia-static-client`, upstream dynamic loading is unchanged;
other Wayland modules retain their existing behavior.

Missing system time services produce a warning and a pending event stream, so
local theme watching and cancellation remain active. Closed time streams also
become pending, avoiding a hot loop. Theme setup retries can be cancelled during
backoff. Ordinary logind, locale, UPower and accessibility failures retain their
upstream behavior. No system bus or service is invented.

Signal registration still requests the original SA_RESTART semantics. Failures
are reported explicitly before logging initializes; they do not become fake
successful handlers. When handlers cannot register, native default TERM can
terminate the process but graceful theme cleanup and SIGHUP restart are not
qualified. General exec remains unchanged, with a diagnostic if restart fails.

Source generation, builds and guest captures belong to the root native lease.
After recording the unmodified baseline, an intermediate export for isolated
offline lock resolution can be generated with:

```sh
python3 ports/cosmic/native-settings/build_patch.py --output artifacts/v017-cosmic-settings-20261115-r1/native-source-04 --no-resolved-lock
```

The generator verifies both complete pinned Git trees and every tracked blob.
For `wayland-sys`, it verifies the `.crate` archive against the original daemon's
locked package checksum, compares every archive file with the cached extraction,
and binds the complete per-file digest map. Cache markers are excluded. If Cargo
provided `.cargo-checksum.json`, its map must match; the current extraction has
no such file, so the checksum-verified archive supplies the authoritative map.
The manifest records this identity under `registry_inputs.wayland-sys`, separately
from Git source identities. The generator
exports an untouched base and a separate modified source tree, validates exact
replacement preimages, and checks source/support bytes again before publishing
receipts. Original checkouts are never edited. The generated native recipe is
based on `ports/cosmic/recipes/cosmic-settings-daemon-x86_64.json` and contains
the actual patch and effective lock hashes. The generator runs no Cargo or
compiler. `PATCH_GENERATED_NOT_BUILT` does not establish build or guest behavior.

The initial local-package lock failed offline because optional randr edges were
absent. The randr revision now matches the pinned compositor's own lockfile.
The first isolated offline resolution added 15 packages without changing the
original checkout. The static client source override requires a new isolated
resolution and preserved delta. `--no-resolved-lock` exports the transformed
original lock for this step. Final generation uses the committed `Cargo.lock`
by default; `--resolved-lock` can select another explicitly bounded and hashed
input. This input must retain the daemon, config and Wayland sys packages as
local packages. Record the actual resolution before final generation. The
initial failure and actual lock deltas are preserved in the stage artifacts.
Never accept an unrecorded lock update. The manifest uses `source_inputs.settings` for
the daemon identity and `source_inputs.compositor` for the genuine config origin.

Required guest evidence includes real D-Bus ownership, WatchConfig and WatchState
signals after persistent writes, client disconnect/name cleanup, real Wayland
transport, NotSupported mutations, and actual process resource reclamation.
Eight global pipes, eight process slots and sixteen broker connections remain
independent capacity limits; each distinct config/state watch opens another
genuine bus connection. This profile does not certify a complete desktop,
hardware controls, audio, graceful signals or general process spawning.
