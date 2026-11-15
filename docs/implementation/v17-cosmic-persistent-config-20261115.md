# COSMIC defaults, persistent settings and child wait collection

This stage continues `2ba70e3` on `CyxiaOS-V0.17`. Complete OS and COSMIC
session acceptance remain false. A03 remains cancelled. The configuration
client uses the actual pinned upstream libraries; it is not a replacement for
cosmic-settings-daemon or cosmic-session.

## Upstream defaults and library build

`ports/cosmic/config-assets.json` pins the compositor's shortcut defaults and
tiling exceptions, the settings daemon's system actions, both installation
recipes and both licenses. Five files totaling 81,993 bytes are installed under
the original `/usr/share/cosmic` and documentation paths. The installer checks
Git commit/blob/content identities, rejects path escape and symbolic links,
preserves inputs and writes a receipt into fresh output. User overrides remain
under the existing UID0 `HOME=/`, separate from immutable defaults.

The real library client parses 116 shortcut bindings, 26 system actions and 35
window rules. It initializes only an absent custom-shortcut key, preserves an
existing valid value byte-for-byte, and reports malformed RON without replacing
it. Session processes now receive `LANG=en_US.UTF-8`; legacy process environment
is unchanged.

`build_cosmic_config.py` links against retained actual COSMIC library archives.
Its manifest binds 1,403 dependency-search files, 201 source dependencies, the
lockfile, compiler and target runtime, native libraries and SDK. It retains the
original compositor build report's failed legacy admission status; successful
linking is not retroactively claimed to have passed that profile. New target
execution establishes the client's behavior. Final client SHA256:
`460696b853cdf0c3c9e72ca45a7861acdb4c1f94418f2c373ecabf56fdc942a0`.

## Measured durability failure and fix

Actual `defaults-red` failed with `NoConfigDirectory`; installation made the
same typed defaults path pass. Actual `config-run-01` passed creation,
preservation, malformed-value rejection, public get/set/watch notifications,
repeated replacement and live cleanup. Its `config-reboot-01` recovered both
values but failed because an empty atomic-write directory reappeared.

The pinned atomicwrites implementation syncs the new file and parent directory
before dropping its temporary directory. CyxiaOS's filesystem snapshot therefore
contained the already-replaced value and the temporary directory. The helper now
checks cleanup and syncs the parent afterward. This extra sync belongs to the
helper; it does not change upstream libraries or claim all COSMIC writers have
acquired that behavior.

Two independent same-disk experiments separate these claims:

- `cosmic-config`: helper-owned cleanup sync, then read-only reboot verification
  of both values and clean probe/custom directories.
- `cosmic-config-library`: actual library writes without additional probe sync,
  then read-only values verification after reboot. This path does not claim
  crash-durable temporary-directory cleanup.

Neither experiment uses a shell/host checkpoint after the library operations.
Every process must exit with the expected code and reclaim image/heap pages,
threads, open descriptions and notification resources. The malformed input is
an expected exit 1, independently checked rather than accepted as a generic
failure. The earlier diagnostic `exercise-01` used an invalid alias; that
harness failure is retained and is not counted as a library defect.

## Sixteen-thread child collection

Full OS already allowed sixteen threads, but `collect_children` still scanned
eight slots. The actual regression holds one child behind a host gate while
fifteen worker threads call waitpid and the main thread waits without a timer.
The host observes all sixteen parent threads parked before releasing the child.

`child-wait-red` observed the real child exit 37, but only seven worker returns.
Changing the scan to `threads::MAX_THREADS` services the configured capacity.
The successful run requires one reap with status 37, fourteen ECHILD responses,
all joins, a subsequent ECHILD check, and full reclamation. Legacy profiles keep
eight slots; process policy, thread admission and model weights are unchanged.

## Actual compositor replay

`cosmic-config-final` uses the unchanged real compositor ELF
`de9c94b47387439414a410bf1a529d8e0a62047af614185889d47d7445b13ab2`.
The initializer runs before it. Both real D-Bus names register, all 192 initial
display tiles complete, and the previous defaults/custom/system-actions/window-
rules and locale errors are absent. Actual mouse input moves the cursor and
changes exactly 751 scanout pixels; the old cursor is cleared.

The process remains active for 60.037958 seconds after input, with ten threads
and 12,225 heap pages. Display operations advance from 192 to 384; this is a
tile-operation count, not a frame count or performance qualification. Killing
the compositor removes its bus names and reclaims its memory, threads and open
descriptions; stopping the real broker returns the complete resource baseline.
Missing system bus and fallback-renderer/cursor limitations remain visible.

## Next session integration

The real `cosmic-session` source is present at
`8093b59bb1262b0612d814e6540ba936303f735a`. Its source audit identifies the actual
launch-pad process/signal boundary and compositor socket/environment handshake.
Settings daemon, notifications and panel are mandatory startup dependencies;
none is replaced with a dummy service. The whole-lock cache inventory finds
106 missing package versions, which is not yet the feature-resolved build set.

Next work is a bounded x86 session build and real process supervision, followed
by the settings daemon, notifications, panel and other applications. Eight
process slots, cross-process signals and ordinary process creation remain
explicit gaps. The fixed child-wait scan removes one real prerequisite only.

## Final checks and evidence

The final OS image binds 1,111 compiled-source files to
`7bce072d2614b4f7c2f28225b6de058b0e0c5f9d1ecdf3ace7f1d2781d88c7e1`.
All twelve final captures pass: two configuration write/reboot pairs, child wait,
native services, inotify, thread exit, real D-Bus, concurrent fsync and its reboot,
and actual compositor render/input/liveness. The retained earlier failures are
historical evidence, not final-source PASS claims.

The default workspace suite passed 1,475 tests before the final two launcher
aliases; all fourteen shell tests pass again on the final source. Final checks
also pass 308 full-OS POSIX/AI tests, 254 legacy large-memory POSIX tests, 26 x86
runtime tests, 34 Python tests, kernel layout validation and AArch64 graphics/
large-memory kernel compilation. The latter is a compilation result, not an ARM
ported-program replay. An initial Python invocation used the wrong test-module
path and is retained; the corrected invocation passes.

[final-evidence.json](../../artifacts/v017-cosmic-config-20261115-r1/final-evidence.json)
binds 132 final capture files, historical failures, build receipts and host logs.
Its SHA256 is `4ef9e6af05602369a8eb7d699952b8e6d09ffa71862d7a66121867091029519d`.
Separate standards/spec source reviews found no remaining blocking issue. The
standards review retained one nonblocking duplication observation about the
standalone producers' small path/JSON validators.
