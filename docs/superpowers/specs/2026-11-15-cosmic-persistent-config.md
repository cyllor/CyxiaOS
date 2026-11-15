# Real COSMIC defaults and persistent configuration

Continue the approved full CyxiaOS/COSMIC plan from `2ba70e3`. Routine steps
and the existing public-API/actual-guest verification seams are authorized.
Keep A03 cancelled and full OS/session acceptance explicitly incomplete.

Package the exact pinned upstream shortcut defaults, system actions and tiling
exceptions at their upstream install paths, with source/install-recipe/license
identities. Fresh-output staging must preserve sources and reject escaping,
symbolically linked, altered or colliding inputs. Keep user overrides separate from immutable
defaults. The real compositor must parse these assets using its existing code.

Use the actual pinned cosmic-config and cosmic-settings-config libraries for a
small configuration initializer and guest lifecycle check. Initialize only an
absent custom-shortcut key; preserve existing settings, including reporting
malformed settings rather than replacing them. Test typed defaults, the public
get/set/watch API, repeated atomic replacement, final-key notification, temporary
directory cleanup and verification after reboot of the same disk. A later host
or shell checkpoint must not mask whether the actual library write was durable.
Keep the existing single UID0 HOME and set a parseable UTF-8 session locale.

The measured first reboot preserved both typed values but restored an empty
atomic-write directory: upstream syncs before dropping its temporary directory.
The helper must sync the parent after confirming cleanup, including the custom
shortcut directory. Retain a separate exercise/reboot path without that added
sync, reading values only, so the cleanup sync cannot mask library durability.

Bind any reused compiled library archives, toolchain, dependency search paths,
native libraries, source records and the original compile report. Preserve the
original compositor build's legacy image-profile rejection; do not relabel it as
a successful legacy build. Only actual new target execution establishes runtime
behavior. This helper is not cosmic-settings-daemon or a full settings service.

The next-session source audit found child-wait collection still scanning eight
thread slots after full-OS capacity became sixteen. Reproduce with a real child
held behind a host gate and all fifteen workers parked in waitpid, then service
the actual configured thread capacity. Require one successful reap, ECHILD for
the other waiters, joins and full reclamation. Preserve eight-thread legacy
profiles and existing process/admission policy.

Root owns the native lease and serializes every compiler, generator and QEMU
run. Independent agents own only assigned files. Retain every actual failed
capture, validate final source/ELF/producer identities, and perform separate
standards/spec reviews before the coherent commit and GitHub push.

Genuine cosmic-session source is fetched at its pinned commit for the next
integration. Process creation/termination, optional service dependencies,
capacity and readiness supervision remain explicit unfinished work. Do not
substitute dummy session, panel or service implementations.
