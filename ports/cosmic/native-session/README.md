# Native COSMIC session process boundary

This port adapts the pinned launch-pad 1.0.1 process boundary to Cyxia's existing
64-byte isolated static-image spawn ABI. The actual upstream manager retains its
callbacks, restart policy, delayed/exponential backoff, and cancellation timeout.
`cyxia-native` is selected explicitly; ordinary launch-pad builds keep Tokio's
normal process backend. Failed spawn is returned before publishing a manager
entry. No service or compositor is replaced by a probe.

`native_child.rs` implements three real pipes, same-number ambient non-CLOEXEC
and explicitly supplied descriptors, inherited environment with overrides, PATH
search, parent cwd inheritance, real PID/wait status, cancellation-safe wait,
SIGKILL, and synchronous kill/reap on drop. It rejects requests outside the
kernel's bounded ABI rather than truncating them. Explicit descriptors 0–2
conflict with mandatory piped stdio and are rejected. General concurrent parent
fd-table mutation is not fork-equivalent snapshotting.

Each wait future checks the kernel receipt immediately, then polls after 10, 20,
40, 80, and at most 100 ms between checks. Cancellation restarts this interval
sequence on the next wait while preserving any real exit status already reaped.

Run `build_patch.py --output <fresh-artifact-directory>` under the root native
lease. It checks both Git commits, Git trees, and every tracked file's actual
content against its pinned blob; then exports sources into the fresh directory.
Untracked cache markers are not exported. The output patch adds the complete
original launch-pad tree, preserving license/workspace/tests, plus the adapter,
and selects the local dependency from session Cargo.toml. The reviewed lockfile
change removes only launch-pad's Git source line. No Cargo or compiler runs in
the generator. Native builds use ordinary recipe `patches[]`; existing compositor
series and build tooling are unchanged.

`native-patch.json` records complete original source identities, support source
hashes, patch hash, and every changed preimage/postimage. The native recipe and
profile are maintained by the root agent. Regenerate the patch/manifest after
an adapter or generator change before building again.

Compile `probe.rs` with the exact patched session target rlibs for `launch_pad`,
`tokio`, and `libc`, register the resulting ELF as `/bin/session-process-probe`, then run
`session-process-probe /bin/session-process-probe` in the guest. Its child modes are test processes
from that same ELF. They exercise the public NativeChild and real ProcessManager
interfaces, including 12000-byte pipe traffic, FD inheritance and parent flags,
argv/environment/PATH/cwd, failed-spawn cleanup, waits, cancellation, kill/drop,
stdio collisions, callbacks, real PID changes, restart limits/backoff, and
notification-style `with_fds`/`update_process_fds` refresh. Host source checks and
compile success do not establish those guest behaviors.

The selected build recipe is `native-recipe.json`; its ordinary patch hash and
`effective_lock_sha256` must be updated from the generated manifest. Build with
`tools/build_cosmic.py build --component cosmic-session --arch x86_64
--recipe ports/cosmic/native-session/native-recipe.json
--resource-profile ports/cosmic/recipes/cosmic-session-x86_64-resource.json
--cache artifacts/cosmic-sources --cargo-cache artifacts/cosmic-cargo-cache
--sysroot artifacts/sysroot/x86_64-musl --jobs 1 --output <fresh-output>` under
the root native lease. Both optional systemd and autostart remain disabled.

`tools/cosmic_session_inputs.py` validates the resulting build and curated ELF
without running compilers. After copying the ELF, `record_origin(output, recipe,
resource, source_export, prefix, patch_manifests=[manifest])` publishes one fresh
receipt; `validate_inputs(prefix)` checks it again. Link and guest receipts are
separate: source validation alone cannot establish a running session. The
original builder records SDK wrapper hashes but not every underlying host tool
at build time; publication-time hashes cannot fill that historical gap.

Native cancellation callbacks derive their code from the real wait receipt,
including TERM (143), KILL (137), or a completed graceful exit. A failed kill/reap
reports an unknown status with its error logged. The guest probe covers both
default TERM and delayed graceful exit as well as ignored TERM followed by KILL.

The `full-os` profile provides 32 global pipe pairs; the current admission policy
reserves two, so 30 pairs are usable. The ordinary profile still has an
eight-pair pool. `NativeChild::spawn` creates three pairs per child, and their
actual lifetime depends on endpoint closure and child reaping. The current
eight-Runner configuration admits seven concurrent processes, so full-session
planning must include the manager, mandatory services and any helper children.
The real FullOs pipe-capacity run is recorded in
`docs/implementation/v17-cosmic-completion-20261116.md`; it does not establish
that a complete COSMIC session fits or runs. Session acceptance still requires
the actual daemon, panel and application images and their runtime evidence.
