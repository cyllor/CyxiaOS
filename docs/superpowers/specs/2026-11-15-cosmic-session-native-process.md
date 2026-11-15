# Genuine x86 COSMIC session process boundary

Continue the approved full OS/COSMIC plan from 6fe8597. A03 stays cancelled;
routine implementation, existing public-API/actual-guest test seams, independent
file ownership, reviewed commits and GitHub push remain authorized. Root alone
holds the native lease; compilers, generators and QEMU run serially.

Build the pinned real cosmic-session on x86_64 musl, without optional
systemd/logind/autostart. Preserve the ARM recipe and original upstream/cache
sources. Capture unmodified target startup before porting its measured process
boundary. No version output or manager bus registration counts as a complete
session. Missing mandatory components must remain explicit failures.

Port the real launch-pad process boundary using Cyxia's existing isolated-image
spawn ABI, preserving its manager, callbacks, backoff, cancellation and restart
logic. Bind the original dependency source and exact applied patch. Do not
pretend to implement fork/exec or substitute a dummy compositor/settings service.
Child argv/environment/cwd, three real stdio pipes, non-CLOEXEC ambient descriptors
and explicit with_fds must retain their actual contracts. Parent FD flags must
not change. Enforce ABI bounds, propagate admission/startup errors and release
all resources on failure, wait, forced kill and drop. Process wait uses real
kernel receipts; poll readiness and notifications may not be synthesized.

Implement positive-PID cross-process signal delivery at the Supervisor boundary
after all AP user contexts drain, using the existing UID0 credential domain and
process signal machinery. Validate signal number and target, support signal0,
self and peer delivery, real SI_USER identity, default/handler TERM, KILL and
wait status/reclamation. Preserve thread-directed semantics; do not silently
accept unsupported process-group operations or SA_RESTART without implementing
its interrupted-wait contract. Reproduce missing behavior with actual native
children before the fix.

The target integration is the genuine manager launching the genuine compositor
through inherited Unix IPC, receiving its actual readiness/environment handshake,
and retaining the subsequent real missing-component failure if settings daemon
is absent. Validate process/descriptor cleanup and the unaffected direct COSMIC
render/input/config/durability paths. Complete OS/COSMIC session flags remain
false until real mandatory services, panel and applications are operational.

Preserve failed captures, bind final source/ELF/tool/patch/SDK identities and
perform independent standards/spec reviews before committing the coherent stage.
