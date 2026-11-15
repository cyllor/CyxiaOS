# Full OS image capacity and actual COSMIC execution

The real pinned x86 `cosmic-comp` now executes in CyxiaOS using the explicit
`full-os-v1` image profile. This is a loader/runtime milestone, not a complete
COSMIC compositor or session result. A03 remains outside this work.

## Implementation

`cyxia-contracts::user_layout` owns the versioned address layout. Legacy APIs
continue to select the historical image/stack profile. The opt-in x86 kernel
`full-os` feature selects a 64-MiB image window, a separate 2-MiB initial stack,
16,384 actual backing pages per process, and an anonymous heap at 0x08000000.
The existing shared window and ownership/permission/revocation mechanisms are
unchanged. Eight executable arenas reserve 512 MiB from discovered boot RAM;
QEMU successfully boots this configuration with four CPUs and 1 GiB RAM.

The full-OS executable policy uses model 8197 and conservative 64-page
quantization. Free pages are rounded down and requests up, without clamping
out-of-domain inputs. The model was produced by the existing **synthetic**
policy-distillation procedure. Its exhaustive quantized boundary checks and
held-out teacher agreement are not production learning or A03 results. All seven
preexisting weight vectors, including model 8195, and their provenance remain
unchanged. The actual pool capacity is still enforced after admission.

`cosmic-desktop` includes the full-OS profile and requires a real catalog ELF.
The full-OS catalog budget is 96 MiB. The shell routes `posix exec cosmic-comp`
to the actual binary with `--no-xwayland`; `posix exec cosmic-version` invokes
the same bytes with `--version`. The latter is solely an execution diagnostic.

## Actual inputs and observed failures

Evidence root: `artifacts/v017-full-os-capacity-20261115-r1/`.
The isolated catalog copies the already linked source08 ELF, without modifying
the SDK or the frozen COSMIC patch series. `input-receipt.json` binds the source
and destination bytes. Its SHA256 is
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`;
the image contains 42,173,224 bytes and 8,548 LOAD pages. Including the new stack,
the actual guest admission is 9,060 pages.

The first guest capture (`cosmic-version-01`) booted successfully but rejected
the shell command before process creation. The shell whitelist omission was
reproduced by `shell-red.log`, repaired, and verified by all 14 shell tests.
The failed build/capture evidence remains intact.

`cosmic-version-02` then ran the exact embedded image twice, with distinct PIDs
using the same reclaimed process slot. Both printed the actual upstream version
and revision `41497b42d9744d9963c4c6d17e8add49489b45ee`, then exited with code 0.
The subsequent real ported C probe passed allocation, TLS, file IO and floating
point checks, and storage checkpoint generation 1 completed with two flushes.
The validator compares exact ELF bytes inside one read-only kernel LOAD and
revalidates source, tools, catalog and producer identities after capture.

The first normal startup (`cosmic-startup-01`) reached the upstream main path,
then exited with code 1: `Failed to initialize event loop`. Inspection of the
actual linked `polling 3.11.0` source showed its readable interest includes
`EPOLLPRI`. The existing epoll mask rejected that valid interest with `EINVAL`.
`epoll-priority-red.log` reproduces the exact registration flags. The fix retains
priority interest in the watch but reports it only if a backend supplies that
readiness; ordinary eventfd reads never acquire a synthetic priority event.
The regression also covers one-shot disarming/rearming, priority-only waiting,
and rejection of unsupported flags. This follows the documented
[epoll event semantics](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html).

With the correction in `os-build-03`, normal startup advances beyond event-loop
creation to the actual Wayland listener. `cosmic-startup-02` first captured the
panic marker mid-write; the diagnostic producer was then changed to drain the
remaining UART bytes while retaining failure status. `cosmic-startup-03`
records the complete failure: `RuntimeDirNotSet` at upstream `src/lib.rs:318`,
followed by exit code 134. An unsupported readlink syscall (89) also appears;
it is not evidence that readlink caused this runtime-directory panic.

The next startup work is now based on that observed failure: provide a real
writable absolute runtime directory and environment, implement Wayland's flock
lifetime/competition behavior, then proceed to inotify configuration watching
and session services. No empty-success syscall adapters are used.

The expanded native regression (`native-01`) also exposed the native heap
workload's historical hard-coded large-memory base. It expected 0x04000000
although full-os-v1 correctly returns 0x08000000. The standalone workload now
reads the shared layout contract, and the x86 build explicitly supplies its
profile. Its zeroing, cross-page IO, isolated contents, rejection, revocation
and recycle assertions remain in place.

Final native image `os-build-05` passes `native-02`: real preemption, expected
user faults, read-only/NX/kernel/guard isolation, FP/TLS, heap allocation/zeroing/
revocation/reuse and IPC all pass, followed by durable storage checkpoint.
`cosmic-version-04` passes two actual version executions and the ported probe
against that same final image. ARM's legacy large-memory kernel also compiles
successfully (`arm-legacy-check.log`); this compile check is not an ARM boot run.
`cosmic-startup-04` confirms the same `RuntimeDirNotSet` / exit-134 boundary on
the final image with source identity preserved. All three final captures share
source digest `257057505ff3ede3bf6a7a7b3e5178bc929dcf3fde7d6e5c423abdbe4158bb18`.
`progress.json` binds their summary hashes and records the remaining work.

## Verification

- Parser: 26 focused executable tests, including observed RED then GREEN;
  actual ELF rejected by legacy, accepted by full-os-v1, wrong ISA rejected.
- Integration before the epoll correction: 407 default contracts/POSIX/kernel
  core tests; 189 full-OS POSIX tests; 43 AI-runtime tests; 14 shell tests.
- Model: all 65,792 quantized input pairs at four physical rounding endpoints
  avoid overcommit; reproducible training `--check`; legacy outputs preserved.
- Python OS build/Smithay identity tests: 10 passed.
- After the observed epoll correction: all 190 full-OS POSIX tests passed.
- Independent Standards and Spec reviews found no confirmed implementation
  defects; actual compositor startup remains a separate verification boundary.

Both `full_os_verified` and `cosmic_session_verified` remain false. Version
output does not establish event-loop operation, compositor output, input,
Wayland application lifecycle, session services, or desktop persistence.

## Reproduce

Use the existing x86 SDK and the isolated actual ELF catalog above, with the
installed Rust toolchain on PATH. Both commands acquire the shared native lease.

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature full-os --feature cosmic-desktop \
  --sysroot artifacts/v017-full-os-capacity-20261115-r1/sysroot \
  --output artifacts/full-os-new-build
python3 tools/os_smoke.py --build artifacts/full-os-new-build \
  --scenario cosmic-version --output artifacts/full-os-new-version
```

Normal-startup observation uses the preserved `capture-startup.py` beside the
evidence. It writes serial/QMP/register/display evidence and records exit/fault
or the first capture failure without issuing a session PASS. Output directories
must be fresh. Earlier captures remain bound to their earlier source snapshots.
