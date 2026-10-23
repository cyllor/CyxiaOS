# Native Rust reactor foundation

This ports the genuine Mio event reactor used in the fixed COSMIC dependency
graph to the CyxiaOS AArch64 musl ABI. It is a bounded foundation for the
compositor event loop. Calloop, polling, Smithay's high-level event integration
and the full COSMIC runtime require additional verification.

## Source closure

The checked `cosmic-comp-epoch/Cargo.lock` has SHA256
`ecfa6705314e3821534170a01afd5014478fd4800bd699abb7ccd04b7dfb34b8`.
It pins Mio 1.1.1, polling 3.11.0 and calloop 0.14.4. This first integration
builds only Mio 1.1.1 with its target dependencies libc 0.2.182 and log 0.4.29.
All three crate archive checksums must match the fixed lock. The complete
download closure is 972,018 bytes.

`ports/cosmic/reactor-source.json` records the exact archives, features and
budgets. Mio uses its normal `os-poll`, `os-ext`, `net` and default log support.
There is no upstream source patch or replacement reactor implementation.
Linux's normal Mio epoll/eventfd backend runs through CyxiaOS's ABI. The
target triple describes that userspace ABI; CyxiaOS remains its own kernel.

The builder uses direct `rustc` invocations for this three-crate closure,
with the unchanged upstream libc build script run on the host using explicit
AArch64/musl target metadata. Its emitted compiler configurations are applied
to the target library. The final executable links the official target Rust
standard library and the existing pinned musl/CRT at the established static
ELF address. Target code is never run on the host. No common Cargo
configuration, source lock, target sysroot or kernel file is changed.

Downloads, expanded sources, build size, minimum free disk and elapsed build
time have explicit limits. Each output directory must be new. Reports bind
the probe and build tools, pinned lock/manifest, exact source trees, actual
compiled crate archives, native linkage inputs and final ELF layout.

## Actual behavior tested

The probe uses public Mio `Poll`, `Registry`, `Events`, `Waker`, `UnixStream`
and `SourceFd` APIs. It checks:

- Empty polling timeout and repeated eventfd-backed Waker wake/poll/quiet
  cycles, with no eventfd read between wakes; multiple wakes coalesce.
- A real Rust thread wakes a waiting reactor, then joins.
- Unix socket readiness after the first write, quiet while unread data
  remains, notification on another committed write, draining to WouldBlock,
  new readiness after draining, token changes on reregistration, deletion
  and re-addition, and peer-close/EOF.
- A real monotonic timerfd registered through Mio: one-shot expiration,
  reading its count, rearming, cancellation and quiet readiness after drain.
- Closing all registered resources and the poller, followed by external
  process/thread/heap/image and grant-accounting verification.

Mio's Linux Waker deliberately leaves its eventfd counter unread during
normal operation. Each later committed write must produce another edge
notification even while the counter remains nonzero. Tracking only a
false-to-true readiness transition cannot satisfy this contract. Mio also
sets `EPOLLET` on its registrations and adds `EPOLLRDHUP` to readable
interests. CyxiaOS must implement those behaviors rather than suppressing
the flags. The probe does not use temporary signal masks or nested epoll.

## Reproduction and acceptance

```sh
python3 tools/build_rust_reactor.py \
  --output artifacts/rust-reactor-build-new \
  --cache artifacts/reactor-research-r0 --fetch
python3 -m unittest discover -s tests/host -p test_rust_reactor.py -v
python3 tools/verify_rust_reactor.py \
  --elf <frozen-kernel.elf> --probe <rust-reactor-probe.elf> \
  --output <fresh-evidence-directory> --runs 3
```

The catalog name is `rust-reactor-probe`. The kernel integrator selects the
exact ELF with `CYXIA_RUST_REACTOR_PROBE_ELF`. The guest verifier requires all
21 ordered check markers and both bounded timing observations, the exact
embedded ELF and build identities, normal process exit and full cleanup.
It records `calloop_verified=false` and `cosmic_runtime_verified=false`.
Cross-compilation alone does not establish reactor behavior in the guest.

## Build evidence

The current isolated build is `artifacts/rust-reactor-build-r6`.
`rust-reactor-probe.elf` is 446,800 bytes, SHA256
`4866b63d891da66f5a4bf8d278710a47f26f9aa2f85de7bd3fc607181f9df951`.
Its `build-report.json` has SHA256
`4f657e7a0a457ec2710b58adcd1b564d37e8d6458380501465c72a817c103101`.
All compilation and linkage logs are clean. The only nonempty log is the
unchanged libc build script's configuration output. Earlier r0/r1 outputs
remain preserved; they exposed omitted Cargo-style check-cfg declarations
in the direct compiler recipe, corrected in r2 without changing upstream
sources or selected runtime behavior. Independent review tightened the
probe's empty-poll and timer lower timing bounds to the complete requested
20 milliseconds in r3; r2 is also retained.

`artifacts/rust-reactor-host-tests-r2.txt` records two passing host tests
that reject missing, duplicate and failed stages, altered versions,
incomplete timing observations and invalid expiration counts or durations.
The matching guest evidence is recorded below.

## Preserved initial guest findings

`artifacts/cosmic-reactor-r1/reactor/summary.json` records a normal failure
after every Waker test passed. The first `UnixStream` write reached missing
AArch64 syscall 206 (`sendto`), which Rust's standard library uses with
`MSG_NOSIGNAL`. The kernel returned ENOSYS, and the probe exited normally.
The separate `failure-cleanup.json` verifies complete process/grant/object
reclamation after that failure. Existing events, timerfd, shared-descriptor,
PTY, thread and Wayland regressions all passed against that same kernel;
their reports and exact commands are retained under `cosmic-reactor-r1`.

The next kernel provided the real sendto path. Its preserved
`artifacts/cosmic-reactor-r2/reactor/summary.json` passes all Waker/socket
observations and both 20 ms timer expirations, then records an EINVAL caused
by the probe's own malformed one-second timer specification. The r6 probe
uses `Duration`, checked seconds conversion and `subsec_nanos()` so its
one-second cancellation test requests a valid timespec. Earlier r4/r5 builds
also refresh build-helper provenance after those helpers changed; their
artifacts remain preserved.

## Verified native Mio, 2026-10-20

`artifacts/cosmic-reactor-r3/reactor/summary.json` passes three sequential
process launches, each with all 21 checks and both timer observations.
The frozen kernel SHA256 is
`45c4b52e96bc57cafce5433885e73ae3c9757a235d2c6d47a45171e408ef36c0`;
the report SHA256 is
`24e07d1f536e3348e915f4f5d78c1244090ddab661a7f0afbdd83114d30c4d29`.
It embeds the exact r6 ELF above and verifies current source/build/native
library identities and the actual ELF segment layout.

All three launches observe repeated Waker events without draining eventfd,
coalescing, a real thread wake, socket readiness/drain/rearm/registration/EOF,
two complete 20 ms timer expirations and valid one-second arm/cancel.
Measured timer intervals range from 20.702 to 21.773 ms. Every process has
one admitted worker thread, normal exit, zero fault registers and complete
thread/heap/image reclamation. Observed process, thread, memory and image
grant units match their releases; OFD, ancillary and shared-memory
objects/references return to zero.

This accepts the tested real Mio reactor on CyxiaOS. It does not establish
Tokio, polling, calloop or the complete COSMIC compositor event loop. The
report explicitly retains `calloop_verified=false` and
`cosmic_runtime_verified=false`.
