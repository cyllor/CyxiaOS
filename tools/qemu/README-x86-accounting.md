# Pinned x86 execution clocks (ABI 1)

`cyxia-x86-execution.patch` is a **standalone** patch against QEMU `v10.2.2`,
commit `f8ed81651e61d9c2166df6121ce2af0f44f06b3e`. It does not apply or change
`cyxia-per-vcpu-pmu.patch`, the Arm source tree, its binary, or historical pins.
`x86-execution-manifest.json` separately binds the patch, six changed source
files, dependency commits, and clock ABI. It does not certify native timing.

| Interface | Exact value / meaning |
| --- | --- |
| CPUID `0x40000000` | Existing `TCGTCGTCGTCG` signature, max `0x40000001` |
| CPUID `0x40000001`.EAX | `0x43595831`, project magic |
| EBX | `0x00010007`: ABI 1; translated-TB/thread-CPU/shared-monotonic flags |
| ECX | `0x4b595801`, private execution MSR index |
| EDX | `1_000_000_000`, counter Hz, one tick = one ns |
| RDMSR `0x4b595801` | This vCPU's cumulative translated-TB thread CPU ns |
| RDMSR `0x4b595802` | Shared `QEMU_CLOCK_VIRTUAL` monotonic ns |

These are project-private MSRs, not architectural or KVM allocations. Both
reject writes with `#GP`. Missing, invalid or failed execution capability rejects
reads with `#GP`; an unknown stock-QEMU MSR reading zero is not a capability.
The guest validates the complete CPUID signature/leaf on every CPU before use.
The capability is present only inside the owning vCPU's translated execution,
on healthy MTTCG with no icount and `tcg-cpuid=on`.

The execution accumulator brackets `tcg_qemu_tb_exec()` and closes intervals
through longjmp cleanup. It charges translated guest code and synchronous
helpers, with the measurement overhead at the boundary. It excludes translation,
JIT setup, host descheduling/halted waits, sibling threads, and work after TB exit.
Clock initialization/read errors, backwards readings, nested starts and overflow
latch failure; a later successful host clock read never restores valid credits.
The shared monotonic clock advances across halted CPU waits and pauses with the
VM. It supports deadlines/leases/windows and **never execution debit**. VM reset
requires fresh guest clock handles; live migration is unsupported.

The guest adapter is `cyxia_arch_x86_64::accounting`:

- `unsafe ExecutionClock::init(logical_cpu, expected_apic_id)` binds a handle to
  the independently discovered xAPIC identity.
- `unsafe sample(&mut self)` produces `ExecutionStamp { cpu, source, ns }`.
- `elapsed_ns(start, end)` rejects changed CPU/source and clock regression.
- `add_debit_ns(total, delta)` rejects overflow.
- `unsafe monotonic(&mut self)` returns the distinct `MonotonicStamp` type.

Calls require CPL0 and no CPU migration through the call. Handles latch detected
errors. A hardware timing failure between capability validation and RDMSR raises
`#GP`; the kernel must fail the paid runtime rather than resume with free work.
KVM may run independent platform checks but cannot use this clock profile.

## Fresh preparation and build

The commands below are a recipe; they are not a claim that a binary or native
accounting observation has passed. Use a new `/private/tmp` destination. All
compilation and VM activity must take the existing shared native lease.
The builder takes that lease itself and checks that competing native/build tools
are idle. Use 1–4 jobs; the default is 2 for the current 32 GiB macOS host.

```sh
python3 tools/qemu/build_x86_accounting.py prepare \
  --base-source /Users/robin/cyxia-native/qemu-exact-20261106 \
  --destination /private/tmp/cyxia-v017-x86-accounting-20261114 \
  --fetch-dependencies
python3 tools/qemu/build_x86_accounting.py build \
  --source /private/tmp/cyxia-v017-x86-accounting-20261114 --jobs 2
python3 tools/qemu/x86_accounting.py \
  --source /private/tmp/cyxia-v017-x86-accounting-20261114 \
  --binary /private/tmp/cyxia-v017-x86-accounting-20261114/build/qemu-system-x86_64
```

Preparation clones tracked upstream source without copying historical changes.
Only `--fetch-dependencies` permits downloading the three explicit GitLab URLs
and exact revisions recorded in the manifest. `--dependency-cache DIR` instead
clones existing pinned Git repositories locally. Berkeley Meson overlay files
come from the pinned QEMU commit. Dependency file hashes are recorded after the
overlay. Configuration disables further downloads, builds only x86 softmmu,
and records compiler/tool/package identities, commands and complete logs.
Toolchain versions are recorded rather than claimed bit-for-bit reproducible
across different hosts. The source/binary receipt is not proof of guest behavior.

## Tests and native evidence requirements

```sh
python3 -m unittest discover -s tools/qemu -p 'test_x86_accounting.py' -v
cargo test --locked --offline -p cyxia-arch-x86_64 --test accounting
python3 tools/qemu/verify_x86_clock_core.py \
  --source /private/tmp/cyxia-v017-x86-accounting-20261114
```

The C fault harness extracts the attested accumulator unchanged and substitutes
its clock provider. It tests failed starts/stops, latched failure, last-read
regression, overflow, nested intervals, non-owner queries, excluded between-TB
work and idempotent cleanup. Its success proves logic, not native timing.

Native checks must separately retain raw busy/HLT/sibling/role-swap/exception
observations, monotonic intervals and predetermined tolerances. HLT measurement
includes real read/wake instructions, so exact-zero assertions are invalid.
The idle debit must stay within a predeclared measured-overhead bound and remain
far below its monotonic waiting interval even when a sibling is busy.
Stock QEMU, `thread=single`, wrong capability and injected failure must reject
accounting. `-cpu qemu64,cyxia-exec-fail-after-ns=0` explicitly injects immediate
failure; a positive per-vCPU cumulative execution threshold injects later failure.
Default `UINT64_MAX` disables injection. Injection must be recorded in launch
arguments and never accepted as a normal accounting run.

A native receipt must bind the clock ABI, current source/patch/binary provenance,
TCG multi/no-icount/no-migration profile, CPU identities, raw observations and
normal exit. Platform/SMP checks alone do not establish native timing, full
runtime completion, or A03 PASS.
