# A02 native scheduling capture

The v1.3 A02 assertion is: an ordinary business task's attempt to bind a control
CPU is rejected, and the complete scheduling trace contains no business entry
on C, T, or Q. The implementation uses the ordinary unified runtime and its
native `prototype-client`, not a second scheduler or a host-written event fixture.

## Execute

Build with `tools/build_unified.py --selftest` and the normal fault profile, then:

```sh
python3 tools/run_v13_a02.py \
  --build artifacts/v13-integration-build \
  --output artifacts/a02-native-UNIQUE \
  --formatter target/debug/examples/prototype-disk \
  --timeout 90
```

The runner requires the current compiled source map to match the build manifest.
It preserves the build commands/tool versions, compiled images, dependency lock,
target configuration, model and schemas, frozen input, disk identities, QEMU
binary identity and launch, the actual guest DTB, serial diagnostics, and QMP
transcript. Polling reads the seal while the VM runs. Only the final capture stops
the VM; periodic stops must not distort its wallclock budget windows.

## Protected observation points

`smp::enter_service` brackets the actual architectural `user::enter`. Every
unified caller supplies its protected context identity and role: the cluster
broker, native controller, learning worker, ordinary task dispatcher, remote
pure task, and built-in SMP memory probes/business loops. The desktop user
entry implementation is excluded from the unified feature configuration.

The ordinary task ABI operation 21 calls `Scheduler::bind_affinity` while the
task ownership gate is held. The scheduler checks current business ownership,
health, the previously admitted affinity, and retention of the current CPU.
It does not implicitly migrate the context or enlarge its admission. The client
requests mask 2 and checks the actual E_AUTH return. No capture-specific path
authorizes or rejects this request.

The capture uses an EL1-only bounded event array, a serialized total order, and
separate boundary accounting. Entry/exit/admission counters update independently
of event append; overflow retains counters and marks loss instead of wrapping.
The initial configuration contains only artifact hashes and a fresh run nonce.
QEMU supplies those before boot to avoid an image hashing itself. BootEpoch
comes from the actual guest's durable storage boot, not that configuration.

The statically reserved 8192-event array occupies 1 MiB; the task roster, counters
and bookkeeping bring the capture state to 1,070,304 bytes in the current layout.
The configuration consumes a further 512 bytes. These are declared kernel test
instrumentation allocations outside the 8 MiB control pool and part of the
kernel's actual physical image reservation.

After business/control progress and a real rejected business-to-C admission,
new EL0 entries park and existing entries finish. A successful seal requires no
active EL0 interval. The VM is then stopped and the trace and counters are read
directly from physical memory at symbol-derived addresses.

## Wire versions and independent checking

The raw decoder in `tools/verify_v13_a02.py` supports the original version 1
fixtures and native version 2. Version 2 permits registration before each task
generation's first entry. Binding events follow an actual return and identify
that exact protected caller and return-origin CPU. The broker can handle a
deferred SVC while another task executes on the original CPU; eligibility is
retained per task and revoked when that same task enters again. Task
roles remain immutable, and no task may execute concurrently on two CPUs.

The raw decoder alone always reports NOT_RUN. Native receipt verifier revision
`a02-native-v4` still decodes wire version 2. It accepts QEMU 10.2's paused
status reply without the deprecated `singlestep` field; if present the field
must be false. The reply must uniquely report `status=paused` and `running=false`.
It rejects duplicate JSON keys,
nonfinite JSON numbers and symlinks in any artifact path component, and bounds
both document and QMP JSONL input. `verify_native_receipt` additionally
checks the immutable build/source/image binding, observed preboot input, exact
launch configuration, successful QMP requests and stopped-memory provenance,
durable BootEpoch, and runtime model/schema identity. It ignores producer PASS
booleans. The runner calls this independent receipt check before returning PASS.
A successful local check sets `native_execution_verified=true`; it always keeps
`runtime_truth_attested=false`. The QMP/RSP and source/build chain is local
execution evidence, not a signed QEMU or hardware attestation.

`check_v13_evidence.py` registers only the fixed A02 native PASS adapter. It
requires the artifact to name `summary.json`, replays the receipt against the
catalogue caller's source root, and rejects native FAIL classification until a
separate failure classifier exists. The default catalogue remains 69 NOT_RUN;
adapter coverage alone never changes a test result.

For historical replay, the operator can explicitly call
`verify_native_receipt(directory, source_root=frozen_checkout)`. The receipt
cannot select this directory or a checker. The frozen checkout must match all
compiled source files and the recorded builder. Capture tool identities must
match either the current reviewed pair or the exact archived runner/verifier
pair from `artifacts/a02-native-20261026-paused-status-v4`, whose actual files
were hashed and whose receipt was independently replayed before enrolment.
This single historical exception preserves the real run after verifier
maintenance; archive scripts are never imported or executed, and unknown pairs
are rejected. Later production changes still require new source-bound execution
before the current catalogue can record PASS.

The receipt's scope is A02 only. Separate budget/quarantine diagnostics are
preserved, and a successful permission case does not certify training, action
coverage, throughput, migration fault handling, or full v1.3 acceptance.

## Remaining review boundary

The current outer coordinator ownership hooks fail closed if a capture reaches
a compound handoff that advances through T and publication in one call: the raw
decoder rejects the skipped intermediate generation. A02 is intended to seal
after the client's initial hostile request, before that handoff. Broader A03/A04
captures require instrumentation at each internal ownership mutation, including
the retained draining flag while a reliably stopped CPU is in T. No receipt may
silently omit those states or relax the zero-violation entry checks.
