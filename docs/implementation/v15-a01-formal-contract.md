# A01 native boot authority contract

This contract implements configuration 1.3 A01. It adds positive architectural
and first-authority facts to the existing stopped boot regression and exact
eight-boot disk lineage. It does not turn an older regression result into a
formal PASS. A new image and new executions are required.

## Native boundary mapping

`A01_FORMAL_EVIDENCE` is 256 little-endian u64 words (2048 bytes), never a guest
configuration input. Only the existing 512-byte `A01_BOOT_CONFIG` is written
before boot; the independent QMP replay rejects other memory writes.

| Words | Meaning and actual writer |
| --- | --- |
| 0..2 | Magic `0x4359413031463031`, schema 1, 256 words. Header magic is release-published by boot initialization. |
| 3..7 | Mode, durable BootEpoch, durable hardware ticks, model-passed ticks, activation ticks; copied at the original durable/model/activation boundaries with exactly the values retained by `A01_BOOT_EVIDENCE`. |
| 8, 9 | Model candidate-key registration and successful model publication counts; updated under the existing control-owner serialization. |
| 10 | Sticky ordering-violation bits. Any key/publication without matching durable epoch, completed model self-test and activation invalidates acceptance. |
| 11..15 | Reserved zero. |
| 16..29 | Exact original two-word nonce and image/input/source hash words from the preboot configuration. |
| 30..31 | Reserved zero. |
| 32 + CPU×24 | Four per-CPU rows. Each CPU is the sole writer of its row. |
| 128..151 | First actual model candidate registration, release-published once. |
| 152..159 | Reserved zero. |
| 160..184 | First actual successful model publication, release-published once. |
| 185..255 | Reserved zero. |

Each architecture row contains the following relative words:

| Relative words | Meaning |
| --- | --- |
| 0 | EL1 observation publication: 0 absent, 1 incomplete, 2 complete. |
| 1..8 | Slot, hardware ticks, actual CurrentEL, SCTLR_EL1, TCR_EL1, TTBR1_EL1, VBAR_EL1, MPIDR_EL1. Captured on CPU0 entering `smp::run`, and secondary CPUs immediately before their actual ONLINE publication. |
| 9..11 | Reserved zero. |
| 12 | First actual captured service EL0-return publication, with the same 0/1/2 protocol. |
| 13..22 | Return ticks, saved SPSR, ESR, return kind, PC, supplied process root, actual TTBR0_EL1, post-return TCR_EL1, actual CurrentEL, task role. Captured directly after the actual `user::enter`/`enter_immutable` return, outside integer-only mapping probes. |
| 23 | Reserved zero. |

Four CPUs must actually observe EL1 with MMU, instruction/data caches, kernel
root and aligned vectors. Any present EL0 observation must be complete and
show EL0t, a real SVC64/preemption return, the actual matching private TTBR0,
and restored EPD0 low-walk revocation. Normal and model-corruption profiles
must show the control model on CPU1 and independently observed business EL0
with a different root. Epoch allocation failure must not require the model to
run; business EL0 and the original two-sample business/timer progress remain
mandatory. CPU0 is not arbitrarily required to execute EL0.

The first-key row relative fields are: publication, observation ticks, boot,
controller epoch, decision sequence, target id/generation, observing CPU,
model generation, domain/kind, reserved zero, four candidate hash words, four
model hash words, prior registry root version, core generation, ledger
generation, control mask. The hook runs only after actual non-read-only
`commit_candidates`/`register` success in `encode_job_inner`. It records the
identity allocated to the production job, including attempts that later fail.

The first-publication row fields are: publication, ticks, boot, controller,
decision sequence, target id/generation, observing CPU, plan sequence,
published version, model generation, domain/kind, candidate hash, model hash,
snapshot sequence, core generation, ledger generation, control mask. The hook
runs only after `Executor::publish` has successfully passed all fallible
commit calls and written the actual desired objects, immediately before its
successful return. An owner-approved baseline has `score_count == 0` and
cannot serve as the positive model publication witness.

Both keys must belong to the observed durable boot and a current control CPU;
the first publication cannot precede the first registered model decision or
activation. If it publishes that same first decision, target and model/candidate
hashes must match exactly. Otherwise the publication sequence must be later.
Unknown/unsettled authority is not invented into a completed publication.
There is no synthetic credit field: these hooks remain inside the original
paid control slices and do not alter reservations or budgets.

## Capture and independent replay

```sh
python3 tools/run_v15_a01.py --build NEW_SELFTEST_BUILD --output NEW_EVIDENCE \
  --formatter target/debug/examples/prototype-disk \
  --qemu TRUSTED_QEMU/build/qemu-system-aarch64 --qemu-source TRUSTED_QEMU --timeout 60
python3 tools/verify_v15_a01.py --directory NEW_EVIDENCE \
  --source-root SOURCE_CHECKOUT --qemu-source TRUSTED_QEMU
```

The runner uses exactly the existing ordered eight scenarios: cold, restart,
epoch-write, after-write, epoch-flush, after-flush, model-corrupt, after-model.
Only cold is formatted. A failure blocks descendants and retains its original
disk, stopped diagnostics and raw transport. No retry-until-green is allowed.

Normal captures wait for actual key and publication evidence; activation alone
is insufficient. Every case records `formal-first.bin` and `formal-last.bin`
inside the same verified QMP stopped capture groups as the original boot
snapshots. Live probes are solely readiness polling and cannot supply evidence.
The independent verifier resolves symbol address/size from the ELF, checks
strict QMP ordering, hashes every artifact and trusted tool revision, binds
source/build/config/platform/model, validates both raw authority samples and
replays every closed-process disk handoff and persistent epoch transition.
Producer PASS flags and claimed observations are ignored.

`verify_v15_a01.py` may return a per-case A01 PASS only after those new native
facts independently replay. `runtime_truth_attested` remains false: the result
is trusted-emulator software evidence, not cryptographic hardware attestation.
Full configuration-1.3 acceptance remains separate.

## A03/A04 obligations not covered by A01

A03 still needs a model-selected actual 1→2→1 trace under distinguishable
control-load rise/fall: full frozen input/candidates/scores, DecisionKey and
approved versions, executor receipt and exact ownership-generation
linearization. Scripted ownership transitions or host ownership tests cannot
substitute for the native model trace.

A04 still needs native fault injections at DRAIN, QUIESCED and PUBLISH, crossed
with actual IRQ routing and in-flight DMA obligations. Each record must retain
the source owner, draining/suspect state, stop proof/ACK, old/new generations,
task/IRQ/DMA/page custody and capacity before/after. Missing ACK must retain
the old C/B owner plus suspect without inventing quiescence or capacity; only
reliable stop proof may transfer to Q. It must also prove no new ordinary IRQ
dispatch to C/T/Q, suspect or draining CPUs. The existing host
`native_core_replay`, `native_irq_replay` and ownership fault tests are useful
seams, but these assertions still require actual guest fault/effect evidence
under the same frozen source.
