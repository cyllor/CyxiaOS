# A06 architectural register context subcase

This independent `register-v15-selftest` profile does not certify all of A06.
It uses the actual AArch64 `user::enter`/exception-return assembly and private
timer PPI, with two private EL0 contexts alternating on each CPU1–3. CPU0 boots
and coordinates all four CPUs. The SVC is an architectural `svc #0x606` boundary;
this profile does not invoke the POSIX syscall dispatcher.

EL0 checks fresh x19–x29, TPIDR_EL0, Q0–Q31, FPCR and FPSR are zero before
installing its own run-specific patterns. Each Q register has distinct low/high
64-bit values; sibling contexts have different seeds, FPCR and FPSR. All six
contexts require four actual timer returns and four actual SVC returns, with
the complete 832-byte Context copied at each observed return. Actual timer IRQ
counter deltas distinguish a timer PPI from an arbitrary lower-EL IRQ.

The 128-byte preboot-only config is `[magic,version,nonce(16),image SHA256(32),
source-manifest SHA256(32),input SHA256(32)]`. The guest never accepts host-written
results. The protected 45056-byte `REGISTER_V15_EVIDENCE` bank has a 64-word header:
magic/version/seal/online/count/error/timer-frequency/start-tick, then the
16 config words, then zero reserved words. Six 928-word task rows contain
CPU/local-index/seed/private-root/timer-count/SVC-count/fresh/ready/last-turn/
error/event-count/reserved. Eight 112-word events at row+32 contain
turn/entry-tick/return-tick/type/task-index/ready/previous-other-turn/IRQ-delta,
followed by the actual 104 Context words. The first four are timer returns;
the next four are SVC returns. The original turn numbers retain their order.
No ring wrap or overwritten event is accepted.

The runner captures two identical stopped banks after actual guest completion,
preserves ELF, build log/manifest, complete source map, frozen inputs, preboot
write packet, exact QMP operations, DTB, framed UART and closed process record.
The QMP CPU and memory queries must each occur exactly once before first resume.
The shared strict FDT parser checks the actual four Cortex-A53/PSCI CPU nodes,
1GiB RAM, GICv2 and fixed VirtIO transport layout, beyond header magic/length.
The independent verifier requires caller-selected trusted source, build and
QEMU checkouts. It never executes archived code or trusts a producer verdict.
Raw contract fixtures only yield `STRUCTURE_VALID` and `NOT_RUN`. A verified
live receipt yields `register_subcase_status=PASS`, while
`native_acceptance_status=NOT_RUN` and `full_a06_verified=false` remain explicit.

Commands (native execution must be scheduled separately from timed acceptance):

```
python3 -B tools/build_v15_registers.py --output artifacts/register-build
python3 -B tools/run_v15_registers.py --build artifacts/register-build --output artifacts/register-live --qemu /trusted/build/qemu-system-aarch64 --qemu-source /trusted --timeout 30
python3 -B tools/verify_v15_registers.py artifacts/register-live --build artifacts/register-build --source-root /trusted/source --qemu-source /trusted
python3 -B tools/audit_v15_register_receipt.py --receipt artifacts/register-live --build artifacts/register-build --source-root /trusted/source --qemu-source /trusted --output artifacts/register-mutations.json
```

Remaining native contracts: A06 concurrent object/capability revocation, TLB
acknowledgement before page reuse, external waits outside locks, delayed old
APPLY ordering and per-operation receipts; A07 exact malformed header/length/
index/digest/generation handling with unchanged resources and duplicate-key
retention/eviction; A09 anonymous sentinel under actual cache pressure with
zero/permissions/ownership checks; A11 simultaneous memory/completion/maintenance
and model-stop pressure, independent recovery resources and actual 100ms charges;
A15 model-timeout/unauthorized-candidate/full-control-queue plus expanded-CACP
death, exact snapshot+10000ms expiry, in-flight completion and healthy baseline.
None is inferred from the register subcase.

DOMAIN_CONTROL compatibility audit: the 640-word record's words21–24 were
unused by existing `parse_control`, `active_control_records` and the Rust
`verify-domain-evidence` example. They now optionally carry full output SHA256
for ownership replay, without changing their unrelated 24-word legacy inference
or training-bank layouts. Existing domain readers do not validate that digest;
the ownership verifier must do so explicitly. Nonzero extension compatibility
is covered by `test_domain_output_digest_compat.py`.
