# A03 actual model-to-owner evidence, A04 partial observations

This increment adds an actual-call-site chain. It does not claim A03 until a
new native execution independently replays, and does not claim complete A04.

`OWNERSHIP_V15_EVIDENCE` is a 64-byte aligned bank of 7296 little-endian u64
words: a 128-word header plus eight 896-word attempts. It records observations
only. No core target, score, candidate, owner or acknowledgment is injected by
the collector. Normal CACP must genuinely choose and execute both directions.

Header: magic `0x43594f574e313531`, schema 1, word count, observed BootEpoch,
attempt count, overflow count, runtime fault profile, reserved zero, row words,
slot count, completed model-witness count, completed executor count. Words
16..29 bind the original preboot nonce and image/input/source hashes; all other
header words are reserved zero. Overflow, incomplete attempts and non-normal
fault profiles cannot pass the A03 verifier.

Each row begins with a seqlock and stage mask: accepted=1, draining=2, actual
owner publication=4, immutable model witness=8, actual executor completion=16.
Failure adds bit 64 and retains a failed-owner snapshot instead of manufacturing
completion. Metadata words 2..7 are the complete actual ApplyId; 8 desired
mask, 9 original snapshot ns, 10 accepted ns, 11 real handoff operation, 12
approved version, 14 original model job sequence, 15 completed-copy validity,
16 header-copy words, 17 original domain-evidence slot, 18..19 frozen executor
core/composite-ledger generations. This distinguishes the combined policy
ledger generation from the Cores ledger's separate generation.

Four sixteen-word state snapshots start at relative offsets 32, 48, 64 and 80:
accepted, draining, actual published ownership, actual completion. Each stores
fresh ns, online/C/B/T/Q/draining/suspect masks, actual Cores core/ledger
generations, the retained accounting window, CPU2's real committed and spent
milli, native stop-domain mask, stop operation and actual CPU2 stop ACK. The
window is read from `Cores::budget_window()`, not guessed from wall time. The
published snapshot is captured after `owner.publish` and before re-opening the
physical dispatch gate. Missing ACK failure is stored at offset 96.

At relative offset 128, 32 original `DOMAIN_CONTROL_EVIDENCE` header words are
copied. Offset 192 stores the complete original 640-word record, including its
4096-byte raw ABI3 input, real first 64 EL0 reply words, original 4096-byte
output digest, input digest, approved version, costs and actual APPLIED receipt.
Copying occurs under the original control-owner gate after actual `progress`,
before the original 64-slot ring can reuse the completed row. No separate lock,
wait or permission is introduced. The original already-computed output digest
is stored in the record's formerly unused words 21..24; it is not recomputed in
the guest.

Production hooks:

1. `domain_services::core_apply` freezes the executor's real context. The native
   coordinator consumes that exact request and records its accepted ApplyId.
2. `core_action_turn` records the actual `propose`-created handoff operation and
   draining source ownership. The source owner/reservation remain intact.
3. `Coordinator::poll_handoff` records actual owner publication while the gate
   is still closed, using the native stop facts actually passed to Handoff.
4. Only successful `domain_services::core_complete` records executor completion.
5. Only actual ControlSet APPLIED reconciliation copies the matching immutable
   original model row and output digest. A baseline or proposal-only row lacks
   that model-to-effect chain and cannot pass.

The structural checker rejects a script ABI, mismatched ApplyId/DecisionKey,
different target/model context, missing source reservation/debt, overlapping
owners, missing stop ACK, non-linear generations, proposal-only or uncompleted
records. It verifies the actual sequence C=2 -> C=6 -> C=2. Structural success
is explicitly `STRUCTURE_VALID`/NOT_RUN, never formal acceptance by itself.

The trusted-source Rust helper reconstructs typed candidates and their hash,
runs the full 64->32->16->1 integer model on every alternative, checks the real
scores and first-maximum selection, reconstructs the complete one-action Plan,
and matches the model/output hash and exact selected ApplyId/DecisionKey. It
also requires observed control pressure to decline between the two directions
and preserves unchanged CPU, publication and proposal wall budgets. A mutable
checksum alone cannot validate a changed candidate/score.

The independent Python adapter first checks exact ELF/build/source/tool/model/
configuration provenance and strict stopped QMP addresses, lengths and order.
It checks both stopped ownership banks, their frozen run identity and immutable
first facts, compiles the helper from the caller-selected trusted source (never
an archive-selected executable), and verifies both banks against the actual
ELF model package. Only the combined pipeline can return per-case A03 PASS.

```sh
python3 tools/run_v15_a03.py --build NEW_BUILD --output NEW_OUTPUT \
  --formatter target/debug/examples/prototype-disk \
  --qemu TRUSTED_QEMU/build/qemu-system-aarch64 --qemu-source TRUSTED_QEMU --timeout 60
python3 tools/verify_v15_ownership.py --directory NEW_OUTPUT \
  --source-root EXACT_SOURCE --qemu-source TRUSTED_QEMU
```

If normal production load does not actually produce both choices, the runner
times out and retains `failure-ownership.bin`; it never drives the target mask
directly or turns a hand-authored score vector into native evidence.

For A04, the same bank retains accepted/draining/published/failed collection,
generations and actual capacity across no-ACK expiry. That is useful evidence,
but not a full fault matrix. The existing IRQ/DMA owner anchors still make
CPU2's relevant device domains empty. The stop mask, including 63, does not
prove in-flight IRQ/DMA intersection. Complete A04 still requires real
DRAIN/QUIESCED/PUBLISH fault profiles crossed with actual device routing,
pending DMA/page obligations, generation changes and reliable quarantine
proofs. The adapter leaves `a04_device_intersection_verified=false`.
